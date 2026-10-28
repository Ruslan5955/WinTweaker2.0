"""guard.py: движок антивирусной проверки WinTweaker (без интерфейса).

Что умеет: проверка по базе хэшей, эвристика (маскировка под документы, подделка
под системные процессы, упаковка, опасные скрипты и ярлыки), карантин,
наблюдение за новыми файлами, аудит процессов, автозагрузки, hosts и соединений,
проверка хэша на VirusTotal (по вашему API-ключу).

Это дополнение к Защитнику Windows, а не замена: нет драйвера уровня ядра,
облачной базы и поведенческой блокировки.
"""
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "WinTweaker")
QUAR_DIR = os.path.join(DATA_DIR, "Quarantine")
BLOCKLIST_FILE = os.path.join(DATA_DIR, "blocklist.txt")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# Встроенная сигнатура: тестовый файл EICAR (безопасный, им проверяют антивирусы)
BUILTIN_HASHES = {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File"}

PE_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".pif"}
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
EXEC_EXT = PE_EXT | SCRIPT_EXT | {".msi", ".jar", ".lnk"}
DISGUISE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".mp3", ".mp4"}

RISKY_DIRS = ("\\temp\\", "\\downloads\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\", "$recycle.bin")
PROC_RISKY_DIRS = ("\\temp\\", "\\downloads\\", "\\users\\public\\", "$recycle.bin")
SKIP_DIRS = {"winsxs", "$recycle.bin", "system volume information", "windows defender", "node_modules", ".git"}
MAX_SIZE = 300 * 1024 * 1024
THRESHOLD = 30

SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe",
    "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "wininit.exe", "dwm.exe", "conhost.exe", "rundll32.exe",
    "dllhost.exe", "searchindexer.exe", "audiodg.exe", "ctfmon.exe", "runtimebroker.exe", "fontdrvhost.exe",
    "sihost.exe", "wmiprvse.exe",
}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\s*\.(exe|scr|com|bat|cmd|js|vbs|ps1|lnk|hta)$")

PATTERNS = [
    (r"-enc(odedcommand)?\s+[a-z0-9+/=]{20,}", 35, "PowerShell с закодированной командой"),
    (r"frombase64string", 20, "Декодирование Base64"),
    (r"invoke-expression|\biex\b\s*[\(\$]", 25, "Выполнение строки как кода (IEX)"),
    (r"downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer", 25, "Загрузка из сети"),
    (r"-w(indowstyle)?\s+hidden", 20, "Скрытое окно"),
    (r"certutil.{0,40}-urlcache|bitsadmin.{0,40}/transfer", 35, "Загрузка через certutil/bitsadmin"),
    (r"mshta\s+https?://|regsvr32.{0,40}/i:https?://", 40, "Запуск удалённого кода"),
    (r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete|bcdedit.{0,60}recoveryenabled\s+no", 60,
     "Удаление точек восстановления (признак шифровальщика)"),
    (r"wscript\.shell|shell\.application", 10, "Запуск программ из скрипта"),
    (r"set-mppreference.{0,40}disablerealtimemonitoring\s+\$?true|add-mppreference.{0,30}exclusionpath", 50,
     "Отключение защиты Защитника Windows"),
    (r"schtasks.{0,20}/create.{0,200}(appdata|temp)", 25, "Задача планировщика из Temp/AppData"),
    (r"reg(\.exe)?\s+add.{0,80}\\run\b", 15, "Запись в автозапуск"),
]
COMPILED = [(re.compile(p, re.I | re.S), w, label) for p, w, label in PATTERNS]


def ensure_dirs():
    os.makedirs(QUAR_DIR, exist_ok=True)


@dataclass
class ScanResult:
    path: str
    score: int
    verdict: str
    reasons: List[str] = field(default_factory=list)
    sha256: str = ""


# ---------- Конфиг и база хэшей ----------
def load_config() -> dict:
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    ensure_dirs()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def load_blocklist() -> Dict[str, str]:
    bl = dict(BUILTIN_HASHES)
    try:
        with open(BLOCKLIST_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split(None, 1)
                if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                    bl[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else "Known-Malware"
    except OSError:
        pass
    return bl


def import_blocklist(path: str) -> int:
    """Добавляет SHA-256 из текстового/CSV-файла (по одному в строке). Возвращает число новых."""
    ensure_dirs()
    known = load_blocklist()
    new = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            for token in re.split(r"[\s,;\"']+", line):
                if re.fullmatch(r"[0-9a-fA-F]{64}", token) and token.lower() not in known:
                    new[token.lower()] = "Imported"
    if new:
        with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
            for h, n in new.items():
                f.write(f"{h} {n}\n")
    return len(new)


# ---------- Проверка файла ----------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def hash_and_sample(path: str, sample_size: int = 8 * 1024 * 1024) -> Tuple[str, bytes]:
    h = hashlib.sha256()
    sample = bytearray()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            if len(sample) < sample_size:
                sample += chunk[: sample_size - len(sample)]
    return h.hexdigest(), bytes(sample)


_sig_cache: Dict[str, bool] = {}


def is_signed(path: str) -> bool:
    """Есть ли действительная цифровая подпись (только Windows)."""
    if sys.platform != "win32":
        return False
    if path in _sig_cache:
        return _sig_cache[path]
    safe = path.replace("'", "''")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-AuthenticodeSignature -LiteralPath '{safe}').Status"],
                           capture_output=True, text=True, timeout=20, creationflags=NO_WINDOW)
        ok = r.stdout.strip() == "Valid"
    except (OSError, subprocess.SubprocessError):
        ok = False
    _sig_cache[path] = ok
    return ok


def verdict_for(score: int) -> str:
    return "Опасно" if score >= 70 else "Подозрительно" if score >= 40 else "Низкий риск"


def scan_file(path: str, blocklist: Optional[Dict[str, str]] = None, check_sig: bool = True) -> Optional[ScanResult]:
    blocklist = blocklist if blocklist is not None else load_blocklist()
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not os.path.isfile(path) or st.st_size == 0 or st.st_size > MAX_SIZE:
        return None
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    p = path.lower().replace("/", "\\")
    risky = any(m in p for m in RISKY_DIRS)
    if ext not in EXEC_EXT and not (ext in DISGUISE_EXT and risky):
        return None
    try:
        digest, sample = hash_and_sample(path)
    except OSError:
        return None

    if digest in blocklist:
        return ScanResult(path, 100, "Опасно", [f"Известная угроза: {blocklist[digest]}"], digest)

    score, reasons = 0, []
    is_pe = sample[:2] == b"MZ"

    if is_pe and ext in DISGUISE_EXT:
        score += 60
        reasons.append(f"Исполняемый файл замаскирован под «{ext}»")
    if DOUBLE_EXT.search(name):
        score += 50
        reasons.append("Двойное расширение (документ.exe)")
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower().replace("/", "\\")
    if name in SYSTEM_NAMES and not p.startswith(windir + "\\"):
        score += 70
        reasons.append("Имитирует системный файл, но лежит не в папке Windows")
    if is_pe and ext in PE_EXT and risky and len(sample) > 4096 and entropy(sample) >= 7.3:
        score += 25
        reasons.append("Высокая энтропия: файл, вероятно, упакован или зашифрован")
    if ext in SCRIPT_EXT:
        text = sample[:2 * 1024 * 1024].decode("utf-8", errors="ignore")
        if "\x00" in text:
            text = sample[:2 * 1024 * 1024].decode("utf-16-le", errors="ignore")
        s = 0
        for rx, w, label in COMPILED:
            if rx.search(text):
                s += w
                reasons.append(label)
        score += min(s, 80)
    if ext == ".lnk":
        text = sample.replace(b"\x00", b"").decode("latin-1").lower()
        if re.search(r"powershell|mshta|wscript|cscript|cmd\.exe /c", text) and "http" in text:
            score += 50
            reasons.append("Ярлык запускает скрипт и обращается к сети")
    if ext in PE_EXT and os.path.exists(os.path.join(os.path.dirname(path), "autorun.inf")):
        drive_root = os.path.dirname(os.path.abspath(path)).rstrip("\\/")
        if len(drive_root) <= 3:
            score += 40
            reasons.append("Лежит в корне диска рядом с autorun.inf")

    score = min(score, 99)
    if score < THRESHOLD:
        return None
    if check_sig and is_pe and score < 70 and is_signed(path):
        return None
    return ScanResult(path, score, verdict_for(score), reasons, digest)


# ---------- Обход папок ----------
def quick_roots() -> List[str]:
    env = os.environ
    home = os.path.expanduser("~")
    cands = [
        os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), env.get("TEMP", ""),
        env.get("APPDATA", ""), os.path.join(env.get("LOCALAPPDATA", ""), "Temp") if env.get("LOCALAPPDATA") else "",
        env.get("PUBLIC", ""), env.get("PROGRAMDATA", ""), os.path.join(env.get("SystemRoot", ""), "Temp") if env.get("SystemRoot") else "",
        os.path.join(env.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup") if env.get("APPDATA") else "",
        os.path.join(env.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp") if env.get("PROGRAMDATA") else "",
    ]
    return [c for c in dict.fromkeys(cands) if c and os.path.isdir(c)]


def fixed_drives() -> List[str]:
    drives = []
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if mask & (1 << i):
                d = f"{chr(65 + i)}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(d) in (2, 3):  # съёмный или жёсткий
                    drives.append(d)
    except Exception:
        pass
    return drives


def iter_files(roots: Iterable[str], stop: threading.Event, skip_paths: Iterable[str] = ()) -> Iterator[str]:
    skip = {s.lower().rstrip("\\/") for s in skip_paths}
    for root in roots:
        if stop.is_set():
            return
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if stop.is_set():
                return
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS
                           and os.path.join(dirpath, d).lower().rstrip("\\/") not in skip]
            for fn in filenames:
                yield os.path.join(dirpath, fn)


def scan_paths(roots, stop, progress: Optional[Callable] = None, on_result: Optional[Callable] = None,
               blocklist=None, skip_paths=()) -> int:
    blocklist = blocklist if blocklist is not None else load_blocklist()
    count = 0
    for path in iter_files(roots, stop, skip_paths):
        count += 1
        if progress and count % 25 == 0:
            progress(count, path)
        r = scan_file(path, blocklist)
        if r and on_result:
            on_result(r)
    return count


# ---------- Карантин ----------
def quarantine(result: ScanResult) -> str:
    ensure_dirs()
    qid = uuid.uuid4().hex[:12]
    shutil.move(result.path, os.path.join(QUAR_DIR, qid + ".quar"))
    meta = {"id": qid, "path": result.path, "sha256": result.sha256, "verdict": result.verdict,
            "reasons": result.reasons, "time": time.strftime("%Y-%m-%d %H:%M")}
    with open(os.path.join(QUAR_DIR, qid + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False)
    return qid


def list_quarantine() -> List[dict]:
    ensure_dirs()
    items = []
    for fn in sorted(os.listdir(QUAR_DIR)):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(QUAR_DIR, fn), encoding="utf-8") as f:
                    items.append(json.load(f))
            except (OSError, ValueError):
                pass
    return items


def restore(qid: str) -> str:
    with open(os.path.join(QUAR_DIR, qid + ".json"), encoding="utf-8") as f:
        meta = json.load(f)
    target = meta["path"]
    if os.path.exists(target):
        target += ".restored"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.move(os.path.join(QUAR_DIR, qid + ".quar"), target)
    os.remove(os.path.join(QUAR_DIR, qid + ".json"))
    return target


def delete_quarantined(qid: str) -> None:
    for ext in (".quar", ".json"):
        try:
            os.remove(os.path.join(QUAR_DIR, qid + ext))
        except FileNotFoundError:
            pass


# ---------- Мониторинг новых файлов ----------
class Monitor:
    """Раз в несколько секунд ищет новые или изменённые файлы и проверяет их."""

    def __init__(self, on_result: Callable, blocklist=None, folders: Optional[List[str]] = None, interval: float = 4.0):
        home = os.path.expanduser("~")
        self.folders = folders or [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"),
                                   os.environ.get("TEMP", "")]
        self.folders = [f for f in self.folders if f and os.path.isdir(f)]
        self.on_result, self.blocklist, self.interval = on_result, blocklist, interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _files(self):
        n = 0
        for folder in self.folders:
            base = folder.rstrip("\\/").count(os.sep)
            for dirpath, dirnames, filenames in os.walk(folder, onerror=lambda e: None):
                if dirpath.count(os.sep) - base >= 3:
                    dirnames[:] = []
                for fn in filenames:
                    n += 1
                    if n > 30000:
                        return
                    yield os.path.join(dirpath, fn)

    def _loop(self):
        seen: Dict[str, tuple] = {}
        pending: Dict[str, tuple] = {}
        first = True
        while not self._stop.wait(self.interval):
            for path in self._files():
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                sig = (st.st_size, st.st_mtime)
                if first:
                    seen[path] = sig
                    continue
                if seen.get(path) == sig:
                    continue
                if pending.get(path) == sig:  # размер не меняется: файл докачался
                    seen[path] = sig
                    pending.pop(path, None)
                    r = scan_file(path, self.blocklist)
                    if r:
                        self.on_result(r)
                else:
                    pending[path] = sig
            first = False


# ---------- VirusTotal ----------
def vt_lookup(sha256: str, api_key: str) -> dict:
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"unknown": True}
        raise
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values())}


# ---------- Аудиты (Windows) ----------
def _powershell_json(command: str):
    r = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True,
                       errors="ignore", creationflags=NO_WINDOW)
    out = (r.stdout or "").strip()
    if not out:
        return []
    data = json.loads(out)
    return [data] if isinstance(data, dict) else data


def audit_processes() -> Tuple[int, List[dict]]:
    procs = _powershell_json("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress")
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower()
    flagged = []
    for p in procs:
        path = p.get("ExecutablePath") or ""
        name = (p.get("Name") or "").lower()
        low = path.lower().replace("/", "\\")
        reasons = []
        if low and any(m in low for m in PROC_RISKY_DIRS):
            reasons.append("Запущен из временной папки, Загрузок или общей папки")
        if name in SYSTEM_NAMES and low and not low.startswith(windir):
            reasons.append("Имя как у системного процесса, но файл не в папке Windows")
        if reasons:
            flagged.append({"pid": p.get("ProcessId"), "name": p.get("Name"), "path": path, "reasons": reasons})
    return len(procs), flagged


def list_connections() -> List[dict]:
    cmd = (r"Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.)' } | "
           r"ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
           r"[PSCustomObject]@{Proc=$p.ProcessName; Pid=$_.OwningProcess; Remote=$_.RemoteAddress; Port=$_.RemotePort; Path=$p.Path} } "
           r"| ConvertTo-Json -Compress")
    return _powershell_json(cmd)


def defender_status() -> dict:
    cmd = ("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,"
           "IoavProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,"
           "QuickScanEndTime,FullScanEndTime | ConvertTo-Json -Compress")
    data = _powershell_json(cmd)
    return data[0] if data else {}


WATCH_DOMAINS = ("microsoft", "windowsupdate", "google", "kaspersky", "avast", "eset", "drweb", "malwarebytes",
                 "mcafee", "norton", "virustotal", "bitdefender", "yandex", "github", "vk.com")


def audit_hosts() -> Tuple[str, List[Tuple[str, str]], List[Tuple[str, str]]]:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    entries, flagged = [], []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split()
                if len(parts) >= 2:
                    for host in parts[1:]:
                        entries.append((parts[0], host))
                        if any(w in host.lower() for w in WATCH_DOMAINS):
                            flagged.append((parts[0], host))
    except OSError:
        pass
    return path, entries, flagged


def suspicious_command(cmd: str) -> List[str]:
    """Проверка строки автозапуска."""
    low = cmd.lower().replace("/", "\\")
    reasons = []
    if any(m in low for m in ("\\temp\\", "\\downloads\\", "\\users\\public\\", "$recycle.bin")):
        reasons.append("запуск из временной или общей папки")
    for rx, w, label in COMPILED:
        if w >= 20 and rx.search(cmd):
            reasons.append(label)
    if re.search(r"\b(wscript|cscript|mshta)\b", low):
        reasons.append("запуск через сценарии Windows")
    return reasons


def write_eicar(folder: str) -> str:
    """Создаёт безопасный тестовый файл EICAR (строка собирается из двух частей)."""
    a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    b = "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    path = os.path.join(folder, "eicar_test.com")
    with open(path, "wb") as f:
        f.write((a + b).encode("ascii"))
    return path
