import hashlib
import os
import threading

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def make_downloads(tmp_path):
    d = tmp_path / "Users" / "x" / "Downloads"
    d.mkdir(parents=True)
    return d


def scan(guard, path):
    return guard.scan_file(str(path), guard.load_blocklist(), check_sig=False)


def test_eicar_detected_by_hash(guard, tmp_path):
    d = make_downloads(tmp_path)
    p = guard.write_eicar(str(d))
    assert hashlib.sha256(open(p, "rb").read()).hexdigest() == EICAR_SHA256
    r = scan(guard, p)
    assert r and r.score == 100 and r.verdict == "Опасно"


def test_exe_disguised_as_jpg(guard, tmp_path):
    p = make_downloads(tmp_path) / "photo.jpg"
    p.write_bytes(b"MZ" + os.urandom(3000))
    r = scan(guard, p)
    assert r and r.score >= 60


def test_double_extension(guard, tmp_path):
    p = make_downloads(tmp_path) / "invoice.pdf.exe"
    p.write_bytes(b"MZ" + b"A" * 100)
    r = scan(guard, p)
    assert r and any("Двойное расширение" in x for x in r.reasons)


def test_ransomware_like_script(guard, tmp_path):
    p = make_downloads(tmp_path) / "run.ps1"
    p.write_text("powershell -w hidden -enc " + "QUJD" * 10 + "\nvssadmin delete shadows /all")
    r = scan(guard, p)
    assert r and r.verdict == "Опасно"


def test_clean_files_not_flagged(guard, tmp_path):
    d = make_downloads(tmp_path)
    (d / "notes.txt").write_text("hello")
    (d / "ok.bat").write_text("echo hi")
    assert scan(guard, d / "notes.txt") is None
    assert scan(guard, d / "ok.bat") is None


def test_scan_paths_counts_and_finds(guard, tmp_path):
    d = make_downloads(tmp_path)
    guard.write_eicar(str(d))
    (d / "a.txt").write_text("x")
    found = []
    n = guard.scan_paths([str(tmp_path)], threading.Event(), None, found.append)
    assert n == 2 and len(found) == 1


def test_quarantine_restore_delete(guard, tmp_path):
    d = make_downloads(tmp_path)
    p = guard.write_eicar(str(d))
    r = scan(guard, p)
    qid = guard.quarantine(r)
    assert not os.path.exists(p) and len(guard.list_quarantine()) == 1
    assert os.path.exists(guard.restore(qid))
    qid = guard.quarantine(r)
    guard.delete_quarantined(qid)
    assert guard.list_quarantine() == []


def test_import_blocklist(guard, tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text(f"{'a' * 64}\nfoo,{'b' * 64},bar\nnot a hash\n")
    before = len(guard.load_blocklist())
    assert guard.import_blocklist(str(f)) == 2
    assert len(guard.load_blocklist()) == before + 2
    assert guard.import_blocklist(str(f)) == 0  # повторно ничего нового


def test_suspicious_startup_command(guard):
    assert guard.suspicious_command(r"C:\Users\x\AppData\Local\Temp\a.exe")
    assert not guard.suspicious_command(r"C:\Program Files\App\app.exe")
