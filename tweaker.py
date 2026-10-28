"""WinTweaker 3.0: твикер настроек Windows 10/11 со встроенным антивирусным сканером.

Каждый твик описан данными (ключ реестра, значение «вкл» и «выкл»),
поэтому любое изменение возвращается обратно тем же переключателем.
Чтобы добавить свой твик, допишите Tweak(...) в список TWEAKS.
"""
import ctypes
import json
import os
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter.filedialog as fd
import tkinter.messagebox as mb
from dataclasses import dataclass
from typing import Any, Optional, Tuple

if sys.platform != "win32":
    sys.exit("WinTweaker работает только в Windows.")

import winreg  # noqa: E402

import customtkinter as ctk  # noqa: E402

import guard  # noqa: E402

HKCU, HKLM, HKU = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_USERS
DW, SZ = winreg.REG_DWORD, winreg.REG_SZ
NO_WINDOW = 0x08000000
BIN = winreg.REG_BINARY
AV_PAGES = ["Сканер", "Карантин", "Процессы", "Соединения", "Защитник и сеть", "Настройки защиты"]

CV = r"Software\Microsoft\Windows\CurrentVersion"
ADV = CV + r"\Explorer\Advanced"
CDM = CV + r"\ContentDeliveryManager"
PERS = CV + r"\Themes\Personalize"
DESK = r"Control Panel\Desktop"
POL = r"SOFTWARE\Policies\Microsoft\Windows"
SVC = r"SYSTEM\CurrentControlSet\Services"
CLASSIC_MENU = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
ICONS = CV + r"\Explorer\HideDesktopIcons\NewStartPanel"


@dataclass
class Tweak:
    category: str
    title: str
    desc: str
    hive: int
    path: str
    name: str
    kind: int
    on: Any                      # значение, когда твик включён
    off: Any                     # значение, когда выключен (None = удалить значение)
    admin: bool = False          # нужны права администратора
    rec: bool = False            # входит в «рекомендуемый набор»
    special: Optional[str] = None
    extra: Tuple = ()            # доп. значения в том же ключе: (имя, тип, вкл, выкл)


T = Tweak
TWEAKS = [
    # ---------------- Интерфейс ----------------
    T("Интерфейс", "Показывать расширения файлов", "Видеть .txt, .exe, .png в именах файлов",
      HKCU, ADV, "HideFileExt", DW, 0, 1, rec=True),
    T("Интерфейс", "Показывать скрытые файлы", "Скрытые файлы и папки видны в Проводнике",
      HKCU, ADV, "Hidden", DW, 1, 2),
    T("Интерфейс", "Показывать защищённые системные файлы", "Файлы ОС тоже видны (осторожно)",
      HKCU, ADV, "ShowSuperHidden", DW, 1, 0),
    T("Интерфейс", "Старое контекстное меню (Win 11)", "Правый клик без «Показать дополнительные параметры»",
      HKCU, CLASSIC_MENU, "", SZ, "", None, special="keyexists", rec=True),
    T("Интерфейс", "Тёмная тема приложений", "Тёмное оформление окон и приложений",
      HKCU, PERS, "AppsUseLightTheme", DW, 0, 1),
    T("Интерфейс", "Тёмная тема системы", "Тёмная панель задач и меню «Пуск»",
      HKCU, PERS, "SystemUsesLightTheme", DW, 0, 1),
    T("Интерфейс", "Панель задач слева (Win 11)", "Значки и «Пуск» слева, как в Win 10",
      HKCU, ADV, "TaskbarAl", DW, 0, 1),
    T("Интерфейс", "Никогда не группировать окна на панели задач", "Каждое окно со своей подписью",
      HKCU, ADV, "TaskbarGlomLevel", DW, 2, 0),
    T("Интерфейс", "Скрыть кнопку «Представление задач»", "Меньше значков на панели задач",
      HKCU, ADV, "ShowTaskViewButton", DW, 0, 1),
    T("Интерфейс", "Скрыть кнопку Copilot", "Убирает значок Copilot с панели",
      HKCU, ADV, "ShowCopilotButton", DW, 0, 1),
    T("Интерфейс", "Скрыть виджеты (Win 11)", "Убирает кнопку погоды и новостей (на новых сборках может не сработать)",
      HKCU, ADV, "TaskbarDa", DW, 0, 1),
    T("Интерфейс", "Скрыть поиск на панели задач", "Убирает строку поиска",
      HKCU, CV + r"\Search", "SearchboxTaskbarMode", DW, 0, 2),
    T("Интерфейс", "Секунды в часах на панели задач", "Часы показывают чч:мм:сс",
      HKCU, ADV, "ShowSecondsInSystemClock", DW, 1, 0),
    T("Интерфейс", "Проводник открывается на «Этот компьютер»", "Вместо «Быстрого доступа»",
      HKCU, ADV, "LaunchTo", DW, 1, 2),
    T("Интерфейс", "Полный путь в заголовке Проводника", "В заголовке окна виден весь путь",
      HKCU, CV + r"\Explorer\CabinetState", "FullPath", DW, 1, 0),
    T("Интерфейс", "Компактный вид Проводника", "Меньше отступов между файлами",
      HKCU, ADV, "UseCompactMode", DW, 1, 0),
    T("Интерфейс", "Значок «Этот компьютер» на рабочем столе", "Классический значок на столе",
      HKCU, ICONS, "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", DW, 0, 1),
    T("Интерфейс", "Значок папки пользователя на рабочем столе", "Быстрый доступ к личной папке",
      HKCU, ICONS, "{59031a47-3f72-44a7-89c5-5595fe6b30ee}", DW, 0, 1),
    T("Интерфейс", "Версия Windows на рабочем столе", "Водяной знак с номером сборки в углу",
      HKCU, DESK, "PaintDesktopVersion", DW, 1, 0),
    T("Интерфейс", "Отключить встряхивание окна (Aero Shake)", "Окна не сворачиваются при тряске",
      HKCU, ADV, "DisallowShaking", DW, 1, 0),
    T("Интерфейс", "Отключить залипание клавиш (Shift x5)", "Нет окна при быстрых нажатиях Shift",
      HKCU, r"Control Panel\Accessibility\StickyKeys", "Flags", SZ, "506", "510", rec=True),
    T("Интерфейс", "Отключить экран блокировки (админ)", "Сразу экран ввода пароля",
      HKLM, POL + r"\Personalization", "NoLockScreen", DW, 1, None, admin=True),
    T("Интерфейс", "Num Lock включён при запуске (админ)", "Цифровая клавиатура работает сразу",
      HKU, r".DEFAULT\Control Panel\Keyboard", "InitialKeyboardIndicators", SZ, "2", "0", admin=True),
    # ---------------- Приватность ----------------
    T("Приватность", "Отключить рекламный ID", "Приложения не получают рекламный идентификатор",
      HKCU, CV + r"\AdvertisingInfo", "Enabled", DW, 0, 1, rec=True),
    T("Приватность", "Отключить рекомендации в «Пуске»", "Меньше предложенных приложений",
      HKCU, ADV, "Start_IrisRecommendations", DW, 0, 1, rec=True),
    T("Приватность", "Отключить советы и рекламу Windows", "Подсказки в уведомлениях и на экране блокировки",
      HKCU, CDM, "SubscribedContent-338389Enabled", DW, 0, 1, rec=True),
    T("Приватность", "Отключить рекламу в настройках и «Пуске»", "Предложения в системной панели",
      HKCU, CDM, "SystemPaneSuggestionsEnabled", DW, 0, 1, rec=True),
    T("Приватность", "Не ставить рекомендуемые приложения сами", "Отключает фоновую установку игр и приложений",
      HKCU, CDM, "SilentInstalledAppsEnabled", DW, 0, 1, rec=True),
    T("Приватность", "Отключить «интересные факты» на экране блокировки", "Нет рекламных подсказок",
      HKCU, CDM, "RotatingLockScreenOverlayEnabled", DW, 0, 1, rec=True),
    T("Приватность", "Отключить Bing в поиске «Пуск»", "Поиск ищет только на вашем ПК",
      HKCU, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", DW, 1, None, rec=True),
    T("Приватность", "Не запрашивать отзывы о Windows", "Нет окон с оценкой системы",
      HKCU, r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", DW, 0, None, rec=True),
    T("Приватность", "Отключить персонализированную рекламу по диагностике", "Windows не подбирает советы по вашим данным",
      HKCU, CV + r"\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", DW, 0, 1, rec=True),
    T("Приватность", "Не отслеживать запуск программ", "«Пуск» не копит статистику запусков",
      HKCU, ADV, "Start_TrackProgs", DW, 0, 1),
    T("Приватность", "Минимум телеметрии (админ)", "Ограничивает отправку диагностических данных",
      HKLM, POL + r"\DataCollection", "AllowTelemetry", DW, 0, None, admin=True, rec=True),
    T("Приватность", "Отключить историю действий (админ)", "Таймлайн не собирает ваши действия",
      HKLM, POL + r"\System", "EnableActivityFeed", DW, 0, None, admin=True,
      extra=(("PublishUserActivities", DW, 0, None),)),
    T("Приватность", "Отключить определение местоположения (админ)", "Службы геолокации выключены",
      HKLM, POL + r"\LocationAndSensors", "DisableLocation", DW, 1, None, admin=True),
    T("Приватность", "Отключить отчёты об ошибках (админ)", "Windows не отправляет отчёты о сбоях",
      HKLM, r"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", DW, 1, 0, admin=True),
    # ---------------- Производительность ----------------
    T("Производительность", "Отключить анимацию окон", "Окна сворачиваются мгновенно",
      HKCU, r"Control Panel\Desktop\WindowMetrics", "MinAnimate", SZ, "0", "1"),
    T("Производительность", "Отключить прозрачность", "Меньше нагрузка на видеокарту",
      HKCU, PERS, "EnableTransparency", DW, 0, 1),
    T("Производительность", "Убрать задержку меню", "Меню открываются без паузы",
      HKCU, DESK, "MenuShowDelay", SZ, "0", "400"),
    T("Производительность", "Отключить игровую панель и запись (Game DVR)", "Меньше фоновой нагрузки в играх",
      HKCU, r"System\GameConfigStore", "GameDVR_Enabled", DW, 0, 1,
      extra=(("GameDVR_FSEBehaviorMode", DW, 2, 0),)),
    T("Производительность", "Отключить фоновые приложения", "Магазинные приложения не работают в фоне",
      HKCU, CV + r"\BackgroundAccessApplications", "GlobalUserDisabled", DW, 1, 0),
    T("Производительность", "Убрать задержку запуска программ", "Автозагрузка стартует без паузы",
      HKCU, CV + r"\Explorer\Serialize", "StartupDelayInMSec", DW, 0, None),
    T("Производительность", "Быстрое закрытие зависших программ", "Не ждать 20 секунд при выключении",
      HKCU, DESK, "AutoEndTasks", SZ, "1", "0",
      extra=(("WaitToKillAppTimeout", SZ, "3000", "20000"), ("HungAppTimeout", SZ, "2000", "5000"))),
    T("Производительность", "Быстрое завершение служб (админ)", "Службы закрываются за 2 секунды",
      HKLM, r"SYSTEM\CurrentControlSet\Control", "WaitToKillServiceTimeout", SZ, "2000", "5000", admin=True),
    T("Производительность", "Отключить быстрый запуск (админ)", "Полное выключение вместо гибернации ядра",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", DW, 0, 1, admin=True),
    T("Производительность", "Отключить ускорение мыши", "Курсор двигается строго пропорционально",
      HKCU, r"Control Panel\Mouse", "MouseSpeed", SZ, "0", "1",
      extra=(("MouseThreshold1", SZ, "0", "6"), ("MouseThreshold2", SZ, "0", "10"))),
    # ---------------- Система ----------------
    T("Система", "Длинные пути файлов (админ)", "Снимает лимит 260 символов в путях",
      HKLM, r"SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled", DW, 1, 0, admin=True),
    T("Система", "Не перезагружаться автоматически после обновлений (админ)", "Нет внезапной перезагрузки при работе",
      HKLM, POL + r"\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers", DW, 1, None, admin=True),
    T("Система", "Отключить автозапуск носителей", "Флешки и диски не запускаются сами",
      HKCU, CV + r"\Explorer\AutoplayHandlers", "DisableAutoplay", DW, 1, 0),
    T("Система", "Отключить всплывающие уведомления", "Нет баннеров в углу экрана",
      HKCU, CV + r"\PushNotifications", "ToastEnabled", DW, 0, 1),
    T("Система", "Отключить удалённый помощник (админ)", "Закрывает вход для Remote Assistance",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", DW, 0, 1, admin=True),
    # ---------------- Ещё интерфейс ----------------
    T("Интерфейс", "Не показывать недавние файлы в Проводнике", "Быстрый доступ без списка последних файлов",
      HKCU, CV + r"\Explorer", "ShowRecent", DW, 0, 1,
      extra=(("ShowFrequent", DW, 0, 1),)),
    T("Интерфейс", "Классический Alt+Tab", "Переключатель окон как в Windows 7-10",
      HKCU, CV + r"\Explorer", "AltTabSettings", DW, 1, None),
    T("Интерфейс", "Быстрые миниатюры на панели задач", "Превью окон появляется почти мгновенно",
      HKCU, ADV, "ExtendedUIHoverTime", DW, 10, None),
    T("Интерфейс", "Убрать «- Ярлык» в названиях новых ярлыков", "Новые ярлыки без дописки",
      HKCU, CV + r"\Explorer", "link", BIN, bytes(4), None),
    T("Интерфейс", "Показывать содержимое окна при перетаскивании", "Выключите для скорости на слабом ПК",
      HKCU, DESK, "DragFullWindows", SZ, "1", "0"),
    T("Интерфейс", "Отключить размытие на экране входа (админ)", "Чёткий фон без акрила",
      HKLM, POL + r"\System", "DisableAcrylicBackgroundOnLogon", DW, 1, None, admin=True),
    # ---------------- Ещё производительность ----------------
    T("Производительность", "Приоритет игр в системе (админ)", "Больше ресурсов процессов-играм (MMCSS)",
      HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority", DW, 6, 2,
      admin=True, extra=(("Scheduling Category", SZ, "High", "Medium"), ("SFIO Priority", SZ, "High", "Normal"))),
    T("Производительность", "Максимальная отзывчивость системы (админ)", "Меньше ресурсов резервируется под фон",
      HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", DW, 0, 20,
      admin=True),
    T("Производительность", "Отключить Prefetch и Superfetch (админ)", "Только для SSD; на HDD лучше оставить",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
      "EnablePrefetcher", DW, 0, 3, admin=True, extra=(("EnableSuperfetch", DW, 0, 3),)),
    T("Производительность", "Отключить Microsoft Edge в фоне (админ)", "Без предзагрузки и фонового режима",
      HKLM, r"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", DW, 0, None, admin=True,
      extra=(("BackgroundModeEnabled", DW, 0, None),)),
    T("Производительность", "Отключить OneDrive (админ)", "Синхронизация OneDrive не запускается",
      HKLM, POL + r"\OneDrive", "DisableFileSyncNGSC", DW, 1, None, admin=True),
    T("Производительность", "Отключить Cortana (админ)", "Голосовой помощник выключен",
      HKLM, POL + r"\Windows Search", "AllowCortana", DW, 0, None, admin=True),
    T("Производительность", "Не ставить драйверы через Центр обновления (админ)", "Драйверы видеокарты ставите сами",
      HKLM, POL + r"\WindowsUpdate", "ExcludeWUDriversInQualityUpdate", DW, 1, None, admin=True),
    # ---------------- Защита ----------------
    T("Защита", "Включить SmartScreen (админ)", "Предупреждает о неизвестных и опасных программах",
      HKLM, POL + r"\System", "EnableSmartScreen", DW, 1, None, admin=True, rec=True),
    T("Защита", "Блокировать автозапуск всех носителей (админ)", "Флешка не запустит вирус сама",
      HKLM, CV + r"\Policies\Explorer", "NoDriveTypeAutoRun", DW, 255, None, admin=True, rec=True),
    T("Защита", "Максимальный уровень UAC (админ)", "Всегда спрашивать при действиях, меняющих систему",
      HKLM, CV + r"\Policies\System", "ConsentPromptBehaviorAdmin", DW, 2, 5, admin=True),
    T("Защита", "Отключить Windows Script Host (админ)", "Блокирует вирусы-скрипты .vbs/.js (старые скрипты перестанут работать)",
      HKLM, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", DW, 0, None, admin=True),
    T("Защита", "Запретить анонимный доступ к системе (админ)", "Ограничивает перечисление учётных записей по сети",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous", DW, 1, 0, admin=True, rec=True),
    T("Защита", "Защита процесса LSA (админ, после перезагрузки)", "Усложняет кражу паролей из памяти",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", DW, 1, None, admin=True),
    T("Защита", "Не хранить пароли в открытом виде в памяти (админ)", "Отключает устаревший WDigest",
      HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", DW, 0, None,
      admin=True, rec=True),
    T("Защита", "Отключить LLMNR (админ)", "Закрывает вектор подмены имён в локальной сети",
      HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", DW, 0, None, admin=True),
    T("Защита", "Запретить удалённый рабочий стол (админ)", "Закрывает вход по RDP",
      HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", DW, 1, 0, admin=True, rec=True),
    T("Защита", "Word: блокировать макросы из интернета", "Макросы из скачанных файлов не запускаются",
      HKCU, r"Software\Policies\Microsoft\Office\16.0\Word\Security", "blockcontentexecutionfrominternet", DW, 1, None,
      rec=True),
    T("Защита", "Excel: блокировать макросы из интернета", "Макросы из скачанных файлов не запускаются",
      HKCU, r"Software\Policies\Microsoft\Office\16.0\Excel\Security", "blockcontentexecutionfrominternet", DW, 1, None,
      rec=True),
    # ---------------- Сеть ----------------
    T("Сеть", "Отключить ограничение сетевого трафика (админ)", "Убирает throttling для мультимедиа",
      HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", DW,
      4294967295, 10, admin=True),
    T("Сеть", "Отключить резерв канала QoS (админ)", "Весь канал доступен приложениям",
      HKLM, POL + r"\Psched", "NonBestEffortLimit", DW, 0, None, admin=True),
    T("Сеть", "Скачивать обновления только с серверов Microsoft (админ)", "Без раздачи обновлений другим ПК (P2P)",
      HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode", DW, 0, None,
      admin=True),
    # ---------------- Службы (эффект после перезагрузки) ----------------
    T("Службы", "Выключить DiagTrack (телеметрия)", "Служба сбора диагностики (админ, после перезагрузки)",
      HKLM, SVC + r"\DiagTrack", "Start", DW, 4, 2, admin=True),
    T("Службы", "Выключить SysMain (Superfetch)", "Полезно для SSD, снижает фоновую нагрузку на диск",
      HKLM, SVC + r"\SysMain", "Start", DW, 4, 2, admin=True),
    T("Службы", "Выключить службу поиска Windows (WSearch)", "Отключает индексацию (поиск станет медленнее)",
      HKLM, SVC + r"\WSearch", "Start", DW, 4, 2, admin=True),
    T("Службы", "Выключить Xbox Live Auth Manager", "Нужна только для игр с входом в Xbox (админ)",
      HKLM, SVC + r"\XblAuthManager", "Start", DW, 4, 3, admin=True),
    T("Службы", "Выключить Xbox Live Game Save", "Облачные сохранения Xbox (админ)",
      HKLM, SVC + r"\XblGameSave", "Start", DW, 4, 3, admin=True),
    T("Службы", "Выключить службу печати (Spooler)", "Только если у вас нет принтера (админ)",
      HKLM, SVC + r"\Spooler", "Start", DW, 4, 2, admin=True),
    T("Службы", "Выключить службу факсов", "Почти никому не нужна (админ)",
      HKLM, SVC + r"\Fax", "Start", DW, 4, 3, admin=True),
    T("Службы", "Выключить карты (MapsBroker)", "Загрузка офлайн-карт в фоне (админ)",
      HKLM, SVC + r"\MapsBroker", "Start", DW, 4, 2, admin=True),
]
CATEGORIES = list(dict.fromkeys(t.category for t in TWEAKS))

DEBLOAT = [
    ("Новости", "Microsoft.BingNews"), ("Погода", "Microsoft.BingWeather"),
    ("Советы (Get Started)", "Microsoft.Getstarted"), ("Получить помощь", "Microsoft.GetHelp"),
    ("Пасьянсы", "Microsoft.MicrosoftSolitaireCollection"), ("Люди", "Microsoft.People"),
    ("Центр отзывов", "Microsoft.WindowsFeedbackHub"), ("Ваш телефон", "Microsoft.YourPhone"),
    ("Музыка Groove", "Microsoft.ZuneMusic"), ("Кино и ТВ", "Microsoft.ZuneVideo"),
    ("Office Hub", "Microsoft.MicrosoftOfficeHub"), ("Карты", "Microsoft.WindowsMaps"),
    ("Clipchamp", "Clipchamp.Clipchamp"), ("Skype", "Microsoft.SkypeApp"),
    ("Microsoft Teams (личный)", "MicrosoftTeams"), ("Заметки Sticky Notes", "Microsoft.MicrosoftStickyNotes"),
    ("Xbox Game Bar", "Microsoft.XboxGamingOverlay"), ("Mixed Reality Portal", "Microsoft.MixedReality.Portal"),
]

QUICK = [
    ("Диспетчер устройств", "devmgmt.msc"), ("Службы", "services.msc"), ("Редактор реестра", "regedit"),
    ("Управление дисками", "diskmgmt.msc"), ("Планировщик заданий", "taskschd.msc"),
    ("Электропитание", "powercfg.cpl"), ("Сетевые подключения", "ncpa.cpl"),
    ("Программы и компоненты", "appwiz.cpl"), ("Свойства системы", "sysdm.cpl"),
    ("Управление компьютером", "compmgmt.msc"), ("Монитор ресурсов", "resmon"),
    ("Конфигурация системы", "msconfig"), ("Автологин (netplwiz)", "netplwiz"),
    ("Групповая политика", "gpedit.msc"), ("Просмотр событий", "eventvwr.msc"),
    ("Безопасность Windows", "windowsdefender:"), ("Параметры: Обновление", "ms-settings:windowsupdate"),
]


# ---------- Реестр ----------
def _open(hive, path, write=False):
    acc = winreg.KEY_WOW64_64KEY | (winreg.KEY_SET_VALUE if write else winreg.KEY_READ)
    return winreg.OpenKey(hive, path, 0, acc)


def is_on(t: Tweak) -> bool:
    try:
        if t.special == "keyexists":
            _open(t.hive, t.path + r"\InprocServer32").Close()
            return True
        with _open(t.hive, t.path) as k:
            val, _ = winreg.QueryValueEx(k, t.name)
        return str(val) == str(t.on)
    except OSError:
        return False


def _put(key, name, kind, value):
    if value is None:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        winreg.SetValueEx(key, name, 0, kind, value)


def set_state(t: Tweak, enable: bool) -> None:
    if t.special == "keyexists":
        sub = t.path + r"\InprocServer32"
        if enable:
            with winreg.CreateKeyEx(t.hive, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "", 0, SZ, "")
        else:
            for p in (sub, t.path):
                try:
                    winreg.DeleteKeyEx(t.hive, p, winreg.KEY_WOW64_64KEY, 0)
                except FileNotFoundError:
                    pass
        return
    with winreg.CreateKeyEx(t.hive, t.path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        _put(k, t.name, t.kind, t.on if enable else t.off)
        for name, kind, on, off in t.extra:
            _put(k, name, kind, on if enable else off)


# ---------- Автозагрузка ----------
RUN = CV + r"\Run"
APPROVED = CV + r"\Explorer\StartupApproved\Run"


def list_startup():
    items = []
    for hive, label in ((HKCU, "пользователь"), (HKLM, "все пользователи")):
        try:
            with _open(hive, RUN) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    enabled = True
                    try:
                        with _open(hive, APPROVED) as ak:
                            data, _ = winreg.QueryValueEx(ak, name)
                            enabled = data[0] % 2 == 0
                    except OSError:
                        pass
                    items.append((hive, label, name, str(val), enabled))
        except OSError:
            pass
    return items


def set_startup(hive, name, enable):
    with winreg.CreateKeyEx(hive, APPROVED, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, bytes([2 if enable else 3]) + bytes(11))


# ---------- Системные действия ----------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd, shell=False):
    return subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                          creationflags=NO_WINDOW, errors="ignore")


def ps(command: str):
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command])


def ps_text(command: str) -> str:
    r = ps(command)
    return ((r.stdout or "") + (r.stderr or "")).strip() or "(нет вывода)"


def ps_job(command: str, ok: str) -> str:
    r = ps("$ErrorActionPreference='Stop'; " + command)
    if r.returncode == 0:
        return ok
    msg = (r.stderr or r.stdout or "").strip().splitlines()
    return "Не удалось (нужен админ или включена защита от изменений): " + (msg[0][:150] if msg else "")


def restart_explorer():
    run(["taskkill", "/f", "/im", "explorer.exe"])
    subprocess.Popen(["explorer.exe"])
    return "Проводник перезапущен"


def clean_temp():
    freed = errors = 0
    folders = {tempfile.gettempdir(), os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Temp"),
               os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Prefetch")}
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for e in os.scandir(folder):
            try:
                size = e.stat().st_size if e.is_file() else 0
                shutil.rmtree(e.path) if e.is_dir(follow_symlinks=False) else os.remove(e.path)
                freed += size
            except OSError:
                errors += 1
    return f"Очищено около {freed / 1048576:.1f} МБ (занятых файлов пропущено: {errors})"


def power_plan(guid, create_from=None):
    if create_from:
        run(["powercfg", "-duplicatescheme", create_from, guid])
    r = run(["powercfg", "/setactive", guid])
    return "План питания изменён" if r.returncode == 0 else "Не удалось сменить план питания"


def simple(cmd, ok, shell=False):
    r = run(cmd, shell=shell)
    return ok if r.returncode == 0 else "Не удалось выполнить (нужны права администратора?)"


def restore_point():
    r = ps('Checkpoint-Computer -Description "WinTweaker" -RestorePointType MODIFY_SETTINGS')
    return "Точка восстановления создана" if r.returncode == 0 else "Не удалось (нужен админ; Windows создаёт не чаще раза в сутки)"


def set_dns(servers):
    if servers:
        addr = ",".join(f"'{s}'" for s in servers)
        body = f"Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses {addr}"
    else:
        body = "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses"
    r = ps("Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { " + body + " }")
    ok = "DNS изменён" if servers else "DNS сброшен на автоматический"
    return ok if r.returncode == 0 else "Не удалось (нужен админ)"


def empty_recycle():
    r = ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue")
    return "Корзина очищена" if r.returncode == 0 else "Не удалось очистить корзину"


def god_mode():
    path = os.path.join(os.path.expanduser("~"), "Desktop", "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}")
    os.makedirs(path, exist_ok=True)
    return "Папка GodMode создана на рабочем столе"


def console(cmd):
    subprocess.Popen(["cmd", "/k", cmd], creationflags=subprocess.CREATE_NEW_CONSOLE)
    return "Команда запущена в новом окне"


def remove_app(pkg):
    r = ps(f"Get-AppxPackage -Name '*{pkg}*' | Remove-AppxPackage")
    return f"Удалено: {pkg}" if r.returncode == 0 else f"Не удалось удалить {pkg}"


def system_info():
    class MS(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
    ms = MS()
    ms.dwLength = ctypes.sizeof(MS)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    cpu = platform.processor()
    try:
        with _open(HKLM, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            cpu = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    except OSError:
        pass
    ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    up = ctypes.windll.kernel32.GetTickCount64() // 1000
    total, used, free = shutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\")
    gb = 1024 ** 3
    return [
        ("Компьютер", platform.node()), ("Пользователь", os.environ.get("USERNAME", "?")),
        ("Система", f"{platform.system()} {platform.release()} (сборка {platform.version()})"),
        ("Процессор", f"{cpu} ({os.cpu_count()} потоков)"),
        ("Память", f"{ms.ullTotalPhys / gb:.1f} ГБ всего, занято {ms.dwMemoryLoad}%"),
        ("Диск C:", f"{total / gb:.0f} ГБ всего, свободно {free / gb:.0f} ГБ"),
        ("Время работы", f"{up // 3600} ч {(up % 3600) // 60} мин"),
        ("Права", "администратор" if is_admin() else "обычный пользователь"),
    ]


# ---------- Интерфейс ----------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("WinTweaker 3.0")
        self.geometry("1120x740")
        self.minsize(860, 560)
        self.page = "Все твики"
        self.token = 0
        self.q = queue.Queue()
        self.results = []
        self.results_frame = None
        self.scan_label = None
        self.scan_text = "Готов к проверке"
        self.scan_thread = None
        self.stop_ev = threading.Event()
        self.monitor = None
        self.after(100, self.pump)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        side = ctk.CTkScrollableFrame(self, width=190, corner_radius=0)
        side.grid(row=0, column=0, sticky="ns")
        ctk.CTkLabel(side, text="WinTweaker", font=ctk.CTkFont(size=20, weight="bold")).pack(padx=16, pady=(16, 2))
        ctk.CTkLabel(side, text="администратор" if is_admin() else "без прав админа",
                     text_color="#5cd65c" if is_admin() else "#e6a23c").pack(pady=(0, 10))
        groups = [("ТВИКИ", ["Все твики"] + CATEGORIES),
                  ("СИСТЕМА", ["Автозагрузка", "Приложения", "Инструменты", "Система"]),
                  ("АНТИВИРУС", AV_PAGES)]
        for title, items in groups:
            ctk.CTkLabel(side, text=title, text_color="gray60", font=ctk.CTkFont(size=11, weight="bold")).pack(
                anchor="w", padx=12, pady=(10, 0))
            for p in items:
                ctk.CTkButton(side, text=p, anchor="w", fg_color="transparent", text_color=("gray10", "gray90"),
                              hover_color=("gray70", "gray30"), command=lambda p=p: self.show(p)).pack(fill="x", padx=4, pady=1)

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(main, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew")
        self.search = ctk.CTkEntry(top, placeholder_text="Поиск по настройкам...", width=260)
        self.search.pack(side="left", padx=(0, 8))
        self.search.bind("<KeyRelease>", lambda e: self.render())
        for text, cmd in (("Рекомендуемые", self.apply_recommended), ("Сбросить всё", self.reset_all),
                          ("Экспорт", self.export_profile), ("Импорт", self.import_profile)):
            ctk.CTkButton(top, text=text, width=110, command=cmd).pack(side="left", padx=3)

        self.content = ctk.CTkScrollableFrame(main)
        self.content.grid(row=1, column=0, sticky="nsew", pady=8)
        self.status = ctk.CTkLabel(main, text="Готово", anchor="w")
        self.status.grid(row=2, column=0, sticky="ew")
        self.render()

    # --- служебное ---
    def say(self, text):
        self.status.configure(text=text)

    def ui(self, fn):
        """Безопасно выполнить функцию в главном потоке (из фонового)."""
        self.q.put(fn)

    def pump(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        except Exception as e:  # не даём сбою убить обработчик очереди
            self.status.configure(text=f"Внутренняя ошибка: {e}")
        self.after(100, self.pump)

    def background(self, fn):
        self.say("Выполняется...")

        def work():
            try:
                msg = fn()
            except Exception as e:
                msg = f"Ошибка: {e}"
            self.ui(lambda: self.say(msg))
        threading.Thread(target=work, daemon=True).start()

    def async_page(self, fn, draw):
        """Выполнить fn в потоке и нарисовать результат, если страница не сменилась."""
        token = self.token

        def work():
            try:
                res = fn()
            except Exception as e:
                res = e
            self.ui(lambda: draw(res) if token == self.token else None)
        threading.Thread(target=work, daemon=True).start()

    def show_text(self, title, text):
        w = ctk.CTkToplevel(self)
        w.title(title)
        w.geometry("780x480")
        w.attributes("-topmost", True)
        tb = ctk.CTkTextbox(w, font=ctk.CTkFont(family="Consolas", size=12))
        tb.pack(fill="both", expand=True, padx=8, pady=8)
        tb.insert("1.0", text)
        tb.configure(state="disabled")

    def out(self, title, text):
        self.ui(lambda: self.show_text(title, text))
        return f"{title}: результат показан в окне"

    def show(self, page):
        self.page = page
        self.search.delete(0, "end")
        self.render()

    def clear(self):
        for w in self.content.winfo_children():
            w.destroy()

    def render(self):
        self.token += 1
        self.clear()
        q = self.search.get().strip().lower()
        if q:
            for t in TWEAKS:
                if q in t.title.lower() or q in t.desc.lower():
                    self.tweak_row(t)
            return
        p = self.page
        if p == "Все твики":
            for t in TWEAKS:
                self.tweak_row(t)
        elif p in CATEGORIES:
            for t in TWEAKS:
                if t.category == p:
                    self.tweak_row(t)
        elif p == "Автозагрузка":
            self.page_startup()
        elif p == "Приложения":
            self.page_apps()
        elif p == "Инструменты":
            self.page_tools()
        elif p == "Система":
            self.page_system()
        elif p == "Сканер":
            self.page_scan()
        elif p == "Карантин":
            self.page_quarantine()
        elif p == "Процессы":
            self.page_processes()
        elif p == "Соединения":
            self.page_connections()
        elif p == "Защитник и сеть":
            self.page_defender()
        elif p == "Настройки защиты":
            self.page_av_settings()

    # --- твики ---
    def tweak_row(self, t: Tweak):
        row = ctk.CTkFrame(self.content)
        row.pack(fill="x", padx=4, pady=3)
        var = ctk.BooleanVar(value=is_on(t))
        sw = ctk.CTkSwitch(row, text=t.title, variable=var, font=ctk.CTkFont(weight="bold"))
        sw.configure(command=lambda: self.toggle(t, var))
        sw.pack(anchor="w", padx=12, pady=(8, 0))
        ctk.CTkLabel(row, text=t.desc, text_color="gray70").pack(anchor="w", padx=48, pady=(0, 8))

    def toggle(self, t, var):
        want = var.get()
        if t.admin and not is_admin():
            mb.showwarning("Нужны права", "Запустите программу от имени администратора.")
            var.set(not want)
            return
        try:
            set_state(t, want)
            self.say(f"{'Включено' if want else 'Выключено'}: {t.title}. Если не видно эффекта, "
                     "перезапустите Проводник (Инструменты).")
        except OSError as e:
            mb.showerror("Ошибка", f"{t.title}\n\n{e}")
            var.set(not want)

    def bulk(self, items, state_of):
        done = fail = 0
        for t in items:
            if t.admin and not is_admin():
                fail += 1
                continue
            try:
                set_state(t, state_of(t))
                done += 1
            except OSError:
                fail += 1
        self.render()
        return done, fail

    def apply_recommended(self):
        if mb.askyesno("Рекомендуемый набор", "Включить безопасные твики приватности и интерфейса, "
                       "помеченные как рекомендуемые? Их можно выключить обратно."):
            d, f = self.bulk([t for t in TWEAKS if t.rec], lambda t: True)
            self.say(f"Применено: {d}, пропущено (нужен админ или ошибка): {f}")

    def reset_all(self):
        if mb.askyesno("Сброс", "Вернуть ВСЕ твики к стандартным значениям Windows?"):
            d, f = self.bulk(TWEAKS, lambda t: False)
            self.say(f"Сброшено: {d}, пропущено: {f}")

    def export_profile(self):
        path = fd.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")],
                                    initialfile="wintweaker-profile.json")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({t.title: is_on(t) for t in TWEAKS}, f, ensure_ascii=False, indent=2)
            self.say(f"Профиль сохранён: {path}")

    def import_profile(self):
        path = fd.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            mb.showerror("Ошибка", str(e))
            return
        d, f = self.bulk([t for t in TWEAKS if t.title in data], lambda t: bool(data[t.title]))
        self.say(f"Профиль применён: {d}, пропущено: {f}")

    # --- страницы ---
    def card(self, title, desc=""):
        row = ctk.CTkFrame(self.content)
        row.pack(fill="x", padx=4, pady=3)
        ctk.CTkLabel(row, text=title, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=12, pady=(8, 0))
        if desc:
            ctk.CTkLabel(row, text=desc, text_color="gray70", wraplength=640, justify="left").pack(anchor="w", padx=12)
        return row

    def page_startup(self):
        items = list_startup()
        if not items:
            self.card("Автозагрузка пуста", "В реестре нет записей Run.")
        for hive, label, name, val, enabled in items:
            bad = guard.suspicious_command(val)
            row = self.card(("⚠ " if bad else "") + f"{name}  ({label})",
                            val + ("\nПодозрительно: " + "; ".join(bad) if bad else ""))
            var = ctk.BooleanVar(value=enabled)

            def cb(h=hive, n=name, v=var):
                if h == HKLM and not is_admin():
                    mb.showwarning("Нужны права", "Для записей «все пользователи» нужен админ.")
                    v.set(not v.get())
                    return
                try:
                    set_startup(h, n, v.get())
                    self.say(f"{'Включён' if v.get() else 'Отключён'} автозапуск: {n}")
                except OSError as e:
                    mb.showerror("Ошибка", str(e))
                    v.set(not v.get())
            ctk.CTkSwitch(row, text="Запускать вместе с Windows", variable=var, command=cb).pack(anchor="w", padx=12, pady=8)

    def page_apps(self):
        self.card("Удаление встроенных приложений",
                  "Удаляются только для вашей учётной записи. Вернуть можно из Microsoft Store.")
        for title, pkg in DEBLOAT:
            row = self.card(title, pkg)

            def go(t=title, p=pkg):
                if mb.askyesno("Удалить?", f"Удалить приложение «{t}»?"):
                    self.background(lambda: remove_app(p))
            ctk.CTkButton(row, text="Удалить", width=100, fg_color="#a83232", hover_color="#802626",
                          command=go).pack(anchor="e", padx=12, pady=(0, 8))

    def page_tools(self):
        actions = [
            ("Перезапустить Проводник", restart_explorer),
            ("Очистить временные файлы", clean_temp),
            ("Очистить корзину", empty_recycle),
            ("Сбросить кэш DNS", lambda: simple(["ipconfig", "/flushdns"], "Кэш DNS сброшен")),
            ("DNS: Cloudflare 1.1.1.1 (админ)", lambda: set_dns(["1.1.1.1", "1.0.0.1"])),
            ("DNS: Google 8.8.8.8 (админ)", lambda: set_dns(["8.8.8.8", "8.8.4.4"])),
            ("DNS: автоматически (админ)", lambda: set_dns(None)),
            ("План питания: сбалансированный", lambda: power_plan("381b4222-f694-41f0-9685-ff5bb260df2e")),
            ("План питания: высокая производительность", lambda: power_plan("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c")),
            ("План питания: максимальная (скрытый)", lambda: power_plan("e9a42b02-d5df-448d-aa00-03f14749eb61",
                                                                       "e9a42b02-d5df-448d-aa00-03f14749eb61")),
            ("Отключить гибернацию (админ)", lambda: simple(["powercfg", "/h", "off"], "Гибернация отключена")),
            ("Включить гибернацию (админ)", lambda: simple(["powercfg", "/h", "on"], "Гибернация включена")),
            ("Создать точку восстановления (админ)", restore_point),
            ("Проверка системных файлов SFC (админ)", lambda: console("sfc /scannow")),
            ("Восстановление образа DISM (админ)", lambda: console("DISM /Online /Cleanup-Image /RestoreHealth")),
            ("Сбросить сеть Winsock (админ, нужна перезагрузка)",
             lambda: simple(["netsh", "winsock", "reset"], "Winsock сброшен, перезагрузите ПК")),
            ("Создать папку GodMode на рабочем столе", god_mode),
            ("Состояние дисков (SMART)", lambda: self.out("Состояние дисков", ps_text(
                "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus,Size | "
                "Format-Table -AutoSize | Out-String -Width 200"))),
            ("Проверка связи: ping 8.8.8.8", lambda: self.out("Ping", ps_text("ping 8.8.8.8 -n 4"))),
            ("Оптимизация TCP: autotuning и RSS (админ)", lambda: simple(
                "netsh int tcp set global autotuninglevel=normal & netsh int tcp set global rss=enabled",
                "Параметры TCP применены", shell=True)),
            ("Очистить кэш Центра обновления (админ)", lambda: ps_job(
                "Stop-Service wuauserv,bits -Force; Remove-Item \"$env:SystemRoot\\SoftwareDistribution\\Download\\*\" "
                "-Recurse -Force; Start-Service wuauserv,bits", "Кэш обновлений очищен")),
            ("Очистить журналы событий (админ)", lambda: ps_job(
                "wevtutil el | ForEach-Object { wevtutil cl $_ }", "Журналы событий очищены")),
            ("Отключить PowerShell 2.0 (админ)", lambda: ps_job(
                "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
                "PowerShell 2.0 отключён")),
            ("Отключить SMBv1 (админ)", lambda: ps_job(
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", "SMBv1 отключён")),
        ]
        for text, fn in actions:
            ctk.CTkButton(self.content, text=text, anchor="w", height=34,
                          command=lambda f=fn: self.background(f)).pack(fill="x", padx=4, pady=3)
        self.card("Быстрый доступ к скрытым окнам настроек")
        grid = ctk.CTkFrame(self.content, fg_color="transparent")
        grid.pack(fill="x", padx=4)
        for i, (text, target) in enumerate(QUICK):
            ctk.CTkButton(grid, text=text, height=32, command=lambda t=target: self.open_tool(t)).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=3, pady=3)
        grid.grid_columnconfigure((0, 1), weight=1)

    def open_tool(self, target):
        try:
            os.startfile(target)
        except OSError as e:
            mb.showerror("Не удалось открыть", f"{target}\n\n{e}")

    def page_system(self):
        for k, v in system_info():
            row = self.card(k, v)
            row.pack_configure(pady=3)

    # ================= Антивирус =================
    def set_scan_text(self, text):
        self.scan_text = text
        try:
            if self.scan_label is not None and self.scan_label.winfo_exists():
                self.scan_label.configure(text=text)
        except Exception:
            pass

    def page_scan(self):
        box = self.card("Антивирусная проверка",
                        "Ищет известные угрозы по хэшам, замаскированные и упакованные программы, опасные скрипты "
                        "и ярлыки. Это дополнение к Защитнику Windows, а не замена ему.")
        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=6)
        for text, cmd in (("Быстрая проверка", self.scan_quick), ("Полная проверка", self.scan_full),
                          ("Проверить папку...", self.scan_folder), ("Стоп", lambda: self.stop_ev.set())):
            ctk.CTkButton(row, text=text, width=140, command=cmd).pack(side="left", padx=3)
        self.mon_var = ctk.BooleanVar(value=self.monitor is not None)
        ctk.CTkSwitch(box, text="Постоянный мониторинг (Загрузки, Рабочий стол, Temp)", variable=self.mon_var,
                      command=self.toggle_monitor).pack(anchor="w", padx=12, pady=(2, 4))
        self.scan_label = ctk.CTkLabel(box, text=self.scan_text, anchor="w", text_color="gray70")
        self.scan_label.pack(anchor="w", padx=12, pady=(0, 8))
        self.results_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        self.results_frame.pack(fill="x")
        for r in self.results:
            self.result_row(r)

    def scan_quick(self):
        self.start_scan(guard.quick_roots(), "быстрая проверка")

    def scan_full(self):
        if not mb.askyesno("Полная проверка", "Будут проверены все локальные и съёмные диски (кроме системной папки "
                           "Windows). Это может занять много времени. Продолжить?"):
            return
        win = os.environ.get("SystemRoot", r"C:\Windows")
        self.start_scan(guard.fixed_drives() + [os.path.join(win, "Temp")], "полная проверка", skip=[win])

    def scan_folder(self):
        path = fd.askdirectory(title="Какую папку проверить?")
        if path:
            self.start_scan([path], "проверка папки")

    def start_scan(self, roots, label, skip=()):
        if self.scan_thread is not None and self.scan_thread.is_alive():
            mb.showinfo("Проверка", "Проверка уже идёт. Нажмите «Стоп», чтобы прервать.")
            return
        if not roots:
            mb.showinfo("Проверка", "Нечего проверять.")
            return
        self.stop_ev = threading.Event()
        stop = self.stop_ev
        blocklist = guard.load_blocklist()

        def work():
            def prog(n, path):
                self.ui(lambda: self.set_scan_text(f"Проверено файлов: {n}  |  ...{path[-60:]}"))

            def found(r):
                self.ui(lambda: self.add_result(r))
            n = guard.scan_paths(roots, stop, prog, found, blocklist, skip)
            end = "остановлена" if stop.is_set() else "завершена"
            self.ui(lambda: self.set_scan_text(
                f"Проверка {end}. Проверено файлов: {n}. Найдено угроз: {len(self.results)}"))
        self.set_scan_text(f"Запущена: {label}...")
        self.scan_thread = threading.Thread(target=work, daemon=True)
        self.scan_thread.start()

    def toggle_monitor(self):
        if self.mon_var.get():
            self.monitor = guard.Monitor(lambda r: self.ui(lambda: self.add_result(r)), guard.load_blocklist())
            self.monitor.start()
            self.say("Мониторинг включён: новые файлы проверяются автоматически (уже лежащие там файлы он не трогает)")
        else:
            if self.monitor:
                self.monitor.stop()
            self.monitor = None
            self.say("Мониторинг выключен")

    def add_result(self, r):
        if any(x.path == r.path for x in self.results):
            return
        self.results.append(r)
        self.say(f"Обнаружено: {os.path.basename(r.path)} ({r.verdict})")
        try:
            if self.page == "Сканер" and self.results_frame is not None and self.results_frame.winfo_exists():
                self.result_row(r)
        except Exception:
            pass

    def result_row(self, r):
        color = "#c0392b" if r.score >= 70 else "#d4a017"
        row = ctk.CTkFrame(self.results_frame, border_width=1, border_color=color)
        row.pack(fill="x", padx=4, pady=3)
        ctk.CTkLabel(row, text=f"{r.verdict}: {os.path.basename(r.path)}   (оценка {r.score}/100)",
                     font=ctk.CTkFont(weight="bold"), text_color=color).pack(anchor="w", padx=12, pady=(8, 0))
        ctk.CTkLabel(row, text=r.path, text_color="gray70", wraplength=700, justify="left").pack(anchor="w", padx=12)
        ctk.CTkLabel(row, text="• " + "\n• ".join(r.reasons), wraplength=700, justify="left").pack(
            anchor="w", padx=12, pady=(2, 4))
        btns = ctk.CTkFrame(row, fg_color="transparent")
        btns.pack(anchor="w", padx=8, pady=(0, 8))

        def quar():
            try:
                guard.quarantine(r)
            except OSError as e:
                mb.showerror("Не удалось", f"Файл занят или нет прав:\n{e}")
                return
            self.results.remove(r)
            row.destroy()
            self.say("Файл перемещён в карантин")

        def drop():
            if r in self.results:
                self.results.remove(r)
            row.destroy()

        for text, cmd in (("В карантин", quar),
                          ("Показать в папке", lambda: subprocess.Popen(["explorer", f"/select,{r.path}"])),
                          ("VirusTotal", lambda: self.vt_check(r)), ("Игнорировать", drop)):
            ctk.CTkButton(btns, text=text, width=130, command=cmd).pack(side="left", padx=3)

    def vt_check(self, r):
        key = guard.load_config().get("vt_key", "")
        if not key:
            mb.showinfo("VirusTotal", "Укажите бесплатный API-ключ VirusTotal в разделе «Настройки защиты».")
            return

        def work():
            try:
                info = guard.vt_lookup(r.sha256, key)
            except Exception as e:
                return f"VirusTotal: ошибка запроса ({e})"
            if info.get("unknown"):
                return "VirusTotal: файла нет в базе (это ещё не значит, что он безопасен)"
            return (f"VirusTotal: опасным считают {info['malicious']} из {info['total']} движков, "
                    f"подозрительным {info['suspicious']}")
        self.background(work)

    def page_quarantine(self):
        self.card("Карантин", "Изолированные файлы не могут запуститься. Отсюда их можно вернуть или удалить навсегда.")
        items = guard.list_quarantine()
        if not items:
            self.card("Карантин пуст")
        for m in items:
            row = self.card(os.path.basename(m["path"]), f'{m["path"]}\n{m["verdict"]}  |  {m["time"]}')
            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(anchor="w", padx=8, pady=(0, 8))

            def back(q=m["id"]):
                try:
                    self.say(f"Восстановлено: {guard.restore(q)}")
                except OSError as e:
                    mb.showerror("Ошибка", str(e))
                self.render()

            def kill(q=m["id"]):
                if mb.askyesno("Удалить", "Удалить файл навсегда?"):
                    guard.delete_quarantined(q)
                    self.render()
            ctk.CTkButton(btns, text="Восстановить", width=130, command=back).pack(side="left", padx=3)
            ctk.CTkButton(btns, text="Удалить навсегда", width=150, fg_color="#a83232", hover_color="#802626",
                          command=kill).pack(side="left", padx=3)

    def holder(self, text="Проверяю..."):
        h = ctk.CTkFrame(self.content, fg_color="transparent")
        h.pack(fill="x")
        ctk.CTkLabel(h, text=text, text_color="gray70").pack(anchor="w", padx=12, pady=6)
        return h

    @staticmethod
    def wipe(h):
        for w in h.winfo_children():
            w.destroy()

    def page_processes(self):
        head = self.card("Проверка запущенных процессов",
                         "Ищет программы, запущенные из Temp, Загрузок и общих папок, и подделки под системные процессы.")
        ctk.CTkButton(head, text="Обновить", width=120, command=self.render).pack(anchor="w", padx=12, pady=(4, 8))
        h = self.holder()
        self.async_page(guard.audit_processes, lambda res: self.draw_processes(h, res))

    def draw_processes(self, h, res):
        self.wipe(h)
        if isinstance(res, Exception):
            ctk.CTkLabel(h, text=f"Не удалось получить список процессов: {res}").pack(anchor="w", padx=12)
            return
        total, flagged = res
        ctk.CTkLabel(h, text=f"Запущено процессов: {total}. Подозрительных: {len(flagged)}").pack(anchor="w", padx=12, pady=4)
        for p in flagged:
            f = ctk.CTkFrame(h, border_width=1, border_color="#d4a017")
            f.pack(fill="x", padx=4, pady=3)
            ctk.CTkLabel(f, text=f'{p["name"]} (PID {p["pid"]})', font=ctk.CTkFont(weight="bold")).pack(
                anchor="w", padx=12, pady=(8, 0))
            ctk.CTkLabel(f, text=p["path"], text_color="gray70", wraplength=700, justify="left").pack(anchor="w", padx=12)
            ctk.CTkLabel(f, text="• " + "\n• ".join(p["reasons"]), wraplength=700, justify="left").pack(anchor="w", padx=12)
            b = ctk.CTkFrame(f, fg_color="transparent")
            b.pack(anchor="w", padx=8, pady=(2, 8))

            def kill(pid=p["pid"], name=p["name"]):
                if mb.askyesno("Завершить процесс", f"Завершить {name} (PID {pid})?"):
                    run(["taskkill", "/pid", str(pid), "/f"])
                    self.render()
            ctk.CTkButton(b, text="Завершить процесс", width=160, fg_color="#a83232", hover_color="#802626",
                          command=kill).pack(side="left", padx=3)
            if p["path"]:
                ctk.CTkButton(b, text="Показать в папке", width=140,
                              command=lambda x=p["path"]: subprocess.Popen(["explorer", f"/select,{x}"])).pack(side="left", padx=3)

    def page_connections(self):
        head = self.card("Активные сетевые соединения",
                         "Какие программы сейчас обмениваются данными с интернетом. Незнакомое имя можно проверить в поиске.")
        ctk.CTkButton(head, text="Обновить", width=120, command=self.render).pack(anchor="w", padx=12, pady=(4, 8))
        h = self.holder()
        self.async_page(guard.list_connections, lambda res: self.draw_connections(h, res))

    def draw_connections(self, h, res):
        self.wipe(h)
        if isinstance(res, Exception):
            ctk.CTkLabel(h, text=f"Не удалось получить соединения: {res}").pack(anchor="w", padx=12)
            return
        lines = []
        for c in sorted(res, key=lambda x: str(x.get("Proc"))):
            path = (c.get("Path") or "").lower()
            mark = "!" if any(m in path.replace("/", "\\") for m in guard.PROC_RISKY_DIRS) else " "
            lines.append(f'{mark} {str(c.get("Proc")):<24} PID {str(c.get("Pid")):<7} -> {c.get("Remote")}:{c.get("Port")}')
        tb = ctk.CTkTextbox(h, height=480, font=ctk.CTkFont(family="Consolas", size=12))
        tb.pack(fill="x", padx=4)
        tb.insert("1.0", "Знак ! = программа запущена из Temp/Загрузок/общей папки\n\n" + ("\n".join(lines) or "Соединений нет"))
        tb.configure(state="disabled")

    def page_defender(self):
        head = self.card("Защитник Windows", "Состояние встроенного антивируса. Если стоит сторонний антивирус, Защитник может быть выключен.")
        h = ctk.CTkFrame(head, fg_color="transparent")
        h.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(h, text="Проверяю...", text_color="gray70").pack(anchor="w")
        self.async_page(guard.defender_status, lambda res: self.draw_defender(h, res))

        acts = [
            ("Обновить базы Защитника", "Update-MpSignature", "Базы обновлены"),
            ("Быстрая проверка Защитником", "Start-MpScan -ScanType QuickScan", "Быстрая проверка Защитника завершена"),
            ("Полная проверка Защитником", "Start-MpScan -ScanType FullScan", "Полная проверка Защитника завершена"),
            ("Удалить найденные Защитником угрозы", "Remove-MpThreat", "Угрозы удалены"),
            ("Включить защиту в реальном времени", "Set-MpPreference -DisableRealtimeMonitoring $false", "Защита в реальном времени включена"),
            ("Включить облачную защиту", "Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -SubmitSamplesConsent SendSafeSamples", "Облачная защита включена"),
            ("Блокировать нежелательные программы (PUA)", "Set-MpPreference -PUAProtection Enabled", "Защита от PUA включена"),
            ("Включить защиту сети", "Set-MpPreference -EnableNetworkProtection Enabled", "Защита сети включена"),
            ("Защита папок от шифровальщиков: включить", "Set-MpPreference -EnableControlledFolderAccess Enabled", "Контролируемый доступ к папкам включён (могут блокироваться некоторые программы)"),
            ("Защита папок от шифровальщиков: выключить", "Set-MpPreference -EnableControlledFolderAccess Disabled", "Контролируемый доступ к папкам выключен"),
        ]
        grid = ctk.CTkFrame(self.content, fg_color="transparent")
        grid.pack(fill="x", padx=4)
        for i, (text, cmd, ok) in enumerate(acts):
            ctk.CTkButton(grid, text=text, height=34, command=lambda c=cmd, o=ok: self.background(lambda: ps_job(c, o))).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=3, pady=3)
        grid.grid_columnconfigure((0, 1), weight=1)

        fw = self.card("Брандмауэр", "Фильтрует входящие и исходящие соединения.")
        b = ctk.CTkFrame(fw, fg_color="transparent")
        b.pack(anchor="w", padx=8, pady=(2, 8))
        ctk.CTkButton(b, text="Включить для всех профилей (админ)", width=240, command=lambda: self.background(
            lambda: simple(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], "Брандмауэр включён"))).pack(side="left", padx=3)
        ctk.CTkButton(b, text="Показать состояние", width=170, command=lambda: self.background(
            lambda: self.out("Брандмауэр", ps_text("netsh advfirewall show allprofiles state")))).pack(side="left", padx=3)

        path, entries, flagged = guard.audit_hosts()
        hosts = self.card("Файл hosts", "Вирусы правят его, чтобы блокировать сайты антивирусов и подменять банки и поисковики.")
        if flagged:
            ctk.CTkLabel(hosts, text="⚠ Подозрительные записи (проверьте):\n" + "\n".join(f"{ip}  {host}" for ip, host in flagged),
                         text_color="#e6a23c", justify="left").pack(anchor="w", padx=12, pady=4)
        else:
            ctk.CTkLabel(hosts, text=f"Подозрительных записей нет (всего записей: {len(entries)}).",
                         text_color="gray70").pack(anchor="w", padx=12, pady=4)
        ctk.CTkButton(hosts, text="Открыть hosts в Блокноте", width=210,
                      command=lambda: subprocess.Popen(["notepad", path])).pack(anchor="w", padx=12, pady=(0, 8))

    def draw_defender(self, h, res):
        self.wipe(h)
        if isinstance(res, Exception) or not res:
            ctk.CTkLabel(h, text="Не удалось получить состояние (возможно, Защитник отключён сторонним антивирусом).").pack(anchor="w")
            return

        def yn(v):
            return "включено" if v else "ВЫКЛЮЧЕНО"
        rows = [("Антивирус", yn(res.get("AntivirusEnabled"))), ("Защита в реальном времени", yn(res.get("RealTimeProtectionEnabled"))),
                ("Поведенческий мониторинг", yn(res.get("BehaviorMonitorEnabled"))), ("Проверка загрузок", yn(res.get("IoavProtectionEnabled"))),
                ("Защита от изменений", yn(res.get("IsTamperProtected"))), ("Версия баз", str(res.get("AntivirusSignatureVersion")))]
        for k, v in rows:
            ctk.CTkLabel(h, text=f"{k}: {v}", text_color="#e74c3c" if v == "ВЫКЛЮЧЕНО" else ("gray90")).pack(anchor="w")

    def page_av_settings(self):
        cfg = guard.load_config()
        box = self.card("VirusTotal", "Бесплатный API-ключ с virustotal.com позволяет сверять хэш найденного файла с 70 антивирусными движками. "
                        "Сам файл не загружается, отправляется только хэш.")
        entry = ctk.CTkEntry(box, width=420, show="*", placeholder_text="API-ключ VirusTotal")
        entry.pack(anchor="w", padx=12, pady=4)
        if cfg.get("vt_key"):
            entry.insert(0, cfg["vt_key"])

        def save():
            cfg["vt_key"] = entry.get().strip()
            guard.save_config(cfg)
            self.say("Ключ сохранён")
        ctk.CTkButton(box, text="Сохранить ключ", width=160, command=save).pack(anchor="w", padx=12, pady=(0, 8))

        db = self.card("База известных угроз (SHA-256)", f"Сейчас в базе: {len(guard.load_blocklist())} хэшей. "
                       "Свои списки хэшей (по одному в строке, например выгрузки abuse.ch) можно импортировать из файла.")
        b = ctk.CTkFrame(db, fg_color="transparent")
        b.pack(anchor="w", padx=8, pady=(2, 8))

        def imp():
            path = fd.askopenfilename(filetypes=[("Текст/CSV", "*.txt *.csv *.list"), ("Все файлы", "*.*")])
            if path:
                try:
                    self.say(f"Добавлено новых хэшей: {guard.import_blocklist(path)}")
                except OSError as e:
                    mb.showerror("Ошибка", str(e))
                self.render()
        ctk.CTkButton(b, text="Импорт хэшей из файла", width=190, command=imp).pack(side="left", padx=3)
        ctk.CTkButton(b, text="Открыть папку данных", width=170,
                      command=lambda: (guard.ensure_dirs(), os.startfile(guard.DATA_DIR))).pack(side="left", padx=3)

        t = self.card("Проверка работы сканера", "Создаёт безопасный тестовый файл EICAR (его используют для проверки антивирусов) "
                      "в папке Загрузки. Защитник Windows, скорее всего, тоже его заметит: это нормально.")

        def eicar():
            folder = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(folder, exist_ok=True)
            try:
                p = guard.write_eicar(folder)
                self.say(f"Тестовый файл создан: {p}. Запустите быструю проверку.")
            except OSError as e:
                self.say(f"Не удалось создать файл (его могла удалить защита): {e}")
        ctk.CTkButton(t, text="Создать тестовый файл EICAR", width=230, command=eicar).pack(anchor="w", padx=12, pady=(2, 8))

        self.card("Честно о возможностях", "Сканер проверяет файлы по хэшам и признакам, следит за новыми загрузками, проверяет процессы, "
                  "автозагрузку, hosts и соединения. У него нет драйвера уровня ядра, облачной базы и блокировки по поведению, "
                  "поэтому держите Защитник Windows включённым и используйте этот инструмент как второй слой.")


if __name__ == "__main__":
    App().mainloop()
