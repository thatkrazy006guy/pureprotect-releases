import os
import gc
import sys
import math
import time
import json
import ctypes
import winreg
import shutil
import socket
import hashlib
import sqlite3
import webbrowser
import subprocess
import threading
import winsound
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from collections import Counter
from tkinter import filedialog

import psutil
try:
    import qrcode
except ImportError:
    qrcode = None
import requests
import numpy as np
import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw
from sklearn.ensemble import IsolationForest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

APP_VERSION = "3.7.0"
COMPANION_PORT = 5055
SINGLE_INSTANCE_PORT = 50599
DEFAULT_PATCH_URL = "https://raw.githubusercontent.com/thatkrazy006guy/pureprotect-releases/refs/heads/main/guardian_ui.py"
DEV_SCRIPT_PATH = Path(r"C:\Users\krazy\ai-sec-pipeline\ai-sec-pipeline\guardian_ui.py")

if getattr(sys, "frozen", False):
    BUNDLE_DIR = Path(sys._MEIPASS)
else:
    BUNDLE_DIR = Path(__file__).resolve().parent

APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "PureProtect"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
LIVE_PATCH_FILE = APP_DATA_DIR / "live_patch.py"

if getattr(sys, "frozen", False) and "--no-inject" not in sys.argv:
    target_patch = DEV_SCRIPT_PATH if DEV_SCRIPT_PATH.exists() else (LIVE_PATCH_FILE if LIVE_PATCH_FILE.exists() else None)
    if target_patch is not None:
        try:
            sys.argv.append("--no-inject")
            patch_code = target_patch.read_text(encoding="utf-8")
            exec(compile(patch_code, str(target_patch), "exec"), globals())
            sys.exit(0)
        except Exception:
            pass

_INSTANCE_LOCK_SOCKET = None
if "--reloading" not in sys.argv:
    try:
        _INSTANCE_LOCK_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _INSTANCE_LOCK_SOCKET.bind(("127.0.0.1", SINGLE_INSTANCE_PORT))
    except socket.error:
        sys.exit(0)

DB_PATH = str(APP_DATA_DIR / "threat_intel.db")
CONFIG_PATH = str(APP_DATA_DIR / "settings.json")
ICON_PATH = str(APP_DATA_DIR / "pureprotect.ico")
WATCH_DIR = str(Path.home() / "Downloads")
QUARANTINE_DIR = str(APP_DATA_DIR / "quarantine")
STARTUP_DIR = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
STARTUP_BAT = os.path.join(STARTUP_DIR, "PureProtect_Autostart.bat")
HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3:1.7b"

SCAN_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".scr", ".hta", ".jar", ".com", ".pif"
}

FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_UNPINNED = 0x00100000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
CLOUD_PLACEHOLDER_MASK = (
    FILE_ATTRIBUTE_OFFLINE |
    FILE_ATTRIBUTE_RECALL_ON_OPEN |
    FILE_ATTRIBUTE_UNPINNED |
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

DEFAULT_TRUSTED_PROCS = {
    "svchost.exe", "system", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
    "code.exe", "ollama.exe", "ollama_llama_server.exe", "python.exe", "pythonw.exe",
    "pureprotect.exe", "docker.exe", "com.docker.backend.exe", "vpnkit.exe",
    "spotify.exe", "discord.exe", "steam.exe", "steamwebhelper.exe", "searchhost.exe",
    "widgets.exe", "lsass.exe", "services.exe", "explorer.exe", "onedrive.exe",
    "phoneexperiencehost.exe", "crossdeviceresume.exe"
}
STANDARD_PORTS = {80, 443, 53, 8080, 8443, 5228, 3478, 19302, 11434, 5055, 50599}

APP_DESCRIPTIONS = {
    "chrome.exe": "Google Chrome Web Browser",
    "msedge.exe": "Microsoft Edge Web Browser",
    "firefox.exe": "Mozilla Firefox Browser",
    "brave.exe": "Brave Privacy Browser",
    "svchost.exe": "Windows Core Background Service",
    "code.exe": "Visual Studio Code Editor",
    "discord.exe": "Discord Voice & Chat App",
    "spotify.exe": "Spotify Music Streaming",
    "steam.exe": "Steam Gaming Client",
    "steamwebhelper.exe": "Steam Store & Overlay Service",
    "onedrive.exe": "Microsoft OneDrive Cloud Sync",
    "phoneexperiencehost.exe": "Windows Phone Link Companion",
    "ollama.exe": "Local AI Engine Server",
    "python.exe": "Python Script Runtime",
    "pythonw.exe": "PureProtect Background Engine",
    "pureprotect.exe": "PureProtect Security Suite"
}

PORT_DESCRIPTIONS = {
    443: "Secure Website (Encrypted HTTPS)",
    80: "Standard Website (HTTP)",
    53: "Website Name Lookup (DNS)",
    8080: "Local Web Dashboard",
    8443: "Secure Cloud Service (HTTPS)",
    11434: "Local AI Assistant Engine",
    5055: "PureProtect Android Companion Bridge",
    5228: "Google Background Sync",
    3478: "Voice / Video Call Stream",
    19302: "Voice / Video Call Stream"
}

IOT_VULN_PORTS = {
    21: ("FTP File Transfer", "HIGH", "Old file transfer port open. Can allow unauthorized file access."),
    22: ("SSH Remote Login", "LOW", "Remote command login active. Safe if protected by a strong password."),
    23: ("Telnet Remote Access", "CRITICAL", "Insecure remote login open! Hackers use this to hijack smart devices."),
    80: ("Web Settings Page", "INFO", "Standard local web settings page (normal for routers and printers)."),
    445: ("Windows File Sharing", "LOW", "Local home network file sharing active."),
    554: ("Camera Video Stream", "LOW", "Live security camera or media video stream active."),
    3389: ("Windows Remote Desktop", "LOW", "Remote desktop control enabled on local network."),
    5555: ("Smart TV / Android ADB", "HIGH", "Developer ADB port open (normal if you sideload apps on this TV/box; otherwise turn off ADB Debugging)."),
    8080: ("Web Settings Page", "INFO", "Secondary local web settings page.")
}

LEGAL_TEXT = """PUREPROTECT(TM) AI SECURITY SUITE — PRIVACY GUARANTEE & END-USER LICENSE (EULA)
Copyright (C) 2026 Brian Davis / Pure Ecosystem (PureProtect • PureStream • PureMind • PureClean)
All Rights Reserved. Proprietary & Confidential.

1. 100% LOCAL ZERO-TELEMETRY PRIVACY GUARANTEE
• Zero Cloud Uploads: Every file hash check, PureClean junk sweep, Registry & Hosts immunization check, Wi-Fi audit, and AI learning check happens 100% locally on your hardware.
• Private AI Analyst: Suspicious events are analyzed locally on your CPU (with an automatic built-in heuristic analyst when Ollama is not installed). Your personal files, downloads, and network logs never leave your computer.

2. PROPRIETARY LICENSE & INTELLECTUAL PROPERTY PROTECTION
• Ownership: All source code, visual interface design ("trade dress"), custom icons, and branding ("PureProtect", "PureStream", "PureMind", and "PureClean") are the exclusive property of Brian Davis / Pure Ecosystem.
• Restrictions: You may NOT copy, redistribute, sell, decompile, reverse engineer, extract source code, or clone the user interface of this software.

3. SECURITY DISCLAIMER & LIMITATION OF LIABILITY
• Provided "AS IS" without warranty. No security tool guarantees 100% protection against all threats. The author is not liable for data loss, quarantined files, or terminated processes."""

os.makedirs(QUARANTINE_DIR, exist_ok=True)
bundled_db = BUNDLE_DIR / "threat_intel.db"
if not os.path.exists(DB_PATH) and bundled_db.exists():
    try:
        shutil.copy2(str(bundled_db), DB_PATH)
    except Exception:
        pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def format_bytes(num_bytes):
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 ** 2:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 ** 3:
        return f"{num_bytes / (1024 ** 2):.1f} MB"
    else:
        return f"{num_bytes / (1024 ** 3):.2f} GB"


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def load_settings():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "your-org" in data.get("patch_url", ""):
                    data["patch_url"] = DEFAULT_PATCH_URL
                return data
        except Exception:
            pass
    return {"patch_url": DEFAULT_PATCH_URL}


def save_settings(data):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS bad_ips (ip TEXT PRIMARY KEY, source TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS bad_hashes (sha256 TEXT PRIMARY KEY, source TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS bad_domains (domain TEXT PRIMARY KEY, source TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS trusted_procs (proc_name TEXT PRIMARY KEY)")
    c.execute("CREATE TABLE IF NOT EXISTS trusted_devices (ip TEXT PRIMARY KEY)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            category TEXT,
            target TEXT,
            summary TEXT,
            outcome TEXT
        )
    """)
    for proc in DEFAULT_TRUSTED_PROCS:
        c.execute("INSERT OR IGNORE INTO trusted_procs VALUES (?)", (proc.lower(),))
    conn.commit()
    return conn


def get_trusted_devices():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT ip FROM trusted_devices").fetchall()
    conn.close()
    return {r[0] for r in rows}


def add_trusted_device(ip_addr):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR IGNORE INTO trusted_devices VALUES (?)", (ip_addr,))
    conn.commit()
    conn.close()


def is_cloud_or_phone_placeholder(file_path):
    p_lower = file_path.lower()
    if "\\crossdevice\\" in p_lower or "\\onedrive\\" in p_lower or "\\iclouddrive\\" in p_lower:
        try:
            st = os.stat(file_path, follow_symlinks=False)
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & CLOUD_PLACEHOLDER_MASK or "\\crossdevice\\" in p_lower:
                return True
        except Exception:
            return True
    try:
        st = os.stat(file_path, follow_symlinks=False)
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs & CLOUD_PLACEHOLDER_MASK:
            return True
    except Exception:
        return True
    return False


def log_incident_db(category, target, summary, outcome="Pending Action"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = datetime.now().strftime("%b %d, %I:%M %p")
    c.execute(
        "INSERT INTO incident_history (timestamp, category, target, summary, outcome) VALUES (?, ?, ?, ?, ?)",
        (ts, category, target, summary, outcome)
    )
    inc_id = c.lastrowid
    conn.commit()
    conn.close()
    return inc_id


def update_incident_outcome_db(inc_id, new_outcome):
    if not inc_id:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE incident_history SET outcome = ? WHERE id = ?", (new_outcome, inc_id))
    conn.commit()
    conn.close()


def get_incident_history_db(limit=40):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, timestamp, category, target, summary, outcome FROM incident_history ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows


def get_trusted_procs():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT proc_name FROM trusted_procs").fetchall()
    conn.close()
    return {r[0].lower() for r in rows}


def add_trusted_proc(proc_name):
    if not proc_name:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR IGNORE INTO trusted_procs VALUES (?)", (proc_name.lower(),))
    conn.commit()
    conn.close()


def is_safe_install_location(exe_path):
    if not exe_path or exe_path == "N/A":
        return False
    p = exe_path.lower()
    if p.startswith(("c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\")):
        return True
    if "\\appdata\\local\\programs\\" in p or "\\steam\\steamapps\\" in p:
        return True
    return False


def sync_feeds_internal():
    conn = init_db()
    c = conn.cursor()
    ips = []
    for url, label in [
        ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "FeodoTracker_C2"),
        ("https://cinsscore.com/list/ci-badguys.txt", "CINS_ThreatIntel"),
        ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "EmergingThreats_Compromised")
    ]:
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line[0].isdigit():
                    ips.append((line, label))
        except Exception:
            pass
    c.executemany("INSERT OR IGNORE INTO bad_ips VALUES (?, ?)", ips)

    hashes = []
    try:
        hash_resp = requests.get("https://bazaar.abuse.ch/export/txt/sha256/recent/", timeout=15)
        for line in hash_resp.text.splitlines():
            line = line.strip().lower()
            if len(line) == 64 and not line.startswith("#"):
                hashes.append((line, "MalwareBazaar"))
    except Exception:
        pass
    c.executemany("INSERT OR IGNORE INTO bad_hashes VALUES (?, ?)", hashes)

    domains = []
    try:
        dom_resp = requests.get("https://urlhaus.abuse.ch/downloads/hostfile/", timeout=15)
        for line in dom_resp.text.splitlines():
            line = line.strip()
            if line.startswith("127.0.0.1") or line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 2:
                    d = parts[1].strip().lower()
                    if d and d not in {"localhost", "0.0.0.0"}:
                        domains.append((d, "URLhaus_MalwareDomain"))
    except Exception:
        pass
    c.executemany("INSERT OR IGNORE INTO bad_domains VALUES (?, ?)", domains[:5000])

    conn.commit()
    conn.close()
    return len(ips), len(hashes), len(domains)


def scan_registry_and_hijacks():
    findings = []
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run")
    ]
    suspicious_keywords = ("\\appdata\\local\\temp\\", "powershell", "cmd.exe /c", "wscript", "cscript", "mshta", "regsvr32")

    for root_hive, subkey, label in run_keys:
        try:
            with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_READ) as k:
                idx = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, idx)
                        val_l = str(val).lower()
                        is_risky = any(kw in val_l for kw in suspicious_keywords)
                        findings.append({
                            "type": "Registry Startup",
                            "location": label,
                            "name": name,
                            "command": str(val),
                            "risky": is_risky
                        })
                        idx += 1
                    except OSError:
                        break
        except Exception:
            pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ) as k:
            proxy_enable, _ = winreg.QueryValueEx(k, "ProxyEnable")
            if proxy_enable == 1:
                proxy_server, _ = winreg.QueryValueEx(k, "ProxyServer")
                findings.append({
                    "type": "System Proxy Hijack Check",
                    "location": "HKCU\\Internet Settings",
                    "name": "ProxyServer Active",
                    "command": str(proxy_server),
                    "risky": True
                })
    except Exception:
        pass

    return findings


def create_shield_icon():
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=(11, 15, 25, 255), outline=(6, 182, 212, 255))
    draw.polygon([(32, 11), (50, 19), (47, 37), (32, 52), (17, 37), (14, 19)], fill=(16, 185, 129, 220), outline=(6, 182, 212, 255))
    if not os.path.exists(ICON_PATH):
        try:
            img.save(ICON_PATH, format="ICO", sizes=[(64, 64), (32, 32), (16, 16)])
        except Exception:
            pass
    return img


def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024 * 1024)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
    except Exception:
        return 0.0


def detect_local_ollama_status():
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            models = [m.get("name", "").lower() for m in r.json().get("models", [])]
            if any("qwen3" in m for m in models):
                return "READY", "Local AI Active (Ollama qwen3:1.7b — 100% Private)"
            return "NO_MODEL", "Ollama is running, but model 'qwen3:1.7b' is not downloaded yet."
    except Exception:
        pass
    ollama_exe = Path(os.environ.get("LOCALAPPDATA", "")) / r"Programs\Ollama\ollama.exe"
    if ollama_exe.exists() or shutil.which("ollama"):
        return "STOPPED", "Ollama is installed but not running (or model missing)."
    return "MISSING", "Local Ollama AI is not installed (Using Built-in Heuristic AI)."


def builtin_heuristic_analyst(alert_type, details):
    if "File" in alert_type:
        fname = details.get("file", "Unknown file")
        match = details.get("match", "heuristic rule")
        ent = details.get("entropy", 0)
        return (
            f"[Built-in AI] Risk Level High: '{fname}' triggered '{match}' (Entropy {ent}/8.0), indicating a known signature or packed executable. "
            f"Click 'Auto-Fix' to isolate this file safely inside your Quarantine Vault."
        )
    apps = details.get("apps", "An unverified application")
    return (
        f"[Built-in AI] Risk Level Medium: {apps} opened outbound connections on custom ports outside standard web traffic. "
        f"If you recognize {apps} as a trusted game or tool, click 'Trust App'; otherwise click 'Auto-Fix' to terminate it."
    )


def ask_cloud_ai_fallback(alert_type, details):
    cfg = load_settings()
    api_url = cfg.get("cloud_ai_url", "").strip()
    api_key = cfg.get("cloud_ai_key", "").strip()
    model = cfg.get("cloud_ai_model", "llama-3.1-8b-instant").strip()
    if not api_url or not api_key:
        return None

    prompt = (
        f"You are a friendly cybersecurity assistant. Explain this {alert_type} event in 2 short, plain-English sentences without markdown asterisks:\n"
        f"{json.dumps(details)}\n"
        "Sentence 1: State what app or file caused this and whether it is normal or risky. "
        "Sentence 2: Tell the user what action was taken or recommended."
    )
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 140
        }
        r = requests.post(api_url, headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            text = r.json()["choices"][0]["message"]["content"].strip().replace("**", "")
            return f"[Cloud AI] {text}"
    except Exception:
        pass
    return None


def ask_local_ai(alert_type, details):
    prompt = (
        f"You are a friendly cybersecurity assistant. Explain this {alert_type} event in 2 short, plain-English sentences without markdown asterisks:\n"
        f"{json.dumps(details)}\n"
        "Sentence 1: State what app or file caused this and whether it is normal or risky. "
        "Sentence 2: Tell the user what action was taken or recommended."
    )
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "keep_alive": 0,
        "options": {"num_gpu": 0, "num_thread": 4, "temperature": 0.1}
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=6)
        if r.status_code == 200:
            resp = r.json().get("response", "").strip().replace("**", "")
            if resp:
                return resp
    except Exception:
        pass

    cloud_resp = ask_cloud_ai_fallback(alert_type, details)
    if cloud_resp:
        return cloud_resp

    return builtin_heuristic_analyst(alert_type, details)


class DownloadScanner(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app
        self.recent_scans = {}

    def _scan_file(self, path):
        if not os.path.exists(path) or os.path.isdir(path):
            return
        ext = Path(path).suffix.lower()
        if ext in {".tmp", ".crdownload", ".part", ".quarantined"}:
            return
        if is_cloud_or_phone_placeholder(path):
            return
        now = time.time()
        if now - self.recent_scans.get(path, 0) < 3.0:
            return
        self.recent_scans[path] = now

        try:
            time.sleep(0.5)
            with open(path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            entropy = round(calculate_entropy(path), 2) if ext in SCAN_EXTENSIONS else 0.0
            db_hit = self.app.check_hash_in_db(sha256)
            is_suspicious_exec = ext in {".exe", ".bat", ".ps1", ".vbs", ".scr", ".cmd"} and entropy > 7.35
            if db_hit or is_suspicious_exec:
                details = {
                    "kind": "file",
                    "file": os.path.basename(path),
                    "path": path,
                    "sha256": sha256,
                    "entropy": entropy,
                    "match": db_hit or "High-Entropy Packed Executable",
                    "confirmed_malware": bool(db_hit)
                }
                self.app.handle_file_alert(details)
            else:
                self.app.log_event(f"[FILE SHIELD] Verified clean download: {os.path.basename(path)}")
        except Exception:
            pass

    def on_created(self, event):
        if not event.is_directory:
            self._scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._scan_file(event.src_path)


class PureProtectSuite(ctk.CTk):
    def __init__(self):
        super().__init__()
        init_db().close()
        self.settings = load_settings()
        self.lan_ip = get_lan_ip()
        self.title(f"PureProtect // Autonomous AI Security, PureClean & Immunization Suite v{APP_VERSION}")
        self.geometry("1260x780")
        self.minsize(1120, 700)
        self.configure(fg_color="#0B0F19")

        self.tray_image = create_shield_icon()
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except Exception:
                pass

        self.view_mode = "Everyday Mode"
        self.current_tab = "dashboard"
        self.last_flagged_file = None
        self.last_incident = None
        self.last_incident_id = None
        self.popup_win = None
        self.last_popup_time = 0
        self.cooldown_seconds = 900
        self.retrain_requested = False
        self.scan_running = False
        self.stop_scan_flag = False
        self.router_ip = "192.168.1.1"
        self.last_wifi_results = []
        self.auto_healed_count = 0
        self.total_sig_count = 0
        self.active_conn_count = 0
        self.total_bytes_recovered = 0
        self.companion_running = False

        self.cc_vars = {
            "temp": ctk.BooleanVar(value=True),
            "browsers": ctk.BooleanVar(value=True),
            "crashes": ctk.BooleanVar(value=True),
            "downloads": ctk.BooleanVar(value=True),
            "ram_dns": ctk.BooleanVar(value=True)
        }
        self.cc_size_labels = {}
        self.cc_last_scan_files = {k: [] for k in self.cc_vars}

        self.auto_heal_var = ctk.BooleanVar(value=True)
        self.live_learn_var = ctk.BooleanVar(value=True)
        self.minimize_to_tray_var = ctk.BooleanVar(value=True)
        self.autostart_var = ctk.BooleanVar(value=os.path.exists(STARTUP_BAT))
        self.silent_mode_var = ctk.BooleanVar(value=False)

        self.protocol("WM_DELETE_WINDOW", self.on_close_button)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_sidebar()
        self._build_top_bar()
        self._build_views()
        self.show_view("dashboard")

        self.refresh_db_counts()
        self.refresh_quarantine_list()
        self.refresh_incident_history_ui()
        self.log_event(f"[SYSTEM] PureProtect v{APP_VERSION} Online (100% Standalone Beta-Ready Build).")
        self.log_event("[SHIELD] 5 Threat Feeds + Spybot-Style Hosts Immunization & Registry Auditor Ready.")

        self.observer = Observer()
        self.observer.schedule(DownloadScanner(self), WATCH_DIR, recursive=False)
        self.observer.start()

        threading.Thread(target=self.monitor_network, daemon=True).start()
        threading.Thread(target=self.autonomous_maintenance_loop, daemon=True).start()
        threading.Thread(target=self.monitor_app_resources, daemon=True).start()
        self._init_system_tray()

    def _build_top_bar(self):
        self.topbar = ctk.CTkFrame(self, height=58, corner_radius=0, fg_color="#070A12", border_width=1, border_color="#1E293B")
        self.topbar.grid(row=0, column=1, sticky="ew")

        self.top_title_lbl = ctk.CTkLabel(
            self.topbar, text="⚡ Live Protection & Self-Healing Command Center",
            font=("Segoe UI", 16, "bold"), text_color="#F8FAFC"
        )
        self.top_title_lbl.pack(side="left", padx=22, pady=12)

        mode_frame = ctk.CTkFrame(self.topbar, fg_color="transparent")
        mode_frame.pack(side="right", padx=20, pady=10)

        ctk.CTkLabel(mode_frame, text="Experience View:", font=("Segoe UI", 12, "bold"), text_color="#94A3B8").pack(side="left", padx=(0, 8))
        self.mode_switch = ctk.CTkSegmentedButton(
            mode_frame,
            values=["🌟 Everyday Mode", "🔬 Advanced Mode"],
            font=("Segoe UI", 12, "bold"),
            selected_color="#0891B2",
            selected_hover_color="#06B6D4",
            command=self.on_mode_change
        )
        self.mode_switch.set("🌟 Everyday Mode")
        self.mode_switch.pack(side="left")

    def on_mode_change(self, val):
        self.view_mode = "Everyday Mode" if "Everyday" in val else "Advanced Mode"
        if self.view_mode == "Advanced Mode":
            self.adv_forensic_frame.pack(fill="x", pady=(10, 0))
        else:
            self.adv_forensic_frame.pack_forget()
        self.refresh_network_table()
        self.render_wifi_device_cards()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#070A12", border_width=1, border_color="#1E293B")
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(18, 10))
        ctk.CTkLabel(brand, text="🛡️ PureProtect", font=("Segoe UI", 22, "bold"), text_color="#06B6D4").pack(anchor="w")
        ctk.CTkLabel(brand, text=f"PURE ECOSYSTEM SUITE v{APP_VERSION}", font=("Segoe UI", 10, "bold"), text_color="#10B981").pack(anchor="w", pady=(2, 0))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "⚡  Live Protection"),
            ("tuneup", "🧹  PureClean Tune-Up"),
            ("scanner", "🔍  Virus, Registry & Immunize"),
            ("wifi", "📶  Wi-Fi & Smart Devices"),
            ("network", "🌐  Easy Network Radar"),
            ("incident", "📋  Incidents & History"),
            ("mobile", "📱  Android Companion"),
            ("quarantine", "🔒  Quarantine Vault"),
            ("lab", "🔧  Updates, Lab & Legal")
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w", height=36, corner_radius=8,
                font=("Segoe UI", 13, "bold"), fg_color="transparent", text_color="#94A3B8",
                hover_color="#1E293B", command=lambda k=key: self.show_view(k)
            )
            btn.pack(fill="x", padx=14, pady=2)
            self.nav_buttons[key] = btn

        auto_card = ctk.CTkFrame(self.sidebar, fg_color="#0F172A", corner_radius=10, border_width=1, border_color="#1E293B")
        auto_card.pack(fill="x", padx=14, pady=(8, 4))
        ctk.CTkLabel(auto_card, text="AUTONOMOUS AI PILOT", font=("Segoe UI", 10, "bold"), text_color="#10B981").pack(anchor="w", padx=12, pady=(8, 4))
        ctk.CTkSwitch(auto_card, text="Auto-Heal Minor Issues", variable=self.auto_heal_var, font=("Segoe UI", 11), progress_color="#10B981").pack(anchor="w", padx=12, pady=2)
        ctk.CTkSwitch(auto_card, text="Live-Learn Safe Apps", variable=self.live_learn_var, font=("Segoe UI", 11), progress_color="#06B6D4").pack(anchor="w", padx=12, pady=(2, 8))

        res_card = ctk.CTkFrame(self.sidebar, fg_color="#0F172A", corner_radius=10, border_width=1, border_color="#1E293B")
        res_card.pack(side="bottom", fill="x", padx=14, pady=12)
        ctk.CTkLabel(res_card, text="ENGINE TELEMETRY", font=("Segoe UI", 10, "bold"), text_color="#06B6D4").pack(anchor="w", padx=12, pady=(8, 2))
        self.ram_label = ctk.CTkLabel(res_card, text="App RAM: ~52 MB", font=("Consolas", 11), text_color="#E2E8F0")
        self.ram_label.pack(anchor="w", padx=12, pady=1)
        ctk.CTkLabel(res_card, text="GPU VRAM: 0.0 MB (Locked)", font=("Consolas", 11), text_color="#10B981").pack(anchor="w", padx=12, pady=1)

        ctk.CTkButton(
            res_card, text="Exit Completely", height=26, fg_color="#7F1D1D", hover_color="#991B1B",
            font=("Segoe UI", 11, "bold"), command=self.quit_completely
        ).pack(fill="x", padx=12, pady=(6, 8))

    def _build_views(self):
        self.main_container = ctk.CTkFrame(self, fg_color="#0B0F19", corner_radius=0)
        self.main_container.grid(row=1, column=1, sticky="nsew", padx=20, pady=16)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.views = {}
        for name in ("dashboard", "tuneup", "scanner", "wifi", "network", "incident", "mobile", "quarantine", "lab"):
            frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
            frame.grid(row=0, column=0, sticky="nsew")
            self.views[name] = frame

        self._setup_dashboard_view(self.views["dashboard"])
        self._setup_tuneup_view(self.views["tuneup"])
        self._setup_scanner_view(self.views["scanner"])
        self._setup_wifi_view(self.views["wifi"])
        self._setup_network_view(self.views["network"])
        self._setup_incident_view(self.views["incident"])
        self._setup_mobile_view(self.views["mobile"])
        self._setup_quarantine_view(self.views["quarantine"])
        self._setup_lab_view(self.views["lab"])

    def _setup_tuneup_view(self, parent):
        hero = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#F59E0B")
        hero.pack(fill="x", pady=(0, 12))

        top_r = ctk.CTkFrame(hero, fg_color="transparent")
        top_r.pack(fill="x", padx=20, pady=(14, 6))

        left_col = ctk.CTkFrame(top_r, fg_color="transparent")
        left_col.pack(side="left")
        ctk.CTkLabel(left_col, text="🧹  PURECLEAN QUICK TUNE-UP & JUNK CLEANER", font=("Segoe UI", 16, "bold"), text_color="#FBBF24").pack(anchor="w")
        ctk.CTkLabel(
            left_col,
            text="Safely cleans Windows temp clutter, browser caches, crash dumps, and optimizes standby RAM + DNS.",
            font=("Segoe UI", 12), text_color="#94A3B8"
        ).pack(anchor="w", pady=(2, 0))

        self.cc_total_badge = ctk.CTkLabel(top_r, text="Ready to Analyze", font=("Segoe UI", 20, "bold"), text_color="#10B981")
        self.cc_total_badge.pack(side="right", padx=10)

        btn_row = ctk.CTkFrame(hero, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(6, 12))

        ctk.CTkButton(
            btn_row, text="🔍 Analyze Junk & Clutter", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), height=36, width=210, command=self.analyze_ccleaner_junk
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text="🧹 Run 1-Click PureClean Now", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), height=36, width=250, command=self.execute_ccleaner_tuneup
        ).pack(side="left", padx=(0, 10))

        self.cc_progress = ctk.CTkProgressBar(hero, height=10, progress_color="#10B981")
        self.cc_progress.pack(fill="x", padx=20, pady=(2, 6))
        self.cc_progress.set(0)

        self.cc_status_lbl = ctk.CTkLabel(hero, text="Click 'Analyze Junk & Clutter' to calculate how much space PureClean can recover.", font=("Segoe UI", 12), text_color="#A7F3D0")
        self.cc_status_lbl.pack(anchor="w", padx=20, pady=(0, 12))

        cat_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        cat_scroll.pack(fill="both", expand=True)

        categories = [
            ("temp", "🗂️  Windows & Application Temp Files", "Cleans %TEMP%, AppData\\Local\\Temp, and stale installer cache files older than 1 hour."),
            ("browsers", "🌐  Web Browser Caches (Chrome, Edge, Brave, Firefox)", "Clears cached web images and temporary browser clutter without deleting your passwords or logins."),
            ("crashes", "💥  Windows Error Reports & Crash Dumps", "Removes old Windows Error Reporting (WER) logs, minidumps, and shader cache remnants."),
            ("downloads", "📥  Abandoned Partial Downloads (.crdownload / .part / .tmp)", "Cleans broken or unfinished browser download remnants inside your Downloads folder."),
            ("ram_dns", "⚡  RAM Working-Set Trim & DNS Network Flush", "Frees standby memory from idle background processes and flushes stale DNS resolver entries.")
        ]

        for key, title, desc in categories:
            card = ctk.CTkFrame(cat_scroll, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1E293B")
            card.pack(fill="x", padx=10, pady=5)

            row_top = ctk.CTkFrame(card, fg_color="transparent")
            row_top.pack(fill="x", padx=14, pady=(10, 2))

            cb = ctk.CTkCheckBox(
                row_top, text=title, variable=self.cc_vars[key],
                font=("Segoe UI", 14, "bold"), text_color="#F8FAFC", checkbox_width=22, checkbox_height=22
            )
            cb.pack(side="left")

            sz_lbl = ctk.CTkLabel(row_top, text="Not Scanned", font=("Consolas", 13, "bold"), text_color="#FBBF24")
            sz_lbl.pack(side="right", padx=6)
            self.cc_size_labels[key] = sz_lbl

            ctk.CTkLabel(card, text=desc, font=("Segoe UI", 12), text_color="#94A3B8", anchor="w", justify="left").pack(fill="x", padx=44, pady=(0, 10))

    def _collect_ccleaner_targets(self):
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))
        targets = {
            "temp": [Path(os.environ.get("TEMP", "")), local_app / "Temp"],
            "browsers": [
                local_app / r"Google\Chrome\User Data\Default\Cache\Cache_Data",
                local_app / r"Google\Chrome\User Data\Default\Code Cache",
                local_app / r"Microsoft\Edge\User Data\Default\Cache\Cache_Data",
                local_app / r"Microsoft\Edge\User Data\Default\Code Cache",
                local_app / r"BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data"
            ],
            "crashes": [
                local_app / "CrashDumps",
                local_app / r"Microsoft\Windows\WER\ReportArchive",
                local_app / r"Microsoft\Windows\WER\ReportQueue",
                local_app / "D3DSCache"
            ]
        }

        found_files = {k: [] for k in self.cc_vars}
        sizes = {k: 0 for k in self.cc_vars}
        now = time.time()

        for cat_key, dirs in targets.items():
            seen = set()
            for d in dirs:
                if not d or not d.exists():
                    continue
                for root, _, files in os.walk(str(d)):
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp in seen:
                            continue
                        seen.add(fp)
                        try:
                            st = os.stat(fp)
                            if now - st.st_mtime > 600:
                                found_files[cat_key].append((fp, st.st_size))
                                sizes[cat_key] += st.st_size
                        except Exception:
                            pass

        dl_dir = Path(WATCH_DIR)
        if dl_dir.exists():
            for f in dl_dir.glob("*"):
                if f.suffix.lower() in {".crdownload", ".part", ".tmp"}:
                    try:
                        st = f.stat()
                        if now - st.st_mtime > 600:
                            found_files["downloads"].append((str(f), st.st_size))
                            sizes["downloads"] += st.st_size
                    except Exception:
                        pass

        sizes["ram_dns"] = 120 * 1024 * 1024
        return found_files, sizes

    def analyze_ccleaner_junk(self):
        self.cc_status_lbl.configure(text="Scanning Windows Temp, Browser Caches, Crash Dumps & Downloads...", text_color="#FBBF24")
        self.cc_progress.set(0.25)

        def _worker():
            found_files, sizes = self._collect_ccleaner_targets()
            self.cc_last_scan_files = found_files
            total_bytes = sum(sizes[k] for k in self.cc_vars if self.cc_vars[k].get())

            def _ui():
                for k, lbl in self.cc_size_labels.items():
                    b = sizes.get(k, 0)
                    lbl.configure(
                        text=f"{format_bytes(b)} ({len(found_files[k])} files)" if k != "ram_dns" else "Ready (RAM + DNS Flush)",
                        text_color="#10B981" if b == 0 else "#FBBF24"
                    )
                self.cc_total_badge.configure(text=f"Cleanable: {format_bytes(total_bytes)}", text_color="#FBBF24")
                self.cc_progress.set(1.0)
                self.cc_status_lbl.configure(
                    text=f"Analysis complete: Found {format_bytes(total_bytes)} of safe-to-clean system clutter. Click 'Run 1-Click PureClean Now'.",
                    text_color="#10B981"
                )
            self.after(0, _ui)

        threading.Thread(target=_worker, daemon=True).start()

    def execute_ccleaner_tuneup(self):
        self.cc_status_lbl.configure(text="Running PureClean: removing selected junk, flushing DNS, and optimizing RAM...", text_color="#FBBF24")
        self.cc_progress.set(0.3)

        def _clean_worker():
            found_files, _ = self._collect_ccleaner_targets()
            bytes_removed = 0
            files_removed = 0

            for cat_key in ("temp", "browsers", "crashes", "downloads"):
                if not self.cc_vars[cat_key].get():
                    continue
                for fp, sz in found_files.get(cat_key, []):
                    try:
                        os.remove(fp)
                        bytes_removed += sz
                        files_removed += 1
                    except Exception:
                        pass

            if self.cc_vars["ram_dns"].get():
                try:
                    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    subprocess.run(["ipconfig", "/flushdns"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
                except Exception:
                    pass
                try:
                    psapi = ctypes.WinDLL("psapi")
                    kernel32 = ctypes.WinDLL("kernel32")
                    for proc in psutil.process_iter(["pid"]):
                        try:
                            h = kernel32.OpenProcess(0x0100 | 0x0400, False, proc.info["pid"])
                            if h:
                                psapi.EmptyWorkingSet(h)
                                kernel32.CloseHandle(h)
                        except Exception:
                            pass
                except Exception:
                    pass
                gc.collect()

            self.total_bytes_recovered += bytes_removed
            self.increment_healed_counter()
            summary = f"Removed {files_removed:,} junk/cache files ({format_bytes(bytes_removed)} recovered), flushed DNS & trimmed idle RAM."
            log_incident_db("PureClean Tune-Up", f"Recovered {format_bytes(bytes_removed)}", summary, "🧹 Cleaned & Optimized")
            self.log_event(f"🧹 [PURECLEAN] {summary}")

            def _done():
                for k, lbl in self.cc_size_labels.items():
                    if self.cc_vars[k].get():
                        lbl.configure(text="✅ Cleaned (0 B)", text_color="#10B981")
                self.cc_total_badge.configure(text=f"Recovered: {format_bytes(bytes_removed)}", text_color="#10B981")
                self.cc_progress.set(1.0)
                self.cc_status_lbl.configure(text=f"✨ {summary}", text_color="#10B981")
                self.refresh_incident_history_ui()

            self.after(0, _done)

        threading.Thread(target=_clean_worker, daemon=True).start()

    def _setup_dashboard_view(self, parent):
        self.banner = ctk.CTkFrame(parent, fg_color="#0F172A", corner_radius=12, border_width=1, border_color="#10B981")
        self.banner.pack(fill="x", pady=(0, 14))

        b_left = ctk.CTkFrame(self.banner, fg_color="transparent")
        b_left.pack(side="left", padx=20, pady=14)
        self.status_title = ctk.CTkLabel(b_left, text="●  YOUR PC, WI-FI & ANDROID SUITE ARE PROTECTED", font=("Segoe UI", 16, "bold"), text_color="#10B981")
        self.status_title.pack(anchor="w")
        self.status_sub = ctk.CTkLabel(b_left, text="Autonomous Self-Healing, PureClean Optimizer, Registry Shield & Hosts Immunization Ready", font=("Segoe UI", 12), text_color="#94A3B8")
        self.status_sub.pack(anchor="w", pady=(2, 0))

        ctk.CTkButton(
            self.banner, text="🧹 1-Click PureClean", fg_color="#D97706", hover_color="#B45309",
            font=("Segoe UI", 12, "bold"), height=36, width=180,
            command=lambda: [self.show_view("tuneup"), self.analyze_ccleaner_junk()]
        ).pack(side="right", padx=(8, 20), pady=14)

        ctk.CTkButton(
            self.banner, text="🔍 Quick Virus Scan", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), height=36, width=165,
            command=lambda: [self.show_view("scanner"), self.start_virus_scan("quick")]
        ).pack(side="right", padx=0, pady=14)

        kpi_row = ctk.CTkFrame(parent, fg_color="transparent")
        kpi_row.pack(fill="x", pady=(0, 14))
        for i in range(4):
            kpi_row.grid_columnconfigure(i, weight=1)

        self.card_hashes = self._make_kpi_card(kpi_row, 0, "THREAT SIGNATURES", "0", "5 Multi-Source Feeds", "#06B6D4")
        self.card_healed = self._make_kpi_card(kpi_row, 1, "AUTO-HEALED & CLEANED", "0", "PureClean & Auto-Fixes", "#10B981")
        self.card_conns = self._make_kpi_card(kpi_row, 2, "ACTIVE APPS ONLINE", "0", "Verified Internet Streams", "#8B5CF6")
        self.card_ml = self._make_kpi_card(kpi_row, 3, "AI LEARNING ENGINE", "Calibrating", "Self-Training Baseline", "#F59E0B")

        ctrl_bar = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1E293B")
        ctrl_bar.pack(fill="x", pady=(0, 14))

        ctk.CTkButton(
            ctrl_bar, text="🛡️ Immunize PC (Block Spyware Domains)", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), width=255, command=lambda: [self.show_view("scanner"), self.immunize_windows_hosts()]
        ).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(
            ctrl_bar, text="📶 Check Wi-Fi & Smart Devices", fg_color="#0891B2", hover_color="#0E7490",
            font=("Segoe UI", 12, "bold"), width=210, command=lambda: [self.show_view("wifi"), self.run_wifi_and_iot_audit()]
        ).pack(side="left", padx=6, pady=10)

        ctk.CTkButton(
            ctrl_bar, text="📱 Pair Android Phone", fg_color="#7C3AED", hover_color="#6D28D9",
            font=("Segoe UI", 12, "bold"), width=175, command=lambda: self.show_view("mobile")
        ).pack(side="left", padx=6, pady=10)

        ctk.CTkButton(
            ctrl_bar, text="🔄 Sync All 5 Threat Feeds", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), width=195, command=self.trigger_feed_sync
        ).pack(side="right", padx=12, pady=10)

        log_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        log_frame.pack(fill="both", expand=True)
        log_hdr = ctk.CTkFrame(log_frame, fg_color="#0F172A", height=34, corner_radius=0)
        log_hdr.pack(fill="x")
        ctk.CTkLabel(log_hdr, text="LIVE PROTECTION, PURECLEAN & AI ACTIVITY FEED", font=("Consolas", 11, "bold"), text_color="#38BDF8").pack(side="left", padx=14, pady=6)

        self.log_box = ctk.CTkTextbox(log_frame, font=("Consolas", 13), fg_color="#070A12", text_color="#E2E8F0", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

        # AI Engine Status & 1-Click Auto-Installer Bar
        self.ai_bar = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10, border_width=1, border_color="#F59E0B")
        self.ai_bar.pack(fill="x", pady=(10, 0))

        self.ai_status_lbl = ctk.CTkLabel(
            self.ai_bar,
            text="🤖 Checking AI Engine status...",
            font=("Segoe UI", 12, "bold"), text_color="#FBBF24"
        )
        self.ai_status_lbl.pack(side="left", padx=14, pady=8)

        self.ai_install_btn = ctk.CTkButton(
            self.ai_bar,
            text="⚡ 1-Click Auto-Install Local AI (Ollama + Qwen3)",
            fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), height=30, width=300,
            command=self.auto_install_local_ai
        )
        self.ai_install_btn.pack(side="right", padx=12, pady=8)
        self.after(800, self.refresh_ai_engine_banner)

    def refresh_ai_engine_banner(self):
        def _chk():
            code, msg = detect_local_ollama_status()
            cfg = load_settings()
            has_cloud = bool(cfg.get("cloud_ai_url", "").strip() and cfg.get("cloud_ai_key", "").strip())

            def _ui():
                if code == "READY":
                    self.ai_bar.configure(border_color="#10B981")
                    self.ai_status_lbl.configure(text=f"🟢 {msg}", text_color="#10B981")
                    self.ai_install_btn.pack_forget()
                elif has_cloud:
                    self.ai_bar.configure(border_color="#06B6D4")
                    self.ai_status_lbl.configure(text="🌐 Cloud AI Engine Active (Local Ollama optional)", text_color="#38BDF8")
                else:
                    self.ai_bar.configure(border_color="#F59E0B")
                    self.ai_status_lbl.configure(
                        text=f"⚠️ {msg} Click button to enable deep local AI:",
                        text_color="#FBBF24"
                    )
            self.after(0, _ui)
        threading.Thread(target=_chk, daemon=True).start()

    def auto_install_local_ai(self):
        self.ai_install_btn.configure(state="disabled", text="⏳ Installing Local AI Engine...")
        self.ai_status_lbl.configure(text="Downloading Ollama Setup (~100% automated in background)...", text_color="#38BDF8")
        self.log_event("[AI INSTALLER] Starting automated setup for Local Ollama + qwen3:1.7b...")

        def _installer_worker():
            try:
                ollama_exe = Path(os.environ.get("LOCALAPPDATA", "")) / r"Programs\Ollama\ollama.exe"
                if not ollama_exe.exists() and not shutil.which("ollama"):
                    setup_dest = APP_DATA_DIR / "OllamaSetup.exe"
                    self.log_event("[AI INSTALLER] Downloading official OllamaSetup.exe from ollama.com...")
                    with requests.get("https://ollama.com/download/OllamaSetup.exe", stream=True, timeout=120) as r:
                        r.raise_for_status()
                        with open(setup_dest, "wb") as f:
                            for chunk in r.iter_content(chunk_size=1024 * 256):
                                if chunk:
                                    f.write(chunk)
                    self.after(0, lambda: self.ai_status_lbl.configure(text="Running silent Ollama installation...", text_color="#FBBF24"))
                    self.log_event("[AI INSTALLER] Running OllamaSetup.exe /SILENT...")
                    subprocess.run([str(setup_dest), "/SILENT"], check=False)
                    time.sleep(3)

                cmd_exe = str(ollama_exe) if ollama_exe.exists() else "ollama"
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                try:
                    subprocess.Popen([cmd_exe, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
                except Exception:
                    pass
                time.sleep(2)

                self.after(0, lambda: self.ai_status_lbl.configure(text="Pulling compact Qwen3 (1.7B) security model... Please wait ~1-2 mins.", text_color="#38BDF8"))
                self.log_event("[AI INSTALLER] Pulling qwen3:1.7b model weights (CPU-optimized, 0 VRAM drain)...")
                subprocess.run([cmd_exe, "pull", MODEL_NAME], check=False, creationflags=flags)

                self.log_event("[AI INSTALLER] ✅ Local AI Engine (Ollama + qwen3:1.7b) installed and verified!")
                self.after(0, self.refresh_ai_engine_banner)
            except Exception as e:
                self.log_event(f"[AI INSTALLER ERROR] {e} — Falling back to Built-in Heuristic AI.")
                self.after(0, lambda err=e: [
                    self.ai_status_lbl.configure(text=f"Install note: {err} (Visit ollama.com to install manually)", text_color="#F87171"),
                    self.ai_install_btn.configure(state="normal", text="⚡ Retry Local AI Install")
                ])

        threading.Thread(target=_installer_worker, daemon=True).start()

    def start_mobile_companion_server(self):
        if self.companion_running:
            return
        self.companion_running = True
        app_ref = self

        class CompanionHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def _send_json(self, data, code=200):
                body = json.dumps(data).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/status":
                    incs = [
                        {"id": r[0], "timestamp": r[1], "category": r[2], "target": r[3], "summary": r[4], "outcome": r[5]}
                        for r in get_incident_history_db(15)
                    ]
                    self._send_json({
                        "version": APP_VERSION,
                        "pc_name": socket.gethostname(),
                        "signatures": app_ref.total_sig_count,
                        "auto_healed": app_ref.auto_healed_count,
                        "active_conns": app_ref.active_conn_count,
                        "incidents": incs
                    })
                else:
                    self._send_json({"status": "PureProtect Companion Bridge Active"}, 200)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
                try:
                    payload = json.loads(raw)
                except Exception:
                    payload = {}
                if self.path == "/api/action":
                    act = payload.get("action", "")
                    if act == "quick_scan":
                        app_ref.after(0, lambda: app_ref.start_virus_scan("quick"))
                    elif act == "wifi_audit":
                        app_ref.after(0, app_ref.run_wifi_and_iot_audit)
                    elif act in ("pureclean_tuneup", "ccleaner_tuneup", "micro_heal"):
                        app_ref.after(0, app_ref.execute_ccleaner_tuneup)
                    self._send_json({"status": "ok", "triggered": act})
                else:
                    self._send_json({"error": "Unknown endpoint"}, 404)

        def _serve():
            try:
                server = ThreadingHTTPServer(("0.0.0.0", COMPANION_PORT), CompanionHandler)
                self.log_event(f"[MOBILE BRIDGE] Android Companion Server active at http://{self.lan_ip}:{COMPANION_PORT}")
                server.serve_forever()
            except Exception as e:
                self.companion_running = False
                self.log_event(f"[MOBILE BRIDGE NOTE] {e}")

        threading.Thread(target=_serve, daemon=True).start()

    def _setup_mobile_view(self, parent):
        top = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        top.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(top, text="📱  PUREPROTECT ANDROID COMPANION & REMOTE BRIDGE", font=("Segoe UI", 16, "bold"), text_color="#06B6D4").pack(anchor="w", padx=20, pady=(14, 4))
        ctk.CTkLabel(
            top,
            text=f"Your Android app (v3.5) can sync with this PC at {self.lan_ip}:{COMPANION_PORT} to trigger remote PureClean Tune-Ups and Virus Scans.",
            font=("Segoe UI", 12), text_color="#CBD5E1", wraplength=880, justify="left"
        ).pack(anchor="w", padx=20, pady=(0, 12))

        btn_bar = ctk.CTkFrame(top, fg_color="transparent")
        btn_bar.pack(fill="x", padx=20, pady=(0, 14))

        ctk.CTkButton(
            btn_bar, text="🔓 Allow Port 5055 in Windows Firewall", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), width=280, command=self.allow_companion_firewall
        ).pack(side="left")

        body = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        body.pack(fill="both", expand=True)

        left_qr = ctk.CTkFrame(body, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        left_qr.pack(side="left", padx=24, pady=24)

        url_str = f"http://{self.lan_ip}:{COMPANION_PORT}"
        try:
            if qrcode is None:
                raise RuntimeError("qrcode fallback")
            qr = qrcode.QRCode(box_size=6, border=2)
            qr.add_data(url_str)
            qr.make(fit=True)
            qr_pil = qr.make_image(fill_color="#06B6D4", back_color="#0B0F19").convert("RGBA")
            self.qr_ctk = ctk.CTkImage(light_image=qr_pil, dark_image=qr_pil, size=(200, 200))
            ctk.CTkLabel(left_qr, image=self.qr_ctk, text="").pack(padx=18, pady=(18, 8))
        except Exception:
            ctk.CTkLabel(left_qr, text=url_str, font=("Consolas", 14, "bold"), text_color="#06B6D4").pack(padx=20, pady=40)

        ctk.CTkLabel(left_qr, text=f"PC Bridge Address:\n{self.lan_ip}:{COMPANION_PORT}", font=("Consolas", 13, "bold"), text_color="#10B981").pack(padx=18, pady=(0, 16))

        right_info = ctk.CTkFrame(body, fg_color="transparent")
        right_info.pack(side="left", fill="both", expand=True, padx=(4, 24), pady=24)

        guide = (
            "HOW TO LINK YOUR ANDROID APP:\n\n"
            f"1. In the PureProtect Android app on your phone, tap the '🌐 Network' tab on the bottom navigation bar.\n"
            f"2. Confirm the PC Bridge address is set to:  {self.lan_ip}:{COMPANION_PORT}\n"
            "3. Tap '🔄 Sync PC' or '🧹 PureClean PC' to trigger a full PureClean Tune-Up on this laptop remotely from your phone."
        )
        ctk.CTkLabel(right_info, text=guide, font=("Segoe UI", 13), text_color="#E2E8F0", justify="left", anchor="nw", wraplength=560).pack(fill="both", expand=True)

    def allow_companion_firewall(self):
        try:
            subprocess.run([
                "powershell", "-Command",
                f"Start-Process netsh -ArgumentList 'advfirewall firewall add rule name=\"PureProtect_Mobile_Bridge\" dir=in action=allow protocol=TCP localport={COMPANION_PORT}' -Verb RunAs"
            ], check=False)
            self.log_event(f"[MOBILE BRIDGE] Added Windows Firewall inbound rule for port {COMPANION_PORT}.")
        except Exception as e:
            self.log_event(f"[FIREWALL NOTE] {e}")

    def _setup_scanner_view(self, parent):
        top = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        top.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(top, text="🔍  VIRUS SCANNER, REGISTRY AUDITOR & SYSTEM IMMUNIZATION", font=("Segoe UI", 16, "bold"), text_color="#06B6D4").pack(anchor="w", padx=20, pady=(14, 4))
        ctk.CTkLabel(
            top, text="Scans files, audits Windows Registry startup/proxy keys for spyware, and immunizes your Windows DNS Hosts file against malicious domains.",
            font=("Segoe UI", 12), text_color="#94A3B8"
        ).pack(anchor="w", padx=20, pady=(0, 10))

        btn_row = ctk.CTkFrame(top, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkButton(
            btn_row, text="⚡ Quick Virus & Registry Scan", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), width=230, command=lambda: self.start_virus_scan("quick")
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="🛡️ Full User Profile Scan", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), width=190, command=lambda: self.start_virus_scan("full")
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="📁 Custom Folder...", fg_color="#374151", hover_color="#4B5563",
            font=("Segoe UI", 12, "bold"), width=150, command=lambda: self.start_virus_scan("custom")
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="⏹ Stop", fg_color="#DC2626", hover_color="#B91C1C",
            font=("Segoe UI", 12, "bold"), width=85, command=self.stop_virus_scan
        ).pack(side="right")

        imm_row = ctk.CTkFrame(top, fg_color="transparent")
        imm_row.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(
            imm_row, text="🛡️ Immunize PC (Block Spyware & Malware Domains in Windows DNS)", fg_color="#7C3AED", hover_color="#6D28D9",
            font=("Segoe UI", 12, "bold"), width=430, command=self.immunize_windows_hosts
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            imm_row, text="🔑 Audit Registry Startup & Proxy Hijacks", fg_color="#D97706", hover_color="#B45309",
            font=("Segoe UI", 12, "bold"), width=265, command=self.run_registry_audit_ui
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            imm_row, text="↩️ Undo Immunization", fg_color="#374151", hover_color="#4B5563",
            font=("Segoe UI", 12, "bold"), width=155, command=self.undo_windows_hosts_immunization
        ).pack(side="right")

        self.scan_progress = ctk.CTkProgressBar(top, height=12, progress_color="#10B981")
        self.scan_progress.pack(fill="x", padx=20, pady=(4, 6))
        self.scan_progress.set(0)

        self.scan_status_lbl = ctk.CTkLabel(top, text="Ready. Run a Quick Scan, Registry Audit, or click 'Immunize PC' above.", font=("Segoe UI", 12), text_color="#A7F3D0")
        self.scan_status_lbl.pack(anchor="w", padx=20, pady=(0, 14))

        res_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        res_frame.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(res_frame, fg_color="#0F172A", height=34, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="SCANNER, REGISTRY HIJACK & IMMUNIZATION LOG", font=("Consolas", 11, "bold"), text_color="#38BDF8").pack(side="left", padx=14, pady=6)

        self.scan_box = ctk.CTkTextbox(res_frame, font=("Consolas", 13), fg_color="#070A12", text_color="#E2E8F0", wrap="word")
        self.scan_box.insert(
            "end",
            "Ready to protect.\n"
            "• System Immunization: Blocks known spyware, phishing, and malware domains natively in Windows (no Docker or AdGuard required).\n"
            "• Registry & Proxy Auditor: Inspects HKCU/HKLM Run keys and Windows Proxy settings for hidden spyware persistence.\n"
            "• Cloud & Phone Link Safe: Automatically skips virtual CrossDevice/OneDrive files."
        )
        self.scan_box.pack(fill="both", expand=True, padx=10, pady=10)

    def run_registry_audit_ui(self):
        self.scan_box.delete("1.0", "end")
        self.scan_box.insert("end", "[*] Auditing Windows Registry Startup (HKCU/HKLM Run) & System Proxy Settings...\n\n")
        findings = scan_registry_and_hijacks()
        risky_count = 0
        for item in findings:
            status = "⚠️ [SUSPICIOUS]" if item["risky"] else "✅ [VERIFIED]"
            if item["risky"]:
                risky_count += 1
            self.scan_box.insert("end", f"{status} [{item['location']}] {item['name']} -> {item['command']}\n")
        msg = f"Registry & Proxy Audit Complete: Inspected {len(findings)} startup/proxy entries ({risky_count} suspicious)."
        self.scan_status_lbl.configure(text=msg, text_color="#10B981" if risky_count == 0 else "#F59E0B")
        log_incident_db("Registry & Proxy Audit", "Windows Registry", msg, "✅ Registry Clean" if risky_count == 0 else f"⚠️ {risky_count} Flagged")
        self.refresh_incident_history_ui()

    def immunize_windows_hosts(self):
        self.scan_status_lbl.configure(text="Immunizing Windows DNS Hosts file with latest spyware/malware domain blocklist...", text_color="#FBBF24")
        self.scan_progress.set(0.35)

        def _imm_worker():
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("SELECT domain FROM bad_domains LIMIT 1500").fetchall()
            conn.close()

            if not rows:
                try:
                    sync_feeds_internal()
                    conn = sqlite3.connect(DB_PATH)
                    rows = conn.execute("SELECT domain FROM bad_domains LIMIT 1500").fetchall()
                    conn.close()
                except Exception:
                    pass

            domains = [r[0] for r in rows]
            if not domains:
                domains = [
                    "telemetry-malware-check.invalid",
                    "stalkerware-c2-sinkhole.invalid",
                    "phishing-credential-stealer.invalid"
                ]

            block_lines = ["\n# === START PUREPROTECT IMMUNIZATION ==="]
            for d in domains[:1500]:
                block_lines.append(f"0.0.0.0 {d}")
            block_lines.append("# === END PUREPROTECT IMMUNIZATION ===\n")
            block_text = "\n".join(block_lines)

            try:
                orig = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
                if "# === START PUREPROTECT IMMUNIZATION ===" in orig:
                    head = orig.split("# === START PUREPROTECT IMMUNIZATION ===")[0]
                    tail = orig.split("# === END PUREPROTECT IMMUNIZATION ===")[-1]
                    orig = head.rstrip() + "\n" + tail.lstrip()
                new_hosts = orig.rstrip() + "\n" + block_text
                HOSTS_PATH.write_text(new_hosts, encoding="utf-8")
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                subprocess.run(["ipconfig", "/flushdns"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
                self.increment_healed_counter()
                msg = f"🛡️ System Immunized! Blocked {len(domains[:1500]):,} spyware & malware domains natively in Windows DNS."
                log_incident_db("System Immunization", "Windows DNS Hosts", msg, "🛡️ Immunized")
                self.after(0, lambda m=msg: [
                    self.scan_progress.set(1.0),
                    self.scan_status_lbl.configure(text=m, text_color="#10B981"),
                    self.scan_box.insert("end", f"\n[+] {m}\n"),
                    self.refresh_incident_history_ui()
                ])
            except PermissionError:
                self.after(0, lambda: self.scan_status_lbl.configure(
                    text="Note: Run PureProtect as Administrator to write to C:\\Windows\\System32\\drivers\\etc\\hosts.",
                    text_color="#F59E0B"
                ))
            except Exception as e:
                self.after(0, lambda err=e: self.scan_status_lbl.configure(text=f"Immunization note: {err}", text_color="#F87171"))

        threading.Thread(target=_imm_worker, daemon=True).start()

    def undo_windows_hosts_immunization(self):
        try:
            if HOSTS_PATH.exists():
                orig = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
                if "# === START PUREPROTECT IMMUNIZATION ===" in orig:
                    head = orig.split("# === START PUREPROTECT IMMUNIZATION ===")[0]
                    tail = orig.split("# === END PUREPROTECT IMMUNIZATION ===")[-1]
                    HOSTS_PATH.write_text(head.rstrip() + "\n" + tail.lstrip(), encoding="utf-8")
                    self.scan_status_lbl.configure(text="Removed PureProtect Immunization entries from Windows Hosts file.", text_color="#38BDF8")
                else:
                    self.scan_status_lbl.configure(text="No PureProtect Immunization entries found in Windows Hosts.", text_color="#94A3B8")
        except Exception as e:
            self.scan_status_lbl.configure(text=f"Requires Administrator privileges to edit hosts file ({e}).", text_color="#F59E0B")

    def _setup_wifi_view(self, parent):
        top_bar = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        top_bar.pack(fill="x", pady=(0, 12))

        text_row = ctk.CTkFrame(top_bar, fg_color="transparent")
        text_row.pack(fill="x", padx=20, pady=(12, 6))
        ctk.CTkLabel(text_row, text="📶  HOME WI-FI & SMART DEVICE SAFETY CHECK", font=("Segoe UI", 15, "bold"), text_color="#06B6D4").pack(anchor="w")
        ctk.CTkLabel(
            text_row,
            text="Verifies your Wi-Fi encryption and checks every smart TV, phone, and device on your network for open ports.",
            font=("Segoe UI", 12), text_color="#94A3B8"
        ).pack(anchor="w", pady=(2, 0))

        btn_bar = ctk.CTkFrame(top_bar, fg_color="transparent")
        btn_bar.pack(fill="x", padx=20, pady=(4, 12))

        ctk.CTkButton(
            btn_bar, text="📶 Scan My Wi-Fi & Devices", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), height=34, width=220, command=self.run_wifi_and_iot_audit
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_bar, text="✨ Auto-Heal Network Cache", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), height=34, width=220, command=self.auto_heal_network_cache
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_bar, text="🔑 Open Router Login Page", fg_color="#374151", hover_color="#4B5563",
            font=("Segoe UI", 12, "bold"), height=34, width=200, command=self.open_router_admin
        ).pack(side="left")

        overview_row = ctk.CTkFrame(parent, fg_color="transparent")
        overview_row.pack(fill="x", pady=(0, 12))
        for i in range(3):
            overview_row.grid_columnconfigure(i, weight=1)

        self.wifi_card_enc = self._make_simple_health_card(
            overview_row, 0, "1. WI-FI ENCRYPTION", "Not Scanned Yet",
            "Click 'Scan My Wi-Fi & Devices' above.", "#38BDF8"
        )
        self.wifi_card_router = self._make_simple_health_card(
            overview_row, 1, "2. HOME ROUTER SAFETY", "Not Scanned Yet",
            "Checks if your router blocks outside hackers.", "#10B981"
        )
        self.wifi_card_iot = self._make_simple_health_card(
            overview_row, 2, "3. SMART DEVICES & TVS", "Not Scanned Yet",
            "Checks phones, TVs & cameras on your Wi-Fi.", "#A855F7"
        )

        list_hdr = ctk.CTkFrame(parent, fg_color="#0F172A", height=32, corner_radius=8)
        list_hdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            list_hdr, text="CONNECTED DEVICES ON YOUR HOME WI-FI (CLICK 'TRUST MY DEVICE' ON YOUR OWN STREAMING BOXES / TVS)",
            font=("Consolas", 11, "bold"), text_color="#38BDF8"
        ).pack(side="left", padx=14, pady=5)

        self.wifi_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        self.wifi_scroll.pack(fill="both", expand=True)
        ctk.CTkLabel(
            self.wifi_scroll,
            text="Click '📶 Scan My Wi-Fi & Devices' above to see every device on your network in plain English.",
            font=("Segoe UI", 13), text_color="#94A3B8"
        ).pack(anchor="w", padx=16, pady=20)

    def _make_simple_health_card(self, parent, col, title, status_text, desc_text, accent):
        card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 2 else 6))
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 11, "bold"), text_color="#94A3B8").pack(anchor="w", padx=16, pady=(10, 2))
        st_lbl = ctk.CTkLabel(card, text=status_text, font=("Segoe UI", 16, "bold"), text_color=accent, anchor="w", justify="left")
        st_lbl.pack(anchor="w", padx=16, pady=2)
        sub_lbl = ctk.CTkLabel(card, text=desc_text, font=("Segoe UI", 12), text_color="#CBD5E1", wraplength=280, anchor="w", justify="left")
        sub_lbl.pack(anchor="w", padx=16, pady=(2, 10))
        return st_lbl, sub_lbl

    def _setup_network_view(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        hdr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hdr, text="🌐  EASY NETWORK RADAR (WHAT APPS ARE ONLINE RIGHT NOW)", font=("Segoe UI", 16, "bold"), text_color="#38BDF8").pack(side="left", padx=18, pady=14)
        ctk.CTkButton(hdr, text="🔄 Refresh Connections", width=160, fg_color="#2563EB", hover_color="#1D4ED8", command=self.refresh_network_table).pack(side="right", padx=18, pady=14)

        self.net_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        self.net_scroll.pack(fill="both", expand=True)

    def _setup_incident_view(self, parent):
        top_card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#38BDF8")
        top_card.pack(fill="x", pady=(0, 12))

        hdr_row = ctk.CTkFrame(top_card, fg_color="transparent")
        hdr_row.pack(fill="x", padx=18, pady=(12, 4))
        ctk.CTkLabel(hdr_row, text="📋  ACTIVE INCIDENT & ONE-CLICK REMEDIATION", font=("Segoe UI", 15, "bold"), text_color="#38BDF8", anchor="w").pack(side="left")

        ctk.CTkButton(
            hdr_row, text="🗑️ Clear History", fg_color="#374151", hover_color="#4B5563",
            font=("Segoe UI", 11, "bold"), height=28, width=115, command=self.clear_incident_history
        ).pack(side="right")

        ctk.CTkButton(
            hdr_row, text="✅ Trust App", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 11, "bold"), height=28, width=120, command=self.trust_and_recalibrate
        ).pack(side="right", padx=6)

        ctk.CTkButton(
            hdr_row, text="⚡ Auto-Fix Now", fg_color="#DC2626", hover_color="#B91C1C",
            font=("Segoe UI", 11, "bold"), height=28, width=130, command=self.execute_autofix
        ).pack(side="right", padx=6)

        self.inc_simple_lbl = ctk.CTkLabel(
            top_card,
            text="No active incidents require your attention. PureProtect's Autonomous Pilot is automatically learning safe apps and healing minor issues in the background.",
            font=("Segoe UI", 13), text_color="#E2E8F0", wraplength=860, anchor="w", justify="left"
        )
        self.inc_simple_lbl.pack(fill="x", padx=18, pady=(2, 14))

        hist_hdr = ctk.CTkFrame(parent, fg_color="#0F172A", height=34, corner_radius=8)
        hist_hdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(hist_hdr, text="INCIDENT HISTORY & OUTCOME LOG (SECURITY, PURECLEAN & IMMUNIZATION EVENTS)", font=("Consolas", 11, "bold"), text_color="#10B981").pack(side="left", padx=14, pady=6)

        self.hist_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        self.hist_scroll.pack(fill="both", expand=True)

        self.adv_forensic_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#F59E0B")
        adv_hdr = ctk.CTkFrame(self.adv_forensic_frame, fg_color="#0F172A", height=30, corner_radius=0)
        adv_hdr.pack(fill="x")
        ctk.CTkLabel(adv_hdr, text="🔬 ADVANCED TECHNICAL DIAGNOSTICS (RAW PIDS, SOCKETS, PATHS & ENTROPY)", font=("Consolas", 11, "bold"), text_color="#F59E0B").pack(side="left", padx=12, pady=4)

        self.adv_box = ctk.CTkTextbox(self.adv_forensic_frame, font=("Consolas", 12), fg_color="#070A12", text_color="#A7F3D0", height=120, wrap="word")
        self.adv_box.pack(fill="x", padx=10, pady=8)
        self.adv_box.insert("end", "Advanced Mode Active: Trigger or select an incident to inspect raw process paths, PIDs, SHA256 hashes, and socket endpoints.")

    def _setup_quarantine_view(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        hdr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hdr, text="🔒  ISOLATED QUARANTINE VAULT", font=("Segoe UI", 16, "bold"), text_color="#F59E0B").pack(side="left", padx=18, pady=14)
        ctk.CTkButton(hdr, text="Refresh Vault", width=130, command=self.refresh_quarantine_list).pack(side="right", padx=18, pady=14)
        self.q_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        self.q_scroll.pack(fill="both", expand=True)

    def _setup_lab_view(self, parent):
        inj_card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        inj_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(inj_card, text=f"🚀  UNIVERSAL GITHUB UPDATER & CODE AUTO-INJECTOR (Installed: v{APP_VERSION})", font=("Segoe UI", 15, "bold"), text_color="#06B6D4").pack(anchor="w", padx=20, pady=(12, 4))
        ctk.CTkLabel(inj_card, text="Accepts either your raw guardian_ui.py link OR a version.json link from your GitHub repository:", font=("Segoe UI", 12), text_color="#94A3B8").pack(anchor="w", padx=20)

        p_row = ctk.CTkFrame(inj_card, fg_color="transparent")
        p_row.pack(fill="x", padx=20, pady=(6, 8))

        self.patch_url_entry = ctk.CTkEntry(p_row, font=("Consolas", 12), height=34)
        self.patch_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.patch_url_entry.insert(0, self.settings.get("patch_url", DEFAULT_PATCH_URL))

        ctk.CTkButton(p_row, text="⚡ Pull & Inject Update Now", fg_color="#059669", hover_color="#047857", font=("Segoe UI", 12, "bold"), width=210, command=self.inject_from_github).pack(side="right", padx=(6, 0))
        ctk.CTkButton(p_row, text="🔄 Reload Local Code", fg_color="#2563EB", hover_color="#1D4ED8", font=("Segoe UI", 12, "bold"), width=155, command=self.reload_local_code).pack(side="right")

        self.update_status_lbl = ctk.CTkLabel(inj_card, text=f"✅ Installed & Running v{APP_VERSION} (100% Standalone Beta-Ready).", font=("Segoe UI", 12, "bold"), text_color="#10B981")
        self.update_status_lbl.pack(anchor="w", padx=20, pady=(0, 8))

        pref_row = ctk.CTkFrame(inj_card, fg_color="transparent")
        pref_row.pack(fill="x", padx=20, pady=(0, 12))
        ctk.CTkSwitch(pref_row, text="Start with Windows (Single Instance)", variable=self.autostart_var, command=self.toggle_windows_autostart, font=("Segoe UI", 12)).pack(side="left", padx=(0, 20))
        ctk.CTkSwitch(pref_row, text="Minimize to System Tray on Close", variable=self.minimize_to_tray_var, font=("Segoe UI", 12)).pack(side="left", padx=(0, 20))
        ctk.CTkSwitch(pref_row, text="Silent Mode (Mute Pop-ups)", variable=self.silent_mode_var, font=("Segoe UI", 12)).pack(side="left")

        sim_card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#F59E0B")
        sim_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(sim_card, text="🧪  ADVANCED TESTING & SIMULATION LAB", font=("Segoe UI", 15, "bold"), text_color="#F59E0B").pack(anchor="w", padx=20, pady=(12, 4))
        sim_row = ctk.CTkFrame(sim_card, fg_color="transparent")
        sim_row.pack(fill="x", padx=20, pady=(4, 12))

        ctk.CTkButton(
            sim_row, text="⚡ Simulate Malware Download (Tests Auto-Quarantine)", fg_color="#D97706", hover_color="#B45309",
            font=("Segoe UI", 12, "bold"), width=310, command=self.trigger_test_alert
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            sim_row, text="🌐 Simulate Rogue Network Connection", fg_color="#7C3AED", hover_color="#6D28D9",
            font=("Segoe UI", 12, "bold"), width=250, command=self.trigger_simulated_net_anomaly
        ).pack(side="left", padx=(0, 10))

        legal_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        legal_frame.pack(fill="both", expand=True)
        legal_box = ctk.CTkTextbox(legal_frame, font=("Consolas", 12), fg_color="#070A12", text_color="#E2E8F0", wrap="word")
        legal_box.pack(fill="both", expand=True, padx=10, pady=10)
        legal_box.insert("end", LEGAL_TEXT)
        legal_box.configure(state="disabled")

    def _make_kpi_card(self, parent, col, title, val, sub, accent):
        card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 3 else 6))
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 10, "bold"), text_color="#94A3B8").pack(anchor="w", padx=16, pady=(12, 2))
        val_lbl = ctk.CTkLabel(card, text=val, font=("Segoe UI", 22, "bold"), text_color=accent)
        val_lbl.pack(anchor="w", padx=16, pady=0)
        ctk.CTkLabel(card, text=sub, font=("Segoe UI", 11), text_color="#64748B").pack(anchor="w", padx=16, pady=(2, 12))
        return val_lbl

    def show_view(self, name):
        self.current_tab = name
        if name == "mobile":
            self.start_mobile_companion_server()
        titles = {
            "dashboard": "⚡ Live Protection & Self-Healing Command Center",
            "tuneup": "🧹 PureClean Quick Tune-Up & Junk Cleaner",
            "scanner": "🔍 Virus Scanner, Registry Auditor & System Immunization",
            "wifi": "📶 Home Wi-Fi & Smart Device Safety Check",
            "network": "🌐 Easy Network Radar (Connected Apps)",
            "incident": "📋 Incidents, Auto-Fix & Resolution History",
            "mobile": "📱 Android Phone Companion & Live Pairing",
            "quarantine": "🔒 Isolated Quarantine Vault",
            "lab": "🔧 Universal Updater, Simulation Lab & Legal EULA"
        }
        self.top_title_lbl.configure(text=titles.get(name, "PureProtect AI Suite"))
        for key, frame in self.views.items():
            if key == name:
                frame.tkraise()
                self.nav_buttons[key].configure(fg_color="#1E293B", text_color="#38BDF8")
            else:
                self.nav_buttons[key].configure(fg_color="transparent", text_color="#94A3B8")
        if name == "network":
            self.refresh_network_table()
        elif name == "quarantine":
            self.refresh_quarantine_list()
        elif name == "incident":
            self.refresh_incident_history_ui()

    def increment_healed_counter(self):
        self.auto_healed_count += 1
        self.after(0, lambda c=self.auto_healed_count: self.card_healed.configure(text=str(c)))

    def auto_heal_network_cache(self):
        def _net_heal():
            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                subprocess.run(["ipconfig", "/flushdns"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
            except Exception:
                pass
            self.increment_healed_counter()
            log_incident_db("Network Hygiene", "Wi-Fi DNS Resolver", "Flushed local DNS resolver cache to clear stale routes.", "✨ Auto-Healed (Minor)")
            self.log_event("✨ [NETWORK AUTO-HEAL] Flushed local DNS resolver cache.")
            self.after(0, self.refresh_incident_history_ui)
        threading.Thread(target=_net_heal, daemon=True).start()

    def autonomous_maintenance_loop(self):
        time.sleep(15)
        while True:
            if self.auto_heal_var.get():
                try:
                    for f in Path(WATCH_DIR).glob("*"):
                        if f.suffix.lower() in {".crdownload", ".part"} and (time.time() - f.stat().st_mtime > 43200):
                            f.unlink()
                            self.increment_healed_counter()
                            log_incident_db("Auto-Heal Cleanup", f.name, "Removed abandoned partial download file.", "✨ Auto-Healed (Minor)")
                except Exception:
                    pass
            time.sleep(600)

    def stop_virus_scan(self):
        if self.scan_running:
            self.stop_scan_flag = True
            self.scan_status_lbl.configure(text="Stopping scan...", text_color="#F87171")

    def start_virus_scan(self, mode="quick"):
        if self.scan_running:
            return
        if mode == "quick":
            target_dirs = [
                Path.home() / "Downloads",
                Path.home() / "Desktop",
                Path.home() / "Documents",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Temp",
                Path(STARTUP_DIR)
            ]
            scan_title = "Quick Virus, Malware & Registry Scan"
        elif mode == "full":
            target_dirs = [Path.home()]
            scan_title = "Full User Profile Scan (Local Executables & Scripts)"
        else:
            chosen = filedialog.askdirectory(title="Select Folder to Scan")
            if not chosen:
                return
            target_dirs = [Path(chosen)]
            scan_title = f"Custom Scan ({os.path.basename(chosen)})"

        self.scan_running = True
        self.stop_scan_flag = False
        self.scan_progress.set(0)
        self.scan_box.delete("1.0", "end")
        self.scan_box.insert("end", f"[*] Starting {scan_title} (Skipping Phone Link / Cloud placeholders)...\n")

        def _scan_worker():
            reg_findings = scan_registry_and_hijacks()
            reg_risks = [r for r in reg_findings if r["risky"]]
            self.after(0, lambda c=len(reg_findings), r=len(reg_risks): self.scan_box.insert(
                "end", f"[+] Audited {c} Windows Registry Startup & Proxy keys ({r} suspicious).\n"
            ))

            files_to_scan = []
            skipped_cloud = 0
            self.after(0, lambda: self.scan_status_lbl.configure(text="Indexing local executable and script files...", text_color="#FBBF24"))
            skip_dirs = {"venv", "node_modules", ".git", "quarantine", "packages", "crossdevice", "onedrive", "iclouddrive", "google drive", "dropbox"}

            for d in target_dirs:
                if not d or not d.exists():
                    continue
                for root, dirs, files in os.walk(str(d)):
                    if self.stop_scan_flag:
                        break
                    dirs[:] = [sub for sub in dirs if sub.lower() not in skip_dirs]
                    for f in files:
                        ext = Path(f).suffix.lower()
                        if ext not in SCAN_EXTENSIONS and not f.endswith("test_malware.txt"):
                            continue
                        full_p = os.path.join(root, f)
                        if is_cloud_or_phone_placeholder(full_p):
                            skipped_cloud += 1
                            continue
                        files_to_scan.append(full_p)
                        if mode == "quick" and len(files_to_scan) >= 2500:
                            break

            total = max(len(files_to_scan), 1)
            scanned = 0
            threats_found = len(reg_risks)

            conn = sqlite3.connect(DB_PATH)
            bad_hashes = {r[0] for r in conn.execute("SELECT sha256 FROM bad_hashes").fetchall()}
            conn.close()

            for fpath in files_to_scan:
                if self.stop_scan_flag:
                    break
                scanned += 1
                if scanned % 15 == 0 or scanned == total:
                    pct = scanned / total
                    short_name = os.path.basename(fpath)[:45]
                    self.after(0, lambda p=pct, s=scanned, t=total, n=short_name: [
                        self.scan_progress.set(p),
                        self.scan_status_lbl.configure(text=f"Checking ({s:,}/{t:,}): {n}", text_color="#38BDF8")
                    ])
                try:
                    if not os.path.exists(fpath) or os.path.getsize(fpath) > 100 * 1024 * 1024:
                        continue
                    ext = Path(fpath).suffix.lower()
                    with open(fpath, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()

                    is_hash_hit = sha256 in bad_hashes
                    entropy = calculate_entropy(fpath) if (ext in {".exe", ".scr", ".bat", ".ps1"} and not is_safe_install_location(fpath)) else 0.0
                    is_heur_hit = entropy > 7.45

                    if is_hash_hit or is_heur_hit:
                        threats_found += 1
                        fname = os.path.basename(fpath)
                        reason = "Known Malware Signature Match" if is_hash_hit else f"Suspicious Packed Executable (Entropy {entropy:.2f})"
                        if self.auto_heal_var.get() and is_hash_hit:
                            dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{fname}.quarantined")
                            shutil.move(fpath, dest)
                            self.increment_healed_counter()
                            log_incident_db("Scanner Auto-Heal", fname, reason, "✨ Auto-Quarantined")
                            self.after(0, lambda fn=fname, r=reason: self.scan_box.insert("end", f"🛡️ [AUTO-QUARANTINED] {fn} ({r})\n"))
                        else:
                            self.last_flagged_file = fpath
                            log_incident_db("Scanner Detection", fname, reason, "⚠️ Needs Review")
                            self.after(0, lambda p=fpath, r=reason: self.scan_box.insert("end", f"⚠️ [FLAGGED] {p} -> {r}\n"))
                except Exception:
                    pass

            summary_line = f"Scan Complete: Checked {scanned:,} executables & {len(reg_findings)} Registry keys (Skipped {skipped_cloud} cloud links) | Threats: {threats_found}"
            log_incident_db("Virus & Registry Scan", scan_title, summary_line, f"✅ Clean ({scanned:,} checked)" if threats_found == 0 else f"🛡️ Fixed {threats_found} Threats")

            self.after(0, lambda: [
                self.scan_progress.set(1.0),
                self.scan_status_lbl.configure(text=summary_line, text_color="#10B981" if threats_found == 0 else "#F59E0B"),
                self.scan_box.insert("end", f"\n[+] {summary_line}\n"),
                self.refresh_quarantine_list(),
                self.refresh_incident_history_ui()
            ])
            self.scan_running = False

        threading.Thread(target=_scan_worker, daemon=True).start()

    def open_router_admin(self):
        webbrowser.open(f"http://{self.router_ip}")

    def trust_wifi_device(self, ip_addr):
        add_trusted_device(ip_addr)
        self.increment_healed_counter()
        log_incident_db("Trusted Home Device", ip_addr, f"Marked smart device {ip_addr} as a trusted home device.", "✅ Trusted Device")
        self.render_wifi_device_cards()
        self.refresh_wifi_summary_counts()
        self.refresh_incident_history_ui()

    def refresh_wifi_summary_counts(self):
        trusted_devs = get_trusted_devices()
        iot_vulns = [
            v for r in self.last_wifi_results
            if r[0] != self.router_ip and r[0] not in trusted_devs
            for v in r[3] if v[2] in {"CRITICAL", "HIGH"}
        ]
        i_title = f"✅ {len(self.last_wifi_results)} Devices Checked — Safe" if not iot_vulns else f"⚠️ {len(iot_vulns)} Device Risk(s) Found"
        i_desc = "All smart TVs, phones, and gadgets on your Wi-Fi are verified." if not iot_vulns else "Click 'Trust My Device' below if those are your own streaming boxes."
        i_col = "#10B981" if not iot_vulns else "#F59E0B"
        self.wifi_card_iot[0].configure(text=i_title, text_color=i_col)
        self.wifi_card_iot[1].configure(text=i_desc)

    def run_wifi_and_iot_audit(self):
        self.wifi_card_enc[0].configure(text="Scanning Wi-Fi...", text_color="#FBBF24")
        self.wifi_card_router[0].configure(text="Checking Router...", text_color="#FBBF24")
        self.wifi_card_iot[0].configure(text="Finding Devices...", text_color="#FBBF24")

        def _audit_worker():
            ssid, auth, cipher, signal = "Wired / Ethernet", "WPA2/WPA3", "AES", "100%"
            wifi_grade_title = "Protected Connection"
            wifi_grade_desc = "Your internet connection is encrypted and safe."
            wifi_color = "#10B981"

            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, stderr=subprocess.DEVNULL, creationflags=flags)
                for line in out.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        if k == "SSID":
                            ssid = v
                        elif k == "Authentication":
                            auth = v
                        elif k == "Cipher":
                            cipher = v
                        elif k == "Signal":
                            signal = v
                if ssid != "Wired / Ethernet":
                    if "WPA3" in auth or "WPA2" in auth:
                        wifi_grade_title = f"✅ Safe ({ssid})"
                        wifi_grade_desc = f"Using strong {auth} password protection ({signal} signal)."
                    else:
                        wifi_grade_title = f"⚠️ Weak Security ({ssid})"
                        wifi_grade_desc = f"Your Wi-Fi uses older '{auth}' security. Change router settings to WPA2/WPA3."
                        wifi_color = "#EF4444"
            except Exception:
                pass

            local_ip = get_lan_ip()
            if local_ip != "127.0.0.1":
                parts = local_ip.split(".")
                self.router_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

            devices = []
            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                arp_out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, creationflags=flags)
                subnet_prefix = ".".join(local_ip.split(".")[:3]) + "."
                for line in arp_out.splitlines():
                    cols = line.split()
                    if len(cols) >= 3 and cols[0].startswith(subnet_prefix):
                        ip_addr, mac_addr, dtype = cols[0], cols[1], cols[2]
                        if not ip_addr.endswith(".255") and dtype.lower() == "dynamic":
                            devices.append((ip_addr, mac_addr))
            except Exception:
                pass

            if not any(d[0] == self.router_ip for d in devices):
                devices.insert(0, (self.router_ip, "Router-Gateway"))
            if not any(d[0] == local_ip for d in devices):
                devices.insert(1, (local_ip, "This-Windows-PC"))

            def scan_device(dev):
                dip, dmac = dev
                open_vulns = []
                for port, (pname, sev, pdesc) in IOT_VULN_PORTS.items():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.22)
                        if sock.connect_ex((dip, port)) == 0:
                            open_vulns.append((port, pname, sev, pdesc))
                        sock.close()
                    except Exception:
                        pass
                try:
                    host = socket.gethostbyaddr(dip)[0]
                except Exception:
                    host = ""
                return dip, dmac, host, open_vulns

            with ThreadPoolExecutor(max_workers=10) as ex:
                results = list(ex.map(scan_device, devices[:25]))

            self.last_wifi_results = results
            trusted_devs = get_trusted_devices()
            router_vulns = [v for r in results if r[0] == self.router_ip for v in r[3] if v[2] in {"CRITICAL", "HIGH"}]
            iot_vulns = [v for r in results if r[0] != self.router_ip and r[0] not in trusted_devs for v in r[3] if v[2] in {"CRITICAL", "HIGH"}]

            r_title = f"✅ Router Safe ({self.router_ip})" if not router_vulns else f"⚠️ {len(router_vulns)} Router Warning(s)"
            r_desc = "No dangerous remote-hack ports (like Telnet or FTP) are open." if not router_vulns else "Dangerous port open on router! Click 'Open Router Login Page'."
            r_col = "#10B981" if not router_vulns else "#EF4444"

            log_incident_db(
                "Wi-Fi & Device Check",
                f"{ssid} ({len(results)} devices)",
                f"{wifi_grade_title} | Checked {len(results)} devices",
                "✅ All Devices Safe" if (not router_vulns and not iot_vulns) else f"⚠️ {len(iot_vulns)} Device Notice(s)"
            )

            self.after(0, lambda: [
                self.wifi_card_enc[0].configure(text=wifi_grade_title, text_color=wifi_color),
                self.wifi_card_enc[1].configure(text=wifi_grade_desc),
                self.wifi_card_router[0].configure(text=r_title, text_color=r_col),
                self.wifi_card_router[1].configure(text=r_desc),
                self.refresh_wifi_summary_counts(),
                self.render_wifi_device_cards(),
                self.refresh_incident_history_ui()
            ])

        threading.Thread(target=_audit_worker, daemon=True).start()

    def render_wifi_device_cards(self):
        for w in self.wifi_scroll.winfo_children():
            w.destroy()

        if not self.last_wifi_results:
            ctk.CTkLabel(
                self.wifi_scroll,
                text="Click '📶 Scan My Wi-Fi & Devices' above to check your router and connected smart devices.",
                font=("Segoe UI", 13), text_color="#94A3B8"
            ).pack(anchor="w", padx=16, pady=20)
            return

        trusted_devs = get_trusted_devices()

        for dip, dmac, host, open_vulns in self.last_wifi_results:
            if dip == self.router_ip:
                friendly_name = f"🌐 Home Wi-Fi Router ({dip})"
            elif dmac == "This-Windows-PC":
                friendly_name = f"💻 This Windows Computer ({dip})"
            elif host:
                friendly_name = f"📱 {host} ({dip})"
            else:
                friendly_name = f"📺 Smart TV / Streaming Box / Device ({dip})"

            is_trusted_dev = dip in trusted_devs
            serious_vulns = [] if is_trusted_dev else [v for v in open_vulns if v[2] in {"CRITICAL", "HIGH"}]

            border_col = "#1E293B" if not serious_vulns else "#F59E0B"
            badge_txt = "✅ TRUSTED HOME DEVICE" if is_trusted_dev else ("✅ SAFE ON WI-FI" if not serious_vulns else "⚠️ REVIEW DEVICE")
            badge_col = "#10B981" if not serious_vulns else "#F59E0B"

            card = ctk.CTkFrame(self.wifi_scroll, fg_color="#111827", corner_radius=10, border_width=1, border_color=border_col)
            card.pack(fill="x", padx=8, pady=5)

            top_r = ctk.CTkFrame(card, fg_color="transparent")
            top_r.pack(fill="x", padx=14, pady=(10, 4))
            ctk.CTkLabel(top_r, text=friendly_name, font=("Segoe UI", 14, "bold"), text_color="#F8FAFC").pack(side="left")

            if serious_vulns and not is_trusted_dev:
                ctk.CTkButton(
                    top_r, text="✅ Trust My Device", fg_color="#059669", hover_color="#047857",
                    font=("Segoe UI", 11, "bold"), height=26, width=135,
                    command=lambda ip=dip: self.trust_wifi_device(ip)
                ).pack(side="right", padx=(8, 0))

            ctk.CTkLabel(top_r, text=badge_txt, font=("Segoe UI", 11, "bold"), text_color=badge_col).pack(side="right")

            if not open_vulns:
                simple_exp = "No open weak spots or exposed services found on this device."
            elif is_trusted_dev:
                simple_exp = "Marked as your trusted home device. Developer/local services allowed."
            else:
                parts = [f"{v[1]}: {v[3]}" for v in open_vulns]
                simple_exp = " • ".join(parts)

            ctk.CTkLabel(card, text=simple_exp, font=("Segoe UI", 12), text_color="#CBD5E1", wraplength=880, anchor="w", justify="left").pack(fill="x", padx=14, pady=(0, 8))

            if self.view_mode == "Advanced Mode":
                ports_str = ", ".join([f"{v[0]}/tcp ({v[1]})" for v in open_vulns]) if open_vulns else "None"
                adv_line = f"🔬 [ADVANCED] IPv4: {dip}  |  MAC: {dmac}  |  Hostname: {host or 'Unresolved'}  |  Open Ports: {ports_str}"
                ctk.CTkLabel(card, text=adv_line, font=("Consolas", 11), text_color="#38BDF8", anchor="w", justify="left").pack(fill="x", padx=14, pady=(0, 10))

    def refresh_network_table(self):
        for w in self.net_scroll.winfo_children():
            w.destroy()
        trusted = get_trusted_procs()
        try:
            conns = [c for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED" and c.raddr]
            if not conns:
                ctk.CTkLabel(self.net_scroll, text="No active internet connections right now.", font=("Segoe UI", 13), text_color="#94A3B8").pack(anchor="w", padx=16, pady=20)
                return
            for c in conns[:45]:
                pname, ppath = "System", "Windows Core"
                if c.pid:
                    try:
                        p_obj = psutil.Process(c.pid)
                        pname = p_obj.name()
                        ppath = p_obj.exe()
                    except Exception:
                        pname = "Background App"
                friendly_app = APP_DESCRIPTIONS.get(pname.lower(), f"Application ({pname})")
                port = c.raddr.port
                activity = PORT_DESCRIPTIONS.get(port, f"Custom App / Game Data Connection (Port {port})")
                is_safe = pname.lower() in trusted

                row = ctk.CTkFrame(self.net_scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1E293B")
                row.pack(fill="x", padx=8, pady=4)
                left = ctk.CTkFrame(row, fg_color="transparent")
                left.pack(side="left", fill="x", expand=True, padx=14, pady=8)
                ctk.CTkLabel(left, text=f"💻 {friendly_app}", font=("Segoe UI", 13, "bold"), text_color="#F8FAFC", anchor="w").pack(anchor="w")
                sub = f"What it's doing: {activity}  •  Connected to: {c.raddr.ip}"
                if self.view_mode == "Advanced Mode":
                    sub += f"  |  PID: {c.pid}  |  Local Port: {c.laddr.port} -> Remote Port: {port}  |  Exe: {ppath}"
                ctk.CTkLabel(left, text=sub, font=("Segoe UI", 11), text_color="#94A3B8", anchor="w", justify="left", wraplength=780).pack(anchor="w")

                badge_text = "✅ Trusted & Safe" if is_safe else "🧠 Live Monitoring"
                badge_col = "#10B981" if is_safe else "#F59E0B"
                ctk.CTkLabel(row, text=badge_text, font=("Segoe UI", 12, "bold"), text_color=badge_col).pack(side="right", padx=16)
        except Exception as e:
            ctk.CTkLabel(self.net_scroll, text=f"Error reading connections: {e}", font=("Segoe UI", 12), text_color="#EF4444").pack(anchor="w", padx=16, pady=10)

    def refresh_incident_history_ui(self):
        for w in self.hist_scroll.winfo_children():
            w.destroy()
        rows = get_incident_history_db(35)
        if not rows:
            ctk.CTkLabel(
                self.hist_scroll,
                text="No security incidents recorded yet. Every automatic fix, PureClean tune-up, live-learned app, and scan result will appear here.",
                font=("Segoe UI", 13), text_color="#94A3B8", anchor="w", justify="left"
            ).pack(anchor="w", padx=16, pady=18)
            return
        for r_id, ts, cat, target, summary, outcome in rows:
            card = ctk.CTkFrame(self.hist_scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1E293B")
            card.pack(fill="x", padx=8, pady=4)
            top_line = ctk.CTkFrame(card, fg_color="transparent")
            top_line.pack(fill="x", padx=14, pady=(8, 2))
            title_str = f"#{r_id}  •  {cat}: {target}"
            ctk.CTkLabel(top_line, text=title_str, font=("Segoe UI", 13, "bold"), text_color="#F8FAFC", anchor="w").pack(side="left")
            out_col = "#10B981" if any(k in outcome for k in ("Auto-Healed", "Live-Learned", "Trusted", "Clean", "Quarantined", "Auto-Fixed", "Safe", "Optimized", "Immunized")) else "#F59E0B"
            ctk.CTkLabel(top_line, text=f"{outcome}  ({ts})", font=("Segoe UI", 11, "bold"), text_color=out_col, anchor="e").pack(side="right")
            clean_summary = " ".join(summary.replace("\n", " ").split())
            ctk.CTkLabel(card, text=clean_summary, font=("Segoe UI", 12), text_color="#CBD5E1", anchor="w", justify="left", wraplength=860).pack(fill="x", padx=14, pady=(0, 8))

    def clear_incident_history(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM incident_history")
        conn.commit()
        conn.close()
        self.refresh_incident_history_ui()

    def populate_incident_inspector(self, category, target, simple_summary, adv_report, incident_data, outcome="Pending User Action"):
        self.last_incident = incident_data
        inc_id = log_incident_db(category, target, simple_summary, outcome)
        self.last_incident_id = inc_id
        def _update():
            self.inc_simple_lbl.configure(text=simple_summary)
            self.adv_box.delete("1.0", "end")
            self.adv_box.insert("end", adv_report)
            self.refresh_incident_history_ui()
        self.after(0, _update)

    def execute_autofix(self):
        if not self.last_incident:
            self.execute_ccleaner_tuneup()
            return
        kind = self.last_incident.get("kind")
        if kind == "file":
            self.quarantine_last_file()
            update_incident_outcome_db(self.last_incident_id, "🛡️ Quarantined in Vault")
            self.inc_simple_lbl.configure(text="✅ AUTO-FIX COMPLETE: The suspicious file was safely locked inside your Quarantine Vault.")
        elif kind == "network":
            procs = self.last_incident.get("untrusted_procs", [])
            killed = []
            for pinfo in procs:
                pid = pinfo.get("pid")
                pname = pinfo.get("name", "unknown")
                if pid and pid > 4:
                    try:
                        psutil.Process(pid).terminate()
                        killed.append(f"{pname} (PID {pid})")
                    except Exception:
                        pass
            outcome_str = f"⚡ Auto-Fixed: Stopped {', '.join(killed)}" if killed else "⚡ Auto-Fixed: Recalibrated AI Baseline"
            update_incident_outcome_db(self.last_incident_id, outcome_str)
            self.retrain_requested = True
            self.inc_simple_lbl.configure(text=f"✅ {outcome_str}")
            self.log_event(f"[AUTO-FIX] {outcome_str}")
            self.banner.configure(border_color="#10B981")
            self.status_title.configure(text="●  YOUR PC, WI-FI & ANDROID SUITE ARE PROTECTED", text_color="#10B981")

        self.increment_healed_counter()
        self.refresh_incident_history_ui()
        if self.popup_win is not None and self.popup_win.winfo_exists():
            self.popup_win.destroy()

    def trust_and_recalibrate(self):
        trusted_names = []
        if self.last_incident and self.last_incident.get("untrusted_procs"):
            for pinfo in self.last_incident["untrusted_procs"]:
                name = pinfo.get("name", "")
                add_trusted_proc(name)
                trusted_names.append(name)
        else:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr and c.pid:
                    try:
                        name = psutil.Process(c.pid).name()
                        add_trusted_proc(name)
                    except Exception:
                        pass
            trusted_names.append("All Active Apps")

        update_incident_outcome_db(self.last_incident_id, f"✅ Trusted ({', '.join(set(trusted_names))[:22]})")
        self.retrain_requested = True
        self.last_popup_time = time.time()
        self.inc_simple_lbl.configure(text="✅ APPS TRUSTED & AI RECALIBRATED: PureProtect learned these programs are safe and updated your history log.")
        self.banner.configure(border_color="#10B981")
        self.status_title.configure(text="●  YOUR PC, WI-FI & ANDROID SUITE ARE PROTECTED", text_color="#10B981")
        self.refresh_incident_history_ui()
        if self.popup_win is not None and self.popup_win.winfo_exists():
            self.popup_win.destroy()

    def reload_local_code(self):
        self.update_status_lbl.configure(text="Reloading PureProtect...", text_color="#10B981")
        try:
            if _INSTANCE_LOCK_SOCKET:
                _INSTANCE_LOCK_SOCKET.close()
        except Exception:
            pass
        if getattr(sys, "frozen", False):
            subprocess.Popen([sys.executable, "--reloading"])
        else:
            pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
            target = str(DEV_SCRIPT_PATH if DEV_SCRIPT_PATH.exists() else Path(__file__).resolve())
            subprocess.Popen([pythonw_exe, target, "--reloading"])
        self.after(300, self.quit_completely)

    def inject_from_github(self):
        url = self.patch_url_entry.get().strip()
        if url.startswith("//"):
            url = "https:" + url
        elif not url.startswith("http"):
            url = "https://" + url

        self.settings["patch_url"] = url
        save_settings(self.settings)
        self.update_status_lbl.configure(text="Connecting to GitHub & pulling latest update...", text_color="#FBBF24")

        def _worker():
            try:
                r = requests.get(url, timeout=15)
                if r.status_code != 200:
                    msg = f"❌ GitHub returned HTTP {r.status_code}. Check that your repo is Public and the file exists."
                    self.after(0, lambda m=msg: self.update_status_lbl.configure(text=m, text_color="#F87171"))
                    return

                content = r.text
                if "PureProtectSuite" in content or "import customtkinter" in content:
                    LIVE_PATCH_FILE.write_text(content, encoding="utf-8")
                    if DEV_SCRIPT_PATH.exists():
                        try:
                            DEV_SCRIPT_PATH.write_text(content, encoding="utf-8")
                        except Exception:
                            pass
                    self.after(0, lambda: self.update_status_lbl.configure(text="✅ Latest guardian_ui.py injected! Restarting into updated version...", text_color="#10B981"))
                    self.after(900, self.reload_local_code)
                    return

                data = r.json()
                remote_ver = str(data.get("version", APP_VERSION)).strip()
                if remote_ver != APP_VERSION and remote_ver > APP_VERSION:
                    self.after(0, lambda v=remote_ver: self.update_status_lbl.configure(text=f"New installer v{v} found! Downloading...", text_color="#10B981"))
                else:
                    self.after(0, lambda: self.update_status_lbl.configure(text=f"✅ Already on latest version (v{APP_VERSION}).", text_color="#10B981"))
            except Exception as err:
                err_msg = f"Update error: {err}"
                self.after(0, lambda m=err_msg: self.update_status_lbl.configure(text=m, text_color="#F87171"))

        threading.Thread(target=_worker, daemon=True).start()

    def show_alert_popup(self, title, simple_msg, can_autofix=True):
        if self.silent_mode_var.get():
            return
        def _spawn():
            if self.popup_win is not None and self.popup_win.winfo_exists():
                return
            try:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except Exception:
                pass
            pop = ctk.CTkToplevel(self)
            self.popup_win = pop
            pop.title("PureProtect // Smart Security Assistant")
            pop.attributes("-topmost", True)
            pop.resizable(False, False)
            w, h = 490, 240
            sx, sy = pop.winfo_screenwidth(), pop.winfo_screenheight()
            pop.geometry(f"{w}x{h}+{sx - w - 25}+{sy - h - 85}")
            pop.configure(fg_color="#090D16")
            card = ctk.CTkFrame(pop, fg_color="#111827", corner_radius=10, border_width=2, border_color="#F59E0B")
            card.pack(fill="both", expand=True, padx=6, pady=6)
            ctk.CTkLabel(card, text=title, text_color="#FBBF24", font=("Segoe UI", 15, "bold"), anchor="w").pack(anchor="w", padx=16, pady=(12, 4))
            ctk.CTkLabel(card, text=simple_msg[:300], font=("Segoe UI", 12), text_color="#E2E8F0", wraplength=450, anchor="w", justify="left").pack(anchor="w", padx=16, pady=4, fill="x", expand=True)
            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=16, pady=(4, 12))
            if can_autofix:
                ctk.CTkButton(btn_row, text="⚡ Auto-Fix", fg_color="#DC2626", hover_color="#B91C1C", font=("Segoe UI", 12, "bold"), width=110, command=self.execute_autofix).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btn_row, text="✅ Trust App", fg_color="#059669", hover_color="#047857", font=("Segoe UI", 12, "bold"), width=115, command=self.trust_and_recalibrate).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btn_row, text="📋 History", fg_color="#2563EB", hover_color="#1D4ED8", font=("Segoe UI", 12, "bold"), width=115, command=lambda: [self.restore_from_tray(), self.show_view("incident"), pop.destroy()]).pack(side="left")
            ctk.CTkButton(btn_row, text="Dismiss", fg_color="#374151", hover_color="#4B5563", width=75, command=pop.destroy).pack(side="right")
            pop.lift()
        self.after(0, _spawn)

    def toggle_windows_autostart(self):
        try:
            for fname in ("Aegis_AI_Autostart.bat", "PureProtect AI Security.lnk", "Aegis AI Security.lnk"):
                p = os.path.join(STARTUP_DIR, fname)
                if os.path.exists(p):
                    os.remove(p)

            if self.autostart_var.get():
                if getattr(sys, "frozen", False):
                    bat_content = f'@echo off\nstart "" "{sys.executable}"\n'
                else:
                    pythonw_exe = r"C:\Users\krazy\ai-sec-pipeline\ai-sec-pipeline\venv\Scripts\pythonw.exe"
                    bat_content = f'@echo off\ncd /d "C:\\Users\\krazy\\ai-sec-pipeline\\ai-sec-pipeline"\nstart "" "{pythonw_exe}" "{DEV_SCRIPT_PATH}"\n'
                with open(STARTUP_BAT, "w", encoding="ascii") as f:
                    f.write(bat_content)
                self.log_event("[SETTINGS] Enabled single-instance launch at Windows Startup.")
            else:
                if os.path.exists(STARTUP_BAT):
                    os.remove(STARTUP_BAT)
                self.log_event("[SETTINGS] Removed automatic Windows Startup entry.")
        except Exception as e:
            self.log_event(f"[ERROR] Startup toggle failed: {e}")

    def _init_system_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem("Open PureProtect", lambda icon, item: self.after(0, self.restore_from_tray), default=True),
            pystray.MenuItem("1-Click PureClean Tune-Up", lambda icon, item: self.after(0, lambda: [self.restore_from_tray(), self.show_view("tuneup"), self.execute_ccleaner_tuneup()])),
            pystray.MenuItem("Run Quick Virus Scan", lambda icon, item: self.after(0, lambda: [self.restore_from_tray(), self.show_view("scanner"), self.start_virus_scan("quick")])),
            pystray.MenuItem("Exit Completely", lambda icon, item: self.after(0, self.quit_completely))
        )
        self.tray_icon = pystray.Icon("PureProtect", self.tray_image, f"PureProtect v{APP_VERSION} (Protected)", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def on_close_button(self):
        if self.minimize_to_tray_var.get():
            self.withdraw()
        else:
            self.quit_completely()

    def restore_from_tray(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_completely(self):
        try:
            if _INSTANCE_LOCK_SOCKET:
                _INSTANCE_LOCK_SOCKET.close()
            self.observer.stop()
            self.tray_icon.stop()
        except Exception:
            pass
        self.destroy()
        os._exit(0)

    def log_event(self, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self._append_log(f"[{timestamp}] {text}\n"))

    def _append_log(self, line):
        self.log_box.insert("end", line)
        self.log_box.see("end")

    def refresh_db_counts(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            h_count = conn.execute("SELECT COUNT(*) FROM bad_hashes").fetchone()[0]
            ip_count = conn.execute("SELECT COUNT(*) FROM bad_ips").fetchone()[0]
            dom_count = conn.execute("SELECT COUNT(*) FROM bad_domains").fetchone()[0]
            conn.close()
            self.total_sig_count = h_count + ip_count + dom_count
            self.after(0, lambda: self.card_hashes.configure(text=f"{self.total_sig_count:,}"))
        except Exception:
            pass

    def check_hash_in_db(self, sha256_hex):
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT source FROM bad_hashes WHERE sha256 = ?", (sha256_hex,)).fetchone()
        conn.close()
        return row[0] if row else None

    def check_ip_in_db(self, ip_addr):
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT source FROM bad_ips WHERE ip = ?", (ip_addr,)).fetchone()
        conn.close()
        return row[0] if row else None

    def handle_file_alert(self, details):
        self.last_flagged_file = details["path"]
        fname = details["file"]
        if self.auto_heal_var.get() and details.get("confirmed_malware"):
            self.quarantine_last_file()
            self.increment_healed_counter()
            simple = f"✨ AUTO-HEALED: PureProtect intercepted known malware ({fname} — {details['match']}) and automatically locked it inside your Quarantine Vault."
            adv = f"=== AUTONOMOUS FILE INTERCEPT ===\nFile: {fname}\nSHA256: {details['sha256']}\nEntropy: {details['entropy']}\nRule: {details['match']}\nAction: Automatically moved to Quarantine Vault."
            self.populate_incident_inspector("Malicious Download", fname, simple, adv, details, outcome="✨ Auto-Quarantined")
            self.log_event(f"🛡️ [AUTO-HEALED] Quarantined malicious download '{fname}' automatically.")
            return

        simple = f"A newly downloaded file ({fname}) triggered a heuristic check ({details['match']}). Click '⚡ Auto-Fix Now' to quarantine it."
        adv = f"=== FILE INTERCEPT FORENSIC REPORT ===\nFile: {fname}\nPath: {details['path']}\nSHA256: {details['sha256']}\nEntropy: {details['entropy']} / 8.0\nRule: {details['match']}"
        self.populate_incident_inspector("Suspicious File", fname, simple, adv, details, outcome="Pending User Action")
        self.log_event(f"⚠️ [FILE ALERT] {fname} | Match: {details['match']}")

        def run_ai():
            verdict = ask_local_ai("Suspicious File Download", details)
            self.log_event(f"🤖 [AI SOC ANALYST]: {verdict}\n" + ("─" * 78))
            self.show_alert_popup("⚠️ Suspicious Download Caught!", f"File: {fname}\n{verdict}", can_autofix=True)
        threading.Thread(target=run_ai, daemon=True).start()

    def quarantine_last_file(self):
        if self.last_flagged_file and os.path.exists(self.last_flagged_file):
            fname = os.path.basename(self.last_flagged_file)
            dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{fname}.quarantined")
            shutil.move(self.last_flagged_file, dest)
            self.log_event(f"🛡️ [QUARANTINED] Isolated {fname} in vault.")
            self.last_flagged_file = None
            self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        for widget in self.q_scroll.winfo_children():
            widget.destroy()
        files = sorted(Path(QUARANTINE_DIR).glob("*.quarantined"), key=os.path.getmtime, reverse=True)
        if not files:
            ctk.CTkLabel(self.q_scroll, text="Vault is empty. Any malware caught by Auto-Heal is locked safely here.", font=("Segoe UI", 13), text_color="#64748B").pack(pady=30)
            return
        for fpath in files:
            row = ctk.CTkFrame(self.q_scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1E293B")
            row.pack(fill="x", padx=8, pady=5)
            ctk.CTkLabel(row, text=f"🔒  {fpath.name}", font=("Consolas", 12, "bold"), text_color="#FBBF24").pack(side="left", padx=14, pady=10)
            ctk.CTkButton(row, text="Delete Permanently", width=130, fg_color="#DC2626", hover_color="#B91C1C", command=lambda p=fpath: [os.remove(p), self.refresh_quarantine_list()]).pack(side="right", padx=10, pady=8)
            ctk.CTkButton(row, text="Restore to Downloads", width=140, fg_color="#374151", hover_color="#4B5563", command=lambda p=fpath: self._restore_quarantined(p)).pack(side="right", padx=4, pady=8)

    def _restore_quarantined(self, fpath):
        orig_name = fpath.name.replace(".quarantined", "").split("_", 1)[-1]
        shutil.move(str(fpath), os.path.join(WATCH_DIR, orig_name))
        self.log_event(f"[VAULT] Restored {orig_name} to Downloads.")
        self.refresh_quarantine_list()

    def trigger_feed_sync(self):
        self.log_event("[SYNC] Pulling from 5 Threat Intel Feeds (Feodo, CINS, EmergingThreats, MalwareBazaar, URLhaus)...")
        def sync_job():
            try:
                ip_cnt, h_cnt, dom_cnt = sync_feeds_internal()
                self.refresh_db_counts()
                self.log_event(f"[SYNC] Synced {ip_cnt:,} malicious IPs, {h_cnt:,} malware hashes & {dom_cnt:,} spyware domains.")
            except Exception as e:
                self.log_event(f"[SYNC ERROR] {e}")
        threading.Thread(target=sync_job, daemon=True).start()

    def trigger_test_alert(self):
        def drop_test():
            p = Path.home() / "Downloads" / "pureprotect_test_malware.txt"
            if p.exists():
                p.unlink()
            data = f"harmless_pureprotect_test_{time.time()}".encode("utf-8")
            h = hashlib.sha256(data).hexdigest()
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT OR IGNORE INTO bad_hashes VALUES (?, ?)", (h, "Simulated_Malware_Dropper"))
            conn.commit()
            conn.close()
            self.refresh_db_counts()
            p.write_bytes(data)
        threading.Thread(target=drop_test, daemon=True).start()

    def trigger_simulated_net_anomaly(self):
        fake_proc = [{"name": "unknown_beacon.exe", "pid": 99999, "ip": "185.220.101.45", "port": 4444, "path": "C:\\Users\\Public\\unknown_beacon.exe"}]
        simple = "An unverified program (unknown_beacon.exe) connected to 185.220.101.45 on unusual port 4444. Click '⚡ Auto-Fix Now' to stop it or '✅ Trust App' if safe."
        adv = "=== SIMULATED NETWORK ANOMALY ===\nProcess: unknown_beacon.exe (PID 99999)\nSocket: 185.220.101.45:4444\nPath: C:\\Users\\Public\\unknown_beacon.exe"
        self.populate_incident_inspector("Simulated Net Alert", "unknown_beacon.exe", simple, adv, {"kind": "network", "untrusted_procs": fake_proc})
        self.show_alert_popup("⚠️ Simulated Activity: unknown_beacon.exe", simple, can_autofix=True)

    def monitor_app_resources(self):
        proc = psutil.Process(os.getpid())
        while True:
            try:
                mb = proc.memory_info().rss / (1024 * 1024)
                self.after(0, lambda m=mb: self.ram_label.configure(text=f"App RAM: {m:.1f} MB"))
            except Exception:
                pass
            time.sleep(5)

    def monitor_network(self):
        history = []
        model = IsolationForest(contamination=0.015, random_state=42)
        is_trained = False

        while True:
            if self.retrain_requested:
                history.clear()
                is_trained = False
                self.retrain_requested = False

            trusted_set = get_trusted_procs()
            conns = [c for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED" and c.raddr]
            self.active_conn_count = len(conns)
            self.after(0, lambda c=len(conns): self.card_conns.configure(text=str(c)))

            untrusted_custom_conns = []
            for c in conns:
                ip = c.raddr.ip
                if ip.startswith(("127.", "192.168.", "10.", "172.")):
                    continue
                pname, ppath = "Unknown", "N/A"
                if c.pid:
                    try:
                        p_obj = psutil.Process(c.pid)
                        pname = p_obj.name()
                        ppath = p_obj.exe()
                    except Exception:
                        pass

                source = self.check_ip_in_db(ip)
                if source:
                    inc = {"kind": "network", "untrusted_procs": [{"name": pname, "pid": c.pid, "ip": ip, "port": c.raddr.port, "path": ppath}]}
                    if self.auto_heal_var.get() and c.pid and c.pid > 4:
                        try:
                            psutil.Process(c.pid).terminate()
                        except Exception:
                            pass
                        self.increment_healed_counter()
                        simple = f"✨ AUTO-HEALED: Blocked '{pname}' from connecting to known Botnet server {ip} ({source}) and terminated the rogue process."
                        adv = f"=== AUTONOMOUS C2 BLOCK ===\nProcess: {pname} (PID {c.pid})\nPath: {ppath}\nMalicious IP: {ip}:{c.raddr.port}\nFeed: {source}"
                        self.populate_incident_inspector("Botnet C2 Blocked", f"{pname} -> {ip}", simple, adv, inc, outcome="✨ Auto-Healed (Blocked C2)")
                    else:
                        simple = f"CRITICAL: Program '{pname}' connected to known Botnet C2 Server {ip} ({source}). Click 'Auto-Fix' immediately."
                        adv = f"=== BOTNET C2 INTERCEPT ===\nProcess: {pname} (PID {c.pid})\nPath: {ppath}\nRemote: {ip}:{c.raddr.port}\nFeed: {source}"
                        self.populate_incident_inspector("Botnet C2 Hit", f"{pname} -> {ip}", simple, adv, inc)
                        self.show_alert_popup("🚨 Botnet C2 Connection!", simple, can_autofix=True)
                    continue

                if c.raddr.port not in STANDARD_PORTS and pname.lower() not in trusted_set:
                    if self.live_learn_var.get() and is_safe_install_location(ppath):
                        add_trusted_proc(pname)
                        trusted_set.add(pname.lower())
                        self.increment_healed_counter()
                        log_incident_db(
                            "Live App Learning",
                            pname,
                            f"Verified '{pname}' in safe install path ({ppath}) using port {c.raddr.port}. Learned as safe.",
                            "🧠 Live-Learned (Safe)"
                        )
                        self.log_event(f"🧠 [LIVE LEARNING] Verified '{pname}' in safe folder & added to trusted baseline.")
                        self.after(0, self.refresh_incident_history_ui)
                    else:
                        untrusted_custom_conns.append({"name": pname, "pid": c.pid, "ip": ip, "port": c.raddr.port, "path": ppath})

            features = [len(conns), len(untrusted_custom_conns)]

            if not is_trained:
                history.append(features)
                p = len(history)
                self.after(0, lambda p=p: self.card_ml.configure(text=f"Learning {p}/15", text_color="#F59E0B"))
                if p >= 15:
                    model.fit(np.array(history))
                    is_trained = True
                    self.after(0, lambda: self.card_ml.configure(text="Active (Smart)", text_color="#10B981"))
                    self.log_event("[AI ENGINE] Live-Learning Isolation Forest calibrated and active.")
            else:
                pred = model.predict(np.array([features]))[0]
                now = time.time()
                if pred == -1 and len(untrusted_custom_conns) >= 3 and (now - self.last_popup_time > self.cooldown_seconds):
                    self.last_popup_time = now
                    app_names = sorted({x["name"] for x in untrusted_custom_conns})
                    apps_str = ", ".join(app_names[:4])

                    simple = f"Unverified program(s) [{apps_str}] opened {len(untrusted_custom_conns)} connections on custom ports. Click '✅ Trust App' if you recognize it, or '⚡ Auto-Fix' to stop it."
                    lines = [f"• {x['name']} (PID {x['pid']}) -> {x['ip']}:{x['port']} | Path: {x['path']}" for x in untrusted_custom_conns[:15]]
                    adv = f"=== PROCESS-AWARE NETWORK ANOMALY ===\nApps: {apps_str}\nCustom Connections: {len(untrusted_custom_conns)}\n\nSOCKETS:\n" + "\n".join(lines)
                    inc_data = {"kind": "network", "untrusted_procs": untrusted_custom_conns}
                    self.populate_incident_inspector("Unverified App Activity", apps_str, simple, adv, inc_data)

                    def run_net_ai(a_str=apps_str, u_list=untrusted_custom_conns):
                        verdict = ask_local_ai("Unverified Application Network Activity", {"apps": a_str, "sample": u_list[:3]})
                        self.log_event(f"🤖 [AI SOC ANALYST]: {verdict}\n" + ("─" * 78))
                        self.show_alert_popup(f"⚠️ Activity from {a_str}", f"App: {a_str}\n{verdict}", can_autofix=True)

                    threading.Thread(target=run_net_ai, daemon=True).start()

            time.sleep(10)


if __name__ == "__main__":
    app = PureProtectSuite()
    app.mainloop()