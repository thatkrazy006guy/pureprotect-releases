import os
import sys
import math
import time
import json
import shutil
import hashlib
import sqlite3
import subprocess
import threading
import winsound
from datetime import datetime
from pathlib import Path
from collections import Counter

import psutil
import requests
import numpy as np
import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw
from sklearn.ensemble import IsolationForest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

APP_VERSION = "2.4.0"
DEFAULT_UPDATE_URL = "https://raw.githubusercontent.com/your-org/pureprotect-releases/main/version.json"
DEFAULT_PATCH_URL = "https://raw.githubusercontent.com/your-org/pureprotect-releases/main/guardian_ui.py"
DEV_SCRIPT_PATH = Path(r"C:\Users\krazy\ai-sec-pipeline\ai-sec-pipeline\guardian_ui.py")

if getattr(sys, "frozen", False):
    BUNDLE_DIR = Path(sys._MEIPASS)
else:
    BUNDLE_DIR = Path(__file__).resolve().parent

APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "PureProtect"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

LIVE_PATCH_FILE = APP_DATA_DIR / "live_patch.py"

# --- AUTO-INJECTOR ENGINE ---
# If running from the frozen Program Files .exe, automatically inject newer code from Dev Folder or GitHub Hot-Patch
if getattr(sys, "frozen", False) and "--no-inject" not in sys.argv:
    target_patch = None
    if DEV_SCRIPT_PATH.exists():
        target_patch = DEV_SCRIPT_PATH
    elif LIVE_PATCH_FILE.exists():
        target_patch = LIVE_PATCH_FILE

    if target_patch is not None:
        try:
            sys.argv.append("--no-inject")
            patch_code = target_patch.read_text(encoding="utf-8")
            exec(compile(patch_code, str(target_patch), "exec"), globals())
            sys.exit(0)
        except Exception:
            pass

DB_PATH = str(APP_DATA_DIR / "threat_intel.db")
CONFIG_PATH = str(APP_DATA_DIR / "settings.json")
ICON_PATH = str(APP_DATA_DIR / "pureprotect.ico")
WATCH_DIR = str(Path.home() / "Downloads")
QUARANTINE_DIR = str(APP_DATA_DIR / "quarantine")
STARTUP_DIR = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
STARTUP_BAT = os.path.join(STARTUP_DIR, "PureProtect_Autostart.bat")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3:1.7b"

DEFAULT_TRUSTED_PROCS = {
    "svchost.exe", "system", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
    "code.exe", "ollama.exe", "ollama_llama_server.exe", "python.exe", "pythonw.exe",
    "pureprotect.exe", "docker.exe", "com.docker.backend.exe", "vpnkit.exe",
    "spotify.exe", "discord.exe", "steam.exe", "steamwebhelper.exe", "searchhost.exe",
    "widgets.exe", "lsass.exe", "services.exe", "explorer.exe", "onedrive.exe"
}
STANDARD_PORTS = {80, 443, 53, 8080, 8443, 5228, 3478, 19302, 11434}

LEGAL_TEXT = """==================================================================================
  PUREPROTECT(TM) AI SECURITY SUITE — PRIVACY GUARANTEE & END-USER LICENSE (EULA)
  Copyright (C) 2026 Brian Davis / Pure Ecosystem (PureProtect • PureStream • PureMind)
  All Rights Reserved. Proprietary & Confidential.
==================================================================================

1. 100% LOCAL ZERO-TELEMETRY PRIVACY GUARANTEE
PureProtect is built from the ground up to protect your privacy without spying on your device:
  * Zero Cloud Uploads: Every file hash check, Shannon entropy calculation, network socket scan, and Isolation Forest machine learning check happens 100% locally on your hardware.
  * Private Local AI Analyst: Suspicious event summaries are analyzed locally via your on-device language model (CPU-only execution with zero persistent RAM/VRAM drain). Your personal files, downloads, and network connections are never sent to external servers.
  * Outbound Connections: PureProtect only connects to the internet when you sync public threat intelligence databases (Abuse.ch Feodo Tracker, MalwareBazaar, CINS Army) or pull updates from your configured URL.

2. PROPRIETARY LICENSE & INTELLECTUAL PROPERTY PROTECTION
This software, including its source code, algorithms, visual user interface ("trade dress"), custom iconography, and branding ("PureProtect", "PureStream", and "PureMind"), is the exclusive intellectual property of Brian Davis / Pure Ecosystem.
  * Permitted Use: You are granted a personal, non-exclusive, revocable license to install and use the compiled application on your personal devices.
  * Prohibited Actions: You may NOT copy, redistribute, sell, decompile, reverse engineer, disassemble, extract the source code of, or clone the user interface or branding of this software without prior written permission from the copyright holder.

3. SECURITY DISCLAIMER & LIMITATION OF LIABILITY
PureProtect is a defense-in-depth security tool designed to supplement your operating system's native kernel protections.
  * No 100% Guarantee: No cybersecurity program can detect or prevent 100% of zero-day malware, spyware, or network attacks.
  * "AS-IS" Provision: This software is provided "AS IS" without warranty of any kind. In no event shall the author be held liable for any damages, data loss, quarantined files, or terminated background processes resulting from the use of this software, including its "Auto-Fix" actions.
"""

os.makedirs(QUARANTINE_DIR, exist_ok=True)

bundled_db = BUNDLE_DIR / "threat_intel.db"
if not os.path.exists(DB_PATH) and bundled_db.exists():
    try:
        shutil.copy2(str(bundled_db), DB_PATH)
    except Exception:
        pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def load_settings():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"update_url": DEFAULT_UPDATE_URL, "patch_url": DEFAULT_PATCH_URL}


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
    c.execute("CREATE TABLE IF NOT EXISTS trusted_procs (proc_name TEXT PRIMARY KEY)")
    for proc in DEFAULT_TRUSTED_PROCS:
        c.execute("INSERT OR IGNORE INTO trusted_procs VALUES (?)", (proc.lower(),))
    conn.commit()
    return conn


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


def sync_feeds_internal():
    conn = init_db()
    c = conn.cursor()
    ips = []
    for url, label in [
        ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "FeodoTracker"),
        ("https://cinsscore.com/list/ci-badguys.txt", "CINS_ThreatIntel")
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
    conn.commit()
    conn.close()
    return len(ips), len(hashes)


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


def ask_local_ai(alert_type, details):
    prompt = (
        f"You are a clear, helpful cybersecurity assistant. Explain this {alert_type} event in 2 plain-English sentences without markdown asterisks:\n"
        f"{json.dumps(details)}\n"
        "Sentence 1: State which app or file triggered this and whether it looks like normal activity or a threat. "
        "Sentence 2: Tell the user whether to click 'Trust App' or 'Auto-Fix'."
    )
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "keep_alive": 0,
        "options": {"num_gpu": 0, "num_thread": 4, "temperature": 0.1}
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=45)
        return r.json().get("response", "No AI response.").strip().replace("**", "")
    except Exception as e:
        return f"Local AI offline ({e}). Use the Auto-Fix or Trust App buttons to resolve."


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
        now = time.time()
        if now - self.recent_scans.get(path, 0) < 3.0:
            return
        self.recent_scans[path] = now

        try:
            time.sleep(0.5)
            with open(path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            entropy = round(calculate_entropy(path), 2)
            db_hit = self.app.check_hash_in_db(sha256)
            is_suspicious_exec = ext in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr"} and entropy > 7.2
            if db_hit or is_suspicious_exec:
                details = {
                    "kind": "file",
                    "file": os.path.basename(path),
                    "path": path,
                    "sha256": sha256,
                    "entropy": entropy,
                    "match": db_hit or "High-Entropy Packed Executable"
                }
                self.app.handle_file_alert(details)
            else:
                self.app.log_event(f"[CLEAN SCAN] {os.path.basename(path)} verified safe (Entropy: {entropy})")
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
        self.title(f"PureProtect // Local AI Security & Network Suite v{APP_VERSION}")
        self.geometry("1160x710")
        self.minsize(1040, 640)
        self.configure(fg_color="#0B0F19")

        self.tray_image = create_shield_icon()
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except Exception:
                pass

        self.last_flagged_file = None
        self.last_incident = None
        self.popup_win = None
        self.last_popup_time = 0
        self.cooldown_seconds = 900
        self.retrain_requested = False

        self.minimize_to_tray_var = ctk.BooleanVar(value=True)
        self.autostart_var = ctk.BooleanVar(value=os.path.exists(STARTUP_BAT))
        self.silent_mode_var = ctk.BooleanVar(value=False)

        self.protocol("WM_DELETE_WINDOW", self.on_close_button)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_views()
        self.show_view("dashboard")

        self.refresh_db_counts()
        self.refresh_quarantine_list()
        self.log_event(f"[SYSTEM] PureProtect v{APP_VERSION} Live Engine Active (Auto-Injector Enabled).")

        self.observer = Observer()
        self.observer.schedule(DownloadScanner(self), WATCH_DIR, recursive=False)
        self.observer.start()

        threading.Thread(target=self.monitor_network, daemon=True).start()
        threading.Thread(target=self.monitor_app_resources, daemon=True).start()
        self._init_system_tray()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color="#070A12", border_width=1, border_color="#1E293B")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(24, 16))
        ctk.CTkLabel(brand, text="🛡️ PureProtect", font=("Segoe UI", 22, "bold"), text_color="#06B6D4").pack(anchor="w")
        ctk.CTkLabel(brand, text=f"PURE ECOSYSTEM SOC v{APP_VERSION}", font=("Segoe UI", 10, "bold"), text_color="#64748B").pack(anchor="w", pady=(2, 0))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "⚡  Command Center"),
            ("incident", "🛠️  Incident & Auto-Fix"),
            ("network", "🌐  Live Network Radar"),
            ("quarantine", "🔒  Quarantine Vault"),
            ("settings", "🚀  Auto-Inject & Updates"),
            ("legal", "📜  Privacy & Legal")
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w", height=40, corner_radius=8,
                font=("Segoe UI", 13, "bold"), fg_color="transparent", text_color="#94A3B8",
                hover_color="#1E293B", command=lambda k=key: self.show_view(k)
            )
            btn.pack(fill="x", padx=14, pady=3)
            self.nav_buttons[key] = btn

        res_card = ctk.CTkFrame(self.sidebar, fg_color="#0F172A", corner_radius=10, border_width=1, border_color="#1E293B")
        res_card.pack(side="bottom", fill="x", padx=14, pady=14)
        ctk.CTkLabel(res_card, text="ENGINE TELEMETRY", font=("Segoe UI", 10, "bold"), text_color="#06B6D4").pack(anchor="w", padx=12, pady=(10, 4))
        self.ram_label = ctk.CTkLabel(res_card, text="App RAM: ~52 MB", font=("Consolas", 12), text_color="#E2E8F0")
        self.ram_label.pack(anchor="w", padx=12, pady=1)
        ctk.CTkLabel(res_card, text="GPU VRAM: 0.0 MB (Locked)", font=("Consolas", 12), text_color="#10B981").pack(anchor="w", padx=12, pady=1)

        ctk.CTkButton(
            res_card, text="Exit Completely", height=28, fg_color="#7F1D1D", hover_color="#991B1B",
            font=("Segoe UI", 11, "bold"), command=self.quit_completely
        ).pack(fill="x", padx=12, pady=(8, 10))

    def _build_views(self):
        self.main_container = ctk.CTkFrame(self, fg_color="#0B0F19", corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.views = {}
        for name in ("dashboard", "incident", "network", "quarantine", "settings", "legal"):
            frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
            frame.grid(row=0, column=0, sticky="nsew")
            self.views[name] = frame

        self._setup_dashboard_view(self.views["dashboard"])
        self._setup_incident_view(self.views["incident"])
        self._setup_network_view(self.views["network"])
        self._setup_quarantine_view(self.views["quarantine"])
        self._setup_settings_view(self.views["settings"])
        self._setup_legal_view(self.views["legal"])

    def _setup_dashboard_view(self, parent):
        self.banner = ctk.CTkFrame(parent, fg_color="#0F172A", corner_radius=12, border_width=1, border_color="#10B981")
        self.banner.pack(fill="x", pady=(0, 14))

        b_left = ctk.CTkFrame(self.banner, fg_color="transparent")
        b_left.pack(side="left", padx=20, pady=14)
        self.status_title = ctk.CTkLabel(b_left, text="●  SYSTEM PROTECTED — PROCESS-AWARE AI SHIELD ACTIVE", font=("Segoe UI", 16, "bold"), text_color="#10B981")
        self.status_title.pack(anchor="w")
        self.status_sub = ctk.CTkLabel(b_left, text="100% Local Zero-Telemetry Engine • Smart App Whitelist & 15-Minute Cooldown Active", font=("Segoe UI", 12), text_color="#94A3B8")
        self.status_sub.pack(anchor="w", pady=(2, 0))

        ctk.CTkButton(
            self.banner, text="⚡ Simulate Malware Attack", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), height=36, command=self.trigger_test_alert
        ).pack(side="right", padx=20, pady=14)

        kpi_row = ctk.CTkFrame(parent, fg_color="transparent")
        kpi_row.pack(fill="x", pady=(0, 14))
        for i in range(4):
            kpi_row.grid_columnconfigure(i, weight=1)

        self.card_hashes = self._make_kpi_card(kpi_row, 0, "MALWARE SIGNATURES", "0", "Abuse.ch SHA256 DB", "#06B6D4")
        self.card_ips = self._make_kpi_card(kpi_row, 1, "BOTNET C2 NODES", "0", "Feodo & CINS Blocklist", "#3B82F6")
        self.card_conns = self._make_kpi_card(kpi_row, 2, "ACTIVE SOCKETS", "0", "Live Outbound Streams", "#8B5CF6")
        self.card_ml = self._make_kpi_card(kpi_row, 3, "ISOLATION FOREST ML", "Calibrating", "Process-Aware Model", "#F59E0B")

        ctrl_bar = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1E293B")
        ctrl_bar.pack(fill="x", pady=(0, 14))

        ctk.CTkButton(
            ctrl_bar, text="🛠️ Open Incident & Auto-Fix Center", fg_color="#D97706", hover_color="#B45309",
            font=("Segoe UI", 12, "bold"), command=lambda: self.show_view("incident")
        ).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(
            ctrl_bar, text="✅ Trust Current Apps & Recalibrate AI", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), command=self.trust_and_recalibrate
        ).pack(side="left", padx=6, pady=10)

        ctk.CTkButton(
            ctrl_bar, text="🔄 Sync Threat Databases", fg_color="#2563EB", hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"), command=self.trigger_feed_sync
        ).pack(side="right", padx=12, pady=10)

        log_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        log_frame.pack(fill="both", expand=True)
        log_hdr = ctk.CTkFrame(log_frame, fg_color="#0F172A", height=34, corner_radius=0)
        log_hdr.pack(fill="x")
        ctk.CTkLabel(log_hdr, text="  LIVE TELEMETRY & LOCAL AI SOC ANALYST STREAM", font=("Consolas", 11, "bold"), text_color="#38BDF8").pack(side="left", padx=10, pady=6)

        self.log_box = ctk.CTkTextbox(log_frame, font=("Consolas", 13), fg_color="#070A12", text_color="#E2E8F0", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

    def _setup_incident_view(self, parent):
        top_card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#38BDF8")
        top_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(top_card, text="🛠️  PLAIN-ENGLISH INCIDENT SUMMARY & ONE-CLICK AUTO-FIX", font=("Segoe UI", 16, "bold"), text_color="#38BDF8").pack(anchor="w", padx=20, pady=(14, 4))

        self.inc_simple_lbl = ctk.CTkLabel(
            top_card,
            text="No active incidents require attention. When an unusual connection or file is caught, PureProtect explains which program caused it in plain English here.",
            font=("Segoe UI", 13), text_color="#E2E8F0", wraplength=820, justify="left"
        )
        self.inc_simple_lbl.pack(anchor="w", padx=20, pady=(2, 12))

        btn_row = ctk.CTkFrame(top_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 14))

        ctk.CTkButton(
            btn_row, text="⚡ Auto-Fix: Stop Process / Quarantine Threat", fg_color="#DC2626", hover_color="#B91C1C",
            font=("Segoe UI", 12, "bold"), width=270, command=self.execute_autofix
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text="✅ Safe App: Trust & Stop Pop-Ups", fg_color="#059669", hover_color="#047857",
            font=("Segoe UI", 12, "bold"), width=240, command=self.trust_and_recalibrate
        ).pack(side="left", padx=6)

        adv_frame = ctk.CTkFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        adv_frame.pack(fill="both", expand=True)
        adv_hdr = ctk.CTkFrame(adv_frame, fg_color="#0F172A", height=36, corner_radius=0)
        adv_hdr.pack(fill="x")
        ctk.CTkLabel(adv_hdr, text="  🔍 ADVANCED TECHNICAL DIAGNOSTICS (EXACT PROCESSES, PIDS, PORTS & POSSIBILITIES)", font=("Consolas", 11, "bold"), text_color="#F59E0B").pack(side="left", padx=10, pady=6)

        self.adv_box = ctk.CTkTextbox(adv_frame, font=("Consolas", 13), fg_color="#070A12", text_color="#A7F3D0", wrap="word")
        self.adv_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.adv_box.insert(
            "end",
            "Waiting for an incident to inspect...\n\n"
            "• Everyday Mode (Top Card): Tells you in plain English what program triggered the alert and lets you fix or trust it in 1 click.\n"
            "• Advanced Mode (This Panel): Shows exact Process Names (.exe), PIDs, Executable Paths, Remote IP:Port sockets, SHA256 hashes, and root-cause possibilities."
        )

    def _setup_legal_view(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        hdr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hdr, text="📜  PRIVACY POLICY, TRADEMARKS & END-USER LICENSE AGREEMENT", font=("Segoe UI", 16, "bold"), text_color="#06B6D4").pack(side="left", padx=18, pady=14)
        ctk.CTkLabel(hdr, text="100% Local Zero-Telemetry Verified", font=("Segoe UI", 12, "bold"), text_color="#10B981").pack(side="right", padx=18, pady=14)

        legal_box = ctk.CTkTextbox(parent, font=("Consolas", 13), fg_color="#070A12", text_color="#E2E8F0", wrap="word")
        legal_box.pack(fill="both", expand=True)
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

    def _setup_network_view(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        hdr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hdr, text="🌐  LIVE OUTBOUND NETWORK RADAR", font=("Segoe UI", 16, "bold"), text_color="#38BDF8").pack(side="left", padx=18, pady=14)
        ctk.CTkButton(hdr, text="Refresh Connections", width=150, command=self.refresh_network_table).pack(side="right", padx=18, pady=14)
        self.net_box = ctk.CTkTextbox(parent, font=("Consolas", 13), fg_color="#070A12", text_color="#A7F3D0")
        self.net_box.pack(fill="both", expand=True)

    def _setup_quarantine_view(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        hdr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hdr, text="🔒  ISOLATED QUARANTINE VAULT", font=("Segoe UI", 16, "bold"), text_color="#F59E0B").pack(side="left", padx=18, pady=14)
        ctk.CTkButton(hdr, text="Refresh Vault", width=130, command=self.refresh_quarantine_list).pack(side="right", padx=18, pady=14)
        self.q_scroll = ctk.CTkScrollableFrame(parent, fg_color="#070A12", corner_radius=12, border_width=1, border_color="#1E293B")
        self.q_scroll.pack(fill="both", expand=True)

    def _setup_settings_view(self, parent):
        # 1. Live Code Auto-Injector Card (Under 25 KB — No .exe rebuild needed!)
        inj_card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#06B6D4")
        inj_card.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(inj_card, text=f"⚡  LIVE CODE AUTO-INJECTOR & GITHUB HOT-PATCH (v{APP_VERSION})", font=("Segoe UI", 16, "bold"), text_color="#06B6D4").pack(anchor="w", padx=24, pady=(16, 4))
        ctk.CTkLabel(inj_card, text="Pulls guardian_ui.py (~25 KB, bypasses GitHub's 25 MB limit) and injects new features immediately without reinstalling:", font=("Segoe UI", 12), text_color="#94A3B8").pack(anchor="w", padx=24)

        p_row = ctk.CTkFrame(inj_card, fg_color="transparent")
        p_row.pack(fill="x", padx=24, pady=(6, 10))

        self.patch_url_entry = ctk.CTkEntry(p_row, font=("Consolas", 12), height=34)
        self.patch_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.patch_url_entry.insert(0, self.settings.get("patch_url", DEFAULT_PATCH_URL))

        ctk.CTkButton(p_row, text="⚡ Auto-Inject from GitHub", fg_color="#059669", hover_color="#047857", font=("Segoe UI", 12, "bold"), width=190, command=self.inject_from_github).pack(side="right", padx=(6, 0))
        ctk.CTkButton(p_row, text="🔄 Reload Local Code", fg_color="#2563EB", hover_color="#1D4ED8", font=("Segoe UI", 12, "bold"), width=160, command=self.reload_local_code).pack(side="right")

        self.update_status_lbl = ctk.CTkLabel(inj_card, text=f"Status: Running Live Code v{APP_VERSION}.", font=("Segoe UI", 12), text_color="#A7F3D0")
        self.update_status_lbl.pack(anchor="w", padx=24, pady=(0, 14))

        # 2. System Preferences Card
        card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1E293B")
        card.pack(fill="both", expand=True)

        ctk.CTkLabel(card, text="⚙️  SYSTEM, POP-UP & STARTUP PREFERENCES", font=("Segoe UI", 16, "bold"), text_color="#38BDF8").pack(anchor="w", padx=24, pady=(18, 12))

        ctk.CTkSwitch(card, text="Launch PureProtect Automatically When Windows Starts", variable=self.autostart_var, command=self.toggle_windows_autostart, font=("Segoe UI", 14)).pack(anchor="w", padx=24, pady=10)
        ctk.CTkSwitch(card, text="Minimize Quietly to Windows System Tray When Clicking 'X'", variable=self.minimize_to_tray_var, font=("Segoe UI", 14)).pack(anchor="w", padx=24, pady=10)
        ctk.CTkSwitch(card, text="Silent Mode (Log anomalies in dashboard without showing bottom-right pop-up windows)", variable=self.silent_mode_var, font=("Segoe UI", 14)).pack(anchor="w", padx=24, pady=10)

        info = f"• Live Dev Script: {DEV_SCRIPT_PATH}\n• Hot-Patch Cache: {LIVE_PATCH_FILE}\n• Local Threat Database: {DB_PATH}"
        ctk.CTkLabel(card, text=info, font=("Consolas", 12), text_color="#94A3B8", justify="left").pack(anchor="w", padx=24, pady=(16, 10))

    def reload_local_code(self):
        self.update_status_lbl.configure(text="Reloading and injecting local guardian_ui.py...", text_color="#10B981")
        pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
        target = str(DEV_SCRIPT_PATH if DEV_SCRIPT_PATH.exists() else Path(__file__).resolve())
        subprocess.Popen([pythonw_exe, target])
        self.after(400, self.quit_completely)

    def inject_from_github(self):
        url = self.patch_url_entry.get().strip()
        self.settings["patch_url"] = url
        save_settings(self.settings)
        self.update_status_lbl.configure(text="Downloading latest guardian_ui.py patch from GitHub...", text_color="#FBBF24")

        def _worker():
            try:
                r = requests.get(url, timeout=15)
                if r.status_code != 200 or "PureProtectSuite" not in r.text:
                    self.after(0, lambda: self.update_status_lbl.configure(text=f"Could not fetch valid code from URL (HTTP {r.status_code}). Upload guardian_ui.py to GitHub first.", text_color="#F87171"))
                    return
                LIVE_PATCH_FILE.write_text(r.text, encoding="utf-8")
                if DEV_SCRIPT_PATH.exists():
                    DEV_SCRIPT_PATH.write_text(r.text, encoding="utf-8")
                self.after(0, lambda: self.update_status_lbl.configure(text="✅ Code injected! Restarting PureProtect...", text_color="#10B981"))
                self.after(800, self.reload_local_code)
            except Exception as e:
                self.after(0, lambda: self.update_status_lbl.configure(text=f"Injection error: {e}", text_color="#F87171"))

        threading.Thread(target=_worker, daemon=True).start()

    def show_view(self, name):
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

    def populate_incident_inspector(self, simple_summary, adv_report, incident_data):
        self.last_incident = incident_data
        def _update():
            self.inc_simple_lbl.configure(text=simple_summary)
            self.adv_box.delete("1.0", "end")
            self.adv_box.insert("end", adv_report)
        self.after(0, _update)

    def execute_autofix(self):
        if not self.last_incident:
            self.log_event("[AUTO-FIX] No active incident requires remediation.")
            return
        kind = self.last_incident.get("kind")
        if kind == "file":
            self.quarantine_last_file()
            self.inc_simple_lbl.configure(text="✅ AUTO-FIX COMPLETE: The suspicious file was isolated in your Quarantine Vault.")
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
            msg = f"✅ AUTO-FIX COMPLETE: Terminated {', '.join(killed)}." if killed else "✅ AUTO-FIX COMPLETE: Recalibrated AI network baseline."
            self.retrain_requested = True
            self.inc_simple_lbl.configure(text=msg)
            self.log_event(f"[AUTO-FIX] {msg}")
            self.banner.configure(border_color="#10B981")
            self.status_title.configure(text="●  SYSTEM PROTECTED — AUTO-FIX APPLIED", text_color="#10B981")

        if self.popup_win is not None and self.popup_win.winfo_exists():
            self.popup_win.destroy()

    def trust_and_recalibrate(self):
        if self.last_incident and self.last_incident.get("untrusted_procs"):
            for pinfo in self.last_incident["untrusted_procs"]:
                add_trusted_proc(pinfo.get("name", ""))
                self.log_event(f"[WHITELIST] Trusted application: {pinfo.get('name')}")
        else:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr and c.pid:
                    try:
                        add_trusted_proc(psutil.Process(c.pid).name())
                    except Exception:
                        pass
            self.log_event("[WHITELIST] Trusted all currently running background applications.")

        self.retrain_requested = True
        self.last_popup_time = time.time()
        self.inc_simple_lbl.configure(text="✅ APPS TRUSTED & AI RECALIBRATED: PureProtect learned these apps are safe and will not alert on them again.")
        self.banner.configure(border_color="#10B981")
        self.status_title.configure(text="●  SYSTEM PROTECTED — AI BASELINE UPDATED", text_color="#10B981")
        if self.popup_win is not None and self.popup_win.winfo_exists():
            self.popup_win.destroy()

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

            w, h = 490, 250
            sx, sy = pop.winfo_screenwidth(), pop.winfo_screenheight()
            pop.geometry(f"{w}x{h}+{sx - w - 25}+{sy - h - 85}")
            pop.configure(fg_color="#090D16")

            card = ctk.CTkFrame(pop, fg_color="#111827", corner_radius=10, border_width=2, border_color="#F59E0B")
            card.pack(fill="both", expand=True, padx=6, pady=6)

            ctk.CTkLabel(card, text=title, text_color="#FBBF24", font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
            ctk.CTkLabel(card, text=simple_msg[:310], font=("Segoe UI", 12), text_color="#E2E8F0", wraplength=450, justify="left").pack(anchor="w", padx=16, pady=4, fill="x", expand=True)

            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=16, pady=(4, 12))

            if can_autofix:
                ctk.CTkButton(btn_row, text="⚡ Auto-Fix", fg_color="#DC2626", hover_color="#B91C1C", font=("Segoe UI", 12, "bold"), width=110, command=self.execute_autofix).pack(side="left", padx=(0, 6))

            ctk.CTkButton(btn_row, text="✅ Trust App", fg_color="#059669", hover_color="#047857", font=("Segoe UI", 12, "bold"), width=115, command=self.trust_and_recalibrate).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btn_row, text="🔍 More Details", fg_color="#2563EB", hover_color="#1D4ED8", font=("Segoe UI", 12, "bold"), width=120, command=lambda: [self.restore_from_tray(), self.show_view("incident"), pop.destroy()]).pack(side="left")
            ctk.CTkButton(btn_row, text="Dismiss", fg_color="#374151", hover_color="#4B5563", width=75, command=pop.destroy).pack(side="right")
            pop.lift()
        self.after(0, _spawn)

    def toggle_windows_autostart(self):
        try:
            if self.autostart_var.get():
                pythonw_exe = r"C:\Users\krazy\ai-sec-pipeline\ai-sec-pipeline\venv\Scripts\pythonw.exe"
                bat_content = f'@echo off\ncd /d "C:\\Users\\krazy\\ai-sec-pipeline\\ai-sec-pipeline"\nstart "" "{pythonw_exe}" "{DEV_SCRIPT_PATH}"\n'
                with open(STARTUP_BAT, "w", encoding="ascii") as f:
                    f.write(bat_content)
                self.log_event("[SETTINGS] Enabled automatic launch at Windows Startup.")
            else:
                if os.path.exists(STARTUP_BAT):
                    os.remove(STARTUP_BAT)
                self.log_event("[SETTINGS] Removed automatic Windows Startup entry.")
        except Exception as e:
            self.log_event(f"[ERROR] Startup toggle failed: {e}")

    def _init_system_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem("Open PureProtect", lambda icon, item: self.after(0, self.restore_from_tray), default=True),
            pystray.MenuItem("Incident & Auto-Fix Center", lambda icon, item: self.after(0, lambda: [self.restore_from_tray(), self.show_view("incident")])),
            pystray.MenuItem("Privacy & Legal Info", lambda icon, item: self.after(0, lambda: [self.restore_from_tray(), self.show_view("legal")])),
            pystray.MenuItem("Exit Completely", lambda icon, item: self.after(0, self.quit_completely))
        )
        self.tray_icon = pystray.Icon("PureProtect", self.tray_image, f"PureProtect v{APP_VERSION} (Active)", menu)
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
            conn.close()
            self.after(0, lambda: self.card_hashes.configure(text=f"{h_count:,}"))
            self.after(0, lambda: self.card_ips.configure(text=f"{ip_count:,}"))
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
        simple = (
            f"WHAT HAPPENED (SIMPLE VIEW):\n"
            f"A newly downloaded file ({details['file']}) matched a threat rule ({details['match']}).\n"
            f"Click 'Auto-Fix' above to lock this file inside the Quarantine Vault."
        )
        adv = (
            f"=== FILE INTERCEPT FORENSIC REPORT ===\n"
            f"File Name       : {details['file']}\n"
            f"Full Path       : {details['path']}\n"
            f"SHA256 Hash     : {details['sha256']}\n"
            f"Shannon Entropy : {details['entropy']} / 8.0\n"
            f"Detection Rule  : {details['match']}\n\n"
            f"TECHNICAL POSSIBILITIES:\n"
            f"1. Known Malware Payload: Hash matched Abuse.ch MalwareBazaar database.\n"
            f"2. Packed/Encrypted Binary: High entropy (>7.2) indicates obfuscated code."
        )
        self.populate_incident_inspector(simple, adv, details)
        self.log_event(f"⚠️ [FILE ALERT] {details['file']} | Match: {details['match']}")

        def run_ai():
            verdict = ask_local_ai("Suspicious File Download", details)
            self.log_event(f"🤖 [AI SOC ANALYST]: {verdict}\n" + ("─" * 78))
            self.show_alert_popup("⚠️ Suspicious Download Caught!", f"File: {details['file']}\n{verdict}", can_autofix=True)
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
            ctk.CTkLabel(self.q_scroll, text="Vault is empty. No quarantined files.", font=("Segoe UI", 13), text_color="#64748B").pack(pady=30)
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

    def refresh_network_table(self):
        self.net_box.delete("1.0", "end")
        trusted = get_trusted_procs()
        header = f"{'PROCESS NAME':<24} {'PID':<8} {'TRUSTED?':<12} {'REMOTE IP:PORT':<26} {'STATUS'}\n" + ("═" * 84) + "\n"
        self.net_box.insert("end", header)
        try:
            conns = [c for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED" and c.raddr]
            for c in conns[:65]:
                try:
                    pname = psutil.Process(c.pid).name()[:22] if c.pid else "System"
                except Exception:
                    pname = "Unknown"
                is_t = "Yes (Safe)" if pname.lower() in trusted else "Unverified"
                raddr = f"{c.raddr.ip}:{c.raddr.port}"
                self.net_box.insert("end", f"{pname:<24} {str(c.pid or 0):<8} {is_t:<12} {raddr:<26} {c.status}\n")
        except Exception as e:
            self.net_box.insert("end", f"Error reading sockets: {e}")

    def trigger_feed_sync(self):
        self.log_event("[SYNC] Pulling latest Abuse.ch Feodo, CINS & MalwareBazaar intelligence feeds...")
        def sync_job():
            try:
                ip_cnt, h_cnt = sync_feeds_internal()
                self.refresh_db_counts()
                self.log_event(f"[SYNC] Synced {ip_cnt:,} malicious IPs and {h_cnt:,} malware hashes.")
            except Exception as e:
                self.log_event(f"[SYNC ERROR] {e}")
        threading.Thread(target=sync_job, daemon=True).start()

    def trigger_test_alert(self):
        def drop_test():
            p = Path.home() / "Downloads" / "pureprotect_test_payload.txt"
            if p.exists():
                p.unlink()
            data = f"harmless_pureprotect_test_{time.time()}".encode("utf-8")
            h = hashlib.sha256(data).hexdigest()
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT OR IGNORE INTO bad_hashes VALUES (?, ?)", (h, "Simulated_ZeroDay_Dropper"))
            conn.commit()
            conn.close()
            self.refresh_db_counts()
            p.write_bytes(data)
        threading.Thread(target=drop_test, daemon=True).start()

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
                    simple = f"CRITICAL: Program '{pname}' (PID {c.pid}) connected to known Botnet C2 Server {ip} ({source}). Click 'Auto-Fix' immediately to terminate '{pname}'."
                    adv = f"=== BOTNET C2 INTERCEPT ===\nProcess : {pname} (PID: {c.pid})\nPath    : {ppath}\nRemote  : {ip}:{c.raddr.port}\nFeed    : {source}"
                    self.populate_incident_inspector(simple, adv, inc)
                    self.show_alert_popup("🚨 Botnet C2 Connection!", simple, can_autofix=True)

                if c.raddr.port not in STANDARD_PORTS and pname.lower() not in trusted_set:
                    untrusted_custom_conns.append({"name": pname, "pid": c.pid, "ip": ip, "port": c.raddr.port, "path": ppath})

            features = [len(conns), len(untrusted_custom_conns)]

            if not is_trained:
                history.append(features)
                p = len(history)
                self.after(0, lambda p=p: self.card_ml.configure(text=f"Sync {p}/20", text_color="#F59E0B"))
                if p >= 20:
                    model.fit(np.array(history))
                    is_trained = True
                    self.after(0, lambda: self.card_ml.configure(text="Active (Smart)", text_color="#10B981"))
                    self.log_event("[ML ENGINE] Process-Aware Isolation Forest calibrated and active.")
            else:
                pred = model.predict(np.array([features]))[0]
                now = time.time()
                if pred == -1 and len(untrusted_custom_conns) >= 3 and (now - self.last_popup_time > self.cooldown_seconds):
                    self.last_popup_time = now
                    app_names = sorted({x["name"] for x in untrusted_custom_conns})
                    apps_str = ", ".join(app_names[:4])

                    simple = (
                        f"WHAT HAPPENED (SIMPLE VIEW):\n"
                        f"The program(s) [{apps_str}] opened {len(untrusted_custom_conns)} connections on non-standard ports.\n"
                        f"• If you recognize [{apps_str}] (like a game, launcher, or tool you use), click '✅ Safe App: Trust & Stop Pop-Ups'.\n"
                        f"• If you do NOT recognize [{apps_str}], click '⚡ Auto-Fix' to shut it down."
                    )
                    lines = [f"• {x['name']} (PID {x['pid']}) -> {x['ip']}:{x['port']} | Path: {x['path']}" for x in untrusted_custom_conns[:15]]
                    adv = (
                        f"=== PROCESS-AWARE NETWORK ANOMALY REPORT ===\n"
                        f"Unverified Apps Involved : {apps_str}\n"
                        f"Unusual Port Connections : {len(untrusted_custom_conns)}\n\n"
                        f"EXACT SOCKETS & EXECUTABLE PATHS:\n" + "\n".join(lines) + "\n\n"
                        f"POSSIBILITIES FOR ADVANCED USERS:\n"
                        f"1. Legitimate App/Game Traffic: P2P sync, game servers, voice chat, or developer tools using high ports.\n"
                        f"2. Unauthorized Backdoor / C2: A background script or trojan calling out on custom TCP ports."
                    )
                    inc_data = {"kind": "network", "untrusted_procs": untrusted_custom_conns}
                    self.populate_incident_inspector(simple, adv, inc_data)
                    self.log_event(f"⚠️ [SMART ANOMALY] Unverified app(s) [{apps_str}] using {len(untrusted_custom_conns)} custom ports.")

                    def run_net_ai(a_str=apps_str, u_list=untrusted_custom_conns):
                        verdict = ask_local_ai("Unverified Application Network Activity", {"apps": a_str, "sample": u_list[:3]})
                        self.log_event(f"🤖 [AI SOC ANALYST]: {verdict}\n" + ("─" * 78))
                        popup_msg = f"App Involved: {a_str}\n{verdict}\n\nClick 'Trust App' if you recognize {a_str}, or 'Auto-Fix' to stop it."
                        self.show_alert_popup(f"⚠️ Activity from {a_str}", popup_msg, can_autofix=True)

                    threading.Thread(target=run_net_ai, daemon=True).start()

            time.sleep(10)


if __name__ == "__main__":
    app = PureProtectSuite()
    app.mainloop()