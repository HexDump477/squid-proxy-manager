#!/usr/bin/env python3
"""
Squid Proxy Manager v2.0
Cross-platform GUI for managing Squid proxy ACLs over SSH.
Author: HexDump477
"""

import re
import os
import sys
import json
import threading
import datetime
import platform
from pathlib import Path

import paramiko
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False

# ═══════════════════════════════════════════════════════════════════════════════
# LOCALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

LANG = {
    "en": {
        "app_title": "Squid Proxy Manager",
        "password_placeholder": "SSH Password",
        "check_status": "Check Status",
        "restart_squid": "Restart Squid",
        "status_unknown": "Status: Unknown",
        "status_checking": "Status: Checking...",
        "status_active": "Status: Active",
        "status_inactive": "Status: Inactive",
        "status_error": "Status: Error",
        "status_unreachable": "Status: Unreachable",
        "tab_parser": "Parser",
        "tab_settings": "Settings",
        "input_label": "Paste text or URLs to extract IOCs",
        "exc_label": "Exclusions (one per line, .domain for subdomains)",
        "extract_text": "Extract from text",
        "extract_pdf": "Extract from PDF",
        "dot_prefix": "Add '.' prefix to domains",
        "send_to": "Send to:",
        "send_selected": "Send selected",
        "remove_rows": "Remove selected rows",
        "copy_selected": "Copy selected",
        "hashes_label": "Found Hashes (MD5 / SHA256)",
        "col_original": "Original",
        "col_extracted": "Extracted",
        "col_type": "Type",
        "col_status": "Status",
        "col_hash": "Hash value",
        "col_algo": "Algorithm",
        "col_address": "Address",
        "sync": "Sync from server",
        "delete_selected": "Delete selected",
        "download_backup": "Download backup",
        "search_placeholder": "Search...",
        "add_placeholder": "IP or domain...",
        "add_btn": "Add",
        "path_label": "Path:",
        "type_label": "Type:",
        "ssh_section": "SSH Connection",
        "host": "Host:",
        "port": "Port:",
        "user": "User:",
        "lists_section": "Managed Lists",
        "lists_desc": "Configure remote Squid ACL file paths.",
        "list_name_ph": "List name",
        "list_path_ph": "/etc/squid/...",
        "add_list": "Add list",
        "appearance": "Appearance",
        "theme": "Theme:",
        "language": "Language:",
        "save_settings": "Save settings",
        "log_label": "Log",
        "err_no_password": "Enter SSH password in the top bar.",
        "err_no_host": "Set SSH host in Settings first.",
        "err_select_rows": "Select rows to send.",
        "err_select_delete": "Select entries to delete.",
        "msg_all_exist": "All selected items already exist on server.",
        "msg_confirm_delete": "Permanently delete {n} entries from server?",
        "msg_confirm": "Confirm",
        "msg_already_exists": "'{v}' already exists in {n}.",
        "msg_added": "Added '{v}' to {n}.",
        "msg_settings_saved": "Settings saved. Restart the app if you changed lists.",
        "msg_restart_needed": "New list added. Restart the app to see the new tab.",
        "msg_backup_saved": "Backup saved to:\n{p}",
        "log_extracting": "Extracting IOCs from text...",
        "log_reading_pdf": "Reading PDF: {p}",
        "log_found": "Found: {items} IPs/domains, {md5} MD5, {sha256} SHA256",
        "log_checking_dups": "Checking duplicates against server...",
        "log_dup_done": "Duplicate check complete.",
        "log_sending": "Sending {n} items to {target}...",
        "log_sent": "Sent {n} items. Skipped duplicates: {s}",
        "log_copied": "Copied {n} items.",
        "log_synced": "Synced '{name}': {n} entries.",
        "log_deleted": "Deleted {n} entries from {name}.",
        "log_squid_ok": "Squid restarted successfully.",
        "log_backup": "Backup saved: {f}",
        "log_settings_saved": "Settings saved.",
        "status_ready": "Ready",
        "status_new": "New",
        "status_dup": "Duplicate",
        "status_sent": "Sent",
    },
    "ru": {
        "app_title": "Squid Proxy Manager",
        "password_placeholder": "Пароль SSH",
        "check_status": "Статус Squid",
        "restart_squid": "Перезапуск Squid",
        "status_unknown": "Статус: Неизвестно",
        "status_checking": "Статус: Проверка...",
        "status_active": "Статус: Активен",
        "status_inactive": "Статус: Остановлен",
        "status_error": "Статус: Ошибка",
        "status_unreachable": "Статус: Недоступен",
        "tab_parser": "Парсер",
        "tab_settings": "Настройки",
        "input_label": "Вставьте текст или URL для извлечения IOC",
        "exc_label": "Исключения (по одному на строку, .домен для субдоменов)",
        "extract_text": "Обработать текст",
        "extract_pdf": "Загрузить из PDF",
        "dot_prefix": "Добавлять '.' перед доменом",
        "send_to": "Отправить в:",
        "send_selected": "Отправить выбранное",
        "remove_rows": "Удалить строки",
        "copy_selected": "Копировать",
        "hashes_label": "Найденные хеши (MD5 / SHA256)",
        "col_original": "Исходный текст",
        "col_extracted": "Извлечено",
        "col_type": "Тип",
        "col_status": "Статус",
        "col_hash": "Значение хеша",
        "col_algo": "Алгоритм",
        "col_address": "Адрес",
        "sync": "Синхронизировать",
        "delete_selected": "Удалить выделенное",
        "download_backup": "Скачать бэкап",
        "search_placeholder": "Поиск...",
        "add_placeholder": "IP или домен...",
        "add_btn": "Добавить",
        "path_label": "Путь:",
        "type_label": "Тип:",
        "ssh_section": "SSH-подключение",
        "host": "Хост:",
        "port": "Порт:",
        "user": "Пользователь:",
        "lists_section": "Управляемые списки",
        "lists_desc": "Настройте пути к файлам ACL на сервере Squid.",
        "list_name_ph": "Имя списка",
        "list_path_ph": "/etc/squid/...",
        "add_list": "Добавить список",
        "appearance": "Внешний вид",
        "theme": "Тема:",
        "language": "Язык:",
        "save_settings": "Сохранить настройки",
        "log_label": "Журнал",
        "err_no_password": "Введите пароль SSH в верхней панели.",
        "err_no_host": "Укажите хост SSH в настройках.",
        "err_select_rows": "Выберите строки для отправки.",
        "err_select_delete": "Выберите записи для удаления.",
        "msg_all_exist": "Все выбранные записи уже есть на сервере.",
        "msg_confirm_delete": "Удалить {n} записей с сервера безвозвратно?",
        "msg_confirm": "Подтверждение",
        "msg_already_exists": "'{v}' уже существует в {n}.",
        "msg_added": "'{v}' добавлено в {n}.",
        "msg_settings_saved": "Настройки сохранены. Перезапустите приложение при изменении списков.",
        "msg_restart_needed": "Список добавлен. Перезапустите приложение для отображения.",
        "msg_backup_saved": "Бэкап сохранен:\n{p}",
        "log_extracting": "Извлечение IOC из текста...",
        "log_reading_pdf": "Чтение PDF: {p}",
        "log_found": "Найдено: {items} IP/домены, {md5} MD5, {sha256} SHA256",
        "log_checking_dups": "Проверка дубликатов на сервере...",
        "log_dup_done": "Проверка дубликатов завершена.",
        "log_sending": "Отправка {n} записей в {target}...",
        "log_sent": "Отправлено {n} записей. Пропущено дубликатов: {s}",
        "log_copied": "Скопировано: {n}",
        "log_synced": "Синхронизировано '{name}': {n} записей.",
        "log_deleted": "Удалено {n} записей из {name}.",
        "log_squid_ok": "Squid успешно перезапущен.",
        "log_backup": "Бэкап сохранен: {f}",
        "log_settings_saved": "Настройки сохранены.",
        "status_ready": "Готово",
        "status_new": "Новый",
        "status_dup": "Дубликат",
        "status_sent": "Отправлено",
    },
}

APP_VERSION = "2.0.0"
CONFIG_FILE = "spm_config.json"
EXCLUSIONS_FILE = "spm_exclusions.txt"

DEFAULT_CONFIG = {
    "ssh_host": "",
    "ssh_port": 22,
    "ssh_user": "root",
    "theme": "dark",
    "language": "en",
    "lists": [
        {"name": "Banned Sites", "path": "/etc/squid/ban/banned_sites.list", "type": "url"},
        {"name": "Gods (Whitelist)", "path": "/etc/squid/pools/gods.list", "type": "ip"},
        {"name": "Mortals (Restricted)", "path": "/etc/squid/pools/mortals.list", "type": "ip"},
    ],
}

DEFAULT_EXCLUSIONS = "google.com\nyandex.ru\n.astralinux.ru\n.gosuslugi.ru"

BLOCKED_EXTENSIONS = {
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
    'exe', 'dll', 'msi', 'bat', 'cmd', 'ps1', 'sh', 'apk', 'dmg', 'iso',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'ico', 'webp', 'tiff',
    'mp3', 'mp4', 'avi', 'mkv', 'mov', 'wav', 'flac', 'ogg',
    'css', 'js', 'json', 'xml', 'txt', 'csv', 'log',
    'py', 'rb', 'php', 'asp', 'aspx', 'htm', 'html',
    'torrent', 'deb', 'rpm', 'pkg',
}


def app_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def load_json(path: Path, default: dict) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text("utf-8"))
        except Exception:
            pass
    return default.copy()


def save_json(path: Path, data: dict):
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    except Exception:
        pass


class IOCExtractor:
    IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_RE = re.compile(r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?')
    MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
    SECOND_LEVEL = {'com', 'co', 'org', 'net', 'edu', 'gov', 'mil', 'ac', 'msk', 'spb'}

    @staticmethod
    def sanitize(text: str) -> str:
        for old, new in [('[.]', '.'), ('(.)', '.'), ('[:]', ':'),
                         ('[:/]', '://'), ('hxxps', 'https'), ('hxxp', 'http'),
                         ('HXXPS', 'https'), ('HXXP', 'http')]:
            text = text.replace(old, new)
        return text

    @classmethod
    def parent_domain(cls, url: str, add_dot: bool = True) -> str:
        url = re.sub(r'^https?://', '', url)
        url = url.split('/')[0].split(':')[0].split('?')[0]
        parts = url.split('.')
        if len(parts) >= 3 and parts[-2] in cls.SECOND_LEVEL:
            domain = '.'.join(parts[-3:])
        elif len(parts) >= 2:
            domain = '.'.join(parts[-2:])
        else:
            domain = url
        if add_dot and not domain.startswith('.'):
            domain = '.' + domain
        return domain

    @staticmethod
    def is_file_ext(domain: str) -> bool:
        clean = domain.lstrip('.').lower()
        return clean.split('.')[-1] in BLOCKED_EXTENSIONS if '.' in clean else False

    @classmethod
    def extract(cls, raw_text: str, exclusions: set, add_dot: bool = True):
        text = cls.sanitize(raw_text)
        processed = set()
        items = []
        for ip in cls.IP_RE.findall(text):
            if ip not in processed and not cls._is_ignored(ip, exclusions):
                items.append({"original": ip, "extracted": ip, "type": "IP"})
                processed.add(ip)
        for match in cls.DOMAIN_RE.findall(text):
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', match):
                continue
            domain = cls.parent_domain(match, add_dot)
            if not domain or cls.is_file_ext(domain):
                continue
            if domain not in processed:
                clean = domain.lstrip('.')
                if not cls._is_ignored(clean, exclusions) and not cls._is_ignored(domain, exclusions):
                    items.append({"original": match, "extracted": domain, "type": "Domain"})
                    processed.add(domain)
        md5 = set(cls.MD5_RE.findall(text))
        sha256 = set(cls.SHA256_RE.findall(text))
        return items, md5, sha256

    @staticmethod
    def _is_ignored(item: str, exclusions: set) -> bool:
        item_l = item.lower().lstrip('.')
        for exc in exclusions:
            exc_s = exc.lstrip('.')
            if item_l == exc_s or item_l.endswith('.' + exc_s):
                return True
        return False

    @staticmethod
    def parse_exclusions(text: str) -> set:
        return {line.strip().lower() for line in text.splitlines()
                if line.strip() and not line.strip().startswith('#')}


class SSHManager:
    def __init__(self, host: str, port: int, user: str, password: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    def _connect(self) -> paramiko.SSHClient:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, port=self.port, username=self.user,
                    password=self.password, timeout=8)
        return ssh

    def read_list(self, remote_path: str) -> list[str]:
        ssh = self._connect()
        ssh.exec_command(f"touch {remote_path}")
        _, stdout, _ = ssh.exec_command(f"cat {remote_path}")
        data = stdout.read().decode("utf-8", errors="ignore")
        ssh.close()
        return [l.strip() for l in data.splitlines() if l.strip()]

    def append_items(self, remote_path: str, items: list[str]):
        ssh = self._connect()
        ssh.exec_command(f'[ -n "$(tail -c1 {remote_path})" ] && echo "" >> {remote_path}')
        for item in items:
            ssh.exec_command(f'echo "{item}" >> {remote_path}')
        ssh.close()

    def delete_items(self, remote_path: str, items_to_remove: set[str]):
        ssh = self._connect()
        sftp = ssh.open_sftp()
        with sftp.file(remote_path, 'r') as f:
            lines = f.read().decode("utf-8", errors="ignore").splitlines()
        new_lines = [l for l in lines if l.strip() and l.strip() not in items_to_remove]
        with sftp.file(remote_path, 'w') as f:
            f.write(('\n'.join(new_lines) + '\n').encode("utf-8"))
        sftp.close()
        ssh.close()

    def restart_squid(self):
        ssh = self._connect()
        stdin, stdout, stderr = ssh.exec_command("sudo -S systemctl restart squid")
        stdin.write(self.password + "\n")
        stdin.flush()
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", errors="ignore")
        ssh.close()
        if exit_code != 0:
            raise RuntimeError(err.replace("[sudo] password for root:", "").strip())

    def squid_status(self) -> str:
        ssh = self._connect()
        stdin, stdout, _ = ssh.exec_command("sudo -S systemctl status squid --no-pager")
        stdin.write(self.password + "\n")
        stdin.flush()
        stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="ignore")
        ssh.close()
        if "Active: active (running)" in output:
            return "active"
        elif "Active: inactive" in output:
            return "inactive"
        return "error"

    def download_file(self, remote_path: str) -> str:
        ssh = self._connect()
        _, stdout, _ = ssh.exec_command(f"cat {remote_path}")
        data = stdout.read().decode("utf-8", errors="ignore")
        ssh.close()
        return data


class SquidProxyManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config_path = app_dir() / CONFIG_FILE
        self.exc_path = app_dir() / EXCLUSIONS_FILE
        self.cfg = load_json(self.config_path, DEFAULT_CONFIG)
        if "lists" not in self.cfg:
            self.cfg["lists"] = DEFAULT_CONFIG["lists"]
        if "language" not in self.cfg:
            self.cfg["language"] = "en"
        self.current_lang = self.cfg.get("language", "en")
        ctk.set_appearance_mode(self.cfg.get("theme", "dark"))
        ctk.set_default_color_theme("blue")
        self.title(f"{self.t('app_title')} v{APP_VERSION}")
        self.geometry("1280x800")
        self.minsize(900, 600)
        self.recent_items = {}
        self.cached_data = {}
        self.parser_results = []
        self._build_ui()

    def t(self, key: str, **kwargs) -> str:
        text = LANG.get(self.current_lang, LANG["en"]).get(key, key)
        if kwargs:
            text = text.format(**kwargs)
        return text

    def _build_ui(self):
        self._build_top_bar()
        self.tabs = ctk.CTkTabview(self, anchor="w")
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 5))
        self._build_parser_tab()
        self._build_list_tabs()
        self._build_settings_tab()
        self._build_bottom_bar()

    def _build_top_bar(self):
        bar = ctk.CTkFrame(self, height=50)
        bar.pack(fill="x", padx=10, pady=(10, 5))
        ctk.CTkLabel(bar, text=self.t("app_title"),
                     font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=15)
        self.status_indicator = ctk.CTkLabel(
            bar, text=self.t("status_unknown"), text_color="gray",
            font=ctk.CTkFont(size=12, weight="bold"))
        self.status_indicator.pack(side="right", padx=15)
        ctk.CTkButton(bar, text=self.t("check_status"), width=120,
                      command=self._check_status).pack(side="right", padx=5)
        ctk.CTkButton(bar, text=self.t("restart_squid"), width=130,
                      fg_color="#c0392b", hover_color="#962d22",
                      command=self._restart_squid).pack(side="right", padx=5)
        self.pwd_entry = ctk.CTkEntry(bar, placeholder_text=self.t("password_placeholder"),
                                      show="*", width=160)
        self.pwd_entry.pack(side="right", padx=15)

    def _apply_treeview_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        is_dark = self.cfg.get("theme") == "dark"
        if is_dark:
            style.configure("Custom.Treeview",
                            background="#1e1e1e", foreground="#e0e0e0",
                            fieldbackground="#1e1e1e", rowheight=28,
                            borderwidth=0,
                            font=("Segoe UI", 10))
            style.configure("Custom.Treeview.Heading",
                            background="#333333", foreground="#ffffff",
                            borderwidth=1, relief="flat",
                            font=("Segoe UI", 10, "bold"))
            style.map("Custom.Treeview",
                      background=[("selected", "#1f6aa5")],
                      foreground=[("selected", "#ffffff")])
            style.map("Custom.Treeview.Heading",
                      background=[("active", "#444444")])
            style.configure("TScrollbar",
                            background="#333333", troughcolor="#1e1e1e",
                            borderwidth=0, arrowsize=14)
            style.map("TScrollbar",
                      background=[("active", "#555555")])
        else:
            style.configure("Custom.Treeview",
                            background="#ffffff", foreground="#1a1a1a",
                            fieldbackground="#ffffff", rowheight=28,
                            borderwidth=0,
                            font=("Segoe UI", 10))
            style.configure("Custom.Treeview.Heading",
                            background="#e8e8e8", foreground="#1a1a1a",
                            borderwidth=1, relief="flat",
                            font=("Segoe UI", 10, "bold"))
            style.map("Custom.Treeview",
                      background=[("selected", "#0078d7")],
                      foreground=[("selected", "#ffffff")])
            style.map("Custom.Treeview.Heading",
                      background=[("active", "#d0d0d0")])

    def _bind_clipboard(self, textbox: ctk.CTkTextbox):
        inner = textbox._textbox
        inner.bind("<Control-v>", lambda e: self._paste_to(inner))
        inner.bind("<Control-V>", lambda e: self._paste_to(inner))
        inner.bind("<Control-a>", lambda e: (inner.tag_add("sel", "1.0", "end"), "break"))
        inner.bind("<Control-A>", lambda e: (inner.tag_add("sel", "1.0", "end"), "break"))

    def _paste_to(self, widget):
        try:
            text = self.clipboard_get()
            try:
                widget.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            widget.insert("insert", text)
        except tk.TclError:
            pass
        return "break"

    def _build_parser_tab(self):
        tab = self.tabs.add(self.t("tab_parser"))
        top = ctk.CTkFrame(tab)
        top.pack(fill="x", padx=10, pady=5)
        left = ctk.CTkFrame(top)
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))
        ctk.CTkLabel(left, text=self.t("input_label"),
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(10, 2))
        self.input_text = ctk.CTkTextbox(left, height=120)
        self.input_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._bind_clipboard(self.input_text)
        right = ctk.CTkFrame(top)
        right.pack(side="right", fill="both", expand=True, padx=(5, 0))
        ctk.CTkLabel(right, text=self.t("exc_label"),
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(10, 2))
        self.exc_text = ctk.CTkTextbox(right, height=120)
        self.exc_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._bind_clipboard(self.exc_text)
        exc_content = DEFAULT_EXCLUSIONS
        if self.exc_path.exists():
            exc_content = self.exc_path.read_text("utf-8")
        self.exc_text.insert("1.0", exc_content)

        ctrl = ctk.CTkFrame(tab)
        ctrl.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(ctrl, text=self.t("extract_text"),
                      command=self._parse_text).pack(side="left", padx=5)
        if HAS_PYPDF2:
            ctk.CTkButton(ctrl, text=self.t("extract_pdf"),
                          command=self._parse_pdf).pack(side="left", padx=5)
        self.dot_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(ctrl, text=self.t("dot_prefix"),
                        variable=self.dot_var).pack(side="left", padx=20)
        ctk.CTkLabel(ctrl, text=self.t("send_to")).pack(side="left", padx=(20, 5))
        list_names = [l["name"] for l in self.cfg["lists"]]
        self.target_list_var = ctk.StringVar(value=list_names[0] if list_names else "")
        self.target_combo = ctk.CTkComboBox(ctrl, values=list_names,
                                            variable=self.target_list_var, width=200)
        self.target_combo.pack(side="left", padx=5)
        ctk.CTkButton(ctrl, text=self.t("send_selected"), fg_color="#27ae60",
                      hover_color="#1e8449",
                      command=self._send_selected).pack(side="left", padx=10)

        table_frame = ctk.CTkFrame(tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self._apply_treeview_style()

        cols = ("original", "extracted", "type", "status")
        is_dark = self.cfg.get("theme") == "dark"
        inner = tk.Frame(table_frame, bg="#2b2b2b" if is_dark else "#f0f0f0")
        inner.pack(fill="both", expand=True, padx=5, pady=5)
        scroll = ttk.Scrollbar(inner)
        scroll.pack(side="right", fill="y")
        self.tree = ttk.Treeview(inner, columns=cols, show="headings",
                                 selectmode="extended", yscrollcommand=scroll.set,
                                 style="Custom.Treeview")
        self.tree.heading("original", text=self.t("col_original"))
        self.tree.heading("extracted", text=self.t("col_extracted"))
        self.tree.heading("type", text=self.t("col_type"))
        self.tree.heading("status", text=self.t("col_status"))
        self.tree.column("original", width=320)
        self.tree.column("extracted", width=280)
        self.tree.column("type", width=80)
        self.tree.column("status", width=140)
        self.tree.tag_configure("new", foreground="#2ecc71")
        self.tree.tag_configure("dup", foreground="#e74c3c")
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.config(command=self.tree.yview)
        self.tree.bind("<Delete>", lambda e: self._delete_tree_rows())

        btm = ctk.CTkFrame(tab)
        btm.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(btm, text=self.t("remove_rows"), fg_color="#7f8c8d",
                      hover_color="#636e72", command=self._delete_tree_rows).pack(side="left", padx=5)
        ctk.CTkButton(btm, text=self.t("copy_selected"),
                      command=self._copy_tree_rows).pack(side="left", padx=5)

        ctk.CTkLabel(tab, text=self.t("hashes_label"),
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 2))
        is_dark = self.cfg.get("theme") == "dark"
        hash_inner = tk.Frame(tab, bg="#2b2b2b" if is_dark else "#f0f0f0")
        hash_inner.pack(fill="x", padx=15, pady=(0, 10))
        hscroll = ttk.Scrollbar(hash_inner)
        hscroll.pack(side="right", fill="y")
        self.hash_tree = ttk.Treeview(hash_inner, columns=("hash", "type"),
                                      show="headings", height=4, yscrollcommand=hscroll.set,
                                      style="Custom.Treeview")
        self.hash_tree.heading("hash", text=self.t("col_hash"))
        self.hash_tree.heading("type", text=self.t("col_algo"))
        self.hash_tree.column("hash", width=600)
        self.hash_tree.column("type", width=100)
        self.hash_tree.pack(side="left", fill="x", expand=True)
        hscroll.config(command=self.hash_tree.yview)

    def _build_list_tabs(self):
        self.list_trees = {}
        self.list_search_vars = {}
        self.list_add_entries = {}
        for lst in self.cfg["lists"]:
            name = lst["name"]
            tab = self.tabs.add(name)
            self.recent_items[name] = set()
            self.cached_data[name] = []
            ctrl = ctk.CTkFrame(tab)
            ctrl.pack(fill="x", padx=10, pady=10)
            ctk.CTkButton(ctrl, text=self.t("sync"),
                          command=lambda n=name: self._sync_list(n)).pack(side="left", padx=5)
            ctk.CTkButton(ctrl, text=self.t("delete_selected"), fg_color="#c0392b",
                          hover_color="#962d22",
                          command=lambda n=name: self._delete_from_list(n)).pack(side="left", padx=5)
            ctk.CTkButton(ctrl, text=self.t("download_backup"),
                          command=lambda n=name: self._download_list(n)).pack(side="left", padx=5)
            svar = ctk.StringVar()
            svar.trace_add("write", lambda *a, n=name: self._filter_list(n))
            self.list_search_vars[name] = svar
            ctk.CTkEntry(ctrl, textvariable=svar, placeholder_text=self.t("search_placeholder"),
                         width=200).pack(side="left", padx=(20, 5))
            ctk.CTkLabel(ctrl, text=self.t("add_btn") + ":").pack(side="left", padx=(20, 5))
            entry = ctk.CTkEntry(ctrl, placeholder_text=self.t("add_placeholder"), width=200)
            entry.pack(side="left", padx=5)
            self.list_add_entries[name] = entry
            ctk.CTkButton(ctrl, text=self.t("add_btn"), width=80,
                          command=lambda n=name: self._manual_add(n)).pack(side="left", padx=5)
            info = ctk.CTkFrame(tab)
            info.pack(fill="x", padx=10, pady=(0, 5))
            ctk.CTkLabel(info, text=f"{self.t('path_label')} {lst['path']}",
                         text_color="gray").pack(side="left", padx=10)
            ctk.CTkLabel(info, text=f"{self.t('type_label')} {lst.get('type', 'mixed')}",
                         text_color="gray").pack(side="left", padx=10)
            is_dark = self.cfg.get("theme") == "dark"
            table_fr = tk.Frame(tab, bg="#2b2b2b" if is_dark else "#f0f0f0")
            table_fr.pack(fill="both", expand=True, padx=10, pady=5)
            sc = ttk.Scrollbar(table_fr)
            sc.pack(side="right", fill="y")
            tree = ttk.Treeview(table_fr, columns=("address",), show="headings",
                                selectmode="extended", yscrollcommand=sc.set,
                                style="Custom.Treeview")
            tree.heading("address", text=self.t("col_address"))
            tree.tag_configure("recent", foreground="#e74c3c")
            tree.tag_configure("normal", foreground="")
            tree.pack(side="left", fill="both", expand=True)
            sc.config(command=tree.yview)
            self.list_trees[name] = tree

    def _build_settings_tab(self):
        tab = self.tabs.add(self.t("tab_settings"))
        ssh_frame = ctk.CTkFrame(tab)
        ssh_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(ssh_frame, text=self.t("ssh_section"),
                     font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        row1 = ctk.CTkFrame(ssh_frame)
        row1.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row1, text=self.t("host"), width=80).pack(side="left")
        self.set_host = ctk.CTkEntry(row1, width=250)
        self.set_host.pack(side="left", padx=5)
        self.set_host.insert(0, self.cfg.get("ssh_host", ""))
        ctk.CTkLabel(row1, text=self.t("port"), width=50).pack(side="left", padx=(20, 0))
        self.set_port = ctk.CTkEntry(row1, width=80)
        self.set_port.pack(side="left", padx=5)
        self.set_port.insert(0, str(self.cfg.get("ssh_port", 22)))
        ctk.CTkLabel(row1, text=self.t("user"), width=80).pack(side="left", padx=(20, 0))
        self.set_user = ctk.CTkEntry(row1, width=150)
        self.set_user.pack(side="left", padx=5)
        self.set_user.insert(0, self.cfg.get("ssh_user", "root"))

        self.lists_frame = ctk.CTkFrame(tab)
        self.lists_frame.pack(fill="both", expand=True, padx=20, pady=10)
        ctk.CTkLabel(self.lists_frame, text=self.t("lists_section"),
                     font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        ctk.CTkLabel(self.lists_frame, text=self.t("lists_desc"),
                     text_color="gray").pack(anchor="w", padx=15, pady=(0, 10))
        self.list_entries = []
        for lst in self.cfg["lists"]:
            self._create_list_row(lst["name"], lst["path"], lst.get("type", "mixed"))
        self.btn_row = ctk.CTkFrame(self.lists_frame)
        self.btn_row.pack(fill="x", padx=15, pady=10)
        ctk.CTkButton(self.btn_row, text=self.t("add_list"), width=120,
                      command=self._add_list_entry).pack(side="left", padx=5)

        appearance_frame = ctk.CTkFrame(tab)
        appearance_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(appearance_frame, text=self.t("appearance"),
                     font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        theme_row = ctk.CTkFrame(appearance_frame)
        theme_row.pack(fill="x", padx=15, pady=(0, 5))
        ctk.CTkLabel(theme_row, text=self.t("theme")).pack(side="left", padx=5)
        self.theme_combo = ctk.CTkComboBox(theme_row, values=["dark", "light", "system"], width=120)
        self.theme_combo.pack(side="left", padx=5)
        self.theme_combo.set(self.cfg.get("theme", "dark"))
        lang_row = ctk.CTkFrame(appearance_frame)
        lang_row.pack(fill="x", padx=15, pady=(0, 15))
        ctk.CTkLabel(lang_row, text=self.t("language")).pack(side="left", padx=5)
        self.lang_combo = ctk.CTkComboBox(lang_row, values=["en", "ru"], width=120)
        self.lang_combo.pack(side="left", padx=5)
        self.lang_combo.set(self.current_lang)

        ctk.CTkButton(tab, text=self.t("save_settings"),
                      font=ctk.CTkFont(size=14, weight="bold"),
                      height=45, command=self._save_settings).pack(padx=20, pady=15)

    def _create_list_row(self, name: str = "", path: str = "", ltype: str = "mixed"):
        row = ctk.CTkFrame(self.lists_frame)
        row.pack(fill="x", padx=15, pady=3, before=self.btn_row if hasattr(self, 'btn_row') else None)
        ne = ctk.CTkEntry(row, placeholder_text=self.t("list_name_ph"), width=180)
        ne.pack(side="left", padx=5)
        if name:
            ne.insert(0, name)
        pe = ctk.CTkEntry(row, placeholder_text=self.t("list_path_ph"), width=350)
        pe.pack(side="left", padx=5)
        if path:
            pe.insert(0, path)
        te = ctk.CTkComboBox(row, values=["ip", "url", "mixed"], width=100)
        te.pack(side="left", padx=5)
        te.set(ltype)
        entry_tuple = (ne, pe, te, row)
        ctk.CTkButton(row, text="X", width=30, height=28,
                      fg_color="#c0392b", hover_color="#962d22",
                      command=lambda et=entry_tuple: self._remove_list_entry(et)).pack(side="left", padx=5)
        self.list_entries.append(entry_tuple)

    def _add_list_entry(self):
        if len(self.list_entries) >= 6:
            messagebox.showwarning("Warning", "Maximum 6 lists allowed.")
            return
        self._create_list_row("New List", "/etc/squid/new.list", "mixed")
        self.log(self.t("msg_restart_needed"))

    def _remove_list_entry(self, entry_tuple):
        if len(self.list_entries) <= 1:
            messagebox.showwarning("Warning", "At least 1 list is required.")
            return
        ne, pe, te, row = entry_tuple
        row.destroy()
        if entry_tuple in self.list_entries:
            self.list_entries.remove(entry_tuple)

    def _build_bottom_bar(self):
        bar = ctk.CTkFrame(self, height=120)
        bar.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(bar, text=self.t("log_label"),
                     font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(5, 0))
        self.log_box = ctk.CTkTextbox(bar, height=80, state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(2, 10))

    def log(self, msg: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        def _do():
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"[{ts}] {msg}\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.after(0, _do)

    def _get_ssh(self) -> SSHManager | None:
        pwd = self.pwd_entry.get()
        if not pwd:
            messagebox.showerror("Error", self.t("err_no_password"))
            return None
        host = self.cfg.get("ssh_host", "")
        if not host:
            messagebox.showerror("Error", self.t("err_no_host"))
            return None
        return SSHManager(host, self.cfg.get("ssh_port", 22),
                          self.cfg.get("ssh_user", "root"), pwd)

    def _get_list_cfg(self, name: str) -> dict | None:
        for l in self.cfg["lists"]:
            if l["name"] == name:
                return l
        return None

    def _parse_text(self):
        raw = self.input_text.get("1.0", "end")
        self._save_exclusions()
        exc = IOCExtractor.parse_exclusions(self.exc_text.get("1.0", "end"))
        self.log(self.t("log_extracting"))
        def work():
            items, md5, sha256 = IOCExtractor.extract(raw, exc, self.dot_var.get())
            self.after(0, lambda: self._show_results(items, md5, sha256))
        threading.Thread(target=work, daemon=True).start()

    def _parse_pdf(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        self._save_exclusions()
        exc = IOCExtractor.parse_exclusions(self.exc_text.get("1.0", "end"))
        self.log(self.t("log_reading_pdf", p=path))
        def work():
            try:
                text = ""
                with open(path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        t = page.extract_text()
                        if t:
                            text += t + "\n"
                items, md5, sha256 = IOCExtractor.extract(text, exc, self.dot_var.get())
                self.after(0, lambda: self._show_results(items, md5, sha256))
            except Exception as e:
                self.log(f"PDF error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _show_results(self, items, md5, sha256):
        self.tree.delete(*self.tree.get_children())
        self.hash_tree.delete(*self.hash_tree.get_children())
        self.parser_results = items
        for d in items:
            self.tree.insert("", "end",
                             values=(d["original"], d["extracted"], d["type"], self.t("status_ready")))
        for h in md5:
            self.hash_tree.insert("", "end", values=(h, "MD5"))
        for h in sha256:
            self.hash_tree.insert("", "end", values=(h, "SHA256"))
        self.log(self.t("log_found", items=len(items), md5=len(md5), sha256=len(sha256)))
        ssh = self._get_ssh()
        if ssh:
            target = self.target_list_var.get()
            lcfg = self._get_list_cfg(target)
            if lcfg:
                self.log(self.t("log_checking_dups"))
                threading.Thread(target=self._check_dups, args=(ssh, lcfg["path"]), daemon=True).start()

    def _check_dups(self, ssh: SSHManager, remote_path: str):
        try:
            existing = set(ssh.read_list(remote_path))
            def update():
                for child in self.tree.get_children():
                    vals = self.tree.item(child, "values")
                    if vals[1] in existing:
                        self.tree.item(child, values=(vals[0], vals[1], vals[2], self.t("status_dup")), tags=("dup",))
                    else:
                        self.tree.item(child, values=(vals[0], vals[1], vals[2], self.t("status_new")), tags=("new",))
                self.log(self.t("log_dup_done"))
            self.after(0, update)
        except Exception as e:
            self.log(f"Duplicate check error: {e}")

    def _send_selected(self):
        ssh = self._get_ssh()
        if not ssh:
            return
        target = self.target_list_var.get()
        lcfg = self._get_list_cfg(target)
        if not lcfg:
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", self.t("err_select_rows"))
            return
        items_to_send = []
        skipped = 0
        dup_status = self.t("status_dup")
        for item in selected:
            vals = self.tree.item(item, "values")
            if vals[3] == dup_status:
                skipped += 1
                continue
            items_to_send.append((item, vals[1]))
        if not items_to_send:
            messagebox.showinfo("Info", self.t("msg_all_exist"))
            return
        self.log(self.t("log_sending", n=len(items_to_send), target=target))
        def work():
            try:
                sent_status = self.t("status_sent")
                ssh.append_items(lcfg["path"], [x[1] for x in items_to_send])
                for item_id, val in items_to_send:
                    self.recent_items.setdefault(target, set()).add(val)
                    self.after(0, lambda i=item_id, s=sent_status: self.tree.item(
                        i, values=(*self.tree.item(i, "values")[:3], s), tags=("new",)))
                self.log(self.t("log_sent", n=len(items_to_send), s=skipped))
                self._sync_list(target)
            except Exception as e:
                self.log(f"Send error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _delete_tree_rows(self):
        for item in self.tree.selection():
            self.tree.delete(item)

    def _copy_tree_rows(self):
        selected = self.tree.selection()
        if selected:
            data = [self.tree.item(i, "values")[1] for i in selected]
            self.clipboard_clear()
            self.clipboard_append("\n".join(data))
            self.log(self.t("log_copied", n=len(data)))

    def _sync_list(self, name: str):
        ssh = self._get_ssh()
        if not ssh:
            return
        lcfg = self._get_list_cfg(name)
        if not lcfg:
            return
        def work():
            try:
                data = ssh.read_list(lcfg["path"])
                self.cached_data[name] = data
                self.after(0, lambda: self._filter_list(name))
                self.log(self.t("log_synced", name=name, n=len(data)))
            except Exception as e:
                self.log(f"Sync error ({name}): {e}")
        threading.Thread(target=work, daemon=True).start()

    def _filter_list(self, name: str):
        tree = self.list_trees.get(name)
        if not tree:
            return
        query = self.list_search_vars.get(name, ctk.StringVar()).get().lower()
        tree.delete(*tree.get_children())
        recent = self.recent_items.get(name, set())
        for item in self.cached_data.get(name, []):
            if query in item.lower():
                tag = "recent" if item in recent else "normal"
                tree.insert("", "end", values=(item,), tags=(tag,))

    def _manual_add(self, name: str):
        ssh = self._get_ssh()
        if not ssh:
            return
        lcfg = self._get_list_cfg(name)
        entry = self.list_add_entries.get(name)
        if not lcfg or not entry:
            return
        value = entry.get().strip()
        if not value:
            return
        def work():
            try:
                existing = set(ssh.read_list(lcfg["path"]))
                if value in existing:
                    self.log(self.t("msg_already_exists", v=value, n=name))
                    return
                ssh.append_items(lcfg["path"], [value])
                self.recent_items.setdefault(name, set()).add(value)
                self.log(self.t("msg_added", v=value, n=name))
                self.after(0, lambda: entry.delete(0, "end"))
                self._sync_list(name)
            except Exception as e:
                self.log(f"Add error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _delete_from_list(self, name: str):
        ssh = self._get_ssh()
        if not ssh:
            return
        lcfg = self._get_list_cfg(name)
        tree = self.list_trees.get(name)
        if not lcfg or not tree:
            return
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", self.t("err_select_delete"))
            return
        items = {tree.item(i, "values")[0] for i in selected}
        if not messagebox.askyesno(self.t("msg_confirm"), self.t("msg_confirm_delete", n=len(items))):
            return
        def work():
            try:
                ssh.delete_items(lcfg["path"], items)
                self.log(self.t("log_deleted", n=len(items), name=name))
                self._sync_list(name)
            except Exception as e:
                self.log(f"Delete error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _download_list(self, name: str):
        ssh = self._get_ssh()
        if not ssh:
            return
        lcfg = self._get_list_cfg(name)
        if not lcfg:
            return
        def work():
            try:
                data = ssh.download_file(lcfg["path"])
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = name.replace(" ", "_").lower()
                filename = f"{safe_name}_{ts}.txt"
                local = app_dir() / filename
                local.write_text(data, "utf-8")
                self.log(self.t("log_backup", f=filename))
                self.after(0, lambda: messagebox.showinfo("Backup", self.t("msg_backup_saved", p=str(local))))
            except Exception as e:
                self.log(f"Download error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _restart_squid(self):
        ssh = self._get_ssh()
        if not ssh:
            return
        def work():
            try:
                ssh.restart_squid()
                self.log(self.t("log_squid_ok"))
                self._check_status()
            except Exception as e:
                self.log(f"Restart error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _check_status(self):
        ssh = self._get_ssh()
        if not ssh:
            return
        self.after(0, lambda: self.status_indicator.configure(
            text=self.t("status_checking"), text_color="orange"))
        def work():
            try:
                st = ssh.squid_status()
                mapping = {
                    "active": ("status_active", "#2ecc71"),
                    "inactive": ("status_inactive", "#f39c12"),
                    "error": ("status_error", "#e74c3c"),
                }
                key, color = mapping.get(st, ("status_error", "#e74c3c"))
                self.after(0, lambda: self.status_indicator.configure(text=self.t(key), text_color=color))
            except Exception:
                self.after(0, lambda: self.status_indicator.configure(
                    text=self.t("status_unreachable"), text_color="#e74c3c"))
        threading.Thread(target=work, daemon=True).start()

    def _save_settings(self):
        self.cfg["ssh_host"] = self.set_host.get().strip()
        try:
            self.cfg["ssh_port"] = int(self.set_port.get().strip())
        except ValueError:
            self.cfg["ssh_port"] = 22
        self.cfg["ssh_user"] = self.set_user.get().strip()
        self.cfg["theme"] = self.theme_combo.get()
        self.cfg["language"] = self.lang_combo.get()
        new_lists = []
        for ne, pe, te, _row in self.list_entries:
            n = ne.get().strip()
            p = pe.get().strip()
            t = te.get()
            if n and p:
                new_lists.append({"name": n, "path": p, "type": t})
        if new_lists:
            self.cfg["lists"] = new_lists
        save_json(self.config_path, self.cfg)
        ctk.set_appearance_mode(self.cfg["theme"])
        self.current_lang = self.cfg["language"]
        self._save_exclusions()
        self.log(self.t("log_settings_saved"))
        messagebox.showinfo("Info", self.t("msg_settings_saved"))

    def _save_exclusions(self):
        try:
            self.exc_path.write_text(self.exc_text.get("1.0", "end").strip(), "utf-8")
        except Exception:
            pass


if __name__ == "__main__":
    app = SquidProxyManager()
    app.mainloop()
