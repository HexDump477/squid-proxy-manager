# Squid Proxy Manager

Cross-platform GUI for managing Squid proxy ACLs over SSH. Supports Windows and Linux.

Кроссплатформенное GUI-приложение для управления ACL-списками Squid через SSH. Поддержка Windows и Linux.

---

## Features / Возможности

- IOC parser: extract IPs, domains, hashes from text and PDF
- Manage multiple Squid ACL files with custom paths
- Add, delete, search, sync entries with the server
- Duplicate detection before sending
- Restart Squid and check service status
- Dark / Light theme, English / Russian interface

---

## System Requirements / Системные требования

| | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 / Ubuntu 20.04 / Astra Linux 1.7 | Windows 11 / Ubuntu 22.04+ |
| Python | 3.10 | 3.11+ |
| RAM | 256 MB | 512 MB |
| Disk | 50 MB | 100 MB |
| Network | SSH access to Squid server | — |

---

## Installation / Установка

### Windows

```
1. Download Python from https://www.python.org/downloads/
   During install check "Add Python to PATH"

2. Open Command Prompt (Win+R → cmd → Enter)

3. Run:
   git clone https://github.com/HexDump477/squid-proxy-manager.git
   cd squid-proxy-manager
   pip install -r requirements.txt
   python squid_proxy_manager.py
```

If `git` is not installed, download the ZIP from GitHub and extract it.

### Windows (RU)

```
1. Скачайте Python с https://www.python.org/downloads/
   При установке отметьте "Add Python to PATH"

2. Откройте командную строку (Win+R → cmd → Enter)

3. Выполните:
   git clone https://github.com/HexDump477/squid-proxy-manager.git
   cd squid-proxy-manager
   pip install -r requirements.txt
   python squid_proxy_manager.py
```

Если `git` не установлен — скачайте ZIP с GitHub и распакуйте.

### Linux (Debian/Ubuntu/Astra Linux)

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk git -y
git clone https://github.com/HexDump477/squid-proxy-manager.git
cd squid-proxy-manager
pip3 install -r requirements.txt
python3 squid_proxy_manager.py
```

### Linux (RedOS/CentOS/RHEL)

```bash
sudo dnf install python3 python3-pip python3-tkinter git -y
git clone https://github.com/HexDump477/squid-proxy-manager.git
cd squid-proxy-manager
pip3 install -r requirements.txt
python3 squid_proxy_manager.py
```

---

## Quick Start / Быстрый старт

1. Open Settings tab, enter SSH host, port, username
2. Set file paths for your Squid ACL lists
3. Enter SSH password in the top bar
4. Use Parser to extract and send IOCs, or manage lists directly

---

1. Откройте вкладку Settings, укажите SSH-хост, порт, пользователя
2. Настройте пути к файлам ACL Squid
3. Введите пароль SSH в верхней панели
4. Используйте Parser для извлечения IOC или управляйте списками напрямую

---

## Configuration / Конфигурация

Settings are saved to `spm_config.json` automatically. You can add any number of lists — each gets its own tab.

Настройки сохраняются в `spm_config.json` автоматически. Можно добавить любое количество списков — каждый получит свою вкладку.

---

## License

MIT
