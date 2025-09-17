---

# WBX Editor

A Python tool to **parse, view, and edit MikroTik Winbox WBX files**.
WBX files store saved sessions (addresses, groups, logins, and passwords) used by Winbox.
This utility allows you to list, export, import, and edit WBX files — including **bulk changes via CSV**.

---

## Features

* ✅ Parse WBX reliably (supports multiple TLV layouts: L2, L1, L0).
* ✅ List records in human-readable or raw hex format.
* ✅ Edit individual records by `host`.
* ✅ Bulk update from CSV (update existing hosts).
* ✅ Mass replace login/password across all records (with modes: **replace** or **add**).
* ✅ Export WBX → CSV and import CSV → WBX.
* ✅ Preview/analyze CSV without importing.
* ✅ Passwords remain **plain text** inside WBX (same as Winbox).

---

## Installation

Clone this repository and run with Python 3:

```bash
git clone https://github.com/yourname/wbx-editor.git
cd wbx-editor
chmod +x wbx_tool.py
```

---

## Usage

### 1. List WBX records

Human-readable list:

```bash
python3 wbx_tool.py --in addresses.WBX --list
```

Hide secrets:

```bash
python3 wbx_tool.py --in addresses.WBX --list --hide-secrets
```

Raw hex with lengths:

```bash
python3 wbx_tool.py --in addresses.WBX --list-raw
```

---

### 2. Edit a single record

Set new login for a host:

```bash
python3 wbx_tool.py --in addresses.WBX \
  --set-login 192.168.88.1 admin \
  --out new.WBX
```

Set new password (also enables `keep-pwd`):

```bash
python3 wbx_tool.py --in addresses.WBX \
  --set-pass 192.168.88.1 MySecret123 \
  --out new.WBX
```

Set `keep-pwd` flag:

```bash
python3 wbx_tool.py --in addresses.WBX \
  --set-keep 192.168.88.1 1 \
  --out new.WBX
```

---

### 3. Mass replace login/password

Replace all records where login = `olduser` with new login/password.

**Mode: replace (default)** → changes in place:

```bash
python3 wbx_tool.py --in addresses.WBX \
  --replace-login olduser newuser NewPass123 \
  --replace-mode replace \
  --out addresses-new.WBX
```

**Mode: add** → duplicates entries with new login/password, keeping originals:

```bash
python3 wbx_tool.py --in addresses.WBX \
  --replace-login olduser newuser NewPass123 \
  --replace-mode add \
  --out addresses-new-add.WBX
```

---

### 4. Bulk update from CSV

Update existing WBX entries by `host` using a CSV file.
Columns supported: `host, login, password, keep` (others ignored for updates).

Example `changes.csv`:

```csv
host,login,password,keep
10.0.0.1,admin,Secret123,1
10.0.0.2,netops,AnotherPass,1
```

Apply updates:

```bash
python3 wbx_tool.py --in addresses.WBX \
  --csv changes.csv \
  --out addresses-updated.WBX
```

⚠️ Note: This updates existing hosts only. New hosts in CSV are ignored unless you use `--import-csv`.

---

### 5. Export WBX → CSV

Dump WBX records to a CSV file:

```bash
python3 wbx_tool.py --in addresses.WBX --export-csv addresses.csv
```

Output columns:

* `group`
* `host`
* `login`
* `password`
* `keep`
* `note`
* `type`
* `secure-mode`

---

### 6. Import CSV → WBX

Build WBX from scratch using a CSV file (creates **all rows**, including new hosts):

```bash
python3 wbx_tool.py --import-csv addresses.csv --out addresses-built.WBX
```

Alias: you can also use `--csv` without `--in`:

```bash
python3 wbx_tool.py --csv addresses.csv --out addresses-built.WBX
```

Notes:

* `host` column is required.
* If `password` is set and `keep` is empty, the tool defaults to `keep=1`.

---

### 7. Preview CSV (analysis only)

Check CSV structure without importing:

```bash
python3 wbx_tool.py --preview-csv addresses.csv
```

Output:

```
Detected delimiter: ','
Headers: ['group','host','login','password','keep','note','type','secure-mode']
Rows (excluding header): 395
Rows missing 'host': 0

First rows:
#1  group=OFFICE, host=10.0.0.1, login=admin, password=Secret123, keep=1
#2  group=LAB, host=10.0.0.2, login=netops, password=AnotherPass, keep=1
...
```

By default shows first 20 rows. Show all rows:

```bash
python3 wbx_tool.py --preview-csv addresses.csv --preview-limit 0
```

---

## Examples

1. **Clone all `YaTv` accounts with new login `NetOps` and password `N3wP@ss!`:**

```bash
python3 wbx_tool.py --in addresses.WBX \
  --replace-login YaTv NetOps N3wP@ss! \
  --replace-mode add \
  --out addresses-cloned.WBX
```

2. **Update 200 servers in bulk from Excel-exported CSV:**

```bash
python3 wbx_tool.py --in servers.WBX \
  --csv update.csv \
  --out servers-updated.WBX
```

3. **Export all saved Winbox sessions to CSV for auditing:**

```bash
python3 wbx_tool.py --in addresses.WBX --export-csv audit.csv
```

4. **Preview a questionable CSV before importing:**

```bash
python3 wbx_tool.py --preview-csv broken.csv --preview-limit 50
```

---

## Safety Notes

* **Always backup your WBX** before editing:

  ```bash
  cp addresses.WBX addresses-backup.WBX
  ```
* WBX stores passwords in **plain text**. Treat exported CSVs carefully.
* This tool is meant for automation, bulk management, and recovery — not for securing credentials.

---

## License

MIT License — free for personal and commercial use.

---

## Info

Website: https://github.com/YATV/WBX-tools/

Author: Taras Yanchuk

Say thank you here: https://www.patreon.com/YATV

---
