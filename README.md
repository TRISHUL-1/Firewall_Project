# Firewall Project

A Linux network packet firewall built with Python, Scapy, FastAPI, and PostgreSQL. It monitors live traffic, detects threats (rate floods, Nimda worm), blocks malicious IPs via iptables, sends Gmail alerts, and exposes a real-time web dashboard.

---

## Architecture

```
Network traffic (Scapy)
        │
        ▼
 basic_firewall.py          ← packet analysis, threat detection
        │
   ┌────┴────┐
   │         │
iptables   log_event.py     ← writes to JSON file + PostgreSQL
  DROP           │
            ┌────┴────┐
            │         │
       logs/*.log   firewall_logs table
                        │
                    FastAPI (api/main.py)
                        │
                  dashboard/index.html   ← live stats, logs, block/unblock
```

**Key design decisions:**
- `log_event.py` writes to both a daily JSON file (durable backup) and PostgreSQL (live dashboard feed). If the DB is unavailable, the file log is unaffected and the firewall keeps running.
- A background thread polls the DB every 15 seconds and syncs any new blocked IPs into the firewall's in-memory blacklist — so IPs blocked from the dashboard take effect without a restart.

---

## Project Structure

```
Firewall_Project/
├── api/
│   ├── database.py        # SQLAlchemy engine + session
│   ├── log_ingestor.py    # manual import of historical log files into DB
│   ├── main.py            # FastAPI routes + WebSocket
│   └── models.py          # Firewall_log, BlockedIP ORM models
├── credentials/           # Gmail OAuth files (git-ignored)
│   ├── credentials.json   ← download from Google Cloud Console
│   └── token.json         ← auto-generated on first run
├── dashboard/
│   └── index.html         # single-file web dashboard
├── firewall/
│   ├── basic_firewall.py  # main packet callback + startup
│   ├── block_manager.py   # block_ip / unblock_ip (iptables + DB)
│   ├── blacklist.txt      # IPs blocked on startup
│   ├── log_event.py       # dual-write logger (file + DB)
│   ├── packet_info.py     # packet field extractor
│   ├── send_mail.py       # Gmail API alert sender
│   └── whitelist.txt      # IPs always allowed through
├── logs/                  # daily JSON log files (auto-created)
├── testing/
│   └── nimda_tester.py    # sends a test Nimda worm packet
├── .env                   # your local config (git-ignored)
├── .env.example           # template
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

---

## Prerequisites

- Linux (Ubuntu 20.04+ recommended)
- Python 3.10+
- PostgreSQL 13+
- Root/sudo access (for the firewall process)
- A Google account (for Gmail alerts)

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/TRISHUL-1/Firewall_Project.git
cd Firewall_Project
pip install -r requirements.txt
pip install "uvicorn[standard]"
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:
```
DATABASE_URL=postgresql://firewall_user:yourpassword@localhost:5432/firewall_db
```

### 3. Set up PostgreSQL

```bash
sudo -u postgres psql
```
```sql
CREATE DATABASE firewall_db;
CREATE USER firewall_user WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE firewall_db TO firewall_user;
\q
```

### 4. Set up Gmail alerts

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project → Enable the **Gmail API**
3. Create **OAuth 2.0 credentials** (Desktop app type)
4. Download `credentials.json` and place it at `credentials/credentials.json`

On first run of the firewall, a browser window opens for OAuth login. After approving, `credentials/token.json` is saved and the prompt won't appear again.

### 5. Whitelist / Blacklist (optional)

Add IPs (one per line) to:
- `firewall/whitelist.txt` — always allowed, never blocked
- `firewall/blacklist.txt` — blocked immediately on startup

---

## Running

You need **two terminals**.

**Terminal 1 — API server:**
```bash
cd Firewall_Project
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2 — Firewall (requires root):**
```bash
cd Firewall_Project
sudo python -m firewall.basic_firewall
```

**Dashboard:**

Open `dashboard/index.html` in your browser. No extra server needed.

---

## Running with Docker

Docker handles PostgreSQL, the API, and the firewall together.

### 1. Place Gmail credentials

```bash
mkdir -p credentials
cp /path/to/your/credentials.json credentials/credentials.json
```

> **Note:** Complete the Gmail OAuth flow locally first (run the firewall once without Docker) so `credentials/token.json` exists. The Docker container cannot open a browser for OAuth.

### 2. Start everything

```bash
docker compose up --build
```

This starts three containers: `db` (PostgreSQL), `api` (FastAPI on port 8000), and `firewall` (Scapy packet sniffer, privileged + host network).

### 3. Stop

```bash
docker compose down
```

To also delete the database volume:
```bash
docker compose down -v
```

---

## Importing Historical Logs

If you have existing JSON log files, import them into the DB:

```bash
python -m api.log_ingestor logs/log_2026-01-07.log
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/stats` | Total logs, blocked, allowed, unique IPs, top ports |
| GET | `/logs?limit=100` | Recent log entries |
| GET | `/blocked_ips` | All currently blocked IPs |
| POST | `/block/{ip}?reason=...` | Block an IP |
| DELETE | `/unblock/{ip}` | Unblock an IP |
| WS | `/ws/logs` | Live log stream (WebSocket) |

Interactive API docs available at `http://127.0.0.1:8000/docs`.

---

## Detection Rules

| Threat | Detection Method | Action |
|--------|-----------------|--------|
| Known bad IP | Matches `blacklist.txt` or DB blocked list | iptables DROP + log |
| Nimda worm | TCP port 80, payload contains `GET /scripts/root.exe` | iptables DROP + log + email alert |
| Packet flood | Source IP exceeds 40 packets/sec | iptables DROP + log + email alert |

The packet rate threshold can be changed by editing `THRESHOLD` in `basic_firewall.py`.

---

## Threat Testing

Send a test Nimda worm packet (from a second machine or terminal):

```bash
sudo python testing/nimda_tester.py
```

Edit `target_ip` inside the script to point at your machine's IP.

---

## Notes

- The firewall process must run as root — it needs raw socket access for Scapy and permission to modify iptables rules.
- iptables rules added by the firewall are not persistent across reboots. Use `iptables-save` / `iptables-restore` or a tool like `ufw` if you need persistence.
- The `credentials/` folder is git-ignored. Never commit your Gmail OAuth files.
