# SSH Security Monitor for Slack

>  Real-time Python service that watches your Linux auth logs and pings Slack the moment someone fails to log in over SSH.

![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Linux-systemd-FCC624?logo=linux&logoColor=black)
![Slack](https://img.shields.io/badge/Slack-Webhook-4A154B?logo=slack&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🧭 How It Works

```mermaid
flowchart LR
    A["🖥️ Linux Server<br/>SSH login attempt"] --> B["📄 Auth Log<br/>/var/log/secure"]
    B -->|"tail new lines"| C["🐍 Python Monitor"]
    C -->|"keyword match"| D["🔗 Slack Webhook"]
    D --> E["📢 Slack Channel"]

    classDef box fill:#1f2937,stroke:#6366f1,stroke-width:2px,color:#fff;
    classDef alert fill:#4a154b,stroke:#e01e5a,stroke-width:2px,color:#fff;
    class A,B,C,D box;
    class E alert;
```

---

## ⏱️ What Happens During an Attack

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant SSHD as 🔐 sshd
    participant Log as 📄 Auth Log
    participant Mon as 🐍 Monitor
    participant Slack as 💬 Slack

    Attacker->>SSHD: Login attempt (wrong credentials)
    SSHD->>Log: Writes "Failed ..." entry
    Mon->>Log: Reads the new line
    Mon->>Mon: Matches a failure keyword
    Mon->>Slack: POST alert to webhook
    Slack-->>Mon: 200 OK
    Note over Slack: 🚨 Team is notified
```

---

## 🔍 Detection Logic

```mermaid
flowchart TD
    S(["▶️ New log line"]) --> Q{"Contains a<br/>failure keyword?"}
    Q -->|No| X(["⏭️ Ignore"])
    Q -->|Yes| K{"Which one?"}
    K --> P1["❌ Failed password"]
    K --> P2["🔑 Failed publickey"]
    K --> P3["👤 Invalid user"]
    P1 --> F["📨 Format message"]
    P2 --> F
    P3 --> F
    F --> W["🚀 Send to Slack"]

    classDef start fill:#065f46,stroke:#10b981,color:#fff;
    classDef bad fill:#7f1d1d,stroke:#ef4444,color:#fff;
    classDef step fill:#1f2937,stroke:#6366f1,color:#fff;
    class S start;
    class P1,P2,P3 bad;
    class F,W,X step;
```

---

## 🚀 Quick Install

```mermaid
flowchart LR
    A["1️⃣ Add script<br/>/usr/local/bin"] --> B["2️⃣ Set webhook<br/>& log path"]
    B --> C["3️⃣ Create<br/>systemd unit"]
    C --> D["4️⃣ Enable<br/>& start"]
    D --> E(["✅ Running"])

    classDef step fill:#1f2937,stroke:#6366f1,stroke-width:2px,color:#fff;
    classDef done fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff;
    class A,B,C,D step;
    class E done;
```

**Requirements:** Linux · Python 3 · `pip install requests` · root/sudo

### 1️⃣ Add the script

```bash
sudo nano /usr/local/bin/ssh_monitor.py
sudo chmod +x /usr/local/bin/ssh_monitor.py
```

### 2️⃣ Configure

Set `WEBHOOK_URL` and pick the right `LOG_FILE` for your distro:

| Distro | `LOG_FILE` |
|---|---|
| 🎩 RHEL · CentOS · Fedora · Amazon Linux | `/var/log/secure` |
| 🟠 Ubuntu · Debian | `/var/log/auth.log` |

### 3️⃣ Create the service

```bash
sudo nano /etc/systemd/system/ssh-monitor.service
```

```ini
[Unit]
Description=SSH Security Monitor for Slack Alerts
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -u /usr/local/bin/ssh_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 4️⃣ Start it

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-monitor.service
```

---

## ♻️ Service Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Starting: systemctl start
    Starting --> Running: script launched
    Running --> Crashed: unexpected error
    Crashed --> Starting: auto-restart after 10s
    Running --> Stopped: systemctl stop
    Stopped --> [*]
```

---

## 🧰 Cheat Sheet

| Action | Command |
|---|---|
| 📊 Status | `sudo systemctl status ssh-monitor` |
| 📜 Live logs | `sudo journalctl -u ssh-monitor -f` |
| 🔄 Restart | `sudo systemctl restart ssh-monitor` |
| ⏹️ Stop | `sudo systemctl stop ssh-monitor` |

---
