# Log Analyzer - Web Server Attack Detection

A Python tool that parses Apache/Nginx access logs and automatically detects common web attack patterns.

Built as part of a Cybersecurity Portfolio.


## Features

- Parses Apache/Nginx Combined Log Format.
- Detects 7 categories of attacks with multiple rules each.
- IP reputation enrichment via [AbuseIPDB](https://www.abuseipdb.com) API.
- Real-time Telegram alerts (watch mode).
- PDF report generation with executive summary and attack breakdown.
- Two operating modes: batch analysis and real-time monitoring.


## Project Structure

```
log-analyzer/
├── analyzer/
│   ├── parser.py                    # Log parsing and field extraction.
│   ├── detector.py                  # Orchestrates all detection rules.
│   ├── abuseipdb.py                 # AbuseIPDB API integration.
│   ├── reporter.py                  # PDF report generation.
│   ├── models.py                    # Shared data models (Alert, LogEntry).
│   └── detectors/
│       ├── brute_force.py           # Brute force detection (4 rules)
│       ├── sql_injection.py         # SQL Injection detection (4 rules)
│       ├── path_traversal.py        # Path Traversal detection (4 rules)
│       ├── vulnerability_scan.py    # Vulnerability Scanning (2 rules)
│       ├── xss.py                   # Cross-Site Scripting detection (2 rules)
│       ├── command_injection.py     # Command Injection detection (2 rules)
│       └── http_method_tampering.py # HTTP Method Tampering (1 rule)
├── notifier/
│   └── telegram.py                  # Telegram bot alerts (alert + summary)
├── samples/
│   └── my_access.log                # Sample logs for demo (by me)
├── output/                          # Generated reports
├── config.example.py                # Configuration template
├── main.py                          # Entry point
└── requirements.txt
```


## How It Works

**Batch Mode** - full log analysis with PDF report:

```
Apache/Nginx Log (access.log files)
      │
      ▼
  parser.py       → Parses Combined Log Format into structured LogEntry objects.
      │
      ▼
  detector.py     → Applies detection rules across 7 attack categories.
      │
      ▼
  abuseipdb.py    → Enriches suspicious IPs with AbuseIPDB reputation data.
      │
      ├─────────────────────────────┐
      ▼                             ▼
  reporter.py                 telegram.py
  PDF Report                  Summary Alert
```

**Watch Mode** - real-time monitoring with instant alerts:

```
Apache/Nginx Log (access.log)
      │
      ▼ (new lines only — seeks to end of file on start)
  parser.py       → Parses each new line as it arrives.
      │
      ▼
  detector.py     → Applies detection rules to each new entry.
      │
      ▼
  abuseipdb.py    → Enriches suspicious IPs in real time.
      │
      ▼
  telegram.py     → Sends immediate alert for each detected attack.
```


## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Then copy my config.py and do with your keys (see below!)
```

**`requirements.txt`**
```
requests # AbuseIPDB and Telegram API calls
fpdf2 # PDF report generation
python-telegram-bot # Telegram bot alerts
```

**`config.example.py`**
```python
# AbuseIPDB
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY = "" # https://www.abuseipdb.com → Login → API
ABUSEIPDB_MIN_SCORE = 50 # 0-100

# Telegram
TELEGRAM_BOT_TOKEN = "" # @BotFather → /newbot
TELEGRAM_CHAT_ID = "" # @userinfobot or /getUpdates
```


## Usage

**Batch mode** -> Analyse an entire log file and generate a PDF report + Telegram summary:

```bash
python3 main.py --log samples/access.log
```

**Watch mode** -> Monitor a log file in real time and send Telegram alerts:

```bash
python3 main.py --log /var/log/nginx/access.log --watch
```


## Detection Engine
The detection engine analyses log entries line by line and applies a set of rules to identify known attack patterns.

### Brute Force (`detectors/brute_force.py`)
Brute force is an attack method where an automated tool repeatedly tries different credentials until it finds a valid one. It is one of the most common attacks against web applications, especially targeting authentication endpoints.

- **Rule 1 - Repeated authentication failures:** 10+ requests returning status `401` or `403` from the same IP within 60 seconds. Indicates automated credential guessing against a login endpoint.
- **Rule 2 - High request rate:** 100+ requests from the same IP within 10 seconds, regardless of status code. Indicates automated tooling or scripted attacks.
- **Rule 3 - Login endpoint hammering:** 20+ POST requests to the same authentication endpoint (e.g. `/login`, `/admin`, `/wp-login.php`) from the same IP within 60 seconds.
- **Rule 4 - Distributed brute force:** 10+ different IPs targeting the same login endpoint with 20+ total requests within 60 seconds. Indicates the use of a botnet to bypass per-IP rate limiting.

### SQL Injection (`detectors/sql_injection.py`)
SQL Injection (SQLi) is an attack where malicious SQL code is inserted into a query through user input, allowing attackers to read, modify or destroy database data without authorisation. It is consistently ranked in the OWASP (pen Worldwide Application Security Project) Top 10 most critical web vulnerabilities.

- **Rule 1 - Known SQLi patterns:** request path matches known SQLi syntax — UNION-based, boolean-based, time-based and stacked queries. Ex: `/users?id=1' UNION SELECT username,password FROM users--`.
- **Rule 2 - URL-encoded SQLi payloads:** request path contains URL-encoded SQLi characters to bypass basic filters. Ex: `%27` instead of `'`, `%20` instead of space.
- **Rule 3 - Blind SQLi probing:** same IP making 10+ requests to the same endpoint with different parameters within 60 seconds. Indicates data inference through response differences.
- **Rule 4 - Error-based SQLi:** server returns `500` after a request containing a SQLi payload. Indicates the payload reached the database and caused an error.

### Path Traversal (`detectors/path_traversal.py`)
Path Traversal is an attack where the attacker manipulates file path variables to access files and directories outside the web root. This allows access to sensitive system files such as `/etc/passwd` or configuration files containing database credentials. It is listed in the OWASP Top 10.

- **Rule 1 - Directory traversal sequences:** request path contains `../` sequences or URL-encoded equivalents (`%2e%2e%2f`). Ex: `/files/../../../etc/passwd`.
- **Rule 2 - Sensitive file access:** direct references to critical system files such as `/etc/passwd`, `/etc/shadow` or `/proc/self`, without requiring `../` sequences.
- **Rule 3 - Web shell access:** attempts to access known web shell filenames (`shell.php`, `cmd.php`, `c99.php`). A web shell gives the attacker full remote control over the server.
- **Rule 4 - Repeated traversal attempts:** same IP making 5+ traversal attempts within 60 seconds. Indicates automated scanning for accessible system files.

### Vulnerability Scanning (`detectors/vulnerability_scan.py`)
Vulnerability scanning is an automated attack where a tool probes the web server for known vulnerabilities, exposed files and misconfigurations. A single scanner can send thousands of requests per second.

- **Rule 1 - Sequential 404s:** 20+ requests returning `404` from the same IP within 60 seconds. Indicates automated probing for known paths and files.
- **Rule 2 - Known scan paths:** 3+ requests to paths commonly probed by vulnerability scanners (e.g. `/.env`, `/.git/config`, `/backup.zip`) from the same IP within 60 seconds.

### Cross-Site Scripting (`detectors/xss.py`)
Cross-Site Scripting (XSS) is an attack where malicious JavaScript code is injected into a web page. When another user visits the page, the code executes in their browser, allowing session cookie theft, redirection to phishing sites or keystroke capture. It is ranked in the OWASP Top 10. 
Note: Only GET-based XSS is detectable in access logs. POST-based payloads (modern XSS) are not logged by default.

- **Rule 1 - Known XSS patterns:** request path contains known JavaScript payloads such as `<script>`, `onerror=`, `javascript:` or `document.cookie`.
- **Rule 2 - URL-encoded XSS payloads:** request path contains URL-encoded XSS characters to bypass basic filters. Ex: `%3Cscript%3E` instead of `<script>`.

### Command Injection (`detectors/command_injection.py`)
Command Injection is an attack where the attacker injects operating system commands through web application parameters. If the server passes these parameters directly to the system without validation, the commands execute with the web server's permissions, giving the attacker full control. It is ranked in the OWASP Top 10. 
Note: Only GET-based command injection is detectable in access logs. POST-based payloads (modern XSS) are not logged by default.

- **Rule 1 - Known command injection patterns:** request path contains command operators followed by system commands. Ex: `/ping?host=192.168.1.1;whoami`.
- **Rule 2 - URL-encoded payloads:** request path contains URL-encoded command operators to bypass basic filters. Ex: `%3Bwhoami` instead of `;whoami`.

### HTTP Method Tampering (`detectors/http_method_tampering.py`)
HTTP Method Tampering is an attack where the attacker uses unexpected HTTP methods to probe or exploit web application endpoints. Methods such as `TRACE`, `DELETE` or `PUT` rarely appear in normal web traffic and their presence often indicates reconnaissance or an attempt to bypass access controls.

- **Rule 1 - Suspicious HTTP methods:** requests using `DELETE`, `PUT`, `TRACE`, `CONNECT` or `PATCH` outside legitimate REST API endpoints (`/api/`).