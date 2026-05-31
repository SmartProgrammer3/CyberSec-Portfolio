# Password Strength Checker

A Python tool that analyses password strength through multiple layers of verification from basic criteria and entropy calculation to real-world breach detection via the Have I Been Pwned API and comparison against known compromised password lists.

Built as part of a Cybersecurity Portfolio.


## Features

- Basic password criteria validation.
- Entropy calculation with estimated crack time.
- Breach detection via [Have I Been Pwned](https://haveibeenpwned.com/API/v3) API (k-anonymity — password never leaves your machine).
- Wordlist verification against RockYou dataset (14M+ compromised passwords).
- Weak pattern detection (common substitutions, keyboard walks, repeated characters).
- Colour-coded terminal output with detailed verdict.


## Project Structure

```
password-checker/
├── checker/
│   ├── base_checks.py      # Basic password criteria validation.
│   ├── entropy.py          # Entropy calculation and crack time estimation.
│   ├── hibp.py             # Have I Been Pwned API integration.
│   └── wordlist.py         # RockYou wordlist verification.
├── wordlists/
│   └── rockyou.txt         # Compromised passwords dataset.
├── main.py                 # Entry point.
├── config.example.py       # Configuration template
├── requirements.txt
├── .gitignore
└── README.md
```


## How It Works

```
Password Input
      │
      ▼
  base_checks.py   → Validates length, character types and weak patterns.
      │
      ▼
  entropy.py       → Calculates entropy in bits and estimated crack time.
      │
      ▼
  hibp.py          → Checks password against Have I Been Pwned breach database.
      │
      ▼
  wordlist.py      → Compares against RockYou wordlist (14M+ passwords).
      │
      ▼
  reporter.py      → PDF Report
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
requests # Have I Been Pwned API calls
colorama # Colour-coded terminal output
```


## Usage

```bash
python3 main.py --password "YourPasswordHere"
```


## Detection Engine

### Basic Checks (`checker/base_checks.py`)

> Validates fundamental password security criteria. A password may pass all basic checks and still be weak. Basic checks are a necessary but not sufficient condition for a strong password.

**Complexity rules:**
- **Length:** Minimum 8 characters, ideal 12+.
- **Character variety:** Uppercase, lowercase, numbers and special characters.

**Weak pattern detection:**
- **Common substitutions:** Character replacements that appear complex but are predictable (`p@ssw0rd`, `s3cur1ty`, `@→a`, `0→o`, `3→e`).
- **Keyboard walks:** Sequential keyboard patterns (`qwerty`, `asdf`, `zxcv`, `123456`).
- **Repeated characters:** Same character repeated consecutively (`aaaa`, `1111`, `....`).
- **Sequential patterns:** alphabetical or numerical sequences (`abc`, `xyz`, `123`, `987`).
- **Year and date patterns:** common years (`1990`–`2024`) and date formats (`0101`, `3112`) — frequently appended to weak base words.