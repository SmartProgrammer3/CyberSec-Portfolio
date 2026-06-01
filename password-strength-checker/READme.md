# Password Strength Checker

A Python tool that analyses password strength through multiple independent verification layers, from structural criteria and information-theoretic entropy to real-world breach detection and estimated brute-force crack times.

Built as part of a Cybersecurity Portfolio.

---

## Features

- **Structural analysis:** Validates length, character class coverage (uppercase, lowercase, digits, special characters), repeated sequences, sequential patterns, and date/year fragments.
- **Substitution detection:** Identifies common words disguised with character substitutions (Ex. `P@ssw0rd` → `password`), preventing artificially inflated scores.
- **Entropy estimation:** Calculates theoretical password entropy in bits using Shannon's formula (`H = L * log2(N)`), penalised (-20 bits) when predictable patterns are detected.
- **Brute-force crack time:** Estimates time to crack under three realistic attack scenarios: online (1,000 guesses/second), offline slow hash (bcrypt/Argon2 at 10M/s), and offline fast hash (MD5/SHA-1 on NVIDIA RTX 3090 at 22B/s).
- **Breach detection:** Checks passwords against the [Have I Been Pwned](https://haveibeenpwned.com/API/v3) Pwned
Passwords database via k-anonymity. Note: Only a 5-character SHA-1 prefix is sent to the API (the full password never leaves the machine).
- **PDF report generation:** Produces a structured, colour-coded PDF report per analysis including a summary score, individual check results, and actionable recommendations. (One report = one password)

---

## How It Works

Each password is evaluated independently across the following checks:

| Check | Description |
|---|---|
| Length | Minimum 8 characters, ideal 12+. |
| Uppercase | At least one uppercase letter (A-Z). |
| Lowercase | At least one lowercase letter (a-z). |
| Digits | At least one numeric character. |
| Special characters | At least one special character. |
| Weak substitutions | Detects common words after symbol normalisation (Ex. `P@ssw0rd` → `password`). |
| Repeated characters | Flags 3 or more consecutive repeated characters (Ex. `aaa`, `111`). |
| Sequential patterns | Detects alphabetic and numeric runs (Ex. `abc`, `123`). |
| Year / Date patterns | Detects appended years (19xx, 20xx) and DDMM date fragments (Ex. `0101`, `3112`). |
| Entropy | Shannon entropy in bits, penalised when predictable substitutions are detected. |
| Crack time (online) | Estimated crack time at 1,000 guesses/second (rate-limited login form). |
| Crack time (offline slow hash) | Estimated crack time at 10M guesses/second (bcrypt/Argon2). |
| Crack time (offline fast hash) | Estimated crack time at 22B guesses/second (MD5/SHA-1 on NVIDIA RTX 3090). |
| HIBP | Breach count from the Have I Been Pwned Pwned Passwords database. |

---

## Project Structure

```
password-strength-checker/
├── checker/
│   ├── models.py # CheckResult dataclass.
│   ├── base_checks.py # Structural password (Basic) criteria validation.
│   ├── entropy.py # Shannon entropy calculation with substitution penalty.
│   ├── crack_time.py # Brute-force crack time estimation across three attack scenarios.
│   ├── haveibeenpwned.py # Have I Been Pwned API integration via k-anonymity.
│   └── reporter.py # PDF report generation.
├── output/ # Generated PDF reports.
├── samples/ # Samples to test.
│   ├── veryWeak.txt
│   ├── weak.txt
│   ├── reasonable.txt
│   ├── strong.txt
│   └── veryStrong.txt
├── main.py                
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Usage

```bash
# Analyse a single password.
python3 main.py "YourPassword"

# Analyse passwords from a file (Only one password in the file!).
python3 main.py samples/weak.txt
```

---

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**`requirements.txt`**
```
fpdf2
```

---

## Detection Engine

### Basic Checks (`checker/base_checks.py`)

> Validates fundamental password security criteria. A password may pass all basic checks and still be weak. Basic checks are a necessary but not sufficient condition for a strong password.

**Complexity rules:**
- **Length:** Minimum 8 characters, ideal 12+. Passwords below 8 characters fail immediately.

- **Character variety:** Requires uppercase, lowercase, digits, and special characters. Each missing class reduces the character pool size, directly lowering entropy and also fails the check.

**Weak pattern detection:**
- **Common substitutions:** Normalises the password by replacing known symbol-to-letter mappings (`@→a`, `0→o`, `3→e`, `1→i`, `5→s`, `7→t`, `$→s`, `!→i`), then checks the result against common weak words and keyboard walk patterns. Catches passwords like `P@ssw0rd` that appear complex but normalise to `password`.

- **Repeated characters:** Flags 3 or more consecutive identical characters (`aaaa`, `1111`) using a regex back-reference. Repeated characters contribute zero entropy.

- **Sequential patterns:** Detects ascending and descending 3-character runs by comparing ASCII values of consecutive characters (`abc` → `97,98,99`; `987` → `57,56,55`).

- **Year patterns:** Matches 4-digit strings starting with `19` or `20` (Ex. `1990`, `2024`) — commonly appended to weak base words to meet length requirements.

- **Date patterns:** Matches DDMM format (Ex. day `01–31` followed by month `01–12`) using word boundaries to avoid false positives on arbitrary digit sequences (Ex. `0101`, `3112`).

### Entropy (`checker/entropy.py`)

> Measures the theoretical unpredictability of a password in bits using Shannon's formula. This value represents an upper bound. It assumes the password was randomly generated, which is rarely true in practice.

**Formula:** `H = L * log2(N)` where `L` is the password length and `N` is the character pool size (sum of detected character classes).

**Character pool sizes:**

| Class | Size |
|---|---|
| Lowercase (a-z) | 26 |
| Uppercase (A-Z) | 26 |
| Digits (0-9) | 10 |
| Special characters | 32 |

**Thresholds (industry reference):**

| Bits | Strength |
|---|---|
| < 28 | Very Weak |
| 28 – 35 | Weak |
| 36 – 59 | Reasonable |
| 60 – 127 | Strong |
| >= 128 | Very Strong |

**Substitution penalty:** If the password failed the substitution check, 20 bits are deducted from the calculated entropy. This reflects the real-world observation that a common word disguised with character substitutions is trivially guessable despite its apparent complexity and the theoretical entropy significantly overestimates the actual security of such passwords.

### Crack Time (`checker/crack_time.py`)

> Estimates how long a brute-force attack would take to crack the password, based on its entropy and the attacker's guessing rate.

**Formula:** `crack_time = 2^(H-1) / guesses_per_second` — uses `2^(H-1)` rather than `2^H` because an attacker finds the password on average after half of all possible combinations.

**Attack scenarios:**

| Scenario | Rate | Context |
|---|---|---|
| Online attack | 1,000/s | Rate-limited login form with network latency. |
| Offline slow hash | 10,000,000/s | Leaked database using bcrypt, scrypt, or Argon2. |
| Offline fast hash | 22,000,000,000/s | Leaked database using MD5/SHA-1, using NVIDIA RTX 3090 benchmark. |

A password passes this check if it would survive more than 6 months under the worst-case scenario (offline fast hash). This threshold reflects common organisational password rotation policies of 90 to 180 days. (NIST SP 800-63B)

### Have I Been Pwned (`checker/haveibeenpwned.py`)
> Checks whether the password has appeared in a known data breach using the HIBP Pwned Passwords API. This is one of the most effective ways to determine whether a password has been compromised in the real world.

**K-Anonymity protocol:**

1. Hash the password locally with SHA-1. Ex: `password` → `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. Send only the first 5 characters of the hash (the prefix) to the API. Ex: `5BAA6`
3. The API returns all hash suffixes in its database matching that prefix.
4. Search the response locally for the remaining 35-character suffix.
5. If found, the password is compromised. The response also includes the total breach count.

The full password and its complete hash never leave the local machine. The API only ever sees a 5-character prefix, which is shared by hundreds of different hashes, making it impossible for the API to determine which password is being checked.

### Report (`checker/reporter.py`)

> Generates a structured, colour-coded PDF report for each password analysed.

**Sections:**

- **Summary:** Displays the overall score (`X/14 checks passed`) and the strength label based on the ratio of passed checks.
- **Check Results:** One card per check, colour-coded green (pass) or red (fail), with the check name and detailed message.
- **Recommendations:** Numbered list of actionable guidance for each failed check. HIBP failures always appear first as they are the most critical. If all checks pass, a success message is shown instead.

**Strength label thresholds (Our evaluation):**

| Ratio | Label |
|---|---|
| 100% | Very Strong |
| >= 90% | Strong |
| >= 70% | Reasonable |
| >= 30% | Weak |
| < 30% | Very Weak |

Each report is saved to `output/` with a timestamp in the filename (`password_strength_report_YYYYMMDD_HHMMSS.pdf`) to avoid overwriting previous reports.