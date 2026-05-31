import requests
import config

from datetime import datetime
from collections import Counter

# Send a message to the configured Telegram chat.
# Returns True if the message was sent successfully, False otherwise.
def send_message(text: str) -> bool:
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"  [!] Telegram notification failed: {e}")
        return False
    
    
# Send a formatted alert to Telegram for a detected attack.
# Used in watch mode - one alert per detected attack in real time.
def send_alert(attack_type: str, ip: str, severity: str, detail: str) -> bool:
    severity_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
    }
    emoji = severity_emoji.get(severity.lower(), "⚪")

    message = (
        f"{emoji} *[{severity.upper()}] {attack_type} Detected*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *IP:* `{ip}`\n"
        f"📋 *Detail:* {detail}\n"
    )

    return send_message(message)


# Send a summary message to Telegram after batch analysis is complete.
# Used in batch mode — one summary message at the end.
def send_summary(alerts: list, total_entries: int, log_path: str, report_path: str) -> bool:
    severity_counts = Counter(alert.severity.lower() for alert in alerts)

    message = (
        f"✅ *Log Analysis Complete*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 *Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"📂 *Log file:* `{log_path}`\n"
        f"📊 *Entries parsed:* {total_entries}\n"
        f"🚨 *Attacks detected:* {len(alerts)}\n"
        f"🔴 Critical: {severity_counts.get('critical', 0)}\n"
        f"🟠 High: {severity_counts.get('high', 0)}\n"
        f"🟡 Medium: {severity_counts.get('medium', 0)}\n"
        f"🟢 Low: {severity_counts.get('low', 0)}\n"
        f"📄 *Report:* `{report_path}`\n"
    )

    return send_message(message)