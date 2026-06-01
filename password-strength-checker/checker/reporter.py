from datetime import datetime
from fpdf import FPDF

from checker.models import CheckResult

COLOR_PASS = (34, 139, 34) # Green (Check passed!)
COLOR_FAIL = (220, 53, 69) # Red (Check failed.)
COLOR_HEADER = (30, 30, 30) # Near black (Section headers.)
COLOR_SUBTEXT = (100, 100, 100) # Grey (Secondary text.)
COLOR_BORDER = (220, 220, 220) # Light grey (Card borders.)
COLOR_CARD_BG = (250, 250, 250) # Off-white (Card background.)
COLOR_WHITE = (255, 255, 255)
COLOR_BLACK = (0, 0, 0)
COLOR_WARNING = (200, 140, 0) # Amber (Mid-range strength.)

# Card Layout constants.
CARD_MARGIN = 10
CARD_WIDTH = 190
CARD_LEFT_BAR = 3
CARD_PADDING = 4
CARD_GAP = 2

# Score thresholds as a ratio of passed/total checks. My evaluation.
STRENGTH_THRESHOLDS = [
    (1.0, "Very Strong"),
    (0.9, "Strong"),
    (0.7, "Reasonable"),
    (0.3, "Weak"),
    (0.0, "Very Weak"),
]

# Recommendations mapped by check name (Displayed when the specific check fails).
RECOMMENDATIONS = {
    "Length": "Use a password with at least 12 characters.",
    "Uppercase": "Include at least one uppercase letter (A-Z).",
    "Lowercase": "Include at least one lowercase letter (a-z).",
    "Digits": "Include at least one digit (0-9).",
    "Special chars": "Include at least one special character (e.g. !@#$%).",
    "Weak substitutions": "Avoid using common words with character substitutions such as '@' for 'a' or '0' for 'o'.",
    "Repeated chars": "Avoid sequences of 3 or more repeated characters (e.g. 'aaa', '111').",
    "Sequential pattern": "Avoid sequential patterns such as 'abc', 'xyz' or '123'.",
    "Year pattern": "Avoid appending years to your password (e.g. 1990, 2024).",
    "Date pattern": "Avoid appending dates to your password (e.g. 0101, 3112).",
    "Entropy": "Increase password complexity by combining multiple character classes and increasing its length.",
    "Crack time (offline fast hash)": "Password is vulnerable to brute-force attacks under realistic conditions. Increase length and use a wider mix of character classes to significantly raise the estimated crack time.",
    "HIBP": "This password has been exposed in a known data breach. Choose a completely different password immediately.",
}


# Map the ratio of passed checks to a human-readable strength label.
# Iterates thresholds from highest to lowest and returns the first match.
def _get_strength_label(passed: int, total: int) -> str:
    ratio = passed / total if total > 0 else 0.0

    for threshold, label in STRENGTH_THRESHOLDS:
        if ratio >= threshold:
            return label

    return "Very Weak"


# Returns the strength color based on pass ratio.
def _get_strength_color(passed: int, total: int) -> tuple:
    ratio = passed / total if total > 0 else 0.0

    if ratio == 1.0:
        return COLOR_PASS
    
    elif ratio >= 0.5:
        return COLOR_WARNING
    
    return COLOR_FAIL


# Build the list of recommendations based on failed checks.
# HIBP failures are always placed first, as they are the most critical for us.
def _get_recommendations(results: list[CheckResult]) -> list[str]:
    failed = [r for r in results if not r.passed]

    hibp_rec = [RECOMMENDATIONS["HIBP"]] if any(r.name == "HIBP" for r in failed) else []
    other_recs = [
        RECOMMENDATIONS[r.name]
        for r in failed
        if r.name in RECOMMENDATIONS and r.name != "HIBP"
    ]

    return hibp_rec + other_recs


# PDF report generator.
# Extends FPDF to add a consistent header and footer on every page.
class PasswordReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*COLOR_SUBTEXT)
        self.set_y(8)
        self.cell(0, 8, "Password Strength Checker", align="L")
        self.set_y(8)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 8, datetime.now().strftime("%Y-%m-%d at %H:%M:%S"), align="R")
        self.set_text_color(*COLOR_BLACK)
        self.set_y(16)
        self.set_draw_color(*COLOR_BORDER)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLOR_SUBTEXT)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")
        self.set_text_color(*COLOR_BLACK)


# Draw the summary section showing the score and overall strength label.
def _draw_summary(pdf: PasswordReport, results: list[CheckResult]) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    label = _get_strength_label(passed, total)
    strength_color = _get_strength_color(passed, total)

    # Title.
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 14, "Password Strength Report", ln=True)
    pdf.ln(6)

    # Score card.
    card_y = pdf.get_y()
    pdf.set_fill_color(245, 245, 245)
    pdf.set_draw_color(*COLOR_BORDER)
    pdf.rect(CARD_MARGIN, card_y, CARD_WIDTH, 26, style="FD")

    # Left color bar.
    pdf.set_fill_color(*strength_color)
    pdf.rect(CARD_MARGIN, card_y, CARD_LEFT_BAR, 26, style="F")

    # Row 1 - Score.
    pdf.set_xy(CARD_MARGIN + CARD_LEFT_BAR + CARD_PADDING, card_y + 4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 7, f"Score: {passed}/{total} checks passed", ln=True)

    # Row 2 - Evaluation.
    pdf.set_x(CARD_MARGIN + CARD_LEFT_BAR + CARD_PADDING)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*strength_color)
    pdf.cell(0, 7, f"Our evaluation: {label}!", ln=True)

    pdf.ln(12)


# Draw a single check result as a card with a colored left bar and square indicator.
def _draw_check_card(pdf: PasswordReport, result: CheckResult) -> None:
    color = COLOR_PASS if result.passed else COLOR_FAIL
    status_label = "PASS" if result.passed else "FAIL"

    card_x = CARD_MARGIN
    message_lines = max(1, len(result.message) // 85 + 1)
    card_height = CARD_PADDING * 2 + 6 + message_lines * 5
    
    if pdf.get_y() + card_height > pdf.page_break_trigger:
        pdf.add_page()
        
    card_y = pdf.get_y()

    pdf.set_fill_color(*COLOR_CARD_BG)
    pdf.set_draw_color(*COLOR_BORDER)
    pdf.rect(card_x, card_y, CARD_WIDTH, card_height, style="FD")

    pdf.set_fill_color(*color)
    pdf.rect(card_x, card_y, CARD_LEFT_BAR, card_height, style="F")

    inner_x = card_x + CARD_LEFT_BAR + CARD_PADDING
    inner_w = CARD_WIDTH - CARD_LEFT_BAR - CARD_PADDING * 2

    pdf.set_fill_color(*color)
    pdf.rect(inner_x, card_y + CARD_PADDING + 1, 4, 4, style="F")

    pdf.set_xy(inner_x + 6, card_y + CARD_PADDING)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*color)
    pdf.cell(16, 6, status_label, ln=False)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(inner_w - 22, 6, result.name, ln=True)

    pdf.set_x(inner_x + 22)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*COLOR_SUBTEXT)
    pdf.multi_cell(inner_w - 22, 5, result.message)

    pdf.set_y(card_y + card_height + CARD_GAP)


# Draw the Checks section.
def _draw_checks(pdf: PasswordReport, results: list[CheckResult]) -> None:
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 8, "Check Results", ln=True)
    pdf.ln(1)

    pdf.set_draw_color(*COLOR_BORDER)
    pdf.line(CARD_MARGIN, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    for result in results:
        _draw_check_card(pdf, result)

    pdf.ln(6)


# Draw the recommendations section.
def _draw_recommendations(pdf: PasswordReport, results: list[CheckResult]) -> None:
    recommendations = _get_recommendations(results)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 8, "Recommendations", ln=True)
    pdf.ln(1)

    pdf.set_draw_color(*COLOR_BORDER)
    pdf.line(CARD_MARGIN, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    if not recommendations:
        card_y = pdf.get_y()
        pdf.set_fill_color(*COLOR_CARD_BG)
        pdf.set_draw_color(*COLOR_BORDER)
        pdf.rect(CARD_MARGIN, card_y, CARD_WIDTH, 14, style="FD")
        pdf.set_fill_color(*COLOR_PASS)
        pdf.rect(CARD_MARGIN, card_y, CARD_LEFT_BAR, 14, style="F")
        pdf.set_xy(CARD_MARGIN + CARD_LEFT_BAR + CARD_PADDING, card_y + 4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*COLOR_PASS)
        pdf.cell(0, 6, "No recommendations. This password passed all checks.", ln=True)
        return

    for i, recommendation in enumerate(recommendations, start=1):
        card_y = pdf.get_y()
        rec_lines = max(1, len(recommendation) // 85 + 1)
        card_height = CARD_PADDING * 2 + rec_lines * 6

        pdf.set_fill_color(*COLOR_CARD_BG)
        pdf.set_draw_color(*COLOR_BORDER)
        pdf.rect(CARD_MARGIN, card_y, CARD_WIDTH, card_height, style="FD")

        pdf.set_fill_color(*COLOR_WARNING)
        pdf.rect(CARD_MARGIN, card_y, CARD_LEFT_BAR, card_height, style="F")

        inner_x = CARD_MARGIN + CARD_LEFT_BAR + CARD_PADDING
        inner_w = CARD_WIDTH - CARD_LEFT_BAR - CARD_PADDING * 2

        pdf.set_xy(inner_x, card_y + CARD_PADDING)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*COLOR_WARNING)
        pdf.cell(8, 6, f"{i}.", ln=False)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*COLOR_SUBTEXT)
        pdf.multi_cell(inner_w - 8, 6, recommendation)

        pdf.set_y(card_y + card_height + CARD_GAP)


# Generate a PDF password strength report.
# Receives the full list of CheckResult objects produced by checker/base_checks.py,
# checker/entropy.py, checker/crack_time.py, and checker/haveibeenpwned.py, and renders:
#   1. Summary — Score and overall strength label.
#   2. Check Results — One card per check with colored indicator and detail.
#   3. Recommendations — Numbered cards with actionable guidance for each failed check.
def generate_report(results: list[CheckResult]) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"output/password_strength_report_{timestamp}.pdf"

    pdf = PasswordReport(orientation="P", unit="mm", format="A4")
    pdf.set_margins(10, 15, 10)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    _draw_summary(pdf, results)
    _draw_checks(pdf, results)
    _draw_recommendations(pdf, results)

    pdf.output(output_path)
    print(f"Report saved to {output_path}")