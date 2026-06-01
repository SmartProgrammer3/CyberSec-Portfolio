from datetime import datetime
from fpdf import FPDF
 
from checker.models import CheckResult

# Color palette.
COLOR_PASS = (34, 139, 34)      
COLOR_FAIL = (220, 53, 69)     
COLOR_HEADER = (30, 30, 30)     
COLOR_SUBTEXT = (100, 100, 100)
COLOR_BORDER = (220, 220, 220)  
COLOR_WHITE = (255, 255, 255)
COLOR_BLACK = (0, 0, 0)

# Score thresholds as a ratio of passed/total checks.
STRENGTH_THRESHOLDS = [
    (1.0, "Very Strong"),
    (0.8, "Strong"),
    (0.5, "Reasonable"),
    (0.3, "Weak"),
    (0.0, "Very Weak"),
]
 
# Recommendations mapped by check name — displayed when a check fails.
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
 

# Build the list of recommendations based on failed checks.
# HIBP failures are always placed first, as they are the most critical.
def _get_recommendations(results: list[CheckResult]) -> list[str]:
    failed = [r for r in results if not r.passed]
 
    hibp_rec = [RECOMMENDATIONS["HIBP"]] if any(r.name == "HIBP" for r in failed) else []
    other_recs = [
        RECOMMENDATIONS[r.name]
        for r in failed
        if r.name in RECOMMENDATIONS and r.name != "HIBP"
    ]
 
    return hibp_rec + other_recs


# PDF report generator for password strength analysis.
# Extends FPDF to add a consistent header and footer on every page.
class PasswordReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*COLOR_SUBTEXT)
        self.cell(0, 10, "Password Strength Report", align="L")
        self.set_text_color(*COLOR_BLACK)
        self.ln(4)
        self.set_draw_color(*COLOR_BORDER)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)
 
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLOR_SUBTEXT)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")
        self.set_text_color(*COLOR_BLACK)
        

#  Draw the summary section showing the score and overall strength label.
def _draw_summary(pdf: PasswordReport, results: list[CheckResult]) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    label = _get_strength_label(passed, total)
 
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 12, "Password Strength Analysis", ln=True)
    pdf.ln(2)
 
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*COLOR_SUBTEXT)
    pdf.cell(0, 6, f"Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}", ln=True)
    pdf.ln(8)
 
    pdf.set_fill_color(*COLOR_BORDER)
    pdf.set_draw_color(*COLOR_BORDER)
    pdf.rect(10, pdf.get_y(), 190, 28, style="F")
 
    pdf.set_xy(14, pdf.get_y() + 6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(60, 8, f"Score: {passed}/{total} checks passed", ln=False)
 
    pdf.set_font("Helvetica", "B", 13)
    strength_color = COLOR_PASS if passed == total else (COLOR_FAIL if passed < total // 2 else (200, 140, 0))
    pdf.set_text_color(*strength_color)
    pdf.cell(0, 8, f"Strength: {label}", ln=True)
    pdf.ln(16)
    

# Draw the checks section with one row per CheckResult.
# Each row shows a pass/fail indicator, the check name, and its message.
def _draw_checks(pdf: PasswordReport, results: list[CheckResult]) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 8, "Check Results", ln=True)
    pdf.ln(2)
 
    pdf.set_draw_color(*COLOR_BORDER)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
 
    for result in results:
        status_color = COLOR_PASS if result.passed else COLOR_FAIL
        status_label = "PASS" if result.passed else "FAIL"
 
        pdf.set_fill_color(*status_color)
        pdf.set_text_color(*COLOR_WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(14, 6, status_label, align="C", fill=True)
 
        pdf.set_text_color(*COLOR_HEADER)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(42, 6, f"  {result.name}", ln=False)
 
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*COLOR_SUBTEXT)
        pdf.multi_cell(0, 6, result.message)
 
        pdf.ln(1)
 
    pdf.ln(4)
    
    
# Draw the recommendations section.
# Only shown if at least one check failed.
# Each recommendation is numbered and maps directly to a failed check.
def _draw_recommendations(pdf: PasswordReport, results: list[CheckResult]) -> None:
    recommendations = _get_recommendations(results)
 
    if not recommendations:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*COLOR_HEADER)
        pdf.cell(0, 8, "Recommendations", ln=True)
        pdf.ln(2)
        pdf.set_draw_color(*COLOR_BORDER)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*COLOR_PASS)
        pdf.cell(0, 8, "No recommendations. This password passed all checks.", ln=True)
        return
 
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.cell(0, 8, "Recommendations", ln=True)
    pdf.ln(2)
 
    pdf.set_draw_color(*COLOR_BORDER)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
 
    for i, recommendation in enumerate(recommendations, start=1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*COLOR_HEADER)
        pdf.cell(8, 7, f"{i}.", ln=False)
 
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*COLOR_SUBTEXT)
        pdf.multi_cell(0, 7, recommendation)
 
        pdf.ln(1)
        
        
# Generate a PDF password strength report
# Receives the full list of CheckResult objects produced by checker/base_checks.py, checker/entropy.py, and checker/haveibeenpwned.py, and renders:
# 1. Summary - Score and overall strength label.
# 2. Check Results - Detailed pass/fail for each individual check.
# 3. Recommendations - Actionable guidance for each failed check.
def generate_report(results: list[CheckResult]) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"output/password_strength_report_{timestamp}.pdf"

    pdf = PasswordReport(orientation="P", unit="mm", format="A4")
    pdf.set_margins(10, 15, 10)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    _draw_summary(pdf, results)
    _draw_checks(pdf, results)
    _draw_recommendations(pdf, results)

    pdf.output(output_path)
    print(f"Report saved to {output_path}")