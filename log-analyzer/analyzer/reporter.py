from datetime import datetime
from fpdf import FPDF

from analyzer.models import Alert

# Severity colors (R, G, B)
SEVERITY_COLORS = {
    "critical": (220, 50,  50),
    "high": (220, 120, 50),
    "medium": (200, 160, 0),
    "low": (80,  160, 80),
}

# Internal PDF class with custom header and footer.
class _PDF(FPDF):
    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(255, 255, 255)
        self.set_y(6)
        self.cell(0, 8, "Web Server Attack Detection Report", align="L")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(160, 168, 184)
        self.cell(0, 8, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), align="R")
        self.ln(14)
        self.set_text_color(50, 50, 50)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")


# Generate a PDF report from a list of alerts.
# Saves the report to the output/directory.
# Returns the path to the generated file.
def generate(alerts: list[Alert], log_path: str, total_entries: int, reputation: dict) -> str:
    pdf = _PDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    _section_title(pdf, "Executive Summary")
    _summary(pdf, log_path, total_entries, alerts)

    _section_title(pdf, "Detected Attacks")
    _alerts_table(pdf, alerts, reputation)

    path = f"output/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(path)
    return path


# Render a section title.
def _section_title(pdf: FPDF, title: str):
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(26, 26, 46)
    pdf.cell(0, 8, title, ln=True)
    pdf.set_draw_color(26, 26, 46)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_line_width(0.2)
    


# Render the executive summary section.
def _summary(pdf: FPDF, log_path: str, total_entries: int, alerts: list[Alert]):
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        severity_counts[alert.severity.lower()] += 1
    
    # Meta info.
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f"Log file: {log_path}    |    Entries parsed: {total_entries}    |    Attacks detected: {len(alerts)}", ln=True)
    pdf.ln(6)
        
    # Severity cards using SEVERITY_COLORS.
    card_w = 42
    card_h = 20    
    
    for severity, color in SEVERITY_COLORS.items():
        x = pdf.get_x()
        y = pdf.get_y()
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.rect(x, y, card_w, card_h, "F")
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_xy(x, y + 2)
        pdf.cell(card_w, 8, str(severity_counts[severity]), align="C")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(x, y + 11)
        pdf.cell(card_w, 6, severity.upper(), align="C")
        pdf.set_xy(x + card_w + 4, y)
        
    pdf.ln(card_h + 6)
    pdf.set_text_color(50, 50, 50)
        
        
# Render the alerts table.
def _alerts_table(pdf: FPDF, alerts: list[Alert], reputation: dict):
    col_ip = 32
    col_type = 36
    col_sev = 22
    col_count = 14
    col_score = 22
    col_country = 14
    col_detail = 0

    # Header
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(26, 26, 46)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(col_ip, 8, "IP Address", fill=True, border=0)
    pdf.cell(col_type, 8, "Attack Type", fill=True, border=0)
    pdf.cell(col_sev, 8, "Severity", fill=True, border=0)
    pdf.cell(col_count, 8, "Count", fill=True, border=0)
    pdf.cell(col_score, 8, "AbuseScore", fill=True, border=0)
    pdf.cell(col_country, 8, "Country", fill=True, border=0)
    pdf.cell(col_detail, 8, "Confirmed", fill=True, border=0, ln=True)
    pdf.ln(1)

    for i, alert in enumerate(alerts):
        rep = reputation.get(alert.ip)
        color = SEVERITY_COLORS.get(alert.severity.lower(), (150, 150, 150))

        # Alternating background
        bg = (245, 245, 245) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)

        # Row 1 — technical data
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_ip, 8, alert.ip, fill=True, border=0)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(col_type, 8, alert.attack_type, fill=True, border=0)
        pdf.set_text_color(*color)
        pdf.cell(col_sev,   8, alert.severity.upper(), fill=True, border=0)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_count, 8, str(alert.count), fill=True, border=0)
        pdf.cell(col_score, 8, f"{rep.score}/100" if rep else "N/A", fill=True, border=0)
        pdf.cell(col_country, 8, rep.country if rep and rep.country else "N/A", fill=True, border=0)
        confirmed = "YES" if rep and rep.confirmed else "NO"
        pdf.set_text_color(0, 150, 80) if confirmed == "YES" else pdf.set_text_color(150, 150, 150)
        pdf.cell(col_detail, 8, confirmed, fill=True, border=0, ln=True)

        # Row 2 — full detail
        pdf.set_fill_color(*bg)
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(10, 7, "", fill=True, border=0)
        pdf.cell(col_detail,  7, f"Detail: {alert.detail}", fill=True, border=0, ln=True)

        pdf.ln(1)

    pdf.ln(2)