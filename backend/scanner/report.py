from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, green, black
import datetime


def generate_pdf_report(result: dict, output_path: str):
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    y = height - 50

    # ===== TITLE =====
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width / 2, y, "ShieldWatch Malware Scan Report")
    y -= 30

    c.setFont("Helvetica", 10)
    c.drawCentredString(
        width / 2,
        y,
        f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )
    y -= 40

    # ===== FILE DETAILS =====
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "File Details")
    y -= 20

    c.setFont("Helvetica", 12)
    c.drawString(60, y, f"Filename: {result['filename']}")
    y -= 30

    # ===== VERDICT =====
    verdict = result["final_verdict"]["verdict"]
    score = result["final_verdict"]["risk_score"]

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Final Verdict")
    y -= 25

    if verdict.lower() == "malicious":
        c.setFillColor(red)
    else:
        c.setFillColor(green)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(60, y, f"{verdict} (Risk Score: {score})")
    c.setFillColor(black)
    y -= 40

    # ===== REASONS =====
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Detection Reasons")
    y -= 20

    c.setFont("Helvetica", 12)
    for reason in result["final_verdict"]["reasons"]:
        c.drawString(60, y, f"- {reason}")
        y -= 18

    y -= 20

    # ===== ENGINE RESULTS =====
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Engine Results")
    y -= 20

    c.setFont("Helvetica", 12)
    c.drawString(60, y, f"ClamAV Detected: {result['clamav']['detected']}")
    y -= 18
    c.drawString(60, y, f"YARA Matched: {result['yara']['matched']}")
    y -= 18
    c.drawString(60, y, f"Entropy: {result['static']['entropy']}")
    y -= 18

    c.showPage()
    c.save()

