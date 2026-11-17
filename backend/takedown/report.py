from io import BytesIO
from textwrap import wrap

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def _pdf_safe_text(value: str) -> str:
    return value.encode("cp1252", errors="replace").decode("cp1252")


def create_report(title: str, details: str) -> bytes:
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    pdf.setTitle(_pdf_safe_text(title))
    y = height - 60
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, _pdf_safe_text(title))
    y -= 30
    pdf.setFont("Helvetica", 9)
    for raw_line in details.splitlines() or [details]:
        safe_line = _pdf_safe_text(raw_line)
        for line in wrap(safe_line, width=100) or [""]:
            pdf.drawString(50, y, line)
            y -= 14
            if y < 55:
                pdf.showPage()
                y = height - 55
                pdf.setFont("Helvetica", 9)
    pdf.save()
    return output.getvalue()
