from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def create_report(title: str, details: str) -> bytes:
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    pdf.setTitle(title)
    y = height - 60
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, title)
    y -= 30
    pdf.setFont("Helvetica", 9)
    for raw_line in details.splitlines() or [details]:
        line = raw_line[:115]
        pdf.drawString(50, y, line)
        y -= 14
        if y < 55:
            pdf.showPage(); y = height - 55; pdf.setFont("Helvetica", 9)
    pdf.save()
    return output.getvalue()
