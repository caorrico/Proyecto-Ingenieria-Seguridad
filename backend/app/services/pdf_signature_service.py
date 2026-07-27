from io import BytesIO

import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


def add_visible_signature(
    pdf_data: bytes,
    signer_name: str,
    verification_text: str,
    page_number: int,
    x_ratio: float,
    y_ratio: float,
    size_percent: int = 100,
) -> bytes:
    """Stamp a PDF with a QR verification mark and signer name."""
    reader = PdfReader(BytesIO(pdf_data))
    if page_number > len(reader.pages):
        raise ValueError(f"El PDF solo tiene {len(reader.pages)} página(s)")

    target = reader.pages[page_number - 1]
    width = float(target.mediabox.width)
    height = float(target.mediabox.height)
    scale = size_percent / 100
    stamp_width, stamp_height = 170.0 * scale, 66.0 * scale
    x = min(max(x_ratio * width, 0), max(width - stamp_width, 0))
    # Browser coordinates start at the top; PDF coordinates start at the bottom.
    y = min(max((1 - y_ratio) * height - stamp_height, 0), max(height - stamp_height, 0))

    qr_image = qrcode.make(verification_text)
    qr_buffer = BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)

    overlay_buffer = BytesIO()
    overlay = canvas.Canvas(overlay_buffer, pagesize=(width, height))
    overlay.setFillColor(HexColor("#F5FFF9"))
    overlay.setStrokeColor(HexColor("#117B64"))
    overlay.roundRect(x, y, stamp_width, stamp_height, 6 * scale, fill=1, stroke=1)
    overlay.drawImage(ImageReader(qr_buffer), x + 7 * scale, y + 7 * scale, 52 * scale, 52 * scale, mask="auto")
    overlay.setFillColor(HexColor("#123B32"))
    overlay.setFont("Helvetica-Bold", 8 * scale)
    overlay.drawString(x + 66 * scale, y + 46 * scale, "FIRMADO DIGITALMENTE")
    overlay.setFont("Helvetica-Bold", 10 * scale)
    overlay.drawString(x + 66 * scale, y + 29 * scale, signer_name[:28])
    overlay.setFont("Helvetica", 6.5 * scale)
    overlay.setFillColor(HexColor("#527069"))
    overlay.drawString(x + 66 * scale, y + 15 * scale, "QR de verificación · SecureSign")
    overlay.save()
    overlay_buffer.seek(0)

    target.merge_page(PdfReader(overlay_buffer).pages[0])
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()
