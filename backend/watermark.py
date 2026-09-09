"""
TraceX — Server-side session watermarking.

Burns one attribution stamp into preview bytes. The file on disk is never modified.
Stamp text is taken only from the authenticated user, document row, access verdict,
and bearer session — nothing is invented for display.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from reportlab.lib.colors import Color
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from PIL import Image, ImageDraw, ImageFont


TIMESTAMP_FMT = "%Y-%m-%d"


def _date_only(value: str) -> str:
    """Keep YYYY-MM-DD; drop any clock time if present."""
    text = (value or "").strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10]
    return text


def build_stamp_lines(
    user: Any,
    doc: Any,
    verdict: Optional[Dict[str, Any]] = None,
    viewed_at: Optional[datetime] = None,
    session_token: Optional[str] = None,
) -> list[str]:
    """One line per live field. Skip empties — never invent placeholder copy."""
    when = _date_only((viewed_at or datetime.now()).strftime(TIMESTAMP_FMT))
    lines: list[str] = []

    name = (getattr(user, "name", None) or "").strip()
    role = (getattr(user, "role", None) or "").strip()
    if name and role:
        lines.append(f"{name} ({role})")
    elif name:
        lines.append(name)

    badge = (getattr(user, "badge_number", None) or "").strip()
    user_id = (getattr(user, "user_id", None) or "").strip()
    department = (getattr(user, "department", None) or "").strip()
    identity = " · ".join(part for part in (badge, user_id, department) if part)
    if identity:
        lines.append(identity)

    case_id = (getattr(doc, "case_id", None) or "").strip()
    document_id = (getattr(doc, "document_id", None) or "").strip()
    classification = (getattr(doc, "classification", None) or "").strip()
    case_line = " / ".join(part for part in (case_id, document_id) if part)
    if classification:
        case_line = f"{case_line} · {classification}" if case_line else classification
    if case_line:
        lines.append(case_line)

    if verdict:
        clearance_parts = []
        if verdict.get("reason"):
            clearance_parts.append(str(verdict["reason"]).strip())
        if verdict.get("request_id"):
            clearance_parts.append(str(verdict["request_id"]).strip())
        if verdict.get("expires_at"):
            clearance_parts.append(_date_only(str(verdict["expires_at"])))
        if clearance_parts:
            lines.append(" · ".join(clearance_parts))

    session_bits = [when]
    if session_token:
        # Full token stays server-side; stamp carries a suffix for attribution.
        session_bits.insert(0, f"session …{session_token[-12:]}")
    lines.append(" · ".join(session_bits))

    return lines


def _draw_stamp_block(c: canvas.Canvas, lines: list[str], x: float, y: float, font_size: float) -> None:
    c.setFont("Helvetica-Bold", font_size)
    line_gap = font_size * 1.35
    top = y + (len(lines) - 1) * line_gap / 2
    for i, line in enumerate(lines):
        c.drawCentredString(x, top - i * line_gap, line)


def _pdf_overlay(width: float, height: float, lines: list[str]) -> PdfReader:
    """Single centred red stamp — no tiling."""
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=(width, height))
    font_size = max(18.0, min(28.0, width / 24.0))

    c.saveState()
    c.translate(width / 2, height / 2)
    c.rotate(28)
    c.setFillColor(Color(0.82, 0.05, 0.05, alpha=0.22))
    _draw_stamp_block(c, lines, 0, 0, font_size)
    c.restoreState()
    c.save()
    packet.seek(0)
    return PdfReader(packet)


def stamp_pdf_bytes(source: bytes, lines: list[str]) -> bytes:
    """Merge one watermark onto every page. Original bytes are not mutated."""
    try:
        reader = PdfReader(io.BytesIO(source))
        if not reader.pages:
            raise ValueError("PDF has no pages")
    except Exception:
        return stamp_text_as_pdf(
            "Source file could not be parsed as a PDF.\n"
            "Session watermark still identifies the viewing officer.",
            lines,
        )

    writer = PdfWriter()
    for page in reader.pages:
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)
        overlay = _pdf_overlay(width, height, lines)
        page.merge_page(overlay.pages[0])
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def stamp_image_bytes(source: bytes, lines: list[str], extension: str) -> Tuple[bytes, str]:
    """Draw one centred stamp into image pixels."""
    image = Image.open(io.BytesIO(source)).convert("RGBA")
    width, height = image.size

    font_size = max(22, min(40, width // 20))
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", font_size)
    except OSError:
        font = ImageFont.load_default()

    line_gap = int(font_size * 1.4)
    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    max_w = max(int(probe.textlength(line, font=font)) for line in lines) if lines else 200
    tile_w = max_w + 40
    tile_h = line_gap * max(len(lines), 1) + 24

    tile = Image.new("RGBA", (tile_w, tile_h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(tile)
    y = 8
    for line in lines:
        tw = int(draw.textlength(line, font=font))
        draw.text(((tile_w - tw) // 2, y), line, fill=(210, 15, 15, 72), font=font)
        y += line_gap

    stamp = tile.rotate(28, expand=True, fillcolor=(0, 0, 0, 0))
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    cx = (width - stamp.size[0]) // 2
    cy = (height - stamp.size[1]) // 2
    overlay.paste(stamp, (cx, cy), stamp)

    stamped = Image.alpha_composite(image, overlay).convert("RGB")
    buf = io.BytesIO()
    ext = extension.lower().lstrip(".")
    if ext in ("jpg", "jpeg"):
        stamped.save(buf, format="JPEG", quality=90)
        return buf.getvalue(), "image/jpeg"
    stamped.save(buf, format="PNG")
    return buf.getvalue(), "image/png"


def stamp_text_as_pdf(source_text: str, lines: list[str]) -> bytes:
    """Render plain text as a PDF, then apply the same single stamp."""
    packet = io.BytesIO()
    c = canvas.Canvas(packet)
    width, height = 595, 842
    c.setPageSize((width, height))

    c.setFillColor(Color(0.08, 0.16, 0.24, alpha=1))
    c.setFont("Helvetica", 10)
    y = height - 56
    for raw in (source_text or "").splitlines() or ["(empty document)"]:
        for chunk in _wrap(raw, 95):
            if y < 48:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 56
            c.drawString(40, y, chunk)
            y -= 14

    c.save()
    return stamp_pdf_bytes(packet.getvalue(), lines)


def _wrap(line: str, width: int) -> list[str]:
    if len(line) <= width:
        return [line]
    parts = []
    while line:
        parts.append(line[:width])
        line = line[width:]
    return parts


def stamp_file_for_preview(
    physical_path: str,
    extension: str,
    user: Any,
    doc: Any,
    verdict: Optional[Dict[str, Any]] = None,
    session_token: Optional[str] = None,
) -> Tuple[bytes, str, str]:
    """
    Return (payload_bytes, media_type, download_name) for one preview response.
    Regenerates the stamp from this request's session. Never writes back to disk.
    """
    lines = build_stamp_lines(user, doc, verdict, session_token=session_token)
    if not lines:
        raise ValueError("Cannot watermark preview: missing officer/document identity.")

    ext = (extension or "").lower()
    base = f"{doc.document_id}_watermarked"

    if ext == ".pdf":
        with open(physical_path, "rb") as handle:
            raw = handle.read()
        return stamp_pdf_bytes(raw, lines), "application/pdf", f"{base}.pdf"

    if ext in (".png", ".jpg", ".jpeg"):
        with open(physical_path, "rb") as handle:
            raw = handle.read()
        payload, media = stamp_image_bytes(raw, lines, ext)
        out_ext = "jpg" if "jpeg" in media else "png"
        return payload, media, f"{base}.{out_ext}"

    if ext in (".txt", ".text", ""):
        with open(physical_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        return stamp_text_as_pdf(text, lines), "application/pdf", f"{base}.pdf"

    raise ValueError(
        f"Preview watermarking is not supported for '{ext}' files. "
        "Convert to PDF or an image before secure viewing."
    )
