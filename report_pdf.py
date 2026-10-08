#!/usr/bin/env python3
"""Build a two-part triage PDF from out/ai_input.md and out/tickets_ai.md."""

from collections import Counter
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
SRC = OUT / "ai_input.md"
TICKETS = OUT / "tickets_ai.md"
DEST = OUT / "triage.pdf"
FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
]


def load_font():
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            pdfmetrics.registerFont(TTFont("Doc", path, subfontIndex=0))
            return "Doc"
    return "Helvetica"


def blocks(path):
    rows = []
    current = {}
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            if current:
                rows.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip()
    if current:
        rows.append(current)
    return [row for row in rows if "cve" in row]


def draw_bars(pdf, rows, font, x, y):
    counts = Counter(row.get("team", "Infrastructure") for row in rows)
    if not counts:
        pdf.setFont(font, 11)
        pdf.drawString(x, y, "No tickets")
        return y - 20
    max_count = max(counts.values())
    pdf.setFont(font, 11)
    pdf.drawString(x, y, "Items by owning team")
    y -= 18
    for team, count in counts.most_common():
        pdf.setFont(font, 10)
        pdf.drawString(x, y, team)
        width = 80 * count / max_count
        pdf.setFillColorRGB(0.2, 0.35, 0.55)
        pdf.rect(x + 90, y - 2, width, 10, fill=1, stroke=0)
        pdf.setFillColorRGB(0, 0, 0)
        pdf.drawString(x + 96 + width, y, str(count))
        y -= 18
    return y


def main():
    font = load_font()
    rows = blocks(SRC)
    OUT.mkdir(exist_ok=True)
    pdf = canvas.Canvas(str(DEST), pagesize=A4)
    width, height = A4
    pdf.setFont(font, 16)
    pdf.drawString(20 * mm, height - 20 * mm, "CVE triage report")
    pdf.setFont(font, 10)
    host = rows[0]["host"] if rows else "-"
    kev = sum(1 for row in rows if row.get("kev") == "true")
    pdf.drawString(20 * mm, height - 30 * mm, f"Host: {host}  /  items {len(rows)}  /  KEV {kev}")
    pdf.drawString(20 * mm, height - 36 * mm, "Banner vs installed version: unverified. Not confirmed.")
    y = draw_bars(pdf, rows, font, 20 * mm, height - 50 * mm)
    y -= 8
    pdf.setFont(font, 11)
    pdf.drawString(20 * mm, y, "KEV P1")
    y -= 14
    pdf.setFont(font, 9)
    for row in rows:
        if row.get("kev") != "true":
            continue
        line = f"{row.get('package')}  {row.get('cve')}  {row.get('team')}  {row.get('priority')}"
        pdf.drawString(20 * mm, y, line[:110])
        y -= 12
    pdf.showPage()
    text = TICKETS.read_text(encoding="utf-8") if TICKETS.exists() else "tickets_ai.md is missing. Run grok_ticket.py, then rebuild."
    pdf.setFont(font, 12)
    pdf.drawString(20 * mm, height - 20 * mm, "Ticket body")
    pdf.setFont(font, 9)
    y = height - 30 * mm
    for line in text.splitlines():
        if y < 20 * mm:
            pdf.showPage()
            pdf.setFont(font, 9)
            y = height - 20 * mm
        pdf.drawString(20 * mm, y, line[:110])
        y -= 12
    pdf.save()
    print(f"wrote {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
