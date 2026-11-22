"""Generate deterministic original and rearranged PDF fixtures.

Scenario script (1-based page numbers), used by both the fixtures and the
documentation so every audit finding can be traced back to a known page:

Original ``paper_original.pdf`` pages O1..O8:
  O1 case caption (Helvetica, image I1)
  O2 statement A   (Helvetica, image I2)
  O3 statement B   (Courier,   image I3)
  O4 contract clause (Times,   image I4)
  O5 signature page (Helvetica, image I5)
  O6 exhibit inventory (Courier, image I6)
  O7 duplicate notice (Helvetica, image I7)
  O8 closing note (Times, image I8)

Rearranged ``digital_rearranged.pdf`` pages R1..R8:
  R1 <- O4            (moved, order change)
  R2 <- O1            (moved, order change)
  R3 <- O2 + O3       (two sources folded into one page)
  R4 <- O5 top half   (one source split into two pages)
  R5 <- O5 bottom half
  R6 <- O6 + O8       (two sources folded into one page)
  R7 <- O7 copy A     (identical content also placed at R8)
  R8 <- O7 copy B     (same-content position conflict with R7)
O7 is therefore present twice (same-content position conflict).
  O9 standalone addendum (Helvetica, image I9): dropped entirely, so it has
     no target page and no surviving content anywhere -> true missing page.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from pypdf import PdfReader, PdfWriter

from .pdf_tools import (
    PAGE_HEIGHT,
    build_page,
    fold_source_page,
    set_crop_box,
    writer_bytes,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
ORIGINAL_NAME = "paper_original.pdf"
REARRANGED_NAME = "digital_rearranged.pdf"


def _image_payload(seed):
    base = bytes((seed * 7 + offset) % 256 for offset in range(12))
    return base


def build_original():
    writer = PdfWriter()
    spec = [
        ("O1", ["Case Caption", "Smith vs Lee", "Folio O1"], "Helvetica", 1),
        ("O2", ["Statement A", "Witness Park", "Folio O2"], "Helvetica", 2),
        ("O3", ["Statement B", "Witness Chen", "Folio O3"], "Courier", 3),
        ("O4", ["Contract Clause", "Section 4.2", "Folio O4"], "Times-Roman", 4),
        ("O5", ["Signature Page", "Signed 2026-11-20", "Folio O5"], "Helvetica", 5),
        ("O6", ["Exhibit Inventory", "Items 1-9", "Folio O6"], "Courier", 6),
        ("O7", ["Duplicate Notice", "Please File Twice", "Folio O7"], "Helvetica", 7),
        ("O8", ["Closing Note", "End Of Bundle", "Folio O8"], "Times-Roman", 8),
        ("O9", ["Standalone Addendum", "Appendix Reference", "Folio O9"], "Helvetica", 9),
    ]
    for label, lines, font, seed in spec:
        build_page(
            writer,
            lines,
            base_font=font,
            image_payload=_image_payload(seed),
        )
    return writer


def build_rearranged(original_reader, original_bytes):
    writer = PdfWriter()

    def clone_single(source_index):
        # A one-element list selects a single page; a tuple would be parsed
        # as an inclusive (start, stop) page range.
        writer.append(
            BytesIO(original_bytes), pages=[source_index]
        )

    clone_single(3)  # R1 <- O4
    clone_single(0)  # R2 <- O1

    # R3 <- O2 + O3 (two sources folded into one page)
    clone_single(1)
    fold_source_page(
        writer, writer.pages[2], original_reader, 2,
        font_alias="F2", image_alias="Im1",
    )

    # R4/R5 <- O5 split into top and bottom crops (one source, two pages)
    clone_single(4)
    clone_single(4)
    half = PAGE_HEIGHT / 2.0
    set_crop_box(writer.pages[3], 0, half, 320, PAGE_HEIGHT)
    set_crop_box(writer.pages[4], 0, 0, 320, half)

    # R6 <- O6 + O8 (two sources folded into one page)
    clone_single(5)
    fold_source_page(
        writer, writer.pages[5], original_reader, 7,
        font_alias="F2", image_alias="Im1",
    )

    # R7/R8 <- O7 duplicated (same-content position conflict)
    clone_single(6)
    clone_single(6)
    return writer


def generate(out_dir=FIXTURE_DIR):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    original_writer = build_original()
    original_bytes = writer_bytes(original_writer)
    original_reader = PdfReader(BytesIO(original_bytes))
    rearranged_writer = build_rearranged(original_reader, original_bytes)

    original_path = out_dir / ORIGINAL_NAME
    rearranged_path = out_dir / REARRANGED_NAME
    original_path.write_bytes(original_bytes)
    rearranged_path.write_bytes(writer_bytes(rearranged_writer))
    return original_path, rearranged_path


if __name__ == "__main__":
    paths = generate()
    for path in paths:
        print(path)
