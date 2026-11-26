from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pypdf import PdfWriter
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
)

ROOT = Path(__file__).resolve().parent
FIXTURE_DIR = ROOT / "fixtures"


def font_dictionary() -> DictionaryObject:
    return DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )


def stream_object(data: bytes) -> DecodedStreamObject:
    stream = DecodedStreamObject()
    stream.set_data(data)
    return stream


WATERMARK_STREAM = b"""/Artifact << /Type /Pagination /Subtype /Watermark >> BDC
q
0.82 0.82 0.82 rg
1 0 0 1 72 390 cm
0.94 -0.34 0.34 0.94 0 0 cm
BT
/FWM 46 Tf
1 0 0 1 0 0 Tm
(TEMPLATE WM OBJECT 7F3A) Tj
ET
Q
EMC
"""

PAGE_ONE_CONTENT = b"""q
0.12 0.31 0.58 RG
2 w
72 706 468 42 re S
Q
BT
/FBody 18 Tf
72 724 Td
(Page 1: content invokes /WM) Tj
ET
q
/WM Do
Q
q
0.2 0.55 0.25 rg
72 120 180 10 re f
Q
"""

PAGE_TWO_CONTENT = b"""q
0.58 0.18 0.12 RG
2 w
72 706 468 42 re S
Q
BT
/FBody 18 Tf
72 724 Td
(Page 2: inherited /WM is not invoked) Tj
ET
q
0.2 0.4 0.8 rg
72 120 260 10 re f
Q
"""


def build_two_page_shared_template(path: Path) -> dict[str, object]:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_blank_page(width=612, height=792)

    body_font = writer._add_object(font_dictionary())
    watermark_font = writer._add_object(font_dictionary())
    watermark = stream_object(WATERMARK_STREAM)
    watermark.update(
        {
            NameObject("/Type"): NameObject("/XObject"),
            NameObject("/Subtype"): NameObject("/Form"),
            NameObject("/FormType"): NumberObject(1),
            NameObject("/BBox"): ArrayObject(
                [NumberObject(0), NumberObject(0), NumberObject(612), NumberObject(792)]
            ),
            NameObject("/Resources"): DictionaryObject(
                {
                    NameObject("/Font"): DictionaryObject(
                        {NameObject("/FWM"): watermark_font}
                    )
                }
            ),
        }
    )
    watermark_ref = writer._add_object(watermark)

    template_resources = writer._add_object(
        DictionaryObject(
            {
                NameObject("/ProcSet"): ArrayObject(
                    [NameObject("/PDF"), NameObject("/Text"), NameObject("/ImageC")]
                ),
                NameObject("/Font"): DictionaryObject(
                    {NameObject("/FBody"): body_font}
                ),
                NameObject("/XObject"): DictionaryObject(
                    {NameObject("/WM"): watermark_ref}
                ),
            }
        )
    )

    page_one = writer.pages[0]
    page_two = writer.pages[1]
    content_one = writer._add_object(stream_object(PAGE_ONE_CONTENT))
    content_two = writer._add_object(stream_object(PAGE_TWO_CONTENT))
    page_one[NameObject("/Contents")] = content_one
    page_two[NameObject("/Contents")] = content_two

    for page in (page_one, page_two):
        if NameObject("/Resources") in page:
            del page[NameObject("/Resources")]

    template_pages = writer._add_object(
        DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Pages"),
                NameObject("/Parent"): writer.root_object.raw_get(NameObject("/Pages")),
                NameObject("/Count"): NumberObject(2),
                NameObject("/Kids"): ArrayObject(
                    [page_one.indirect_reference, page_two.indirect_reference]
                ),
                NameObject("/MediaBox"): ArrayObject(
                    [NumberObject(0), NumberObject(0), NumberObject(612), NumberObject(792)]
                ),
                NameObject("/Resources"): template_resources,
            }
        )
    )
    page_one[NameObject("/Parent")] = template_pages
    page_two[NameObject("/Parent")] = template_pages

    root_pages = writer.root_object[NameObject("/Pages")]
    root_pages[NameObject("/Kids")] = ArrayObject([template_pages])
    root_pages[NameObject("/Count")] = NumberObject(2)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        writer.write(output)

    return {
        "pdf": str(path.relative_to(ROOT.parent)),
        "claimed_pages": [1, 2],
        "expected_proven_pages": [1],
        "expected_resource_only_pages": [2],
        "shared_resource_object": template_resources.idnum,
        "template_pages_object": template_pages.idnum,
        "watermark_object": watermark_ref.idnum,
    }


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    sample_path = FIXTURE_DIR / "two_page_shared_template.pdf"
    receipt_path = FIXTURE_DIR / "review_receipt.example.json"
    manifest = build_two_page_shared_template(sample_path)
    receipt = {
        "receipt_id": "WM-REVIEW-EXAMPLE-037",
        "claim": "All specified pages apply the template watermark.",
        "archive": manifest["pdf"],
        "specified_pages": manifest["claimed_pages"],
        "page_claims": [
            {"page": 1, "receipt_status": "watermark_applied"},
            {"page": 2, "receipt_status": "watermark_applied"},
        ],
        "note": "Synthetic control receipt; page 2 intentionally only inherits /WM.",
    }
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(manifest | {"receipt": str(receipt_path)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
