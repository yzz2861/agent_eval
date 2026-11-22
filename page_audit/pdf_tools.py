"""PDF construction helpers for deterministic test fixtures.

Only the generator package imports this module. The read-only auditor never
writes or mutates a PDF.
"""

from __future__ import annotations

import re
from io import BytesIO

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
)

PAGE_WIDTH = 320.0
PAGE_HEIGHT = 440.0
BACKSLASH = chr(92)


def writer_bytes(writer):
    buf = BytesIO()
    writer.write(buf)
    return buf.getvalue()


def make_font(base_font="Helvetica"):
    font = DictionaryObject()
    font.update(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/" + base_font),
        }
    )
    return font


def make_image(width, height, payload):
    image = DecodedStreamObject()
    image.set_data(payload)
    image.update(
        {
            NameObject("/Type"): NameObject("/XObject"),
            NameObject("/Subtype"): NameObject("/Image"),
            NameObject("/Width"): NumberObject(width),
            NameObject("/Height"): NumberObject(height),
            NameObject("/ColorSpace"): NameObject("/DeviceRGB"),
            NameObject("/BitsPerComponent"): NumberObject(8),
        }
    )
    return image


def text_stream(lines, font_name="/F1", font_size=16):
    parts = [b"BT", font_name.encode(), str(font_size).encode(), b"Tf"]
    y = PAGE_HEIGHT - 40
    for index, line in enumerate(lines):
        if index:
            parts.append(b"0 -22 Td")
        else:
            parts.extend([b"24", str(int(y)).encode(), b"Td"])
        safe = (
            str(line)
            .replace(BACKSLASH, BACKSLASH + BACKSLASH)
            .replace("(", BACKSLASH + "(")
            .replace(")", BACKSLASH + ")")
        )
        parts.extend([b"(" + safe.encode("latin-1") + b")", b"Tj"])
    parts.append(b"ET")
    return b" ".join(parts)


def image_draw_stream(image_name, x, y, size):
    return (
        b"q "
        + str(size).encode() + b" 0 0 " + str(size).encode()
        + b" " + str(int(x)).encode() + b" " + str(int(y)).encode()
        + b" cm " + image_name.encode() + b" Do Q"
    )


def build_page(writer, lines, font_name="F1", base_font="Helvetica",
               image_payload=None, image_name="Im0",
               width=PAGE_WIDTH, height=PAGE_HEIGHT):
    page = writer.add_blank_page(width=width, height=height)
    font_ref = writer._add_object(make_font(base_font))
    resources = DictionaryObject(
        {NameObject("/Font"): DictionaryObject(
            {NameObject("/" + font_name): font_ref}
        )}
    )
    stream = text_stream(lines, "/" + font_name)
    image_ref = None
    if image_payload is not None:
        image_ref = writer._add_object(make_image(2, 2, image_payload))
        resources[NameObject("/XObject")] = DictionaryObject(
            {NameObject("/" + image_name): image_ref}
        )
        stream += bytes([10]) + image_draw_stream("/" + image_name, 24, 60, 120)
    resources_ref = writer._add_object(resources)
    page[NameObject("/Resources")] = resources_ref
    content = DecodedStreamObject()
    content.set_data(stream)
    content_ref = writer._add_object(content)
    page[NameObject("/Contents")] = content_ref
    return {
        "page": page,
        "font_ref": font_ref,
        "image_ref": image_ref,
        "content_ref": content_ref,
        "content": stream,
    }


def _rename_resource_refs(stream, mapping):
    word_boundary = bytes([92, 98])
    for old, new in mapping.items():
        pattern = b"/" + re.escape(old.encode()) + word_boundary
        stream = re.sub(pattern, b"/" + new.encode(), stream)
    return stream


def fold_source_page(target_writer, target_page, source_reader, source_index,
                     font_alias, image_alias):
    source = source_reader.pages[source_index]
    resources = target_page["/Resources"]
    fonts = resources["/Font"]
    source_fonts = source["/Resources"]["/Font"]
    rename = {}
    for original_name, ref in source_fonts.items():
        cloned = target_writer._add_object(ref.get_object())
        fonts[NameObject("/" + font_alias)] = cloned
        rename[original_name.lstrip("/")] = font_alias
    stream = source.get_contents().get_data()
    source_xobjects = source["/Resources"].get("/XObject")
    if source_xobjects and image_alias:
        xobjects = resources.get("/XObject")
        if xobjects is None:
            xobjects = DictionaryObject()
            resources[NameObject("/XObject")] = xobjects
        for original_name, ref in source_xobjects.items():
            cloned = target_writer._add_object(ref.get_object())
            xobjects[NameObject("/" + image_alias)] = cloned
            rename[original_name.lstrip("/")] = image_alias
    stream = _rename_resource_refs(stream, rename)
    existing = target_page.get_contents().get_data()
    merged = DecodedStreamObject()
    merged.set_data(existing + bytes([10]) + stream)
    target_page[NameObject("/Contents")] = target_writer._add_object(merged)


def set_crop_box(page, left, bottom, right, top):
    page[NameObject("/CropBox")] = RectangleObject(
        [float(left), float(bottom), float(right), float(top)]
    )
