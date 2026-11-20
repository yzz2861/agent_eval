"""Build deterministic multi-revision PDF fixtures with pypdf.

The fixtures use incremental updates so every change lands in a new revision.
Signature dictionaries carry a fixed-size Contents placeholder and a ByteRange
that is patched to cover everything except that placeholder; cryptographic
validation is intentionally left to the injected verifier.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    PdfObject,
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
    TextStringObject,
)

CONTENTS_HEX_LENGTH = 256
PLACEHOLDER_HEX = b"0" * CONTENTS_HEX_LENGTH



class _FixedWidthArray(PdfObject):
    # Renders a constant-width array of four numbers so ByteRange can be
    # patched in place without changing the file length.

    def __init__(self, width: int = 10) -> None:
        self.width = width
        self.rendered = '[' + ' '.join('0' * width for _ in range(4)) + ']'

    def write_to_stream(self, stream) -> None:
        stream.write(self.rendered.encode('ascii'))


def _content_stream(text: str, extra: str = '') -> DecodedStreamObject:
    stream = DecodedStreamObject()
    lines = ['BT', '/F1 12 Tf', '1 0 0 1 40 250 Tm', f'({text}) Tj', 'ET']
    if extra:
        lines.append(extra)
    stream.set_data('\n'.join(lines).encode('latin-1'))
    return stream


def _shared_resources(writer: PdfWriter) -> DictionaryObject:
    font = DictionaryObject()
    font[NameObject('/Type')] = NameObject('/Font')
    font[NameObject('/Subtype')] = NameObject('/Type1')
    font[NameObject('/BaseFont')] = NameObject('/Helvetica')
    font_ref = writer._add_object(font)
    resources = DictionaryObject()
    font_dict = DictionaryObject({NameObject('/F1'): font_ref})
    resources[NameObject('/Font')] = font_dict
    return resources


def _text_field(writer, page, acro, name: str, x: int) -> None:
    field = DictionaryObject()
    field[NameObject('/FT')] = NameObject('/Tx')
    field[NameObject('/T')] = TextStringObject(name)
    field[NameObject('/V')] = TextStringObject('')
    field[NameObject('/Subtype')] = NameObject('/Widget')
    field[NameObject('/Rect')] = RectangleObject([x, 220, x + 130, 240])
    field[NameObject('/F')] = NumberObject(4)
    ref = writer._add_object(field)
    field[NameObject('/P')] = page.indirect_reference
    acro[NameObject('/Fields')].append(ref)
    annots = page.get('/Annots')
    if annots is None:
        annots = ArrayObject()
        page[NameObject('/Annots')] = annots
    annots.append(ref)


def build_base_form(path: Path) -> Path:
    writer = PdfWriter()
    page_one = writer.add_blank_page(width=300, height=300)
    page_two = writer.add_blank_page(width=300, height=300)
    resources = _shared_resources(writer)
    res_ref = writer._add_object(resources)
    for page, text in ((page_one, 'Intake form page 1'), (page_two, 'Intake form page 2')):
        page[NameObject('/Resources')] = res_ref
        content = writer._add_object(_content_stream(text))
        page[NameObject('/Contents')] = content
    acro = DictionaryObject()
    acro[NameObject('/Fields')] = ArrayObject()
    acro[NameObject('/DA')] = TextStringObject('/F1 12 Tf 0 g')
    acro_ref = writer._add_object(acro)
    writer._root_object[NameObject('/AcroForm')] = acro_ref
    _text_field(writer, page_one, acro, 'officer_name', 30)
    _text_field(writer, page_one, acro, 'case_id', 160)
    _text_field(writer, page_two, acro, 'review_note', 30)
    with open(path, 'wb') as handle:
        writer.write(handle)
    return path


def _signature_field(writer, page, acro, name: str):
    field = DictionaryObject()
    field[NameObject('/FT')] = NameObject('/Sig')
    field[NameObject('/T')] = TextStringObject(name)
    field[NameObject('/Subtype')] = NameObject('/Widget')
    field[NameObject('/Rect')] = RectangleObject([30, 120, 180, 160])
    field[NameObject('/F')] = NumberObject(4)
    value = DictionaryObject()
    value[NameObject('/Type')] = NameObject('/Sig')
    value[NameObject('/Filter')] = NameObject('/Adobe.PPKLite')
    value[NameObject('/SubFilter')] = NameObject('/adbe.pkcs7.detached')
    value[NameObject('/Name')] = TextStringObject('Legal Officer')
    value[NameObject('/Contents')] = ByteStringObject(bytes.fromhex('00' * (CONTENTS_HEX_LENGTH // 2)))
    value[NameObject('/ByteRange')] = _FixedWidthArray()
    value_ref = writer._add_object(value)
    field[NameObject('/V')] = value_ref
    ref = writer._add_object(field)
    field[NameObject('/P')] = page.indirect_reference
    acro[NameObject('/Fields')].append(ref)
    annots = page.get('/Annots')
    if annots is None:
        annots = ArrayObject()
        page[NameObject('/Annots')] = annots
    annots.append(ref)
    return value


def _patch_byte_range(data: bytes) -> bytes:
    sig_pos = data.index(b'/Type /Sig')
    open_angle = data.index(b'<', sig_pos)
    close_angle = data.index(b'>', open_angle)
    placeholder_width = close_angle - open_angle - 1
    if placeholder_width != CONTENTS_HEX_LENGTH:
        raise ValueError(f'unexpected Contents width {placeholder_width}')
    range_pos = data.index(b'/ByteRange', close_angle)
    open_bracket = data.index(b'[', range_pos)
    close_bracket = data.index(b']', open_bracket)
    head_end = open_angle
    tail_start = close_angle + 1
    numbers = [0, head_end, tail_start, len(data) - tail_start]
    parts = [str(n).rjust(10) for n in numbers]
    rendered = ('[' + ' '.join(parts) + ']').encode('ascii')
    original_width = close_bracket + 1 - open_bracket
    if len(rendered) != original_width:
        raise ValueError(f'ByteRange width mismatch: {len(rendered)} != {original_width}')
    return data[:open_bracket] + rendered + data[close_bracket + 1:]


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _incremental(path: Path, mutate) -> bytes:
    data = _read(path)
    reader = PdfReader(BytesIO(data))
    writer = PdfWriter(reader, incremental=True)
    mutate(writer, reader)
    with open(path, 'wb') as handle:
        writer.write(handle)
    return _read(path)


def add_signature_revision(path: Path) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        acro = writer._root_object['/AcroForm']
        if hasattr(acro, 'get_object'):
            acro = acro.get_object()
        _signature_field(writer, writer.pages[0], acro, 'legal_signature')
    data = _incremental(path, mutate)
    patched = _patch_byte_range(data)
    path.write_bytes(patched)
    return patched


def _field_on_page(reader: PdfReader, name: str, page_index: int) -> bool:
    page = reader.pages[page_index]
    for annotation in page.get('/Annots', []):
        obj = annotation.get_object() if hasattr(annotation, 'get_object') else annotation
        if obj.get('/T') == name:
            return True
    return False


def fill_fields_revision(path: Path, values: dict[str, str]) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        first_page = {k: v for k, v in values.items() if not _field_on_page(reader, k, 1)}
        if first_page:
            writer.update_page_form_field_values(
                writer.pages[0], first_page, auto_regenerate=False)
        second_page = {k: v for k, v in values.items() if _field_on_page(reader, k, 1)}
        if second_page and len(writer.pages) > 1:
            writer.update_page_form_field_values(
                writer.pages[1], second_page, auto_regenerate=False)
    return _incremental(path, mutate)


def change_field_appearance_revision(path: Path, name: str) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        for field_ref in writer._root_object['/AcroForm']['/Fields']:
            field = field_ref.get_object()
            if field.get('/T') != name:
                continue
            appearance = DecodedStreamObject()
            appearance.set_data(b'q /F1 10 Tf BT (stamped) Tj ET Q')
            appearance_ref = writer._add_object(appearance)
            field[NameObject('/AP')] = DictionaryObject(
                {NameObject('/N'): appearance_ref})
    return _incremental(path, mutate)


def change_page_content_revision(path: Path, page_index: int = 0) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        page = writer.pages[page_index]
        stream = DecodedStreamObject()
        stream.set_data(b'BT /F1 14 Tf 1 0 0 1 40 100 Tm (UNAUTHORIZED EDIT) Tj ET')
        page[NameObject('/Contents')] = writer._add_object(stream)
    return _incremental(path, mutate)


def add_page_revision(path: Path) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        page = writer.add_blank_page(width=300, height=300)
        stream = DecodedStreamObject()
        stream.set_data(b'BT /F1 12 Tf 1 0 0 1 40 250 Tm (Inserted page) Tj ET')
        page[NameObject('/Contents')] = writer._add_object(stream)
    return _incremental(path, mutate)


def change_shared_resource_revision(path: Path) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        font = DictionaryObject()
        font[NameObject('/Type')] = NameObject('/Font')
        font[NameObject('/Subtype')] = NameObject('/Type1')
        font[NameObject('/BaseFont')] = NameObject('/Courier')
        font_ref = writer._add_object(font)
        page = writer.pages[0]
        resources = page['/Resources'].get_object()
        resources[NameObject('/Font')][NameObject('/F2')] = font_ref
    return _incremental(path, mutate)


def change_inherited_rotation_revision(path: Path, rotation: int = 90) -> bytes:
    def mutate(writer: PdfWriter, reader: PdfReader) -> None:
        for page in writer.pages:
            page[NameObject('/Rotate')] = NumberObject(rotation)
    return _incremental(path, mutate)


def append_truncated_tail(path: Path) -> bytes:
    data = _read(path)
    tail = b'\n999 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\nxref\n999 1\n'
    path.write_bytes(data + tail)
    return data + tail


def build_clear_form(path: Path) -> Path:
    build_base_form(path)
    add_signature_revision(path)
    fill_fields_revision(path, {'officer_name': 'Zhang Wei', 'case_id': 'LF-2026-019'})
    return path


def build_manual_form(path: Path) -> Path:
    build_base_form(path)
    add_signature_revision(path)
    fill_fields_revision(path, {'officer_name': 'Li Na'})
    change_field_appearance_revision(path, 'case_id')
    change_page_content_revision(path, page_index=1)
    change_shared_resource_revision(path)
    change_inherited_rotation_revision(path, 90)
    return path


def build_truncated_form(path: Path) -> Path:
    build_manual_form(path)
    append_truncated_tail(path)
    return path


def build_all(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    return {
        'clear': build_clear_form(directory / 'clear_form.pdf'),
        'manual': build_manual_form(directory / 'manual_form.pdf'),
        'truncated': build_truncated_form(directory / 'truncated_form.pdf'),
    }
