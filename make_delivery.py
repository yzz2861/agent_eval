from io import BytesIO

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

SECRETS = [
    "APPROVAL_MANAGER_SECRET_111",
    "APPROVAL_CODE_SECRET_222",
    "SHARED_APPROVAL_AP_7788",
    "MULTI_PAGE_APPROVAL_SECRET_333",
    "MULTI_PAGE_DEFAULT_SECRET_444",
    "MULTI_WIDGET_AP_ONE_555",
    "MULTI_WIDGET_AP_TWO_666",
    "INTERNAL_NOTE_SECRET_1010",
    "HR_NOTE_SECRET_1111",
]

writer = PdfWriter()
page1 = writer.add_blank_page(width=595, height=842)
page2 = writer.add_blank_page(width=595, height=842)
for page in (page1, page2):
    page[NameObject("/Annots")] = ArrayObject()

title_stream = DecodedStreamObject()
title_stream.set_data(
    b"BT /Helv 20 Tf 72 800 Td (Synthetic Contract Form) Tj ET"
)
page1[NameObject("/Contents")] = writer._add_object(title_stream)


def appearance(text):
    stream = DecodedStreamObject()
    command = "BT /Helv 9 Tf 2 7 Td (" + text + ") Tj ET"
    stream.set_data(command.encode("ascii"))
    stream[NameObject("/Type")] = NameObject("/XObject")
    stream[NameObject("/Subtype")] = NameObject("/Form")
    stream[NameObject("/BBox")] = ArrayObject(
        [NumberObject(0), NumberObject(0), NumberObject(220), NumberObject(20)]
    )
    return writer._add_object(stream)


def widget(page, secret, x, y, shared=None):
    appearance_ref = shared or appearance(secret)
    annotation = DictionaryObject()
    annotation[NameObject("/Type")] = NameObject("/Annot")
    annotation[NameObject("/Subtype")] = NameObject("/Widget")
    annotation[NameObject("/Rect")] = ArrayObject(
        [NumberObject(x), NumberObject(y), NumberObject(x + 220), NumberObject(y + 20)]
    )
    annotation[NameObject("/P")] = page.indirect_reference
    appearance_dictionary = DictionaryObject()
    appearance_dictionary[NameObject("/N")] = appearance_ref
    annotation[NameObject("/AP")] = appearance_dictionary
    reference = writer._add_object(annotation)
    page[NameObject("/Annots")].append(reference)
    return reference


# main marker


def field(page, name, value, secret, x, y, shared=None):
    reference = widget(page, secret, x, y, shared)
    obj = reference.get_object()
    obj[NameObject("/FT")] = NameObject("/Tx")
    obj[NameObject("/T")] = TextStringObject(name)
    obj[NameObject("/V")] = TextStringObject(value)
    obj[NameObject("/DV")] = TextStringObject("DV_" + value)
    obj[NameObject("/DA")] = TextStringObject("/Helv 11 Tf 0 g")
    return reference
