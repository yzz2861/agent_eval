from io import BytesIO

from pypdf import PdfReader, PdfWriter
from pypdf.generic import *


def ap(w, text):
    s = DecodedStreamObject()
    s.set_data(("BT /Helv 12 Tf 1 0 0 1 2 10 Tm (" + text + ") Tj ET").encode())
    s[NameObject("/Type")] = NameObject("/XObject")
    s[NameObject("/Subtype")] = NameObject("/Form")
    s[NameObject("/BBox")] = ArrayObject([NumberObject(0), NumberObject(0), NumberObject(180), NumberObject(24)])
    return w._add_object(s)


def widget(w, page, text, x):
    a = ap(w, text)
    d = DictionaryObject()
    d[NameObject("/Type")] = NameObject("/Annot")
    d[NameObject("/Subtype")] = NameObject("/Widget")
    d[NameObject("/Rect")] = ArrayObject([NumberObject(x), NumberObject(100), NumberObject(x + 180), NumberObject(124)])
    d[NameObject("/P")] = page.indirect_reference
    apd = DictionaryObject()
    apd[NameObject("/N")] = a
    d[NameObject("/AP")] = apd
    r = w._add_object(d)
    page[NameObject("/Annots")].append(r)
    return r


def field(w, page, name, value, secret, x=40):
    r = widget(w, page, secret, x)
    d = r.get_object()
    d[NameObject("/FT")] = NameObject("/Tx")
    d[NameObject("/T")] = TextStringObject(name)
    d[NameObject("/V")] = TextStringObject(value)
    d[NameObject("/DV")] = TextStringObject("DV_" + value)
    d[NameObject("/DA")] = TextStringObject("/Helv 12 Tf 0 g")
    return r


w = PdfWriter()
p = w.add_blank_page(width=500, height=300)
p[NameObject("/Annots")] = ArrayObject()
approval = field(w, p, "approval", "SECRET_APPROVAL_XYZ", "AP_SECRET_XYZ")
applicant = field(w, p, "applicant", "APPLICANT_SAMPLE_123", "AP_APPLICANT_456", y if False else 260)
acro = DictionaryObject()
acro[NameObject("/Fields")] = ArrayObject([approval, applicant])
acro[NameObject("/NeedAppearances")] = BooleanObject(False)
w._root_object[NameObject("/AcroForm")] = w._add_object(acro)
buf = BytesIO()
w.write(buf)
print("before", b"SECRET_APPROVAL_XYZ" in buf.getvalue(), b"AP_SECRET_XYZ" in buf.getvalue())

w.publish_form_fields([approval])
out = BytesIO()
w.write(out)
data = out.getvalue()
print("after bytes", b"SECRET_APPROVAL_XYZ" in data, b"AP_SECRET_XYZ" in data, b"APPLICANT_SAMPLE_123" in data)
r = PdfReader(BytesIO(data))
print("fields", r.get_fields())
w2 = PdfWriter(clone_from=r)
w2.update_page_form_field_values(None, {"applicant": "NEW_FILL_789"}, auto_regenerate=False)
out2 = BytesIO(); w2.write(out2)
r2 = PdfReader(BytesIO(out2.getvalue()))
print("filled", r2.get_form_text_fields())
print("raw new", b"NEW_FILL_789" in out2.getvalue())
