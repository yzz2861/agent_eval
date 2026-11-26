from io import BytesIO

from pypdf import PdfReader, PdfWriter, SharedAppearanceError, publish_form
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


def _name(value):
    return NameObject(value)


def _text(value):
    return TextStringObject(value)


def _appearance(writer, secret):
    stream = DecodedStreamObject()
    command = "BT /Helv 12 Tf 1 0 0 1 2 10 Tm (" + secret + ") Tj ET"
    stream.set_data(command.encode("ascii"))
    stream[NameObject("/Type")] = NameObject("/XObject")
    stream[NameObject("/Subtype")] = NameObject("/Form")
    stream[NameObject("/BBox")] = ArrayObject(
        [NumberObject(0), NumberObject(0), NumberObject(180), NumberObject(24)]
    )
    return writer._add_object(stream)


def _widget(writer, page, secret, x=40, shared_appearance=None):
    appearance = shared_appearance or _appearance(writer, secret)
    annotation = DictionaryObject()
    annotation[NameObject("/Type")] = NameObject("/Annot")
    annotation[NameObject("/Subtype")] = NameObject("/Widget")
    annotation[NameObject("/Rect")] = ArrayObject(
        [NumberObject(x), NumberObject(100), NumberObject(x + 180), NumberObject(124)]
    )
    annotation[NameObject("/P")] = page.indirect_reference
    appearance_dictionary = DictionaryObject()
    appearance_dictionary[NameObject("/N")] = appearance
    annotation[NameObject("/AP")] = appearance_dictionary
    reference = writer._add_object(annotation)
    if "/Annots" not in page:
        page[NameObject("/Annots")] = ArrayObject()
    page[NameObject("/Annots")].append(reference)
    return reference


def _merged_field(writer, page, name, value, secret, x=40):
    reference = _widget(writer, page, secret, x=x)
    field = reference.get_object()
    field[NameObject("/FT")] = NameObject("/Tx")
    field[NameObject("/T")] = TextStringObject(name)
    field[NameObject("/V")] = TextStringObject(value)
    field[NameObject("/DV")] = TextStringObject("DV_" + value)
    field[NameObject("/DA")] = TextStringObject("/Helv 12 Tf 0 g")
    return reference


def _acroform(writer, fields, calculation_order=None):
    acroform = DictionaryObject()
    acroform[NameObject("/Fields")] = ArrayObject(fields)
    acroform[NameObject("/DA")] = TextStringObject("/Helv 12 Tf 0 g")
    if calculation_order is not None:
        acroform[NameObject("/CO")] = ArrayObject(calculation_order)
    writer._root_object[NameObject("/AcroForm")] = writer._add_object(acroform)
    return acroform


def _bytes_without_strings(data, value):
    assert value.encode("ascii") not in data
    assert value.encode("utf-16-be") not in data
    assert b"\xfe\xff" + value.encode("utf-16-be") not in data


def test_publish_removes_checked_field_and_keeps_form_fillable():
    writer = PdfWriter()
    page = writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()
    approval = _merged_field(
        writer, page, "approval", "ApprovalSecret9281", "ApprovalAppearance9281"
    )
    applicant = _merged_field(
        writer, page, "applicant", "ApplicantSample123", "ApplicantAppearance456", x=260
    )
    acroform = _acroform(
        writer,
        [approval, applicant],
        calculation_order=[applicant, approval],
    )

    writer.publish_form_fields([approval])
    assert list(acroform["/CO"]) == [applicant.indirect_reference]

    output = BytesIO()
    writer.write(output)
    data = output.getvalue()
    _bytes_without_strings(data, "ApprovalSecret9281")
    _bytes_without_strings(data, "ApprovalAppearance9281")

    reader = PdfReader(BytesIO(data))
    fields = reader.get_fields()
    assert list(fields) == ["applicant"]
    assert reader.get_form_text_fields() == {"applicant": "ApplicantSample123"}

    filler = PdfWriter(clone_from=reader)
    filler.update_page_form_field_values(
        None, {"applicant": "ApplicantFilled789"}, auto_regenerate=False
    )
    filled_output = BytesIO()
    filler.write(filled_output)
    filled_reader = PdfReader(BytesIO(filled_output.getvalue()))
    assert filled_reader.get_form_text_fields() == {
        "applicant": "ApplicantFilled789"
    }
    _bytes_without_strings(filled_output.getvalue(), "ApprovalSecret9281")
    _bytes_without_strings(filled_output.getvalue(), "ApprovalAppearance9281")


def test_field_with_widgets_on_multiple_pages_is_removed_everywhere():
    writer = PdfWriter()
    first_page = writer.add_blank_page(width=500, height=200)
    second_page = writer.add_blank_page(width=500, height=200)
    first_page[NameObject("/Annots")] = ArrayObject()
    second_page[NameObject("/Annots")] = ArrayObject()

    parent = DictionaryObject()
    parent[NameObject("/T")] = TextStringObject("repeated_approval")
    parent[NameObject("/FT")] = NameObject("/Tx")
    parent[NameObject("/V")] = TextStringObject("RepeatedSecretValue")
    parent[NameObject("/DV")] = TextStringObject("RepeatedDefaultValue")
    parent_reference = writer._add_object(parent)

    first_widget = _widget(writer, first_page, "RepeatedAppearanceOne")
    second_widget = _widget(writer, second_page, "RepeatedAppearanceTwo")
    first_widget.get_object()[NameObject("/Parent")] = parent_reference
    second_widget.get_object()[NameObject("/Parent")] = parent_reference
    parent[NameObject("/Kids")] = ArrayObject([first_widget, second_widget])
    _acroform(writer, [parent_reference])

    writer.publish_form_fields([parent_reference])

    assert list(first_page["/Annots"]) == []
    assert list(second_page["/Annots"]) == []
    output = BytesIO()
    writer.write(output)
    data = output.getvalue()
    reader = PdfReader(BytesIO(data))
    assert reader.get_fields() == {}
    _bytes_without_strings(data, "RepeatedSecretValue")
    _bytes_without_strings(data, "RepeatedDefaultValue")
    _bytes_without_strings(data, "RepeatedAppearanceOne")
    _bytes_without_strings(data, "RepeatedAppearanceTwo")


def test_same_short_names_are_distinguished_by_object_identity():
    writer = PdfWriter()
    page = writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()

    sender_city = _merged_field(writer, page, "city", "SenderCityValue", "SenderCityAP", x=20)
    receiver_city = _merged_field(writer, page, "city", "ReceiverCitySecret", "ReceiverCityAP", x=260)
    sender = DictionaryObject()
    sender[NameObject("/T")] = TextStringObject("sender")
    sender_ref = writer._add_object(sender)
    receiver = DictionaryObject()
    receiver[NameObject("/T")] = TextStringObject("receiver")
    receiver_ref = writer._add_object(receiver)
    for child, parent_ref in ((sender_city, sender_ref), (receiver_city, receiver_ref)):
        child.get_object()[NameObject("/Parent")] = parent_ref
    sender[NameObject("/Kids")] = ArrayObject([sender_city])
    receiver[NameObject("/Kids")] = ArrayObject([receiver_city])
    _acroform(writer, [sender_ref, receiver_ref])

    writer.publish_form_fields([receiver_city])
    output = BytesIO()
    writer.write(output)
    reader = PdfReader(BytesIO(output.getvalue()))

    assert reader.get_form_text_fields(full_qualified_name=True) == {
        "sender.city": "SenderCityValue"
    }
    _bytes_without_strings(output.getvalue(), "ReceiverCitySecret")
    _bytes_without_strings(output.getvalue(), "ReceiverCityAP")


def test_removed_ancestor_materializes_inherited_default_value():
    writer = PdfWriter()
    page = writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()

    removed_parent = DictionaryObject()
    removed_parent[NameObject("/T")] = TextStringObject("contract")
    removed_parent[NameObject("/DV")] = TextStringObject("InheritedDefaultKeep")
    removed_parent_ref = writer._add_object(removed_parent)

    approval = _merged_field(writer, page, "approval", "ParentApprovalSecret", "ParentApprovalAP", x=20)
    applicant = _merged_field(writer, page, "applicant", "ApplicantValue", "ApplicantAP", x=260)
    applicant.get_object().pop(NameObject("/DV"), None)
    for child in (approval, applicant):
        child.get_object()[NameObject("/Parent")] = removed_parent_ref
    removed_parent[NameObject("/Kids")] = ArrayObject([approval, applicant])
    _acroform(writer, [removed_parent_ref])

    writer.publish_form_fields([removed_parent_ref, approval])

    applicant_object = applicant.get_object()
    assert applicant_object.get_inherited("/DV") == "InheritedDefaultKeep"
    assert applicant_object[NameObject("/TM")] == "contract.applicant"

    output = BytesIO()
    writer.write(output)
    reader = PdfReader(BytesIO(output.getvalue()))
    fields = reader.get_fields()
    assert fields["contract.applicant"]["/DV"] == "InheritedDefaultKeep"
    assert "contract.approval" not in fields
    _bytes_without_strings(output.getvalue(), "ParentApprovalSecret")
    _bytes_without_strings(output.getvalue(), "ParentApprovalAP")


def test_shared_appearance_with_retained_widget_is_rejected():
    writer = PdfWriter()
    page = writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()
    shared = _appearance(writer, "SharedAppearanceSecret")
    approval = _merged_field(writer, page, "approval", "SharedValueSecret", "unused")
    applicant = _merged_field(writer, page, "applicant", "ApplicantValue", "unused", x=260)
    approval.get_object()["/AP"][NameObject("/N")] = shared
    applicant.get_object()["/AP"][NameObject("/N")] = shared
    acroform = _acroform(writer, [approval, applicant])

    try:
        writer.publish_form_fields([approval])
    except SharedAppearanceError as exc:
        assert "shared" in str(exc).lower()
    else:
        raise AssertionError("shared appearance must be rejected")

    assert list(acroform["/Fields"]) == [approval.indirect_reference, applicant.indirect_reference]


def test_appearance_shared_only_by_removed_fields_can_be_deleted():
    writer = PdfWriter()
    page = writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()
    shared = _appearance(writer, "DeletedSharedAppearance")
    first = _merged_field(writer, page, "approval1", "ApprovalOne", "unused")
    second = _merged_field(writer, page, "approval2", "ApprovalTwo", "unused", x=260)
    first.get_object()["/AP"][NameObject("/N")] = shared
    second.get_object()["/AP"][NameObject("/N")] = shared
    _acroform(writer, [first, second])

    writer.publish_form_fields([first, second])
    output = BytesIO()
    writer.write(output)

    assert PdfReader(BytesIO(output.getvalue())).get_fields() == {}
    _bytes_without_strings(output.getvalue(), "DeletedSharedAppearance")


def test_publish_form_accepts_reader_field_identity():
    source_writer = PdfWriter()
    page = source_writer.add_blank_page(width=500, height=200)
    page[NameObject("/Annots")] = ArrayObject()
    approval = _merged_field(source_writer, page, "approval", "ReaderIdentitySecret", "ReaderIdentityAP")
    applicant = _merged_field(source_writer, page, "applicant", "KeepValue", "KeepAP", x=260)
    _acroform(source_writer, [approval, applicant])
    source = BytesIO()
    source_writer.write(source)
    source.seek(0)

    reader = PdfReader(source)
    checked_approval = reader.trailer["/Root"]["/AcroForm"]["/Fields"][0]
    output = BytesIO()
    publish_form(reader, output, [checked_approval])

    published = PdfReader(BytesIO(output.getvalue()))
    assert list(published.get_fields()) == ["applicant"]
    _bytes_without_strings(output.getvalue(), "ReaderIdentitySecret")
    _bytes_without_strings(output.getvalue(), "ReaderIdentityAP")
