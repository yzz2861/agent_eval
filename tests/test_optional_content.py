"""Tests for optional content (layer) visibility inspection."""

from io import BytesIO
from typing import Any

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf._optional_content import HIDDEN, UNKNOWN, VISIBLE
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


def _add_ocg(writer: PdfWriter, name: str) -> IndirectObject:
    return writer._add_object(
        DictionaryObject(
            {
                NameObject("/Type"): NameObject("/OCG"),
                NameObject("/Name"): TextStringObject(name),
            }
        )
    )


def _add_form(writer: PdfWriter, property_value: Any, *, own_resources: bool = True) -> IndirectObject:
    form = DecodedStreamObject()
    form.set_data(b"/OC /Stamp BDC\nEMC\n")
    form[NameObject("/Type")] = NameObject("/XObject")
    form[NameObject("/Subtype")] = NameObject("/Form")
    form[NameObject("/BBox")] = ArrayObject([NumberObject(0), NumberObject(0), NumberObject(10), NumberObject(10)])
    if own_resources:
        form[NameObject("/Resources")] = writer._add_object(
            DictionaryObject({NameObject("/Properties"): DictionaryObject({NameObject("/Stamp"): property_value})})
        )
    return writer._add_object(form)


def _build_handover_pdf(*, form_own_resources: bool = True) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=100, height=100)

    review = _add_ocg(writer, "Review Stamp")
    logo = _add_ocg(writer, "Logo")
    form = _add_form(writer, logo, own_resources=form_own_resources)

    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Properties"): DictionaryObject({NameObject("/Stamp"): review}),
            NameObject("/XObject"): DictionaryObject({NameObject("/X"): form}),
        }
    )
    content = ContentStream(None, writer)
    content.operations = [
        ([NameObject("/OC"), NameObject("/Stamp")], b"BDC"),
        ([], b"EMC"),
        ([NameObject("/X")], b"Do"),
    ]
    page[NameObject("/Contents")] = writer._add_object(content)

    writer.root_object[NameObject("/OCProperties")] = DictionaryObject(
        {
            NameObject("/OCGs"): ArrayObject([review, logo]),
            NameObject("/D"): DictionaryObject(
                {
                    NameObject("/BaseState"): NameObject("/ON"),
                    NameObject("/OFF"): ArrayObject([review]),
                    NameObject("/Order"): ArrayObject([review, logo]),
                }
            ),
            NameObject("/Configs"): ArrayObject(
                [
                    DictionaryObject(
                        {
                            NameObject("/Name"): TextStringObject("Review ready"),
                            NameObject("/BaseState"): NameObject("/OFF"),
                            NameObject("/ON"): ArrayObject([review]),
                        }
                    )
                ]
            ),
        }
    )

    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_hidden_group_is_reported_and_keeps_original_reference():
    reader = PdfReader(BytesIO(_build_handover_pdf()))

    groups = reader.optional_content_groups
    assert [group.name for group in groups] == ["Review Stamp", "Logo"]
    assert groups[0].reference.idnum == groups[0].dictionary.indirect_reference.idnum

    report = reader.get_optional_content_visibility("Review Stamp")
    assert [item.state for item in report] == [HIDDEN, VISIBLE]
    assert [item.configuration_name for item in report] == ["Default", "Review ready"]
    assert report[0].reference is not None
    assert report[0].reference.idnum == groups[0].reference.idnum
    assert report[0].evidence[0].ocg_reference.idnum == groups[0].reference.idnum


def test_hidden_group_is_absent_from_visible_list_but_still_in_inventory():
    reader = PdfReader(BytesIO(_build_handover_pdf()))

    assert [group.name for group in reader.optional_content_groups] == ["Review Stamp", "Logo"]
    assert [group.name for group in reader.get_visible_optional_content_groups()] == ["Logo"]


def test_property_scope_is_resolved_per_page_and_nested_form():
    reader = PdfReader(BytesIO(_build_handover_pdf()))

    report = reader.get_optional_content_visibility("/Stamp", page=0)
    by_name = {(item.name, item.configuration_name): item.state for item in report}
    assert by_name[("Review Stamp", "Default")] is HIDDEN
    assert by_name[("Review Stamp", "Review ready")] is VISIBLE
    assert by_name[("Logo", "Default")] is VISIBLE
    assert by_name[("Logo", "Review ready")] is HIDDEN

    form_evidence = [evidence for item in report for evidence in item.evidence if evidence.source_kind == "form"]
    assert form_evidence
    assert form_evidence[0].resource is not None
    assert form_evidence[0].resource_reference is not None
    assert form_evidence[0].property_reference is not None


def test_unknown_group_and_unsupported_expression_are_unknown():
    writer = PdfWriter()
    page = writer.add_blank_page(width=100, height=100)
    unknown = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/NotAnOCG"),
            NameObject("/Name"): TextStringObject("Unknown"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Properties"): DictionaryObject({NameObject("/Mystery"): writer._add_object(unknown)})}
    )
    content = ContentStream(None, writer)
    content.operations = [([NameObject("/OC"), NameObject("/Mystery")], b"BDC")]
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.root_object[NameObject("/OCProperties")] = DictionaryObject(
        {
            NameObject("/OCGs"): ArrayObject(),
            NameObject("/D"): DictionaryObject({NameObject("/BaseState"): NameObject("/ON")}),
        }
    )
    output = BytesIO()
    writer.write(output)

    report = PdfReader(BytesIO(output.getvalue())).get_optional_content_visibility("/Mystery")
    assert report
    assert report[0].state is UNKNOWN


@pytest.mark.parametrize(
    "policy",
    [
        DictionaryObject({NameObject("/P"): NameObject("/NotAPolicy")}),
        DictionaryObject({NameObject("/VE"): ArrayObject([TextStringObject("unsupported-expression")])}),
    ],
)
def test_unknown_ocmd_expression_is_not_coerced(policy):
    writer = PdfWriter()
    page = writer.add_blank_page(width=100, height=100)
    review = _add_ocg(writer, "Review Stamp")
    policy[NameObject("/Type")] = NameObject("/OCMD")
    policy[NameObject("/OCGs")] = ArrayObject([review])
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Properties"): DictionaryObject({NameObject("/Stamp"): writer._add_object(policy)})}
    )
    content = ContentStream(None, writer)
    content.operations = [([NameObject("/OC"), NameObject("/Stamp")], b"BDC")]
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.root_object[NameObject("/OCProperties")] = DictionaryObject(
        {
            NameObject("/OCGs"): ArrayObject([review]),
            NameObject("/D"): DictionaryObject({NameObject("/BaseState"): NameObject("/ON")}),
        }
    )
    output = BytesIO()
    writer.write(output)

    report = PdfReader(BytesIO(output.getvalue())).get_optional_content_visibility("/Stamp")
    assert report
    assert report[0].state is UNKNOWN


def test_form_without_resources_inherits_caller_scope():
    reader = PdfReader(BytesIO(_build_handover_pdf(form_own_resources=False)))

    report = reader.get_optional_content_visibility("/Stamp", page=0)
    assert len(report) == 2
    assert report[0].group.name == "Review Stamp"
    assert [item.state for item in report] == [HIDDEN, VISIBLE]
    form_evidence = [item for item in report[0].evidence if item.source_kind == "form"]
    assert form_evidence
    assert form_evidence[0].resource is not None


def _build_expression_pdf(expression: DictionaryObject, groups: dict[str, Any]) -> BytesIO:
    writer = PdfWriter()
    page = writer.add_blank_page(width=100, height=100)
    refs = [_add_ocg(writer, name) for name in ("A", "B")]
    expression[NameObject("/OCGs")] = ArrayObject(refs)
    expression[NameObject("/Type")] = NameObject("/OCMD")
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Properties"): DictionaryObject({NameObject("/Expr"): writer._add_object(expression)})}
    )
    content = ContentStream(None, writer)
    content.operations = [([NameObject("/OC"), NameObject("/Expr")], b"BDC")]
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.root_object[NameObject("/OCProperties")] = DictionaryObject(
        {
            NameObject("/OCGs"): ArrayObject(refs),
            NameObject("/D"): DictionaryObject(
                {
                    NameObject("/BaseState"): NameObject("/ON"),
                    NameObject("/ON"): ArrayObject([refs[0]]),
                    NameObject("/OFF"): ArrayObject([refs[1]]),
                    **groups,
                }
            ),
        }
    )
    output = BytesIO()
    writer.write(output)
    return BytesIO(output.getvalue())


def test_ocmd_policy_states():
    expectations = {
        "/AllOn": HIDDEN,
        "/AnyOn": VISIBLE,
        "/NoneOn": HIDDEN,
        "/AllOff": HIDDEN,
        "/AnyOff": VISIBLE,
    }
    for policy, expected in expectations.items():
        reader = PdfReader(
            _build_expression_pdf(
                DictionaryObject({NameObject("/P"): NameObject(policy)}),
                {},
            )
        )
        assert reader.get_optional_content_state("/Expr") is expected


def test_radio_button_group_turns_multiple_on_members_off():
    reader = PdfReader(
        _build_expression_pdf(
            DictionaryObject({NameObject("/P"): NameObject("/AllOn")}),
            {},
        )
    )
    properties = reader.root_object["/OCProperties"]
    refs = properties["/OCGs"]
    config = properties["/D"]
    del config["/ON"]
    del config["/OFF"]
    config[NameObject("/RBGroups")] = ArrayObject([ArrayObject([refs[0], refs[1]])])

    assert reader.get_optional_content_state("A") is HIDDEN
    assert reader.get_optional_content_state("B") is HIDDEN


def test_usage_application_overrides_base_state():
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    a = _add_ocg(writer, "A")
    a.get_object()[NameObject("/Usage")] = DictionaryObject(
        {NameObject("/View"): DictionaryObject({NameObject("/ViewState"): NameObject("/OFF")})}
    )
    writer.root_object[NameObject("/OCProperties")] = DictionaryObject(
        {
            NameObject("/OCGs"): ArrayObject([a]),
            NameObject("/D"): DictionaryObject(
                {
                    NameObject("/BaseState"): NameObject("/ON"),
                    NameObject("/AS"): ArrayObject(
                        [
                            DictionaryObject(
                                {
                                    NameObject("/Event"): NameObject("/View"),
                                    NameObject("/OCGs"): ArrayObject([a]),
                                }
                            )
                        ]
                    ),
                }
            ),
        }
    )
    output = BytesIO()
    writer.write(output)
    reader = PdfReader(BytesIO(output.getvalue()))
    assert reader.get_optional_content_state("A") is HIDDEN
    assert reader.get_optional_content_state("A", event="print") is VISIBLE
