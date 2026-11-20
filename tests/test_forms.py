"""Test form-related functionality. Separate file to keep overview."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
    TextStringObject,
)
from tests import get_data_from_url


@pytest.mark.enable_socket
def test_form_button__v_value_should_be_name_object():
    url = "https://github.com/user-attachments/files/18736500/blank-form.pdf"
    name = "issue3115.pdf"
    reader = PdfReader(BytesIO(get_data_from_url(url=url, name=name)))
    writer = PdfWriter(clone_from=reader)
    writer.update_page_form_field_values(
        writer.pages[0],
        {"Other": "/On"},
        auto_regenerate=False,
    )
    stream = BytesIO()
    writer.write(stream)

    # Wrong: `/V (/On)`.
    assert b"\n/V /On\n" in stream.getvalue()



def _button_appearance(writer: PdfWriter) -> DictionaryObject:
    streams = {}
    for state in ("/Yes", "/Off"):
        stream = DecodedStreamObject()
        stream.set_data(b"")
        stream[NameObject("/Type")] = NameObject("/XObject")
        stream[NameObject("/Subtype")] = NameObject("/Form")
        stream[NameObject("/BBox")] = RectangleObject((0, 0, 10, 10))
        streams[NameObject(state)] = writer._add_object(stream)
    return DictionaryObject(
        {
            NameObject("/N"): DictionaryObject(streams),
        }
    )


def _make_widget(
    writer: PdfWriter,
    field_ref,
    page,
    appearance_state: str | None,
    *,
    with_appearance: bool = True,
) -> object:
    widget = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/Rect"): RectangleObject((10, 10, 20, 20)),
            NameObject("/F"): NumberObject(4),
            NameObject("/Parent"): field_ref,
        }
    )
    if page.indirect_reference is not None:
        widget[NameObject("/P")] = page.indirect_reference
    if with_appearance:
        widget[NameObject("/AP")] = _button_appearance(writer)
    if appearance_state is not None:
        widget[NameObject("/AS")] = NameObject(appearance_state)
    return writer._add_object(widget)


def _make_repeated_button_pdf(
    *,
    second_state: str | None = "/Off",
    second_has_appearance: bool = True,
    with_yes_value: bool = True,
) -> PdfReader:
    writer = PdfWriter()
    page0 = writer.add_blank_page(width=100, height=100)
    page1 = writer.add_blank_page(width=100, height=100)

    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("ContractAccepted"),
            NameObject("/FT"): NameObject("/Btn"),
        }
    )
    if with_yes_value:
        field[NameObject("/V")] = NameObject("/Yes")
    field_ref = writer._add_object(field)

    widget0 = _make_widget(writer, field_ref, page0, "/Yes")
    widget1 = _make_widget(
        writer,
        field_ref,
        page1,
        second_state,
        with_appearance=second_has_appearance,
    )
    field[NameObject("/Kids")] = ArrayObject([widget0, widget1])
    page0[NameObject("/Annots")] = ArrayObject([widget0])
    page1[NameObject("/Annots")] = ArrayObject([widget1])

    acro_form = DictionaryObject({NameObject("/Fields"): ArrayObject([field_ref])})
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(acro_form)

    data = BytesIO()
    writer.write(data)
    data.seek(0)
    return PdfReader(data)


def test_field_display_state_repeated_widgets_are_per_page() -> None:
    reader = _make_repeated_button_pdf()

    state = reader.get_field_display_state("ContractAccepted")

    assert state.value == "/Yes"
    assert state.field_type == "/Btn"
    assert state.determined is True
    assert [widget.page_number for widget in state.widgets] == [0, 1]
    assert [widget.state for widget in state.widgets] == ["/Yes", "/Off"]
    assert [widget.is_selected for widget in state.widgets] == [True, False]
    assert all(widget.widget is not None for widget in state.widgets)

    page_zero = reader.get_field_display_state("ContractAccepted", page=0)
    assert page_zero.value == "/Yes"
    assert len(page_zero.widgets) == 1
    assert page_zero.widgets[0].state == "/Yes"

    page_one = reader.get_form_field_display_state("ContractAccepted", page=1)
    assert page_one.value == "/Yes"
    assert len(page_one.widgets) == 1
    assert page_one.widgets[0].state == "/Off"

    all_states = reader.get_form_field_display_states()
    assert list(all_states) == ["ContractAccepted"]
    assert all_states["ContractAccepted"].value == "/Yes"


def test_field_display_state_unknown_keeps_object_reference() -> None:
    reader = _make_repeated_button_pdf(second_state=None)

    state = reader.get_field_display_state("ContractAccepted")

    assert state.value == "/Yes"
    assert state.determined is False
    assert state.widgets[0].determined is True
    assert state.widgets[1].determined is False
    assert state.widgets[1].state is None
    assert "no /AS" in (state.widgets[1].reason or "")
    assert state.widgets[1].object_reference is not None
    assert state.widgets[1].object_reference == state.widgets[1].widget


def test_field_display_state_missing_ap_is_unknown() -> None:
    reader = _make_repeated_button_pdf(second_has_appearance=False)

    state = reader.get_field_display_state("ContractAccepted", page=1)

    assert state.widgets[0].determined is False
    assert state.widgets[0].appearance_present is False
    assert state.widgets[0].object_reference is not None


def test_choice_display_state_retains_selection_once() -> None:
    writer = PdfWriter()
    page0 = writer.add_blank_page(width=100, height=100)
    page1 = writer.add_blank_page(width=100, height=100)

    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("ContractType"),
            NameObject("/FT"): NameObject("/Ch"),
            NameObject("/V"): TextStringObject("b"),
            NameObject("/I"): ArrayObject([NumberObject(1)]),
            NameObject("/Opt"): ArrayObject(
                [
                    ArrayObject([TextStringObject("a"), TextStringObject("Alpha")]),
                    ArrayObject([TextStringObject("b"), TextStringObject("Beta")]),
                    ArrayObject([TextStringObject("c"), TextStringObject("Gamma")]),
                ]
            ),
        }
    )
    field_ref = writer._add_object(field)
    widget0 = _make_widget(writer, field_ref, page0, None, with_appearance=False)
    widget1 = _make_widget(writer, field_ref, page1, None, with_appearance=False)
    field[NameObject("/Kids")] = ArrayObject([widget0, widget1])
    page0[NameObject("/Annots")] = ArrayObject([widget0])
    page1[NameObject("/Annots")] = ArrayObject([widget1])

    acro_form = DictionaryObject(
        {
            NameObject("/Fields"): ArrayObject([field_ref]),
            NameObject("/NeedAppearances"): BooleanObject(True),
        }
    )
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(acro_form)

    data = BytesIO()
    writer.write(data)
    data.seek(0)
    reader = PdfReader(data)

    state = reader.get_field_display_state("ContractType")
    assert state.value == "b"
    assert state.selected_values == ("b",)
    assert state.selected_indices == (1,)
    assert state.needs_appearance_regeneration is True
    assert [widget.state for widget in state.widgets] == ["Beta", "Beta"]
    assert [widget.page_number for widget in state.widgets] == [0, 1]
