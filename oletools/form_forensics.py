#!/usr/bin/env python
"""
form_forensics.py

Offline, static forensic interface over VBA UserForm streams (MS-OFORMS).

This module only reads the "f" (form/control sites) and "o" (embedded ActiveX
controls) streams already parsed by oletools.oleform. It never executes macros
or forms and never infers that a control is used by a VBA procedure from its
name.

Each control is reported with a stable identity, its persisted default value,
the exact source location the value was read from, and an explicit parse
status. Three distinct situations are kept separate:

- STATUS_NO_DEFAULT:   the control stores no default value at all;
- STATUS_EMPTY_DEFAULT: a value is stored and it is an empty string;
- STATUS_UNREADABLE:    the value exists in the file but cannot be parsed
  or decoded with the information currently available.

Author: oletools project
License: BSD, see LICENSE.txt in the oletools package.
"""

import re
import struct

from . import oleform


# High bit of CountOfBytesWithCompressionFlag / CountOfCharsWithCompressionFlag:
# set means the text is compressed ANSI (project code page), clear means UTF-16LE.
# [MS-OFORMS] 2.4.14.2 and 2.4.14.3
_COMPRESSION_FLAG = 0x80000000
_LENGTH_MASK = 0x7FFFFFFF


# Explicit parse statuses. They are intentionally distinct strings so that a
# report consumer can tell "no value was stored" apart from "an empty value was
# stored" and from "the stored value could not be read".
STATUS_NO_DEFAULT = "no_default"
STATUS_EMPTY_DEFAULT = "empty_default"
STATUS_PRESENT = "present"
STATUS_UNREADABLE = "unreadable"
STATUS_NOT_SUPPORTED = "not_supported"

ENCODING_ANSI = "ansi"
ENCODING_UTF16 = "utf-16le"

DEFAULT_CODEPAGE = 1252

_PARSE_ERRORS = (oleform.OleFormParsingError, struct.error, IndexError)


_CODEPAGE_RE = re.compile(br"^\s*CodePage\s*=\s*(\d+)\s*$", re.MULTILINE)


class ForensicStream(oleform.ExtendedStream):
    """ExtendedStream that remembers byte offsets of every read."""

    def read_count(self):
        """Read a CountOf{Bytes,Chars}WithCompressionFlag.

        :return: (raw_length, is_compressed) with the compression flag split out
        """
        flagged = self.unpack("<L", 4)
        return flagged & _LENGTH_MASK, bool(flagged & _COMPRESSION_FLAG)

    def read_text(self, length, is_compressed, codepage):
        """Read a text blob and decode it without hiding decode failures.

        :return: dict with raw bytes, decoded text (or None), encoding label and
                 a decode_ok flag plus an explanatory note
        """
        offset = self._pos
        raw = self.read(length)
        result = {
    'raw': raw,
            "offset": offset,
            "length": length,
            "compressed": is_compressed,
            "encoding": None,
            "text": None,
            "decode_ok": True,
            "note": None,
        }
        if is_compressed:
            result["encoding"] = "{0}:cp{1}".format(ENCODING_ANSI, codepage)
            try:
                result["text"] = raw.decode("cp{0}".format(codepage))
            except (LookupError, UnicodeDecodeError) as exc:
                result["decode_ok"] = False
                result["note"] = "ANSI decode failed: {0}".format(exc)
        else:
            result["encoding"] = ENCODING_UTF16
            try:
                result["text"] = raw.decode("utf-16-le")
            except UnicodeDecodeError as exc:
                result["decode_ok"] = False
                result["note"] = "UTF-16LE decode failed: {0}".format(exc)
        return result

def _parse_sites(f_stream):
    """Parse the "f" stream, yielding one site dict per OleSiteConcreteControl.

    Unlike oleform.consume_OleSiteConcreteControl, the compression flag of the
    site name is kept so that name and value encodings are handled separately.
    Errors are local: a malformed site ends the form with an error marker
    instead of silently dropping every later control.
    """
    f_stream.check_values("FormControl (versions)", "<BB", 2, (0, 4))
    cbform = f_stream.unpack("<H", 2)
    with f_stream.will_jump_to(cbform):
        propmask = oleform.FormPropMask(f_stream.unpack("<L", 4))
        with f_stream.padded_struct():
            propmask.consume(f_stream, [("fBackColor", 4), ("fForeColor", 4),
                                        ("fNextAvailableID", 4)])
            dont_save_class_table = 0
            if propmask.fBooleanProperties:
                boolean_properties = f_stream.unpack("<L", 4)
                dont_save_class_table = (boolean_properties & (1 << 15)) >> 15
    if propmask.fMouseIcon:
        oleform.consume_GuidAndPicture(f_stream)
    if propmask.fFont:
        oleform.consume_GuidAndFont(f_stream)
    if propmask.fPicture:
        oleform.consume_GuidAndPicture(f_stream)
    if not dont_save_class_table:
        count_site_class_info = f_stream.unpack("<H", 2)
        for _ in range(count_site_class_info):
            oleform.consume_SiteClassInfo(f_stream)
    count_of_sites, count_of_bytes = f_stream.unpacks("<LL", 8)
    with f_stream.will_jump_to(count_of_bytes):
        with f_stream.will_pad():
            remaining = count_of_sites
            while remaining > 0:
                remaining -= oleform.consume_FormObjectDepthTypeCount(f_stream)
        for site_index in range(count_of_sites):
            try:
                site = _parse_one_site(f_stream, site_index)
            except _PARSE_ERRORS as exc:
                yield {"_error": str(exc), "_index": site_index}
                return
            yield site


def _parse_one_site(f_stream, site_index):
    """Parse one OleSiteConcreteControl with full text provenance."""
    f_stream.check_value("OleSiteConcreteControl (version)", "<H", 2, 0)
    cb_site = f_stream.unpack("<H", 2)
    with f_stream.will_jump_to(cb_site):
        propmask = oleform.SitePropMask(f_stream.unpack("<L", 4))
        with f_stream.padded_struct():
            name_meta = tag_meta = None
            site_id = 0
            if propmask.fName:
                name_meta = f_stream.read_count()
            if propmask.fTag:
                tag_meta = f_stream.read_count()
            if propmask.fID:
                site_id = f_stream.unpack("<L", 4)
            object_stream_size = 0
            if propmask.fHelpContextID:
                f_stream.read(4)
            if propmask.fBitFlags:
                f_stream.read(4)
            if propmask.fObjectStreamSize:
                object_stream_size = f_stream.unpack("<L", 4)
            tabindex = clsid_cache_index = 0
            if propmask.fTabIndex:
                tabindex = f_stream.unpack("<H", 2)
            if propmask.fClsidCacheIndex:
                clsid_cache_index = f_stream.unpack("<H", 2)
            if propmask.fGroupID:
                f_stream.read(2)
            tip_meta = None
            if propmask.fControlTipText:
                tip_meta = f_stream.read_count()
            propmask.consume(f_stream, [("fRuntimeLicKey", 4),
                                        ("fControlSource", 4), ("fRowSource", 4)])
        name_info = _read_optional_text(f_stream, name_meta)
        tag_info = _read_optional_text(f_stream, tag_meta)
        if propmask.fPosition:
            f_stream.read(8)
        tip_info = _read_optional_text(f_stream, tip_meta)
        if tip_info is not None and tip_info["length"] == 0:
            tip_info = None
    return {
        "site_index": site_index,
        "id": site_id,
        "tabindex": tabindex,
        "clsid_cache_index": clsid_cache_index,
        "object_stream_size": object_stream_size,
        "name": name_info,
        "tag": tag_info,
        "control_tip_text": tip_info,
    }


def _read_optional_text(stream, meta):
    """Read a SiteDataBlock text field described by (length, compressed).""" 
    if meta is None or meta[0] == 0:
        return None
    length, compressed = meta
    return stream.read_text(length, compressed, DEFAULT_CODEPAGE)

def _parse_morph(o_stream, codepage):
    """Parse a MorphDataControl (text box, combo, list, option, toggle...).""" 
    out = {"value": None, "caption": None, "group_name": None, "error": None}
    try:
        o_stream.check_values("MorphDataControl (versions)", "<BB", 2, (0, 2))
        cb_morph = o_stream.unpack("<H", 2)
        with o_stream.will_jump_to(cb_morph):
            propmask = oleform.MorphDataPropMask(o_stream.unpack("<Q", 8))
            with o_stream.padded_struct():
                propmask.consume(o_stream, [("fVariousPropertyBits", 4), ("fBackColor", 4),
                                            ("fForeColor", 4), ("fMaxLength", 4),
                                            ("fBorderStyle", 1), ("fScrollBars", 1),
                                            ("fDisplayStyle", 1), ("fMousePointer", 1),
                                            ("fPasswordChar", 2), ("fListWidth", 4),
                                            ("fBoundColumn", 2), ("fTextColumn", 2),
                                            ("fColumnCount", 2), ("fListRows", 2),
                                            ("fcColumnInfo", 2), ("fMatchEntry", 1),
                                            ("fListStyle", 1), ("fShowDropButtonWhen", 1),
                                            ("fDropButtonStyle", 1), ("fMultiSelect", 1)])
                value_meta = o_stream.read_count() if propmask.fValue else None
                caption_meta = o_stream.read_count() if propmask.fCaption else None
                propmask.consume(o_stream, [("fPicturePosition", 4), ("fBorderColor", 4),
                                            ("fSpecialEffect", 4), ("fMouseIcon", 2),
                                            ("fPicture", 2), ("fAccelerator", 2)])
                group_meta = o_stream.read_count() if propmask.fGroupName else None
            o_stream.read(8)  # Size in MorphDataExtraDataBlock
            out["value"] = _read_field(o_stream, value_meta, codepage)
            out["caption"] = _read_field(o_stream, caption_meta, codepage)
            out["group_name"] = _read_field(o_stream, group_meta, codepage)
        if propmask.fMouseIcon:
            oleform.consume_GuidAndPicture(o_stream)
        if propmask.fPicture:
            oleform.consume_GuidAndPicture(o_stream)
        oleform.consume_TextProps(o_stream)
    except _PARSE_ERRORS as exc:
        out["error"] = str(exc)
    return out

def _parse_label(o_stream, codepage):
    """Parse a LabelControl; its caption is the displayed default text."""
    out = {"caption": None, "error": None}
    try:
        o_stream.check_values("LabelControl (versions)", "<BB", 2, (0, 2))
        cb_label = o_stream.unpack("<H", 2)
        with o_stream.will_jump_to(cb_label):
            propmask = oleform.LabelPropMask(o_stream.unpack("<L", 4))
            with o_stream.padded_struct():
                propmask.consume(o_stream, [("fForeColor", 4), ("fBackColor", 4),
                                            ("fVariousPropertyBits", 4)])
                caption_meta = o_stream.read_count() if propmask.fCaption else None
                propmask.consume(o_stream, [("fPicturePosition", 4), ("fMousePointer", 1),
                                            ("fBorderColor", 4), ("fBorderStyle", 2),
                                            ("fSpecialEffect", 2), ("fPicture", 2),
                                            ("fAccelerator", 2), ("fMouseIcon", 2)])
            out["caption"] = _read_field(o_stream, caption_meta, codepage)
            o_stream.read(8)  # Size in LabelExtraDataBlock
        if propmask.fPicture:
            oleform.consume_GuidAndPicture(o_stream)
        if propmask.fMouseIcon:
            oleform.consume_GuidAndPicture(o_stream)
        oleform.consume_TextProps(o_stream)
    except _PARSE_ERRORS as exc:
        out["error"] = str(exc)
    return out


def _read_field(stream, meta, codepage):
    """Read a Morph/Label text field, recording absence explicitly.

    meta is None when the property mask says the field is not persisted; an
    explicit zero length means an empty string was stored on purpose, which is
    a different situation from the field being absent.
    """
    if meta is None:
        return {"stored": False}
    length, compressed = meta
    info = stream.read_text(length, compressed, codepage)
    info["stored"] = True
    return info

class ControlDefaultValue(object):
    """Forensic record for one control default value.

    Identity is the tuple (project, container, form_path, site_index, site_id):
    it stays unique even when two controls share the same name. The value is
    never guessed from the control name or from VBA procedure references.
    """

    def __init__(self, project, container, form_path, site, status, value,
                 value_source, parse_note=None, name=None, name_status=None,
                 name_source=None, control_type=None, caption=None,
                 caption_status=None, caption_source=None):
        self.project = project
        self.container = container
        self.form_path = form_path
        self.site_index = site["site_index"]
        self.site_id = site["id"]
        self.tabindex = site["tabindex"]
        self.control_type = control_type
        self.name = name
        self.name_status = name_status
        self.name_source = name_source
        self.status = status
        self.value = value
        self.value_source = value_source
        self.parse_note = parse_note
        self.caption = caption
        self.caption_status = caption_status
        self.caption_source = caption_source

    @property
    def record_id(self):
        """Stable, enumeration-order independent identifier."""
        return "{0}|{1}|{2}|site{3:04d}-id{4:04d}".format(
            self.project, self.container, self.form_path,
            self.site_index, self.site_id)

    def as_dict(self):
        """JSON-serialisable view; raw bytes are rendered as hexadecimal."""
        return {
            "record_id": self.record_id,
            "project": self.project,
            "container": self.container,
            "form_path": self.form_path,
            "site_index": self.site_index,
            "site_id": self.site_id,
            "tabindex": self.tabindex,
            "control_type": self.control_type,
            "name": self.name,
            "name_status": self.name_status,
            "name_source": _source_to_dict(self.name_source),
            "status": self.status,
            "value": self.value,
            "value_source": _source_to_dict(self.value_source),
            "parse_note": self.parse_note,
            "caption": self.caption,
            "caption_status": self.caption_status,
            "caption_source": _source_to_dict(self.caption_source),
        }


def _source_to_dict(source):
    if source is None:
        return None
    result = dict(source)
    raw = result.get("raw")
    if isinstance(raw, bytes):
        result["raw_hex"] = raw.hex()
        del result["raw"]
    return result

# ClsidCacheIndex values handled by oleform (MS-OFORMS 2.4.5 table).
_CLSID_FORM_LIKE = (7, 14, 57)
_CLSID_MORPH = (15, 23, 24, 25, 26, 27, 28)
_CLSID_IMAGE = (12,)
_CLSID_SPIN = (16,)
_CLSID_BUTTON = (17,)
_CLSID_TABSTRIP = (18,)
_CLSID_LABEL = (21,)
_CLSID_SCROLLBAR = (47,)

_CONTROL_TYPES = {
    7: "FormControl", 12: "Image", 14: "Frame", 15: "MorphData",
    16: "SpinButton", 17: "CommandButton", 18: "TabStrip", 21: "Label",
    23: "TextBox", 24: "ListBox", 25: "ComboBox", 26: "CheckBox",
    27: "OptionButton", 28: "ToggleButton", 47: "ScrollBar", 57: "MultiPage",
}


def resolve_codepage(ole_file):
    """Read CodePage from the PROJECT stream without executing anything.

    The PROJECT stream lives at the root of a VBA project. When it is absent
    or has no CodePage entry, cp1252 is used as a documented fallback and the
    fallback is reported through the second return value.
    """
    project_path = None
    for entry in ole_file.listdir(streams=True, storages=False):
        if entry and entry[-1] == "PROJECT":
            project_path = entry
            break
    if project_path is None:
        return DEFAULT_CODEPAGE, "default (no PROJECT stream)"
    try:
        data = ole_file.openstream(project_path).read()
    except Exception as exc:  # pragma: no cover - defensive
        return DEFAULT_CODEPAGE, "default (PROJECT unreadable: {0})".format(exc)
    match = _CODEPAGE_RE.search(data)
    if match is None:
        return DEFAULT_CODEPAGE, "default (no CodePage entry)"
    try:
        codepage = int(match.group(1))
    except ValueError:
        return DEFAULT_CODEPAGE, "default (invalid CodePage entry)"
    return codepage, "PROJECT CodePage"


def find_form_storages(ole_file):
    """Return sorted storage path tuples that contain a form "f" stream.

    Sorting makes the output independent of the storage enumeration order,
    including reversed synthetic stream order.
    """
    storages = set()
    for entry in ole_file.listdir(streams=True, storages=False):
        if entry and entry[-1] == "f" and len(entry) >= 2:
            storages.add(tuple(entry[:-1]))
    return sorted(storages, key=lambda path: tuple(part.lower() for part in path))

def _field_status(field):
    """Map a parsed text field to one of the explicit statuses."""
    if field is None or not field.get("stored", False):
        return STATUS_NO_DEFAULT, None
    if not field.get("decode_ok", True):
        return STATUS_UNREADABLE, field.get("note")
    if field.get("length", 0) == 0:
        return STATUS_EMPTY_DEFAULT, None
    return STATUS_PRESENT, None



def extract_from_ole(ole_file, project, container):
    """Yield ControlDefaultValue records for every control of one OLE file.

    Static read-only: only listdir/openstream are used, nothing is executed.
    """
    codepage, codepage_source = resolve_codepage(ole_file)
    for form_storage in find_form_storages(ole_file):
        form_path = "/".join(form_storage)
        f_path = form_storage + ("f",)
        o_path = form_storage + ("o",)
        try:
            f_stream = ForensicStream.open(ole_file, "/".join(f_path))
            sites = list(_parse_sites(f_stream))
        except _PARSE_ERRORS as exc:
            yield _unreadable_form_record(project, container, form_path,
                                          "f stream parse error: {0}".format(exc))
            continue
        except Exception as exc:
            yield _unreadable_form_record(project, container, form_path,
                                          "f stream unreadable: {0}".format(exc))
            continue
        if not ole_file.exists(o_path):
            for site in sites:
                if "_error" in site:
                    continue
                yield _no_o_record(project, container, form_path, site)
            continue
        for record in _parse_object_stream(ole_file, project, container,
                                           form_path, o_path, sites, codepage):
            yield record


def _unreadable_form_record(project, container, form_path, note):
    fake_site = {"site_index": -1, "id": -1, "tabindex": -1}
    return ControlDefaultValue(
        project=project, container=container, form_path=form_path, site=fake_site,
        status=STATUS_UNREADABLE, value=None,
        value_source={"stream": form_path + "/f"}, parse_note=note,
        control_type="<form>")

def _no_o_record(project, container, form_path, site):
    name, name_status, name_info = _name_view(site, form_path)
    return ControlDefaultValue(
        project=project, container=container, form_path=form_path, site=site,
        status=STATUS_UNREADABLE, value=None,
        value_source={"reason": "missing o stream", "stream": form_path + "/o"},
        parse_note="control data stream is not present in this storage",
        name=name, name_status=name_status, name_source=name_info,
        control_type=_CONTROL_TYPES.get(site["clsid_cache_index"],
                                        "clsid{0}".format(site["clsid_cache_index"])))


def _parse_object_stream(ole_file, project, container, form_path, o_path,
                         sites, codepage):
    """Walk the o stream in lockstep with the sites parsed from the f stream."""
    try:
        o_stream = ForensicStream.open(ole_file, "/".join(o_path))
    except Exception as exc:
        for site in sites:
            if "_error" not in site:
                yield _no_o_record(project, container, form_path, site)
        return
    for site in sites:
        if "_error" in site:
            fake = {"site_index": site["_index"], "id": -1, "tabindex": -1,
                    "clsid_cache_index": None}
            yield ControlDefaultValue(
                project=project, container=container, form_path=form_path,
                site=fake, status=STATUS_UNREADABLE, value=None,
                value_source={"stream": form_path + "/f"},
                parse_note=site["_error"], control_type="<site>")
            continue
        record = _dispatch_site(o_stream, project, container, form_path,
                                site, codepage)
        if record is not None:
            yield record


def _dispatch_site(o_stream, project, container, form_path, site, codepage):
    clsid = site["clsid_cache_index"]
    name, name_status, name_info = _name_view(site, form_path)
    common = dict(project=project, container=container, form_path=form_path,
                  site=site, name=name, name_status=name_status,
                  name_source=name_info,
                  control_type=_CONTROL_TYPES.get(clsid, "clsid{0}".format(clsid)))
    if clsid in _CLSID_MORPH:
        return _record_morph(o_stream, common, codepage)
    if clsid in _CLSID_LABEL:
        return _record_label(o_stream, common, codepage)
    if clsid in _CLSID_FORM_LIKE:
        # Parent control (Frame/MultiPage/form). Its embedded sites live in a
        # child storage and are enumerated separately; the o stream entry here
        # has the size given by fObjectStreamSize (0 means no bytes at all).
        object_size = site.get("object_stream_size", 0)
        if object_size > 0:
            try:
                list(oleform.consume_FormControl(o_stream))
            except _PARSE_ERRORS as exc:
                common["status"] = STATUS_UNREADABLE
                common["value"] = None
                common["value_source"] = {"stream": form_path + "/o"}
                common["parse_note"] = "nested form parse error: {0}".format(exc)
                return ControlDefaultValue(**common)
        common["status"] = STATUS_NOT_SUPPORTED
        common["value"] = None
        common["value_source"] = {
            "stream": form_path + "/o",
            "property": "nested FormControl",
            "present": object_size > 0,
            "object_stream_size": object_size,
            "child_storage": form_path + "/i{0:02d}".format(site["id"]),
        }
        common["parse_note"] = ("parent control; default values are reported via"
                                " the child form storage")
        return ControlDefaultValue(**common)
    return _record_simple(o_stream, common, clsid)

def _record_morph(o_stream, common, codepage):
    parsed = _parse_morph(o_stream, codepage)
    if parsed["error"] is not None:
        common["status"] = STATUS_UNREADABLE
        common["value"] = None
        common["value_source"] = {"stream": common["form_path"] + "/o",
                                  "property": "MorphData Value"}
        common["parse_note"] = parsed["error"]
        return ControlDefaultValue(**common)
    field = parsed["value"]
    status, note = _field_status(field)
    source = _morph_source(common["form_path"], field, "MorphData Value")
    value = field.get("text") if field is not None and field.get("stored") else None
    caption_field = parsed["caption"]
    caption_status, caption_note = _field_status(caption_field)
    caption = (caption_field.get("text")
               if caption_field is not None and caption_field.get("stored") else None)
    if note is None and caption_note is not None:
        note = caption_note
    common.update({
        "status": status, "value": value, "value_source": source,
        "parse_note": note,
        "caption": caption, "caption_status": caption_status,
        "caption_source": _morph_source(common["form_path"], caption_field,
                                        "MorphData Caption"),
    })
    return ControlDefaultValue(**common)


def _morph_source(form_path, field, property_name):
    source = {"stream": form_path + "/o", "property": property_name}
    if field is None or not field.get("stored", False):
        source["present"] = False
        return source
    source.update({
        "present": True,
        "offset": field.get("offset"),
        "length": field.get("length"),
        "compressed": field.get("compressed"),
        "encoding": field.get("encoding"),
        "decode_ok": field.get("decode_ok", True),
    })
    return source


def _record_label(o_stream, common, codepage):
    parsed = _parse_label(o_stream, codepage)
    if parsed["error"] is not None:
        common["status"] = STATUS_UNREADABLE
        common["value"] = None
        common["value_source"] = {"stream": common["form_path"] + "/o",
                                  "property": "Label Caption"}
        common["parse_note"] = parsed["error"]
        return ControlDefaultValue(**common)
    field = parsed["caption"]
    status, note = _field_status(field)
    source = _morph_source(common["form_path"], field, "Label Caption")
    caption = field.get("text") if field is not None and field.get("stored") else None
    # Labels expose their default through the caption property, not Value.
    common.update({
        "status": status, "value": caption,
        "value_source": source, "parse_note": note,
        "caption": caption, "caption_status": status,
        "caption_source": source,
    })
    return ControlDefaultValue(**common)


def _record_simple(o_stream, common, clsid):
    """Consume controls without a textual default and keep stream alignment."""
    try:
        if clsid in _CLSID_IMAGE:
            oleform.consume_ImageControl(o_stream)
        elif clsid in _CLSID_SPIN:
            oleform.consume_SpinButtonControl(o_stream)
        elif clsid in _CLSID_BUTTON:
            oleform.consume_CommandButtonControl(o_stream)
        elif clsid in _CLSID_TABSTRIP:
            oleform.consume_TabStripControl(o_stream)
        elif clsid in _CLSID_SCROLLBAR:
            oleform.consume_ScrollBarControl(o_stream)
        else:
            # Unknown control: skip exactly fObjectStreamSize bytes so the next
            # site stays aligned, and mark the value as unreadable rather than
            # guessing a default from the control name.
            object_size = common["site"].get("object_stream_size", 0)
            if object_size:
                o_stream.read(object_size)
            common["status"] = STATUS_UNREADABLE
            common["value"] = None
            common["value_source"] = {
                "stream": common["form_path"] + "/o",
                "property": "unknown ClsidCacheIndex {0}".format(clsid),
                "object_stream_size": object_size}
            common["parse_note"] = ("control type is not described by the current"
                                    " MS-OFORMS table")
            return ControlDefaultValue(**common)
    except _PARSE_ERRORS as exc:
        common["status"] = STATUS_UNREADABLE
        common["value"] = None
        common["value_source"] = {"stream": common["form_path"] + "/o"}
        common["parse_note"] = "control parse error: {0}".format(exc)
        return ControlDefaultValue(**common)
    common["status"] = STATUS_NO_DEFAULT
    common["value"] = None
    common["value_source"] = {"stream": common["form_path"] + "/o",
                              "property": common["control_type"],
                              "present": False,
                              "reason": "no textual default value property for this control"}
    return ControlDefaultValue(**common)

def _name_view(site, form_path):
    info = site["name"]
    if info is None:
        return None, STATUS_UNREADABLE, {"stream": form_path + "/f",
                                         "reason": "site has no persisted name"}
    source = {"stream": form_path + "/f", "property": "Site Name",
              "present": True, "offset": info.get("offset"),
              "length": info.get("length"), "compressed": info.get("compressed"),
              "encoding": info.get("encoding"),
              "decode_ok": info.get("decode_ok", True)}
    if not info.get("decode_ok", True):
        return None, STATUS_UNREADABLE, source
    return info.get("text"), STATUS_PRESENT, source


def extract_control_defaults(ole_file, project, container):
    """Return ControlDefaultValue records sorted by stable identity.

    Records are sorted here so that reversing the underlying storage
    enumeration (e.g. a synthetic stream listing) cannot change attribution or
    the missing-value markers.
    """
    records = list(extract_from_ole(ole_file, project, container))
    return sorted(records, key=lambda record: (
        record.project, record.container, record.form_path,
        record.site_index, record.site_id))


def extract_from_vba_parser(vba_parser):
    """Yield records from an olevba.VBA_Parser (OLE or OpenXML, static only)."""
    if vba_parser.ole_file is None:
        for subfile in vba_parser.ole_subfiles:
            for record in extract_from_vba_parser(subfile):
                yield record
        return
    project = _project_name(vba_parser.ole_file)
    for record in extract_control_defaults(vba_parser.ole_file, project,
                                           vba_parser.filename):
        yield record


def _project_name(ole_file):
    try:
        data = ole_file.openstream("PROJECT").read()
        for line in data.splitlines():
            if line.startswith(b"Name="):
                return line.split(b"=", 1)[1].strip().strip(b"\x22").decode(
                    "cp{0}".format(DEFAULT_CODEPAGE), errors="replace")
    except Exception:
        pass
    return "<unknown-project>"

def records_as_dicts(records):
    """JSON-serialisable list, sorted by stable record identity."""
    ordered = sorted(records, key=lambda r: r.record_id)
    return [record.as_dict() for record in ordered]


def render_text_report(records):
    """Deterministic human-readable report grouped by project/form."""
    lines = []
    ordered = sorted(records, key=lambda r: (r.project, r.container,
                                             r.form_path, r.site_index,
                                             r.site_id))
    current_project = current_form = None
    for record in ordered:
        if record.project != current_project:
            current_project = record.project
            lines.append("Project: {0}".format(current_project))
            current_form = None
        form_label = "{0} :: {1}".format(record.container, record.form_path)
        if form_label != current_form:
            current_form = form_label
            lines.append("  Form: {0}".format(form_label))
        name = record.name if record.name is not None else "<unnamed>"
        lines.append("    [{status}] {type} name={name!r} site={index} id={sid}"
                     .format(status=record.status, type=record.control_type,
                             name=name, index=record.site_index,
                             sid=record.site_id))
        lines.append("        value={0!r}".format(record.value))
        lines.append("        source={0}".format(_format_source(record.value_source)))
        if record.parse_note:
            lines.append("        note={0}".format(record.parse_note))
    return "\n".join(lines)


def _format_source(source):
    if not source:
        return "<none>"
    parts = []
    for key in sorted(source):
        value = source[key]
        if isinstance(value, bytes):
            value = value.hex()
        parts.append("{0}={1}".format(key, value))
    return ", ".join(parts)


def main(argv=None):
    """Minimal offline CLI: print the forensic report for one or more files."""
    import argparse
    import json
    from .olevba import VBA_Parser
    parser = argparse.ArgumentParser(
        description="Static forensic report of VBA UserForm control defaults")
    parser.add_argument("filenames", nargs="+")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of the text report")
    args = parser.parse_args(argv)
    all_records = []
    for filename in args.filenames:
        vba_parser = VBA_Parser(filename)
        all_records.extend(extract_from_vba_parser(vba_parser))
        vba_parser.close()
    if args.json:
        print(json.dumps(records_as_dicts(all_records), indent=2,
                         sort_keys=True, ensure_ascii=False))
    else:
        print(render_text_report(all_records))


if __name__ == "__main__":
    main()
