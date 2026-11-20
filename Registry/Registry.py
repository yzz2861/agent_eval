#!/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011, 2012 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import print_function

import sys
import ntpath
import binascii
import hashlib
from enum import Enum

from . import RegistryParse

RegSZ = 0x0001
RegExpandSZ = 0x0002
RegBin = 0x0003
RegDWord = 0x0004
RegMultiSZ = 0x0007
RegQWord = 0x000B
RegNone = 0x0000
RegBigEndian = 0x0005
RegLink = 0x0006
RegResourceList = 0x0008
RegFullResourceDescriptor = 0x0009
RegResourceRequirementsList = 0x000A
RegFileTime = 0x0010

DEVPROP_MASK_TYPE = 0x00000FFF

# Value evidence classifications. These names are deliberately explicit:
# the same stored bytes can mean different things when the type marker or the
# declared length changes.
EVIDENCE_UNCHANGED = "unchanged"
EVIDENCE_REPRESENTATION_CHANGED = "representation_changed"
EVIDENCE_VALUE_CHANGED = "value_changed"

EVIDENCE_BIG_ENDIAN = "big-endian"
EVIDENCE_LITTLE_ENDIAN = "little-endian"
EVIDENCE_INCOMPLETE = "incomplete"
EVIDENCE_NOT_APPLICABLE = "not-applicable"

class HiveType(Enum):
    UNKNOWN = ""
    NTUSER = "ntuser.dat"
    SAM = "sam"
    SECURITY = "security"
    SOFTWARE = "software"
    SYSTEM = "system"
    USRCLASS = "usrclass.dat"
    BCD = "bcd"
    COMPONENTS = "components"
    DEFAULT = "default"
    SCHEMA = "schema.dat"
    SETTINGS = "settings.dat"


class RegistryKeyHasNoParentException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(RegistryKeyHasNoParentException, self).__init__(value)

    def __str__(self):
        return "Registry key has no parent key: %s" % (self._value)


class RegistryKeyNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryKeyNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry key not found: %s" % (self._value)

class RegistryValueNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryValueNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry value not found: %s" % (self._value)

class RegistryValue(object):
    """
    This is a high level structure for working with the Windows Registry.
    It represents the 3-tuple of (name, type, value) associated with 
      a registry value.
    """
    def __init__(self, vkrecord):
        self._vkrecord = vkrecord

    def __repr__(self):
        return 'RegistryValue(name="{0}", value="{1}", type="{2}")'.format(self.name(), self.value(), self.value_type_str())
        
    def name(self):
        """
        Get the name of the value as a string.
        The name of the default value is returned as "(default)".
        """
        if self._vkrecord.has_name():
            return self._vkrecord.name()
        else:
            return  "(default)"

    def value_type(self):
        """
        Get the type of the value as an integer constant.

        One of:
         - RegSZ = 0x0001
         - RegExpandSZ = 0x0002
         - RegBin = 0x0003
         - RegDWord = 0x0004
         - RegMultiSZ = 0x0007
         - RegQWord = 0x000B
         - RegNone = 0x0000
         - RegBigEndian = 0x0005
         - RegLink = 0x0006
         - RegResourceList = 0x0008
         - RegFullResourceDescriptor = 0x0009
         - RegResourceRequirementsList = 0x000A
         - RegUint8 = 0x101
         - RegInt16 = 0x102
         - RegUint16 = 0x103
         - RegInt32 = 0x104
         - RegUint32 = 0x105
         - RegInt64 = 0x106
         - RegUint64 = 0x107
         - RegFloat = 0x108
         - RegDouble = 0x109
         - RegUnicodeChar = 0x10A
         - RegBoolean = 0x10B
         - RegUnicodeString = 0x10C
         - RegCompositeValue = 0x10D
         - RegDateTimeOffset = 0x10E
         - RegTimeSpan = 0x10F
         - RegGUID = 0x110
         - RegUnk111 = 0x111
         - RegUnk112 = 0x112
         - RegUnk113 = 0x113
         - RegBytesArray = 0x114
         - RegInt16Array = 0x115
         - RegUint16Array = 0x116
         - RegInt32Array = 0x117
         - RegUInt32Array = 0x118
         - RegInt64Array = 0x119
         - RegUInt64Array = 0x11A
         - RegFloatArray = 0x11B
         - RegDoubleArray = 0x11C
         - RegUnicodeCharArray = 0x11D
         - RegBooleanArray = 0x11E
         - RegUnicodeStringArray = 0x11F
        """
        return self._vkrecord.data_type()

    def value_type_str(self):
        """
        Get the type of the value as a string.

        One of:
         - RegSZ
         - RegExpandSZ
         - RegBin
         - RegDWord
         - RegMultiSZ
         - RegQWord
         - RegNone
         - RegBigEndian
         - RegLink
         - RegResourceList
         - RegFullResourceDescriptor
         - RegResourceRequirementsList
         - RegUint8
         - RegInt16
         - RegUint16
         - RegInt32
         - RegUint32
         - RegInt64
         - RegUint64
         - RegFloat
         - RegDouble
         - RegUnicodeChar
         - RegBoolean
         - RegUnicodeString
         - RegCompositeValue
         - RegDateTimeOffset
         - RegTimeSpan
         - RegGUID
         - RegUnk111
         - RegUnk112
         - RegUnk113
         - RegBytesArray
         - RegInt16Array
         - RegUint16Array
         - RegInt32Array
         - RegUInt32Array
         - RegInt64Array
         - RegUInt64Array
         - RegFloatArray
         - RegDoubleArray
         - RegUnicodeCharArray
         - RegBooleanArray
         - RegUnicodeStringArray
        """
        return self._vkrecord.data_type_str()

    def value(self, overrun=0):
        return self._vkrecord.data(overrun)

    def raw_data(self, overrun=0):
        return self._vkrecord.raw_data(overrun)

    def raw_value_type(self):
        """
        Get the literal, unmasked type field stored in the VK record.

        value_type() returns the effective type after applying the
        DEVPROP_MASK_TYPE mask. The unmasked field is retained for evidence
        views so that no recorded marker information is lost.
        """
        return self._vkrecord.raw_data_type()

    def evidence(self, overrun=0):
        """
        Return a per-value evidence view.

        The result keeps the stored bytes, the type marker, the declaration
        from the VK record, the decoded value, and canonical comparison keys
        together. The legacy value()/raw_data() methods are unchanged.
        """
        return RegistryValueEvidence(self, overrun=overrun)

    def evidence_view(self, overrun=0):
        """
        Alias for evidence() for callers that prefer an explicit view name.
        """
        return self.evidence(overrun=overrun)

    def compare(self, other, overrun=0):
        """
        Compare this value's evidence with another value or evidence view.

        The result distinguishes an unchanged value, an evidence
        representation change, and an actual policy value change.
        """
        return compare_evidence(self.evidence(overrun=overrun), other)

    def compare_evidence(self, other, overrun=0):
        """
        Alias for compare().
        """
        return self.compare(other, overrun=overrun)

    def timestamp(self):
        """
        Get the last modified timestamp as a Python datetime. Only valid for
        AppContainer settings.dat reg hive
        """
        return self._vkrecord.timestamp()


def _hexlify(data):
    if data is None:
        return None
    return binascii.hexlify(data).decode("ascii")


def _canonical_value(value):
    """
    Return a stable, human-readable key for a decoded value.
    """
    if isinstance(value, (bytes, bytearray)):
        return "bytes:{0}".format(_hexlify(value))
    if isinstance(value, bool):
        return "bool:{0}".format(1 if value else 0)
    if isinstance(value, (int, float)):
        return "{0}:{1!r}".format(type(value).__name__, value)
    if isinstance(value, (list, tuple)):
        return "list:[{0}]".format(",".join(_canonical_value(item) for item in value))
    if hasattr(value, "isoformat"):
        return "datetime:{0}".format(value.isoformat())
    if isinstance(value, str):
        return "text:{0}".format(value)
    return "repr:{0}".format(repr(value))


def _json_safe_value(value):
    if isinstance(value, (bytes, bytearray)):
        return _hexlify(value)
    if isinstance(value, (list, tuple)):
        return [_json_safe_value(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _expected_storage_length(data_type):
    if data_type in (RegDWord, RegBigEndian):
        return 4
    if data_type in (RegQWord, RegFileTime):
        return 8
    return None


class RegistryValueEvidence(dict):
    """
    A per-value evidence view.

    The object behaves as both a mapping and a small object with attributes,
    so it can be serialized by report tooling without losing the distinction
    between storage bytes and their declared interpretation.

    The three important encodings are:
      - explicit big-endian integers (RegBigEndian)
      - ordinary little-endian integers (RegDWord and other little-endian types)
      - records whose value is still readable but whose declared length is
        shorter than the storage width
    """

    _ALIASES = {
        "raw": "raw_data",
        "raw_bytes": "raw_data",
        "hex": "raw_hex",
        "type": "value_type",
        "type_marker": "value_type",
        "type_id": "value_type",
        "data_type": "value_type",
        "type_field": "raw_type_marker",
        "raw_type": "raw_type_marker",
        "raw_type_field": "raw_type_marker",
        "data_length": "declared_length",
        "raw_data_length": "raw_length_field",
        "value_type_str": "type_name",
        "type_str": "type_name",
        "decoded_result": "decoded",
        "raw_storage": "raw_data",
        "storage_bytes": "raw_data",
        "compare_key": "comparison_key",
        "endianness": "byte_order",
        "decoded_value": "decoded",
        "value": "decoded",
        "declared_incomplete": "incomplete",
        "evidence_kind": "kind",
        "encoding_class": "encoding",
        "comparison": "comparison_key",
        "report_comparison": "comparison_view",
        "comparison_summary": "comparison_view",
        "evidence_key": "comparison_key",
        "storage_key": "comparison_key",
        "fingerprint": "comparison_key",
        "legacy_key": "display_key",
    }

    def __init__(self, value, overrun=0):
        if not isinstance(value, RegistryValue):
            raise TypeError("RegistryValueEvidence requires a RegistryValue")

        vkrecord = value._vkrecord
        value_type = value.value_type()
        raw_type_marker = value.raw_value_type()
        declared_length = vkrecord.data_length()
        raw_length_field = vkrecord.raw_data_length()
        expected_length = _expected_storage_length(value_type)

        raw_data = b""
        raw_error = None
        try:
            raw_data = value.raw_data(overrun=overrun)
        except Exception as e:
            raw_error = str(e)

        inline_marker_present = raw_length_field >= 0x80000000
        inline_required = (
            expected_length is not None and
            expected_length <= 4 and
            value_type in (RegDWord, RegBigEndian)
        )
        if expected_length is None:
            declared_length_complete = len(raw_data) >= declared_length
        else:
            declared_length_complete = (
                declared_length >= expected_length and
                len(raw_data) >= expected_length
            )
        complete = declared_length_complete and (
            inline_marker_present or not inline_required
        )

        if value_type == RegBigEndian:
            byte_order = "big"
            encoding = EVIDENCE_BIG_ENDIAN
        elif value_type in (RegDWord, RegQWord, RegFileTime):
            byte_order = "little"
            encoding = EVIDENCE_LITTLE_ENDIAN
        else:
            byte_order = "not-applicable"
            encoding = EVIDENCE_NOT_APPLICABLE

        if not complete:
            kind = EVIDENCE_INCOMPLETE
        else:
            kind = encoding

        decoded = None
        decode_error = raw_error
        if raw_error is None:
            try:
                decoded = value.value(overrun=overrun)
            except Exception as e:
                decode_error = str(e)
        readable = decode_error is None

        raw_hex = _hexlify(raw_data)
        raw_key = "raw:{0}".format(raw_hex)
        value_key = _canonical_value(decoded) if readable else None
        display_key = raw_hex

        comparison_material = (
            "python-registry-evidence-v1|"
            "type={0}|raw_type={1}|order={2}|encoding={3}|"
            "declared={4}|raw_field={5}|complete={6}|raw={7}"
        ).format(
            value_type,
            raw_type_marker,
            byte_order,
            encoding,
            1 if complete else 0,
            declared_length,
            raw_length_field,
            raw_hex,
        )
        comparison_key = hashlib.sha256(
            comparison_material.encode("utf-8")
        ).hexdigest()

        notes = []
        if not complete:
            if not declared_length_complete:
                if expected_length is not None:
                    notes.append(
                        "declared length {0} is shorter than the {1}-byte "
                        "storage width; value is still readable".format(
                            declared_length, expected_length
                        )
                    )
                else:
                    notes.append(
                        "declared length {0} exceeds the {1} bytes available".format(
                            declared_length, len(raw_data)
                        )
                    )
            elif inline_required and not inline_marker_present:
                notes.append(
                    "four-byte inline value does not set the 0x80000000 "
                    "marker; value is still readable"
                )
        if inline_marker_present:
            notes.append("inline data field")
        if raw_type_marker != value_type:
            notes.append(
                "raw type marker 0x{0:x} masks to 0x{1:x}".format(
                    raw_type_marker, value_type
                )
            )

        path = None
        try:
            path = vkrecord.parent().parent().path()
        except Exception:
            pass

        super(RegistryValueEvidence, self).__init__(
            name=value.name(),
            path=path,
            value_type=value_type,
            type_name=value.value_type_str(),
            raw_type_marker=raw_type_marker,
            raw_data=raw_data,
            raw_hex=raw_hex,
            byte_order=byte_order,
            encoding=encoding,
            kind=kind,
            declared_length=declared_length,
            raw_length_field=raw_length_field,
            expected_length=expected_length,
            declared_length_complete=declared_length_complete,
            inline=inline_marker_present,
            inline_marker_present=inline_marker_present,
            inline_required=inline_required,
            complete=complete,
            incomplete=not complete,
            readable=readable,
            decoded=decoded,
            decoded_key=value_key,
            value_key=value_key,
            raw_key=raw_key,
            display_key=display_key,
            comparison_key=comparison_key,
            decode_error=decode_error,
            notes=notes,
        )
        self["comparison_view"] = {
            "display_key": display_key,
            "evidence_key": comparison_key,
            "value_key": value_key,
            "type_marker": value_type,
            "byte_order": byte_order,
            "complete": complete,
        }

    def __getitem__(self, key):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        alias = self._ALIASES.get(key)
        if alias is not None and dict.__contains__(self, alias):
            return dict.__getitem__(self, alias)
        raise KeyError(key)

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    @property
    def is_big_endian(self):
        return self["byte_order"] == "big"

    @property
    def is_little_endian(self):
        return self["byte_order"] == "little"

    @property
    def is_incomplete(self):
        return not self["complete"]

    @property
    def is_usual_little_endian(self):
        return self["value_type"] in (RegDWord, RegQWord)

    @property
    def is_complete(self):
        return self["complete"]

    @property
    def is_explicit_big_endian(self):
        return self["value_type"] == RegBigEndian

    def to_dict(self):
        """
        Return a JSON-friendly copy. Raw bytes become lowercase hex strings.
        """
        result = dict(self)
        result["raw_data"] = self["raw_hex"]
        result["decoded"] = _json_safe_value(self["decoded"])
        return result

    def as_dict(self):
        """
        Alias for to_dict().
        """
        return self.to_dict()

    def compare(self, other):
        """
        Compare this evidence view with another evidence view or RegistryValue.
        """
        return compare_evidence(self, other)


class RegistryValueComparison(dict):
    """
    Result of comparing two per-value evidence views.
    """

    _ALIASES = {
        "classification": "status",
        "category": "status",
        "result": "verdict",
        "reason": "report",
        "is_representation_change": "representation_changed",
        "is_value_change": "value_changed",
        "evidence_changed": "representation_changed",
        "evidence_representation_changed": "representation_changed",
        "policy_value_changed": "value_changed",
        "same_raw": "same_raw_data",
        "same_type": "same_type_marker",
        "same_value": "same_decoded_value",
        "raw_changed": "raw_data_changed",
        "type_changed": "type_marker_changed",
    }

    def __getitem__(self, key):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        alias = self._ALIASES.get(key)
        if alias is not None and dict.__contains__(self, alias):
            return dict.__getitem__(self, alias)
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def to_dict(self):
        result = dict(self)
        if isinstance(result.get("left"), RegistryValueEvidence):
            result["left"] = result["left"].to_dict()
        if isinstance(result.get("right"), RegistryValueEvidence):
            result["right"] = result["right"].to_dict()
        return result

    def as_dict(self):
        """
        Alias for to_dict().
        """
        return self.to_dict()


def _coerce_evidence(value):
    if isinstance(value, RegistryValueEvidence):
        return value
    if isinstance(value, RegistryValue):
        return value.evidence()
    if hasattr(value, "evidence"):
        return _coerce_evidence(value.evidence())
    raise TypeError("expected RegistryValue or RegistryValueEvidence")


def compare_evidence(left, right):
    """
    Compare two values and classify the difference.

    - unchanged: stored bytes, type/declaration, and decoded value match.
    - representation_changed: the bytes were reinterpreted or re-encoded
      (for example, a DWord marker became RegBigEndian), so the report must
      not treat the raw hex key alone as evidence of a policy change.
    - value_changed: stored bytes and the decoded policy value both changed.
    """
    left = _coerce_evidence(left)
    right = _coerce_evidence(right)

    same_raw = left["raw_data"] == right["raw_data"]
    same_type = (
        left["value_type"] == right["value_type"] and
        left["raw_type_marker"] == right["raw_type_marker"]
    )
    same_declaration = (
        left["declared_length"] == right["declared_length"] and
        left["raw_length_field"] == right["raw_length_field"]
    )
    same_evidence = left["comparison_key"] == right["comparison_key"]
    if not left["readable"] and not right["readable"]:
        same_decoded = same_raw
    else:
        same_decoded = (
            left["readable"] and right["readable"] and
            left["value_key"] == right["value_key"]
        )

    if same_evidence and same_decoded:
        status = EVIDENCE_UNCHANGED
        verdict = "unchanged"
        report = "stored bytes, type/declaration, and decoded value are unchanged"
    elif not same_raw and not same_decoded:
        status = EVIDENCE_VALUE_CHANGED
        verdict = "policy_value_changed"
        report = "stored bytes and the decoded policy value both changed"
    elif not same_raw and same_decoded:
        status = EVIDENCE_REPRESENTATION_CHANGED
        verdict = "evidence_representation_changed"
        report = (
            "stored bytes were re-encoded but the decoded policy value is "
            "unchanged"
        )
    elif same_raw and not same_type:
        status = EVIDENCE_REPRESENTATION_CHANGED
        verdict = "evidence_representation_changed"
        report = (
            "stored bytes are unchanged but the type marker changed "
            "({0} -> {1}); this is an evidence representation change, not "
            "new policy bytes".format(
                left["type_name"], right["type_name"]
            )
        )
    elif same_raw and not same_declaration:
        status = EVIDENCE_REPRESENTATION_CHANGED
        verdict = "evidence_representation_changed"
        report = (
            "stored bytes are unchanged but the declared length changed "
            "({0} -> {1})".format(
                left["declared_length"], right["declared_length"]
            )
        )
    elif same_raw and not same_decoded:
        status = EVIDENCE_REPRESENTATION_CHANGED
        verdict = "evidence_representation_changed"
        report = (
            "stored bytes and type marker are unchanged; only the decoded "
            "representation changed"
        )
    else:
        status = EVIDENCE_VALUE_CHANGED
        verdict = "policy_value_changed"
        report = "stored bytes changed and the decoded policy value differs"

    representation_changed = status == EVIDENCE_REPRESENTATION_CHANGED
    value_changed = status == EVIDENCE_VALUE_CHANGED

    return RegistryValueComparison(
        status=status,
        verdict=verdict,
        report=report,
        left=left,
        right=right,
        same_raw_data=same_raw,
        same_type_marker=same_type,
        same_declaration=same_declaration,
        same_decoded_value=same_decoded,
        same_evidence=same_evidence,
        raw_data_changed=not same_raw,
        type_marker_changed=not same_type,
        declaration_changed=not same_declaration,
        decoded_value_changed=not same_decoded,
        representation_changed=representation_changed,
        value_changed=value_changed,
        left_display_key=left["display_key"],
        right_display_key=right["display_key"],
        left_comparison_key=left["comparison_key"],
        right_comparison_key=right["comparison_key"],
    )


class RegistryKey(object):
    """
    A high level structure for use in traversing the Windows Registry.
    A RegistryKey is a node in a tree-like structure.
    A RegistryKey may have a set of values associated with it,
      as well as a last modified timestamp.
    """
    def __init__(self, nkrecord):
        """

        Arguments:
        - `NKRecord`:
        """
        self._nkrecord = nkrecord

    def __str__(self):
        return "Registry Key %s with %d values and %d subkeys" % \
            (self.path(), len(self.values()), len(self.subkeys()))

    def __repr__(self):
        return 'RegistryKey(name="{0}", path="{1}")'.format(self.name(), self.path())
    

    def __getitem__(self, key):
        return self.value(key)

    def timestamp(self):
        """
        Get the last modified timestamp as a Python datetime.
        """
        return self._nkrecord.timestamp()

    def name(self):
        """
        Get the name of the key as a string.

        For example, "Windows" if the key path were
        /{hive name}/SOFTWARE/Microsoft/Windows
        See RegistryKey.path() to get the complete key name.
        """
        return self._nkrecord.name()

    def path(self):
        """
        Get the full path of the RegistryKey as a string.
        For example, "/{hive name}/SOFTWARE/Microsoft/Windows"
        """
        return self._nkrecord.path()

    def parent(self):
        """
        Get the parent RegistryKey of this key, or raise
        RegistryKeyHasNoParentException if it does not exist (for example,
        the root key has no parent).
        """
        # there may be a memory inefficiency here, since we create
        # a new RegistryKey from the NKRecord parent key, rather
        # than using the parent of this instance, if it exists.
        try:
            return RegistryKey(self._nkrecord.parent_key())
        except RegistryParse.ParseException:
            raise RegistryKeyHasNoParentException(self.name())

    def subkeys(self):
        """
        Return a list of all subkeys.
        Each element in the list is a RegistryKey.
        If the key has no subkeys, the empty list is returned.
        """
        if self._nkrecord.subkey_number() == 0:
            return []

        l = self._nkrecord.subkey_list()
        return [RegistryKey(k) for k in l.keys()]

    def subkey(self, name):
        """
        Return the subkey with a given name as a RegistryKey.
        Raises RegistryKeyNotFoundException if the subkey with 
          the given name does not exist.
        """
        if self._nkrecord.subkey_number() == 0:
            raise RegistryKeyNotFoundException(self.path() + "\\" + name)

        for k in self._nkrecord.subkey_list().keys():
            if k.name().lower() == name.lower():
                return RegistryKey(k)
        raise RegistryKeyNotFoundException(self.path() + "\\" + name)

    def values(self):
        """
        Return a list containing the values associated with this RegistryKey.
        Each element of the list will be a RegistryValue.
        If there are no values associated with this RegistryKey, then the
        empty list is returned.
        """
        try:
            return [RegistryValue(v) for v in self._nkrecord.values_list().values()]
        except RegistryParse.RegistryStructureDoesNotExist:
            return []

    def value(self, name):
        """
        Return the value with the given name as a RegistryValue.
        Raises RegistryValueNotFoundExceptiono if the value with
          the given name does not exist.
        """
        if name == "(default)":
            name = ""
        try:
            for v in self._nkrecord.values_list().values():
                if v.name().lower() == name.lower():
                    return RegistryValue(v)
        except RegistryParse.RegistryStructureDoesNotExist:
            raise RegistryValueNotFoundException(self.path() + " : " + name)
        raise RegistryValueNotFoundException(self.path() + " : " + name)

    def find_key(self, path):
        """
        Perform a search for a RegistryKey with a specific path.
        """
        if len(path) == 0:
            return self

        (immediate, _, future) = path.partition("\\")
        return self.subkey(immediate).find_key(future)

    def values_number(self):
    	"""
    	Return the number of values associated with this key
    	"""
    	return self._nkrecord.values_number()

    def subkeys_number(self):
    	"""
    	Return the number of subkeys associated with this key
    	"""
    	return self._nkrecord.subkey_number()


class Registry(object):
    """
    A class for parsing and reading from a Windows Registry file.
    """
    def __init__(self, filelikeobject):
        """
        Constructor.
        Arguments:
        - `filelikeobject`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._buf = filelikeobject.read()
        except AttributeError:
            with open(filelikeobject, "rb") as f:
                self._buf = f.read()
        self._regf = RegistryParse.REGFBlock(self._buf, 0, False)

    def __repr__(self):
        return 'Registry(hive_name="{0}", hive_type="{1}")'.format(self.hive_name(), self.hive_type())
    
    def hive_name(self):
        """Returns the internal file name"""
        return self._regf.hive_name()

    def hive_type(self):
        """Returns the hive type"""
        temp = self.hive_name()
        temp = temp.replace('\\??\\', '')
        temp = ntpath.basename(temp)

        if temp.lower() == HiveType.NTUSER.value:
            return HiveType.NTUSER
        elif temp.lower() == HiveType.SAM.value:
            return HiveType.SAM
        elif temp.lower() == HiveType.SECURITY.value:
            return HiveType.SECURITY
        elif temp.lower() == HiveType.SOFTWARE.value:
            return HiveType.SOFTWARE
        elif temp.lower() == HiveType.SYSTEM.value:
            return HiveType.SYSTEM
        elif temp.lower() == HiveType.USRCLASS.value:
            return HiveType.USRCLASS
        elif temp.lower() == HiveType.BCD.value:
            return HiveType.BCD
        elif temp.lower() == HiveType.COMPONENTS.value:
            return HiveType.COMPONENTS
        elif temp.lower() == HiveType.DEFAULT.value:
            return HiveType.DEFAULT
        elif temp.lower() == HiveType.SCHEMA.value:
            return HiveType.SCHEMA
        elif temp.lower() == HiveType.SETTINGS.value:
            return HiveType.SETTINGS
        else:
            return HiveType.UNKNOWN

    def root(self):
        """
        Return the first RegistryKey in the hive.
        """
        return RegistryKey(self._regf.first_key())

    def open(self, path):
        """
        Return a RegistryKey by full path.
        Subkeys are separated by the backslash character ('\').
        A trailing backslash may or may not be present.
        The hive name should not be included.
        """
        # is the first registry key always the root?
        # are there any other keys at this
        # level? is this the name of the hive?
        return RegistryKey(self._regf.first_key()).find_key(path)

def print_all(key):
    if len(key.subkeys()) == 0:
        print(key.path())
    else:
        for k in key.subkeys():
            print_all(k)

if __name__ == '__main__':
    r = Registry(sys.argv[1])
    print_all(r.root())
