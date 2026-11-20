import os
import json

import Evtx.Evtx as evtx

from Evtx.Annotation import SOURCE_RECORD, annotate_record, MessageDictionary, SOURCE_DICTIONARY

PROVIDER = "Microsoft-Windows-Security-Auditing"

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class FakeRecord(object):
    """
    a minimal stand-in for Evtx.Record built from a rendered XML document,
    used to exercise records whose version element differs from the test files.
    """

    def __init__(self, xml):
        self._xml = xml

    def xml(self):
        return self._xml


def make_event_xml(event_id, version, data=None):
    fields = "".join('<Data Name="{}">{}</Data>'.format(name, value) for name, value in (data or []))
    version_element = "<Version>{}</Version>".format(version) if version is not None else ""
    return (
        "<Event><System>"
        '<Provider Name="{}"></Provider>'.format(PROVIDER)
        + "<EventID>{}</EventID>".format(event_id)
        + version_element
        + "<EventRecordID>1</EventRecordID>"
        + "</System><EventData>"
        + fields
        + "</EventData></Event>"
    )


def make_dictionary_data(versions):
    """
    build dictionary JSON data for the security provider, event 4624.

    Args:
      versions (dict): mapping of version (int) -> {language tag -> language resource}.
    """
    return {
        "providers": {
            PROVIDER: {
                "events": {
                    "4624": {
                        "versions": {str(version): {"languages": languages} for version, languages in versions.items()}
                    }
                }
            }
        }
    }


def security_annotations(dictionary, language="en-US", fallback_language=None):
    """
    annotate every record of the security.evtx test file.

    Returns:
      dict: mapping of event record id -> annotation.
    """
    annotations = {}
    with evtx.Evtx(os.path.join(DATA_DIR, "security.evtx")) as log:
        for record in log.records():
            annotation = annotate_record(record, dictionary, language, fallback_language)
            annotations[annotation["record_id"]["value"]] = annotation
    return annotations


# event record id 1 is event 4608 (no event data); record id 2 is event 4624.
RECORD_4608 = 1
RECORD_4624 = 2


def test_dictionary_retains_only_two_newest_versions():
    data = make_dictionary_data({0: {"en-US": {}}, 1: {"en-US": {}}, 2: {"en-US": {}}})
    dictionary = MessageDictionary.from_dict(data)

    assert dictionary.versions(PROVIDER, 4624) == [1, 2]
    assert dictionary.resource(PROVIDER, 4624, 0) is None
    assert dictionary.resource(PROVIDER, 4624, 2) is not None


def test_dictionary_loads_from_file(tmp_path):
    path = tmp_path / "messages.json"
    path.write_text(json.dumps(make_dictionary_data({0: {"en-US": {}}})), encoding="utf-8")

    dictionary = MessageDictionary.load(str(path))

    assert dictionary.providers() == [PROVIDER]
    assert dictionary.event_ids(PROVIDER) == [4624]
    assert dictionary.versions(PROVIDER, 4624) == [0]


def test_annotate_exact_match_marks_provenance():
    data = make_dictionary_data(
        {
            0: {
                "zh-CN": {
                    "message": "logon type %9",
                    "fields": {"LogonType": {"label": "Logon Type", "type": "integer"}},
                }
            }
        }
    )
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary, language="zh-CN")[RECORD_4624]

    assert annotation["provider"] == {"name": PROVIDER, "source": SOURCE_RECORD}
    assert annotation["event_id"]["value"] == 4624
    assert annotation["event_id"]["source"] == SOURCE_RECORD
    assert annotation["version"] == {"value": 0, "source": SOURCE_RECORD}
    assert annotation["language"]["used"] == "zh-CN"
    assert annotation["message"]["source"] == SOURCE_DICTIONARY
    assert annotation["message"]["resource_version"] == 0
    assert annotation["message"]["language"] == "zh-CN"
    assert annotation["message"]["content"] == "logon type 0"

    fields = {field["name"]: field for field in annotation["fields"]}
    assert fields["LogonType"]["value"] == "0"
    assert fields["LogonType"]["value_source"] == SOURCE_RECORD
    assert fields["LogonType"]["label"] == "Logon Type"
    assert fields["LogonType"]["label_source"] == SOURCE_DICTIONARY
    # fields not present in the dictionary carry record content only.
    assert "label" not in fields["SubjectUserSid"]
    for field in annotation["fields"]:
        assert field["value_source"] == SOURCE_RECORD


def test_explicit_fallback_language_is_used_and_noted():
    data = make_dictionary_data({0: {"en-US": {"message": "logon type %9"}}})
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary, language="zh-CN", fallback_language="en-US")[RECORD_4624]

    assert annotation["language"]["requested"] == "zh-CN"
    assert annotation["language"]["used"] == "en-US"
    assert annotation["message"]["content"] == "logon type 0"
    assert any("fallback" in note for note in annotation["notes"])


def test_missing_language_without_fallback_keeps_original():
    data = make_dictionary_data({0: {"en-US": {"message": "logon type %9"}}})
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary, language="zh-CN")[RECORD_4624]

    assert annotation["language"]["used"] is None
    assert annotation["message"] == {"content": None, "source": SOURCE_RECORD}
    assert any("no resource in language" in note for note in annotation["notes"])


def test_unknown_record_version_keeps_original_and_explains_unused_resources():
    # the record declares version 0; the dictionary only carries versions 1 and 2.
    data = make_dictionary_data(
        {
            1: {"en-US": {"message": "v1", "fields": {"LogonType": {"label": "v1"}}}},
            2: {"en-US": {"message": "v2"}},
        }
    )
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary)[RECORD_4624]

    assert annotation["message"] == {"content": None, "source": SOURCE_RECORD}
    assert all("label" not in field for field in annotation["fields"])
    assert "resource version 1 not used: does not match record version 0" in annotation["notes"]
    assert "resource version 2 not used: does not match record version 0" in annotation["notes"]


def test_readable_older_resource_explains_why_it_was_not_used():
    # the record declares version 1; the dictionary still carries the older version 0.
    data = make_dictionary_data(
        {
            0: {"en-US": {"message": "old"}},
            1: {"en-US": {"message": "new"}},
        }
    )
    dictionary = MessageDictionary.from_dict(data)
    record = FakeRecord(make_event_xml(4624, 1))

    annotation = annotate_record(record, dictionary, "en-US")

    assert annotation["message"]["content"] == "new"
    assert annotation["message"]["resource_version"] == 1
    assert "resource version 0 not used: record declares version 1" in annotation["notes"]


def test_record_without_version_keeps_original_and_explains():
    data = make_dictionary_data({0: {"en-US": {"message": "v0"}}})
    dictionary = MessageDictionary.from_dict(data)
    record = FakeRecord(make_event_xml(4624, None))

    annotation = annotate_record(record, dictionary, "en-US")

    assert annotation["version"] == {"value": None, "source": SOURCE_RECORD}
    assert annotation["message"] == {"content": None, "source": SOURCE_RECORD}
    assert any("record carries no version" in note for note in annotation["notes"])
    assert "resource version 0 not used: record version is unknown" in annotation["notes"]


def test_field_type_drift_keeps_original_value():
    data = make_dictionary_data(
        {
            0: {
                "en-US": {
                    "fields": {
                        # the record value "-" is a string, not an integer.
                        "SubjectUserName": {"label": "Subject", "type": "integer"},
                        "LogonType": {"label": "Logon Type", "type": "integer"},
                    }
                }
            }
        }
    )
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary)[RECORD_4624]
    fields = {field["name"]: field for field in annotation["fields"]}

    assert fields["SubjectUserName"]["value"] == "-"
    assert fields["SubjectUserName"]["value_source"] == SOURCE_RECORD
    assert "label" not in fields["SubjectUserName"]
    assert fields["LogonType"]["label"] == "Logon Type"
    assert any("SubjectUserName" in note and "type" in note for note in annotation["notes"])


def test_message_placeholder_without_value_is_left_as_is():
    data = make_dictionary_data({0: {"en-US": {"message": "%1 / %9 / %99"}}})
    dictionary = MessageDictionary.from_dict(data)

    annotation = security_annotations(dictionary)[RECORD_4624]

    assert annotation["message"]["content"] == "S-1-0-0 / 0 / %99"
    assert any("%99" in note for note in annotation["notes"])


def test_event_without_dictionary_entry_keeps_original():
    data = make_dictionary_data({0: {"en-US": {"message": "v0"}}})
    dictionary = MessageDictionary.from_dict(data)

    # event 4608 has no dictionary entry.
    annotation = security_annotations(dictionary)[RECORD_4608]

    assert annotation["message"] == {"content": None, "source": SOURCE_RECORD}
    assert annotation["fields"] == []
    assert any("no dictionary entry" in note for note in annotation["notes"])
