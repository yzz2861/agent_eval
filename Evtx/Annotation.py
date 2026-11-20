"""
Offline annotation of EVTX records with a separately collected message dictionary.

When event logs are received from another machine, the message resources that
Windows would use to render them are often unavailable.  This module aligns a
JSON message dictionary with the provider, event version, and language of each
record, and annotates the rendered event.  Every piece of content in the
annotation is marked with its provenance: whether it came from the original
record or from the dictionary.

Dictionary format (JSON)::

    {
      "providers": {
        "Microsoft-Windows-Security-Auditing": {
          "events": {
            "4624": {
              "versions": {
                "0": {
                  "languages": {
                    "en-US": {
                      "message": "An account was successfully logged on. Logon type: %9",
                      "fields": {
                        "LogonType": {"label": "Logon Type", "type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

Only the two newest message resource versions are kept per (provider, event id);
when an older resource is still readable but does not apply to the current
event, the annotation notes explain why it was not used.
"""

import re
import json
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# provenance markers used throughout the annotation.
SOURCE_RECORD = "record"
SOURCE_DICTIONARY = "dictionary"

# at most this many message resource versions are retained per (provider, event id).
MAX_RESOURCE_VERSIONS = 2

_INTEGER_RE = re.compile(r"^-?\d+$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_PLACEHOLDER_RE = re.compile(r"%(\d+)")


class MessageDictionary(object):
    """
    An offline event message dictionary aligned by provider, event id,
    event version, and language.

    At most ``max_versions`` resource versions (the newest ones) are retained
    per (provider, event id); older entries are discarded at load time.
    """

    def __init__(self, providers=None, max_versions=MAX_RESOURCE_VERSIONS):
        """
        Args:
          providers (dict): mapping of provider name -> {event id (int) -> {version (int) -> resource}}.
          max_versions (int): number of resource versions retained per (provider, event id).
        """
        self._providers = providers or {}
        self._max_versions = max_versions

    @classmethod
    def from_dict(cls, data, max_versions=MAX_RESOURCE_VERSIONS):
        """
        build a dictionary from parsed JSON data, discarding all but the
        newest ``max_versions`` resource versions per (provider, event id).

        Args:
          data (dict): the parsed dictionary document.
          max_versions (int): number of resource versions to retain.

        Returns:
          MessageDictionary: the dictionary.
        """
        providers = {}
        for provider_name, provider_entry in (data.get("providers") or {}).items():
            events = {}
            for event_id, event_entry in (provider_entry.get("events") or {}).items():
                versions = {}
                for version, version_entry in (event_entry.get("versions") or {}).items():
                    versions[int(version)] = version_entry
                kept = sorted(versions, reverse=True)[:max_versions]
                discarded = sorted(set(versions) - set(kept))
                if discarded:
                    logger.info(
                        "discarding resource versions %s for %s event %s; keeping %s",
                        discarded,
                        provider_name,
                        event_id,
                        sorted(kept),
                    )
                events[int(event_id)] = {version: versions[version] for version in sorted(kept)}
            providers[provider_name] = events
        return cls(providers, max_versions=max_versions)

    @classmethod
    def load(cls, path, max_versions=MAX_RESOURCE_VERSIONS):
        """
        load a dictionary from a JSON file.

        Args:
          path (str): file system path of the dictionary document.
          max_versions (int): number of resource versions to retain.

        Returns:
          MessageDictionary: the dictionary.
        """
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f), max_versions=max_versions)

    def providers(self):
        """
        Returns:
          list[str]: the provider names known to this dictionary.
        """
        return sorted(self._providers)

    def event_ids(self, provider):
        """
        Returns:
          list[int]: the event ids known for the given provider, or an empty list.
        """
        return sorted(self._providers.get(provider, {}))

    def versions(self, provider, event_id):
        """
        Returns:
          list[int]: the retained resource versions for the given event, or an empty list.
        """
        return sorted(self._providers.get(provider, {}).get(int(event_id), {}))

    def resource(self, provider, event_id, version):
        """
        Returns:
          dict or None: the resource entry for the given (provider, event id, version).
        """
        return self._providers.get(provider, {}).get(int(event_id), {}).get(int(version))


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _child(element, name):
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _child_text(element, name):
    child = _child(element, name)
    if child is None:
        return None
    return child.text


def _parse_int(text):
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def _extract_record(record):
    """
    pull the annotation-relevant values out of a record.

    Args:
      record (Evtx.Record): the record to inspect.

    Returns:
      dict: provider, event id, qualifiers, version, record id, and ordered event data.
    """
    root = ET.fromstring(record.xml())
    system = _child(root, "System")

    provider = None
    if system is not None:
        provider_element = _child(system, "Provider")
        if provider_element is not None:
            provider = provider_element.get("Name")

    qualifiers = None
    event_id = None
    event_id_element = _child(system, "EventID") if system is not None else None
    if event_id_element is not None:
        event_id = _parse_int(event_id_element.text)
        qualifiers = event_id_element.get("Qualifiers") or None

    version = _parse_int(_child_text(system, "Version")) if system is not None else None
    record_id = _parse_int(_child_text(system, "EventRecordID")) if system is not None else None

    data = []
    event_data = _child(root, "EventData")
    if event_data is None:
        event_data = _child(root, "UserData")
    if event_data is not None:
        for element in event_data.iter():
            if _local_name(element.tag) != "Data":
                continue
            data.append((element.get("Name"), element.text or ""))

    return {
        "provider": provider,
        "event_id": event_id,
        "qualifiers": qualifiers,
        "version": version,
        "record_id": record_id,
        "data": data,
    }


def _infer_type(value):
    """
    infer the type of a record value: "integer", "hex", or "string".
    """
    if value is None or value == "":
        return "string"
    if _INTEGER_RE.match(value):
        return "integer"
    if _HEX_RE.match(value):
        return "hex"
    return "string"


def _type_compatible(declared, value):
    """
    check whether a record value is compatible with the type the dictionary
    declares for the field.  "string" accepts anything.
    """
    if not declared:
        return True
    if declared == "string":
        return True
    return declared == _infer_type(value)


def _render_message(message, values):
    """
    substitute %1..%N placeholders with the Nth event data value (1-based).

    Returns:
      tuple[str, list[int]]: the rendered message and the placeholder indexes
        that had no corresponding value and were left in place.
    """
    missing = []

    def replace(match):
        index = int(match.group(1))
        if 1 <= index <= len(values):
            return values[index - 1]
        missing.append(index)
        return match.group(0)

    return _PLACEHOLDER_RE.sub(replace, message), missing


def annotate_record(record, dictionary, language, fallback_language=None):
    """
    annotate a record using an offline message dictionary.

    The result aligns dictionary entries with the record's provider, event
    version, and the requested language (with an optional explicit fallback
    language).  Every item is marked as coming from the original record or
    from the dictionary.  If the applicable resource version is unknown, or a
    field's type no longer matches the dictionary, the original number and
    value are kept and a note explains the decision.

    Args:
      record (Evtx.Record): the record to annotate.
      dictionary (MessageDictionary): the offline message dictionary.
      language (str): the preferred language tag, such as "zh-CN".
      fallback_language (str or None): an explicit fallback language tag.

    Returns:
      dict: the JSON-serializable annotation.
    """
    info = _extract_record(record)
    notes = []

    annotation = {
        "provider": {"name": info["provider"], "source": SOURCE_RECORD},
        "event_id": {"value": info["event_id"], "qualifiers": info["qualifiers"], "source": SOURCE_RECORD},
        "version": {"value": info["version"], "source": SOURCE_RECORD},
        "record_id": {"value": info["record_id"], "source": SOURCE_RECORD},
        "language": {"requested": language, "fallback": fallback_language, "used": None},
        "message": {"content": None, "source": SOURCE_RECORD},
        "fields": [],
        "notes": notes,
    }

    provider = info["provider"]
    event_id = info["event_id"]
    record_version = info["version"]

    resource = None
    if event_id is None or not dictionary.versions(provider, event_id):
        notes.append("no dictionary entry for provider %r event %r; kept original values" % (provider, event_id))
    else:
        available_versions = dictionary.versions(provider, event_id)
        if record_version is None:
            notes.append("record carries no version; cannot select a resource version; kept original values")
            for version in available_versions:
                notes.append("resource version %d not used: record version is unknown" % version)
        elif record_version in available_versions:
            resource = dictionary.resource(provider, event_id, record_version)
            for version in available_versions:
                if version != record_version:
                    notes.append("resource version %d not used: record declares version %d" % (version, record_version))
        else:
            notes.append("no resource for record version %d; kept original values" % record_version)
            for version in available_versions:
                notes.append(
                    "resource version %d not used: does not match record version %d" % (version, record_version)
                )

    language_resource = None
    used_language = None
    if resource is not None:
        languages = resource.get("languages") or {}
        if language in languages:
            used_language = language
        elif fallback_language is not None and fallback_language in languages:
            used_language = fallback_language
            notes.append("language %r unavailable; used explicit fallback language %r" % (language, fallback_language))
        elif fallback_language is not None:
            notes.append(
                "no resource in language %r or fallback language %r; kept original values"
                % (language, fallback_language)
            )
        else:
            notes.append("no resource in language %r and no fallback language given; kept original values" % language)

        if used_language is not None:
            language_resource = languages[used_language]
            annotation["language"]["used"] = used_language

    values = [value for _, value in info["data"]]

    if language_resource is not None:
        message = language_resource.get("message")
        if message is not None:
            rendered, missing = _render_message(message, values)
            for index in missing:
                notes.append("message placeholder %%%d has no matching event data value; left as-is" % index)
            annotation["message"] = {
                "content": rendered,
                "source": SOURCE_DICTIONARY,
                "resource_version": record_version,
                "language": used_language,
            }

    dictionary_fields = (language_resource or {}).get("fields") or {}
    for name, value in info["data"]:
        field = {"name": name, "value": value, "value_source": SOURCE_RECORD}
        spec = dictionary_fields.get(name) if name is not None else None
        if spec:
            declared_type = spec.get("type")
            if _type_compatible(declared_type, value):
                if spec.get("label") is not None:
                    field["label"] = spec["label"]
                    field["label_source"] = SOURCE_DICTIONARY
            else:
                notes.append(
                    "field %r: dictionary declares type %r but record value %r is %s; kept original value"
                    % (name, declared_type, value, _infer_type(value))
                )
        annotation["fields"].append(field)

    return annotation
