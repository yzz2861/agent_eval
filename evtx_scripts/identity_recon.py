#!/usr/bin/env python3
#
# This file is part of python-evtx.
#
# Purpose: reconcile the identity claims found in Windows security event
# records against an offline, point-in-time account dictionary.
#
# The incident report this supports treated two identically spelled display
# names as the same person, while the offline account roster actually holds
# the name in two different domains. Matching therefore never collapses
# claims on names alone: the SID explicitly present in the event is the
# primary key, and the dictionary version used must have been in force at
# the time the event was recorded.

import json
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Result statuses. Pending statuses keep the raw source fields plus the
# evidence an analyst needs to finish the reconciliation manually.
STATUS_CONFIRMED = "confirmed"
STATUS_NO_SID = "pending_no_sid"
STATUS_DICTIONARY_STALE = "pending_dictionary_stale"
STATUS_CONFLICT = "pending_conflicting_registrations"
STATUS_UNKNOWN_SID = "pending_sid_not_registered"

EMPTY_VALUES = ("", "-", None)

# Security events describe the acted-upon account with Target* fields and
# the acting account with Subject* fields. Target wins because it is the
# identity the event is principally about (e.g. the logged-on user).
IDENTITY_FIELD_SETS = (
    ("TargetUserSid", "TargetUserName", "TargetDomainName"),
    ("SubjectUserSid", "SubjectUserName", "SubjectDomainName"),
    ("UserSid", "UserName", "DomainName"),
)


def _clean(value):
    """Normalize an event field, mapping placeholder dashes to None."""
    if value in EMPTY_VALUES:
        return None
    return value


def parse_event_xml(record_xml):
    """
    Parse one EVTX record XML document into an identity claim.

    The claim only carries values that are explicit in the record. A SID
    that is missing or rendered as "-" is never guessed from the username.

    Args:
      record_xml (str): the XML text produced by Record.xml().

    Returns:
      dict: identity claim with event metadata and the raw source fields.
    """
    root = ET.fromstring(record_xml)
    system = root.find("%sSystem" % EVENT_NS)

    event_id = None
    event_id_node = system.find("%sEventID" % EVENT_NS)
    if event_id_node is not None and event_id_node.text is not None:
        event_id = int(event_id_node.text)

    record_id = None
    record_id_node = system.find("%sEventRecordID" % EVENT_NS)
    if record_id_node is not None and record_id_node.text is not None:
        record_id = int(record_id_node.text)

    computer = None
    computer_node = system.find("%sComputer" % EVENT_NS)
    if computer_node is not None:
        computer = computer_node.text

    time_created = None
    time_node = system.find("%sTimeCreated" % EVENT_NS)
    if time_node is not None:
        time_created = time_node.get("SystemTime")

    data_by_name = {}
    event_data = root.find("%sEventData" % EVENT_NS)
    if event_data is not None:
        for data_node in event_data.findall("%sData" % EVENT_NS):
            name = data_node.get("Name")
            if name:
                data_by_name[name] = data_node.text

    sid = None
    username = None
    domain = None
    used_field_set = None
    for sid_field, name_field, domain_field in IDENTITY_FIELD_SETS:
        candidate_sid = _clean(data_by_name.get(sid_field))
        candidate_name = _clean(data_by_name.get(name_field))
        if candidate_sid is None and candidate_name is None:
            continue
        sid = candidate_sid
        username = candidate_name
        domain = _clean(data_by_name.get(domain_field))
        used_field_set = (sid_field, name_field, domain_field)
        break

    return {
        "event_id": event_id,
        "event_record_id": record_id,
        "computer": computer,
        "time_created": time_created,
        "sid": sid,
        "username": username,
        "domain": domain,
        "source_field_set": used_field_set,
        "source_fields": dict(data_by_name),
    }


def iter_claims(evtx_path):
    """
    Yield an identity claim for every record in an EVTX file.

    Records that cannot be parsed are skipped; their absence is surfaced by
    the caller via the record count, rather than aborting the whole review.

    Args:
      evtx_path (str): path to the Windows EVTX file.

    Yields:
      dict: identity claims as returned by parse_event_xml.
    """
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                yield parse_event_xml(record.xml())
            except ET.ParseError:
                continue


def load_dictionary(dictionary_path):
    """
    Load the offline account dictionary JSON document.

    Expected shape:
      {
        "version": "v3",
        "generated_at": "2026-11-01T00:00:00+08:00",
        "accounts": [
          {"sid": "S-...", "username": "jdoe", "domain": "CORP",
           "display_name": "John Doe",
           "registered_from": "...", "registered_to": null}
        ]
      }

    Args:
      dictionary_path (str): path to the dictionary JSON file.

    Returns:
      dict: the validated dictionary document.
    """
    with open(dictionary_path, "r", encoding="utf-8") as handle:
        dictionary = json.load(handle)
    if "accounts" not in dictionary or not isinstance(dictionary["accounts"], list):
        raise ValueError("dictionary must contain an 'accounts' list")
    return dictionary


def _registration_active(registration, event_time):
    """
    Check whether a registration was in force when the event was recorded.

    A registration without explicit bounds is treated as always active.
    Bounds and event_time are compared as ISO 8601 strings, which order
    correctly when they share a timezone designator.
    """
    event_dt = _parse_timestamp(event_time)
    registered_from = _parse_timestamp(registration.get("registered_from"))
    registered_to = _parse_timestamp(registration.get("registered_to"))
    if event_dt is None:
        return True
    if registered_from is not None and event_dt < registered_from:
        return False
    if registered_to is not None and event_dt > registered_to:
        return False
    return True


def _dictionary_in_force(dictionary, event_time):
    """
    Decide whether the dictionary snapshot covers the event timestamp.

    The caller's roster is a point-in-time local dictionary: a snapshot taken
    at generated_at. Events recorded before the snapshot can be checked, but
    events newer than the snapshot cannot, because later SID assignments are
    not represented in it.
    """
    event_dt = _parse_timestamp(event_time)
    generated_at = _parse_timestamp(dictionary.get("generated_at"))
    if generated_at is None or event_dt is None:
        return True
    return event_dt <= generated_at


def _parse_timestamp(value):
    """
    Parse an ISO 8601 timestamp into a timezone-aware datetime.

    EVTX SystemTime values use a space separator and explicit offsets,
    while dictionary JSON files commonly use the "T" separator. Both are
    accepted. A timestamp with no offset is assumed to be UTC so that
    comparisons always stay timezone-aware.

    Returns:
      datetime.datetime | None: the parsed timestamp, or None when absent.
    """
    if value is None:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = text.replace(" ", "T", 1) if "T" not in text else text
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _find_registrations(dictionary, claim):
    """Return the dictionary registrations keyed by the claim's explicit SID."""
    sid = claim["sid"]
    return [account for account in dictionary["accounts"] if account.get("sid") == sid]


def reconcile_claim(claim, dictionary):
    """
    Reconcile one identity claim against the offline dictionary.

    Args:
      claim (dict): output of parse_event_xml.
      dictionary (dict): output of load_dictionary.

    Returns:
      dict: a review record containing the original source fields, the
        decision status, and either the matched registration or the
        pending evidence explaining why no match could be made.
    """
    result = {
        "event_id": claim["event_id"],
        "event_record_id": claim["event_record_id"],
        "computer": claim["computer"],
        "time_created": claim["time_created"],
        "claimed_sid": claim["sid"],
        "claimed_username": claim["username"],
        "claimed_domain": claim["domain"],
        "source_field_set": claim["source_field_set"],
        "source_fields": claim["source_fields"],
        "dictionary_version": dictionary.get("version"),
        "dictionary_generated_at": dictionary.get("generated_at"),
        "status": None,
        "matched_registration": None,
        "candidate_registrations": [],
        "pending_reason": None,
        "evidence": [],
    }

    if claim["sid"] is None:
        result["status"] = STATUS_NO_SID
        result["pending_reason"] = "record carries no explicit SID; username alone cannot identify an account"
        result["evidence"].append(
            {
                "type": "username_only",
                "username": claim["username"],
                "domain": claim["domain"],
                "note": "display names and usernames repeat across domains; require an SID-bearing record",
            }
        )
        return result

    if not _dictionary_in_force(dictionary, claim["time_created"]):
        result["status"] = STATUS_DICTIONARY_STALE
        result["pending_reason"] = (
            "event is newer than dictionary snapshot generated_at; obtain a newer dictionary version"
        )
        result["evidence"].append(
            {
                "type": "dictionary_version",
                "event_time": claim["time_created"],
                "dictionary_generated_at": dictionary.get("generated_at"),
                "dictionary_version": dictionary.get("version"),
            }
        )
        return result

    registrations = [
        account
        for account in _find_registrations(dictionary, claim)
        if _registration_active(account, claim["time_created"])
    ]
    result["candidate_registrations"] = registrations

    if not registrations:
        result["status"] = STATUS_UNKNOWN_SID
        result["pending_reason"] = "no active dictionary registration for the explicit SID"
        result["evidence"].append(
            {
                "type": "unregistered_sid",
                "sid": claim["sid"],
                "username": claim["username"],
                "domain": claim["domain"],
            }
        )
        return result

    if len(registrations) > 1:
        result["status"] = STATUS_CONFLICT
        result["pending_reason"] = "multiple active registrations share the SID; manual disambiguation required"
        result["evidence"].append(
            {
                "type": "conflicting_registrations",
                "sid": claim["sid"],
                "registrations": registrations,
            }
        )
        return result

    registration = registrations[0]
    result["status"] = STATUS_CONFIRMED
    result["matched_registration"] = registration
    if claim["username"] is not None and registration.get("username") not in (None, claim["username"]):
        result["evidence"].append(
            {
                "type": "username_mismatch",
                "claimed_username": claim["username"],
                "registered_username": registration.get("username"),
            }
        )
    if claim["domain"] is not None and registration.get("domain") not in (None, claim["domain"]):
        result["evidence"].append(
            {
                "type": "domain_mismatch",
                "claimed_domain": claim["domain"],
                "registered_domain": registration.get("domain"),
            }
        )
    return result


def review(evtx_path, dictionary):
    """
    Reconcile every identity claim in an EVTX file.

    Args:
      evtx_path (str): path to the Windows EVTX file.
      dictionary (dict): output of load_dictionary.

    Returns:
      list[dict]: one review record per EVTX record.
    """
    return [reconcile_claim(claim, dictionary) for claim in iter_claims(evtx_path)]


PENDING_STATUSES = (
    STATUS_NO_SID,
    STATUS_DICTIONARY_STALE,
    STATUS_CONFLICT,
    STATUS_UNKNOWN_SID,
)


def summarize(results):
    """
    Aggregate review records into per-status counts.

    Args:
      results (list[dict]): output of review().

    Returns:
      dict: status name to record count, plus the total record count.
    """
    counts = {"total": len(results)}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    counts["pending_total"] = sum(counts.get(status, 0) for status in PENDING_STATUSES)
    return counts


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Reconcile explicit SID/username identity claims in an EVTX file against an "
            "offline, point-in-time account dictionary."
        )
    )
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX file")
    parser.add_argument("dictionary", type=str, help="Path to the offline account dictionary JSON file")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional path to write the full JSON report; defaults to stdout",
    )
    args = parser.parse_args()

    dictionary = load_dictionary(args.dictionary)
    results = review(args.evtx, dictionary)
    report = {
        "evtx_path": args.evtx,
        "dictionary_path": args.dictionary,
        "dictionary_version": dictionary.get("version"),
        "dictionary_generated_at": dictionary.get("generated_at"),
        "summary": summarize(results),
        "records": results,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
