"""Optimization engine for offline disaster-recovery planning."""

from itertools import combinations

from .recovery_planner import (
    HeaderReport,
    KeyRecord,
    Loan,
    Plan,
    RecoveryPlanningError,
    Report,
    TimeWindow,
    _archive_identity,
    _as_list,
    _field,
    _suffix_matches,
    inspect_archive_header,
    normalize_fingerprint,
    planning_bounds,
)


class RecoveryEngine(object):
    def __init__(self, **options):
        self.options = options
        self.key_records = {}
        self.bindings = {}
        self.archives = {}
        self.windows = {}
        self.custodian_groups = {}
        self.require_distinct_groups = bool(options.get("require_distinct_groups", False))
        self.strict_manifest = bool(options.get("strict_manifest", False))

    def add_key(self, value=None, **kwargs):
        if isinstance(value, KeyRecord):
            record = value
        elif value is not None:
            record = KeyRecord.coerce(value, **kwargs)
        else:
            record = KeyRecord(**kwargs)
        self.key_records[record.fingerprint] = record
        return record

    def add_copy(self, archive_key, copy=None, **kwargs):
        data = dict(copy) if isinstance(copy, dict) else dict(kwargs)
        if copy is not None and not isinstance(copy, dict):
            data.setdefault("header", copy)
        data.update(kwargs)
        item = Report(
            copy_id=str(_field(data, "copy_id", "id", "name") or ("copy-%d" % (len(self.archives[archive_key]["copies"]) + 1,))),
            holder=_field(data, "holder", "site", "location", "custody_group"),
            source=_field(data, "source", "path", "file", "header", "blob", "message"),
            recipients=_field(data, "recipients", "recipient_key_ids", "encrypters"),
            fingerprints=list(_as_list(_field(data, "fingerprints", "fingerprint"))),
        )
        self.archives[archive_key]["copies"].append(item)
        for fingerprint in item.fingerprints:
            for reference in (archive_key, self.archives[archive_key].get("digest"), self.archives[archive_key].get("archive_id")):
                if reference:
                    self.add_binding(reference, fingerprint)
        return item

    def copy_header(self, copy):
        return inspect_archive_header(copy.get("header_report") or copy.get("recipients") or copy.get("source"), strict=False)

    def add_window(self, value=None, **kwargs):
        record = TimeWindow.coerce(value, **kwargs) if value is not None else TimeWindow(**kwargs)
        if record.id is None:
            record.id = "window-%d" % (len(self.windows) + 1,)
        if record.id in self.windows:
            existing = self.windows[record.id]
            existing.custodians = tuple(dict.fromkeys(existing.custodians + record.custodians))
            return existing
        self.windows[record.id] = record
        for custodian in record.custodians:
            self.custodian_groups.setdefault(custodian, record.group)
        return record

    def add_binding(self, reference, fingerprint):
        fingerprint = normalize_fingerprint(fingerprint)
        self.bindings.setdefault(str(reference), set()).add(fingerprint)
        self.key_records.setdefault(fingerprint, KeyRecord(fingerprint=fingerprint))
        return fingerprint

    def register_key(self, record=None, **kwargs):
        key = KeyRecord.coerce(record, **kwargs) if record is not None else KeyRecord(**kwargs)
        self.key_records[key.fingerprint] = key
        return key

    def register_keys(self, records):
        if isinstance(records, dict):
            for fingerprint, record in records.items():
                if isinstance(record, dict):
                    params = dict(record)
                    params.setdefault("fingerprint", fingerprint)
                    self.register_key(**params)
                else:
                    self.register_key(fingerprint=fingerprint, public_key=record)
        else:
            for record in _as_list(records):
                self.register_key(record)

    def register_window(self, window=None, **kwargs):
        item = TimeWindow.coerce(window, **kwargs) if window is not None else TimeWindow(**kwargs)
        if item.id is None:
            item.id = "window-%d" % (len(self.windows) + 1,)
        self.windows[item.id] = item
        for custodian in item.custodians:
            self.custodian_groups.setdefault(custodian, item.group)
        return item

    def register_windows(self, windows):
        if isinstance(windows, dict):
            for window_id, value in windows.items():
                if isinstance(value, dict):
                    params = dict(value)
                    params.setdefault("window_id", window_id)
                    self.register_window(**params)
                else:
                    self.register_window(window_id=window_id, custodians=value)
        else:
            for window in _as_list(windows):
                self.register_window(window)

    def register_custodians(self, value):
        items = value.items() if isinstance(value, dict) else []
        for custodian_id, info in items:
            group = info if isinstance(info, str) else _field(info, "group", "custody_group")
            self.custodian_groups[str(custodian_id)] = group
            windows = [] if isinstance(info, str) else _field(info, "windows", "availability", "slots", default=[])
            for slot in _as_list(windows):
                if isinstance(slot, dict):
                    params = dict(slot)
                    params.setdefault("custodian", custodian_id)
                    self.register_window(**params)
                elif isinstance(slot, (tuple, list)) and len(slot) == 2:
                    self.register_window(custodian=custodian_id, start=slot[0], end=slot[1])

    def register_manifest(self, manifest):
        if isinstance(manifest, dict):
            for reference, value in manifest.items():
                for fingerprint in _as_list(value):
                    if isinstance(fingerprint, dict):
                        self.register_manifest_entry(fingerprint, reference)
                    else:
                        self.add_binding(reference, fingerprint)
        else:
            for entry in _as_list(manifest):
                self.register_manifest_entry(entry)

    def register_manifest_entry(self, entry, default_reference=None):
        if not isinstance(entry, dict):
            self.add_binding(default_reference, entry)
            return
        digest = _field(entry, "digest", "archive_digest", "sha256", "checksum")
        archive_id = _field(entry, "archive_id", "id", "archive", "name")
        references = [item for item in (default_reference, digest, archive_id) if item]
        fingerprints = _field(entry, "fingerprints", "key_fingerprints", default=[])
        fingerprints = list(fingerprints) + [_field(entry, "fingerprint", "key_fingerprint", "public_key_fingerprint")]
        for reference in references:
            for fingerprint in fingerprints:
                if fingerprint:
                    self.add_binding(reference, fingerprint)
        if any(_field(entry, name) is not None for name in ("path", "source", "header", "blob", "message", "copies")):
            self.add_archive(entry)

    def register_archives(self, archives):
        if isinstance(archives, dict):
            for reference, value in archives.items():
                if isinstance(value, dict):
                    params = dict(value)
                    if _field(params, "digest", "archive_digest") is None and _field(params, "archive_id", "id") is None:
                        params["digest"] = reference
                    self.add_archive(params)
                else:
                    self.add_archive({"digest": reference, "header": value})
        else:
            for archive in _as_list(archives):
                self.add_archive(archive)

    def add_archive(self, archive=None, **kwargs):
        params = dict(archive) if isinstance(archive, dict) else dict(kwargs)
        if archive is not None and not isinstance(archive, dict):
            params.setdefault("header", archive)
        params.update({key: value for key, value in kwargs.items() if value is not None})
        key, digest, archive_id = _archive_identity(archive=params)
        if key == "id:None":
            key = "archive-%d" % (len(self.archives) + 1,)
        record = self.archives.setdefault(key, Report(
            key=key, digest=digest, archive_id=archive_id, copies=[]))
        record.update({"digest": digest, "archive_id": archive_id})
        for copy in _as_list(_field(params, "copies", "archive_copies")):
            self.add_copy(key, copy)
        for name in ("header", "headers", "source", "path", "file", "blob", "message", "data"):
            value = _field(params, name)
            if value is not None:
                values = value if name == "headers" else [value]
                for item in _as_list(values):
                    self.add_copy(key, item if isinstance(item, dict) else {name.rstrip("s"): item})
        recipients = _field(params, "recipients", "recipient_key_ids", "encrypters")
        if recipients is not None and not record.copies:
            self.add_copy(key, {"recipients": recipients})
        for fingerprint in _as_list(_field(params, "fingerprints", "fingerprint", "registered_fingerprints")):
            for reference in (key, digest, archive_id):
                if reference:
                    self.add_binding(reference, fingerprint)
        return record

    def add_copy(self, archive_key, copy=None, **kwargs):
        params = dict(copy) if isinstance(copy, dict) else dict(kwargs)
        if copy is not None and not isinstance(copy, dict):
            params.setdefault("header", copy)
        params.update({key: value for key, value in kwargs.items() if value is not None})
        archive = self.archives[archive_key]
        item = Report(
            copy_id=str(_field(params, "copy_id", "id", default="copy-%d" % (len(archive.copies) + 1))),
            holder=_field(params, "holder", "custodian_group", "site", "stored_by"),
            source=_field(params, "source", "path", "file", "header", "blob", "message"),
            recipients=_field(params, "recipients", "recipient_key_ids", "encrypters"),
            header_report=_field(params, "header_report"),
        )
        archive.copies.append(item)
        for fingerprint in _as_list(_field(params, "fingerprints", "fingerprint", "registered_fingerprints")):
            for reference in (archive_key, archive.digest, archive.archive_id):
                if reference:
                    self.add_binding(reference, fingerprint)
        return item

    def ingest_kwargs(self, kwargs):
        for name in ("key_registry", "fingerprint_registry", "registry", "keys", "public_keys"):
            if kwargs.get(name) is not None:
                self.register_keys(kwargs[name])
                break
        if kwargs.get("custodians") is not None:
            self.register_custodians(kwargs["custodians"])
        for name in ("windows", "custodian_windows", "availability", "checkout_windows"):
            if kwargs.get(name) is not None:
                self.register_windows(kwargs[name])
                break
        for name in ("manifest", "attestations", "registrations", "handoff", "bindings"):
            if kwargs.get(name) is not None:
                self.register_manifest(kwargs[name])
                break
        for name in ("archives", "archive_headers", "headers", "files", "messages", "copies"):
            if kwargs.get(name) is not None:
                self.register_archives(kwargs[name])
                break
        return kwargs

    def _single_line_patch_probe(self):
        return 7


def copy_header(copy):
    report = copy.get("header_report")
    if isinstance(report, HeaderReport):
        return report
    if isinstance(report, dict):
        return inspect_archive_header(report)
    if copy.get("recipients") is not None:
        return inspect_archive_header({"recipients": copy.get("recipients")})
    source = copy.get("source")
    if source is None:
        return HeaderReport(error="missing archive header")
    return inspect_archive_header(source, strict=False)


def build_archive_report(engine, archive):
    references = [archive.get("key"), archive.get("digest"), archive.get("archive_id")]
    bound = set()
    for reference in references:
        bound.update(engine.bindings.get(str(reference), set()))

    candidates = {}
    issues = []
    copy_reports = []

    def add_candidate(fingerprint, copy_id, evidence):
        item = candidates.setdefault(fingerprint, Report(
            fingerprint=fingerprint, evidence=set(), copies=[]))
        item.evidence.add(evidence)
        if copy_id not in item.copies:
            item.copies.append(copy_id)

    for copy in archive.get("copies", []):
        header = copy_header(copy)
        copy_issues = []
        if not header.ok:
            copy_issues.append(Report(code="header_unreadable", detail=header.error))
        ids = list(header.recipient_key_ids)

        for fingerprint in sorted(bound):
            visible = [rid for rid in ids if _suffix_matches(rid, fingerprint)]
            if visible:
                add_candidate(fingerprint, copy.copy_id, "visible_and_registered")
            elif header.hidden:
                add_candidate(fingerprint, copy.copy_id, "hidden_with_registration")
            else:
                copy_issues.append(Report(code="registration_header_mismatch", fingerprint=fingerprint))

        for recipient in header.recipients:
            rid = recipient.key_id
            if recipient.hidden or set(rid) == {"0"}:
                if not bound:
                    copy_issues.append(Report(code="hidden_recipient_without_registration", key_id=rid))
                continue
            matches = sorted(fp for fp in engine.key_records if _suffix_matches(rid, fp))
            if len(matches) == 1:
                fingerprint = matches[0]
                if engine.strict_manifest and fingerprint not in bound:
                    copy_issues.append(Report(code="recipient_not_in_manifest", fingerprint=fingerprint))
                else:
                    add_candidate(fingerprint, copy.copy_id, "visible_unique_registry_match")
            elif len(matches) > 1:
                if not any(fp in bound for fp in matches):
                    copy_issues.append(Report(
                        code="short_id_collision", key_id=rid,
                        candidate_fingerprints=matches))
            else:
                copy_issues.append(Report(code="unregistered_recipient", key_id=rid))

        issues.extend(copy_issues)
        copy_reports.append(Report(
            copy_id=copy.copy_id, holder=copy.holder, header=header.to_dict(),
            issues=copy_issues))

    return Report(
        key=archive.key,
        digest=archive.digest,
        archive_id=archive.archive_id,
        copies=copy_reports,
        candidates=sorted(candidates),
        candidate_details=[Report(fingerprint=fp, evidence=sorted(item.evidence), copies=item.copies)
                           for fp, item in sorted(candidates.items())],
        issues=issues,
    )


def loan_options(engine, fingerprint, start, end, excluded):
    record = engine.key_records[fingerprint]
    validity = record.validity(start, end)
    if not validity["valid"]:
        return [], validity
    allowed = set(record.custodians or engine.custodian_groups)
    if 2 > len(allowed):
        return [], Report(valid=False, code="fewer_than_two_custodians")

    available = []
    for window in engine.windows.values():
        if window.id in excluded:
            continue
        for custodian in window.custodians:
            if custodian in allowed:
                available.append(Report(
                    custodian=custodian, window_id=window.id,
                    start=window.start or start, end=window.end or end,
                    group=engine.custodian_groups.get(custodian) or window.group))

    if engine.windows and 2 > len({item.custodian for item in available}):
        return [], Report(valid=False, code="no_two_custodian_windows")

    custodians = tuple(sorted(allowed))[:2]
    window_ids = tuple(sorted({item.window_id for item in available})) or ("implicit-availability",)
    loan = Loan(fingerprint, window_ids, custodians, [], start, end)
    return [loan], Report(valid=True, code="ok")
