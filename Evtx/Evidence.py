#!/usr/bin/python
#    This file is part of python-evtx.
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
"""Per-record provenance for the BinXML nodes used to render an event.

The XML view of an EVTX record is intentionally lossy: a template definition
and the record's substitution area are turned into one string.  Once that
happens, two records that render to the same XML are indistinguishable.  This
module keeps the link between the rendered values and the binary structures
they came from.

The important identity rule is that a template is identified by *where it is
stored*, not merely by its template id or by a chunk-relative template
offset.  Chunk-relative offsets are reused by different chunks (and by
different evidence files), so a cache entry for one chunk must never satisfy a
lookup from another chunk.  Within a single chunk it is safe (and useful) to
reuse a parsed template.
"""

from __future__ import absolute_import

import hashlib

import Evtx.Nodes as e_nodes


class EvidenceRecord(dict):
    """A dict with attribute access and a few compatibility aliases.

    The public evidence interface is deliberately a plain mapping so that it
    can be serialized directly.  Attribute access and aliases make the report
    convenient to consume without constraining callers to one spelling of a
    field name.
    """

    _aliases = {}

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        target = self._aliases.get(key, key)
        if callable(target):
            return target()
        return dict.__getitem__(self, target)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        target = self._aliases.get(key, key)
        if callable(target):
            return True
        return dict.__contains__(self, target)


class ByteRange(EvidenceRecord):
    """The absolute byte range occupied by a piece of evidence.

    `start` is inclusive and `end` is exclusive.  Record- and chunk-relative
    views of the same range are included because both are useful during a
    review: the former verifies the bytes inside the record, the latter
    locates the bytes inside a page/block.
    """

    _aliases = {
        "start_offset": "start",
        "end_offset": "end",
        "offset": "start",
        "size": "length",
        "absolute_range": ("absolute_start", "absolute_end"),
        "record_range": ("record_start", "record_end"),
        "chunk_range": ("chunk_start", "chunk_end"),
    }

    def __getitem__(self, key):
        if key == 0:
            return dict.__getitem__(self, "start")
        if key == 1:
            return dict.__getitem__(self, "end")
        target = self._aliases.get(key)
        if isinstance(target, tuple):
            return (dict.__getitem__(self, target[0]), dict.__getitem__(self, target[1]))
        return super(ByteRange, self).__getitem__(key)

    def __eq__(self, other):
        if isinstance(other, (tuple, list)) and len(other) == 2:
            return (self["start"], self["end"]) == other
        return dict.__eq__(self, other)

    __hash__ = None


def _range(start, length, record=None, chunk=None):
    end = start + length
    return ByteRange(
        start=start,
        end=end,
        length=length,
        offset_length=(start, length),
        span=(start, length),
        absolute_start=start,
        absolute_end=end,
        chunk_start=(start - chunk.offset()) if chunk is not None else None,
        chunk_end=(end - chunk.offset()) if chunk is not None else None,
        record_start=(start - record.offset()) if record is not None else None,
        record_end=(end - record.offset()) if record is not None else None,
    )


def _chunk_of(record):
    return getattr(record, "_chunk", None)


def _chunk_offset(chunk):
    if chunk is None:
        return None
    try:
        return chunk.offset()
    except Exception:
        return None


def _artifact_id(chunk):
    """Return an identity for the file/buffer that contains a chunk.

    The same chunk-relative template offset in two files is not the same
    evidence.  The buffer identity keeps those two origins apart when a cache
    is shared across more than one log.
    """

    buf = getattr(chunk, "_buf", None)
    return id(buf) if buf is not None else id(chunk)


def _chunk_identity(chunk):
    artifact = _artifact_id(chunk)
    offset = _chunk_offset(chunk)
    return (artifact, offset)


def _node_token(node):
    try:
        return node.token()
    except Exception:
        return None


def _node_range(node, record, chunk):
    try:
        offset = node.offset()
        length = node.length()
    except Exception:
        return None
    return _range(offset, length, record=record, chunk=chunk)


def _template_fingerprint(template, chunk):
    """Identify the template bytes, so a stale cache entry cannot be reused
    after the same offset has been replaced by different evidence."""

    try:
        template_id = template.template_id()
    except Exception:
        template_id = None
    try:
        guid = template.guid()
    except Exception:
        guid = None
    try:
        data_length = template.data_length()
    except Exception:
        data_length = None

    digest = None
    buf = getattr(chunk, "_buf", None)
    if buf is not None:
        try:
            start = template.offset()
            end = start + template.length()
            digest = hashlib.sha256(bytes(buf[start:end])).hexdigest()
        except Exception:
            digest = None

    return (template_id, guid, data_length, digest)


def _make_template_source(record, chunk, instance, template, cache):
    chunk_offset = _chunk_offset(chunk)
    template_offset = instance.template_offset()
    template_absolute = template.offset()
    fingerprint = _template_fingerprint(template, chunk)
    cache_key = ("evtx.evidence.template", _artifact_id(chunk), chunk_offset, template_absolute)

    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]

    digest = fingerprint[3]
    source_id = "{}:{}:{}:{}".format(
        _artifact_id(chunk),
        "-" if chunk_offset is None else hex(chunk_offset),
        hex(template_offset),
        "-" if digest is None else digest[:12],
    )

    data_offset = template.offset() + 0x18
    data_length = template.data_length()
    source = EvidenceRecord(
        kind="template",
        source_id=source_id,
        source=source_id,
        artifact_id=_artifact_id(chunk),
        chunk_offset=chunk_offset,
        template_offset=template_offset,
        template_absolute_offset=template_absolute,
        template_id=fingerprint[0],
        guid=fingerprint[1],
        data_offset=data_offset,
        data_length=data_length,
        digest=digest,
        resident=(bool(instance.is_resident_template()) if chunk is not None else False),
        origin=(chunk_offset, template_offset),
        range=_range(template.offset(), template.length(), record=record, chunk=chunk),
        data_range=_range(data_offset, data_length, record=record, chunk=chunk),
        record_offset=(template.offset() - record.offset()) if record is not None else None,
    )
    source._aliases = {
        "chunk": "chunk_offset",
        "chunk_file_offset": "chunk_offset",
        "offset": "template_absolute_offset",
        "absolute_offset": "template_absolute_offset",
        "template_range": "range",
        "byte_range": "range",
        "template_data_range": "data_range",
        "hash": "digest",
        "sha256": "digest",
        "template_guid": "guid",
        "id": "source_id",
        "origin": "origin",
        "source_locator": "origin",
    }
    # Keep the mmap/buffer alive for as long as the source object is reachable.
    # This prevents Python from recycling its id and accidentally aliasing a
    # later artifact's template cache entry.
    source._artifact_buffer = getattr(chunk, "_buf", None)

    if cache is not None:
        cache[cache_key] = (fingerprint, source, getattr(chunk, "_buf", None))
    return source


class _Collector(object):
    def __init__(self, record, cache=None):
        self.record = record
        self.chunk = _chunk_of(record)
        self.cache = cache if cache is not None else {}
        self._owns_cache = cache is None
        self.sources = []
        self._source_ids = set()
        self.values = []
        self.literals = []
        self.missing = []
        self.visited = 0
        self._visited_root_ids = set()

    def add_source(self, source):
        source_id = source["source_id"]
        if source_id not in self._source_ids:
            self._source_ids.add(source_id)
            self.sources.append(source)
        return source

    def add_missing(self, node, path, source, reason):
        entry = EvidenceRecord(
            kind="missing_node",
            node_type=node.__class__.__name__,
            token=_node_token(node),
            offset=getattr(node, "offset", lambda: None)(),
            length=(node.length() if hasattr(node, "length") else None),
            range=_node_range(node, self.record, self.chunk),
            path=path,
            reason=reason,
            template_source=source,
        )
        entry._aliases = {
            "class": "node_type",
            "node": "node_type",
            "node_class": "node_type",
            "source": "template_source",
        }
        self.missing.append(entry)
        return entry

    def _value_entry(
        self, node, index, value, kind, scope, path, source, template_node_offset=None, template_node=None
    ):
        declared_type = None
        try:
            declared_type = node.type()
        except Exception:
            pass
        template_node_range = None
        if template_node is not None:
            try:
                template_node_offset = template_node.offset() - source["template_absolute_offset"]
                template_node_range = _node_range(template_node, self.record, self.chunk)
            except Exception:
                template_node_range = None
        entry = EvidenceRecord(
            kind=kind,
            index=index,
            type=declared_type,
            token=_node_token(node),
            value_type=node.__class__.__name__,
            value=value,
            scope=scope,
            offset=getattr(node, "offset", lambda: None)(),
            length=(node.length() if hasattr(node, "length") else None),
            range=_node_range(node, self.record, self.chunk),
            path=path,
            paths=[path] if path else [],
            referenced=(kind == "substitution"),
            conditional=None,
            suppressed=False,
            template_source=source,
            template_node_offset=template_node_offset,
            template_node_range=template_node_range,
        )
        entry._aliases = {
            "byte_range": "range",
            "value_range": "range",
            "start": lambda: (entry["range"]["start"] if entry["range"] else None),
            "end": lambda: (entry["range"]["end"] if entry["range"] else None),
            "absolute_range": lambda: (
                (entry["range"]["absolute_start"], entry["range"]["absolute_end"]) if entry["range"] else None
            ),
            "chunk_range": lambda: (
                (entry["range"]["chunk_start"], entry["range"]["chunk_end"]) if entry["range"] else None
            ),
            "record_range": lambda: (
                (entry["range"]["record_start"], entry["range"]["record_end"]) if entry["range"] else None
            ),
            "source": "template_source",
            "template_source_id": lambda: (
                entry["template_source"]["source_id"] if entry["template_source"] else None
            ),
            "class": "value_type",
            "value_class": "value_type",
        }
        if kind == "substitution":
            self.values.append(entry)
        else:
            self.literals.append(entry)
        return entry

    def collect(self):
        root = self.record.root()
        self._collect_root(root, path="", parent_path="")
        report = EvidenceRecord(
            record_number=self.record.record_num(),
            record_offset=self.record.offset(),
            chunk_offset=_chunk_offset(self.chunk),
            template_source=(self.sources[0] if self.sources else None),
            template_sources=self.sources,
            value_ranges=self.values,
            literal_ranges=self.literals,
            uncaptured_nodes=self.missing,
            evidence=None,
            visited_node_count=self.visited,
            captured_value_count=len(self.values) + len(self.literals),
        )
        report._aliases = {
            "record_num": "record_number",
            "record_id": "record_number",
            "chunk": "chunk_offset",
            "template": "template_source",
            "source": "template_source",
            "template_origin": "template_source",
            "templates": "template_sources",
            "values": "value_ranges",
            "substitutions": "value_ranges",
            "substitution_values": "value_ranges",
            "values_by_index": lambda: {value["index"]: value for value in self.values},
            "substitutions_by_index": lambda: {value["index"]: value for value in self.values},
            "value_evidence": "value_ranges",
            "literals": "literal_ranges",
            "missing": "uncaptured_nodes",
            "missing_nodes": "uncaptured_nodes",
            "missing_node_evidence": "uncaptured_nodes",
            "missing_node_types": lambda: [n["node_type"] for n in self.missing],
            "missing_node_names": lambda: [n["node_type"] for n in self.missing],
            "uncollected_nodes": "uncaptured_nodes",
            "uncollected_node_evidence": "uncaptured_nodes",
            "node_gaps": "uncaptured_nodes",
            "manifest": "evidence",
            "source_id": lambda: (self.sources[0]["source_id"] if self.sources else None),
            "guid": lambda: (self.sources[0]["guid"] if self.sources else None),
            "template_guid": lambda: (self.sources[0]["guid"] if self.sources else None),
            "template_range": lambda: (self.sources[0]["range"] if self.sources else None),
        }
        report["evidence"] = self.evidence_manifest()
        report.visited_node_count = self.visited
        return report

    def evidence_manifest(self):
        manifest = []
        for source in self.sources:
            manifest.append(
                EvidenceRecord(kind="template", source=source, template_source=source, range=source["range"])
            )
        for value in self.values + self.literals:
            manifest.append(value)
        for gap in self.missing:
            manifest.append(gap)
        return manifest

    def _collect_root(self, root, path, parent_path=""):
        root_id = id(root)
        if root_id in self._visited_root_ids:
            return None
        self._visited_root_ids.add(root_id)

        instance = root.template_instance()
        template = root.template()
        source = _make_template_source(self.record, self.chunk, instance, template, self.cache)
        self.add_source(source)

        # The root's stream-start token and the template instance are outside
        # the template body.  Stream starts are structural and therefore have
        # no value payload; report them rather than silently dropping them.
        for child in root.children():
            self.visited += 1
            if isinstance(child, e_nodes.TemplateInstanceNode):
                continue
            if isinstance(child, e_nodes.StreamStartNode):
                self.add_missing(child, path, source, "structural token has no value payload")
            else:
                self.add_missing(child, path, source, "node is outside the rendered template")

        self._walk_template(root, template, source, path)
        return source

    def _walk_template(self, root, template, source, path):
        subs = root.substitutions()
        sub_entries = {}

        def get_sub_entry(index, node, node_path, conditional):
            if index < 0 or index >= len(subs):
                self.add_missing(node, node_path, source, "substitution index out of range")
                return None
            sub = subs[index]
            entry = sub_entries.get(index)
            if entry is None:
                entry = self._value_entry(
                    sub,
                    index,
                    sub.string(),
                    "substitution",
                    "record",
                    node_path,
                    source,
                    template_node=node,
                )
                sub_entries[index] = entry
                if isinstance(sub, e_nodes.BXmlTypeNode):
                    nested_source = self._collect_root(sub.root(), node_path, parent_path=node_path)
                    entry["nested_template_source"] = nested_source
            else:
                if node_path and node_path not in entry["paths"]:
                    entry["paths"].append(node_path)
                if not entry["path"]:
                    entry["path"] = node_path
            if conditional is not None:
                entry["conditional"] = bool(entry["conditional"] or conditional)
                if conditional and isinstance(sub, e_nodes.NullTypeNode):
                    entry["suppressed"] = True
            return entry

        def walk(node, node_path):
            self.visited += 1

            if isinstance(node, e_nodes.OpenStartElementNode):
                tag_path = node_path.rstrip("/") + "/" + node.tag_name()
                for child in node.children():
                    if isinstance(child, e_nodes.AttributeNode):
                        walk(child, tag_path)
                    else:
                        walk(child, tag_path)
                return

            if isinstance(node, e_nodes.AttributeNode):
                attr_path = node_path.rstrip("/") + "/@" + node.attribute_name().string()
                walk(node.attribute_value(), attr_path)
                return

            if isinstance(node, e_nodes.ValueNode):
                variant = node.children()[0]
                self._value_entry(variant, None, variant.string(), "literal", "template", node_path, source)
                if isinstance(variant, e_nodes.BXmlTypeNode):
                    self._collect_root(variant.root(), node_path, parent_path=node_path)
                return

            if isinstance(node, e_nodes.NormalSubstitutionNode):
                get_sub_entry(node.index(), node, node_path, conditional=False)
                return

            if isinstance(node, e_nodes.ConditionalSubstitutionNode):
                get_sub_entry(node.index(), node, node_path, conditional=True)
                return

            if isinstance(node, e_nodes.CDataSectionNode):
                self._value_entry(node, None, node.cdata(), "literal", "template", node_path, source)
                return

            if isinstance(node, (e_nodes.CharacterReferenceNode, e_nodes.EntityReferenceNode)):
                self._value_entry(
                    node, None, node.entity_reference(), "literal", "template", node_path, source
                )
                return

            if isinstance(node, e_nodes.ProcessingInstructionTargetNode):
                self._value_entry(
                    node, None, node.processing_instruction_target(), "literal", "template", node_path, source
                )
                return

            if isinstance(node, e_nodes.ProcessingInstructionDataNode):
                self._value_entry(node, None, node.string(), "literal", "template", node_path, source)
                return

            if isinstance(node, e_nodes.TemplateInstanceNode):
                # A nested instance is unusual inside a template body, but if
                # it occurs its own template is a separate origin.
                self.add_missing(node, node_path, source, "template instance without a record root")
                return

            if isinstance(
                node,
                (
                    e_nodes.StreamStartNode,
                    e_nodes.EndOfStreamNode,
                    e_nodes.CloseStartElementNode,
                    e_nodes.CloseEmptyElementNode,
                    e_nodes.CloseElementNode,
                ),
            ):
                self.add_missing(node, node_path, source, "structural token has no value payload")
                return

            self.add_missing(node, node_path, source, "node type has no evidence collector")

        for child in template.children():
            walk(child, path)

        # Substitutions that the template does not reference still exist in
        # the record and are part of the replacement data.  Include them so
        # the evidence list is complete.
        for index, sub in enumerate(subs):
            if index not in sub_entries:
                entry = self._value_entry(
                    sub, index, sub.string(), "substitution", "record", "", source, template_node_offset=None
                )
                sub_entries[index] = entry
                if isinstance(sub, e_nodes.BXmlTypeNode):
                    entry["nested_template_source"] = self._collect_root(
                        sub.root(), "", parent_path=""
                    )
            if not sub_entries[index]["referenced"]:
                sub_entries[index]["referenced"] = False


def collect_record_evidence(record, cache=None):
    """Collect per-record binary evidence used to render an event.

    Args:
      record (Evtx.Evtx.Record): the record to inspect.
      cache (dict, optional): a cache shared by callers.  It is namespaced by
        the artifact buffer, chunk offset, and absolute template offset, so a
        chunk-relative template offset from one page/block (or another file)
        never resolves to a template from a different origin.

    Returns:
      EvidenceRecord: a mapping describing the template origin, every
        substitution value range, and the nodes for which no value evidence
        exists.
    """

    return _Collector(record, cache=cache).collect()


def evtx_record_evidence_view(record, cache=None):
    """Alias for :func:`collect_record_evidence`."""
    return collect_record_evidence(record, cache=cache)


evtx_record_provenance_view = evtx_record_evidence_view
evtx_record_forensic_view = evtx_record_evidence_view
record_evidence = evtx_record_evidence_view
collect_evidence = collect_record_evidence

# Type aliases for callers that prefer to name the records explicitly.  They
# are the same mapping type, so no conversion is required.
RecordEvidence = EvidenceRecord
TemplateSource = EvidenceRecord
ValueEvidence = EvidenceRecord
MissingNodeEvidence = EvidenceRecord
