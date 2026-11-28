"""
Tools for lawful redaction of pcap-ng files before external disclosure.

The capture team may only disclose a subset of the comments stored in a
capture, while the retention scope of the file itself still has to be
proven.  This module keeps the two required actions strictly separate:

* **Comment preservation** (:py:func:`preserve_options`) records every
  option of every block -- together with its original location -- into an
  internal evidence log.  Nothing is removed at this stage.

* **Lawful redaction** (:py:func:`redact_options`) trims a block's options
  down to the items approved for external disclosure, based on the
  decisions recorded during preservation.

:py:func:`redact_capture` drives both actions over a capture, producing
the external file and the internal evidence log.  Packet payloads are
copied through verbatim and are never parsed.  Options whose code is not
part of the known schema are protected: they are preserved raw in the
evidence log and only disclosed externally when the policy says so.
"""


import json
from collections import defaultdict

from pcapng.blocks import SectionHeader, UnknownBlock
from pcapng.scanner import FileScanner
from pcapng.writer import FileWriter

COMMENT_OPTION_CODE = 1  # opt_comment, common to all blocks

#: Option is approved for disclosure and stays in the external copy.
DISCLOSE = "disclose"
#: Option is withheld from the external copy; the evidence log is the
#: only place where it is retained.
SEAL = "seal"
#: Option is not subject to approval and passes through unchanged.
RETAIN = "retain"


class RedactionPolicy(object):
    """
    Decides which comments may be disclosed externally.

    :param approved_comments:
        Either a callable taking (block_index, comment_text) and returning
        a boolean, or an iterable of (block_index, comment_text) tuples
        approving one specific occurrence of a comment.  The block index
        is the position of the block in the original capture, starting at
        0 -- this is what allows the same comment text to be approved in
        one place and sealed in another.
    :param keep_unknown_options:
        If True, options with a code that is not part of the known schema
        are also kept in the external copy.  They are always preserved in
        the evidence log regardless of this flag.
    """

    def __init__(self, approved_comments=(), keep_unknown_options=False):
        if callable(approved_comments):
            self._approved = approved_comments
        else:
            approved = set(approved_comments)
            self._approved = (
                lambda block_index, text: (block_index, text) in approved
            )
        self.keep_unknown_options = keep_unknown_options

    def is_comment_approved(self, block_index, text):
        """Whether this occurrence of a comment may be disclosed."""
        return bool(self._approved(block_index, text))


class EvidenceLog(object):
    """
    Internal cross-reference of where each option came from and what
    happened to it.  Written as JSON lines, one record per option, plus
    one summary record proving the retention scope of the file itself.

    :param stream: a text-mode stream the records are written to.
    """

    def __init__(self, stream):
        self.stream = stream
        self.counters = defaultdict(int)

    def _write_record(self, record):
        self.stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
        self.stream.write("\n")

    def record_option(self, block_index, block_type, code, name, action, value):
        record = {
            "record": "option",
            "block_index": block_index,
            "block_type": block_type,
            "option_code": code,
            "option_name": name,
            "action": action,
        }
        record.update(_value_evidence(value))
        self.counters["options_" + action] += 1
        self._write_record(record)

    def record_block(self, block_index, block_type, action, detail=None):
        record = {
            "record": "block",
            "block_index": block_index,
            "block_type": block_type,
            "action": action,
        }
        if detail is not None:
            record["detail"] = detail
        self.counters["blocks_" + action] += 1
        self._write_record(record)

    def summary(self, blocks_scanned):
        """Write the closing record proving the file's retention scope."""
        record = {"record": "summary", "blocks_scanned": blocks_scanned}
        record.update(sorted(self.counters.items()))
        self._write_record(record)


def _value_evidence(value):
    if isinstance(value, str):
        return {"value": value}
    if isinstance(value, (bytes, bytearray)):
        return {"value_hex": bytes(value).hex()}
    return {"value_repr": repr(value)}


def _option_action(options, code, value, block_index, policy):
    if code == COMMENT_OPTION_CODE:
        if policy.is_comment_approved(block_index, value):
            return DISCLOSE
        return SEAL
    if code not in options.schema:
        if policy.keep_unknown_options:
            return RETAIN
        return SEAL
    return RETAIN


def preserve_options(options, block_index, block_type, policy, evidence):
    """
    Preservation pass: record every option of a block, with its original
    location, into the evidence log.  The block is not modified.

    :returns: a list of (option_code, position, action) decisions, one
        per option value, to be consumed by :py:func:`redact_options`.
    """
    decisions = []
    for code in sorted(options.data):
        name = options.schema[code].name if code in options.schema else None
        for position, value in enumerate(options.data[code]):
            action = _option_action(options, code, value, block_index, policy)
            evidence.record_option(
                block_index, block_type, code, name, action, value
            )
            decisions.append((code, position, action))
    return decisions


def redact_options(options, decisions):
    """
    Redaction pass: remove every sealed option value from the block, so
    only approved items remain in the external copy.
    """
    kept_positions = defaultdict(list)
    for code, position, action in decisions:
        if action != SEAL:
            kept_positions[code].append(position)
    for code in list(options.data):
        positions = kept_positions.get(code)
        if positions is None:
            del options.data[code]
        elif len(positions) != len(options.data[code]):
            options.data[code] = [options.data[code][i] for i in positions]


def redact_capture(in_stream, out_stream, evidence_stream, policy):
    """
    Produce the external copy of a capture and its internal evidence log.

    Blocks are scanned from in_stream and written to out_stream after
    redaction; packet payloads are copied verbatim and never parsed.
    Every option decision is recorded to evidence_stream (a text-mode
    stream) with the option's original location.

    :returns: the :py:class:`EvidenceLog` used, for inspection of the
        recorded counters.
    """
    evidence = EvidenceLog(evidence_stream)
    writer = None
    block_index = 0
    for block in FileScanner(in_stream):
        if isinstance(block, UnknownBlock):
            evidence.record_block(
                block_index,
                "UnknownBlock",
                SEAL,
                detail="block_type=0x{0:08x}".format(block.block_type),
            )
            block_index += 1
            continue
        if hasattr(block, "options"):
            decisions = preserve_options(
                block.options, block_index, type(block).__name__, policy, evidence
            )
            redact_options(block.options, decisions)
        if isinstance(block, SectionHeader):
            writer = FileWriter(out_stream, block)
        else:
            writer.write_block(block)
        block_index += 1
    evidence.summary(block_index)
    return evidence

