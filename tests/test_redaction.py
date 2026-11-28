import io
import json

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.redaction import (
    DISCLOSE,
    RETAIN,
    SEAL,
    EvidenceLog,
    RedactionPolicy,
    preserve_options,
    redact_capture,
    redact_options,
)

SHARED_COMMENT = "外发前需审批的备注"
UNKNOWN_OPTION_CODE = 65000
UNKNOWN_OPTION_RAW = b"\xde\xad\xbe\xef"
PACKET_PAYLOAD = b"\x00\x01\x02payload-bytes"

# Block positions in the capture built by build_capture()
IDX_SHB = 0
IDX_IDB = 1
IDX_ISB_APPROVED = 2
IDX_ISB_SEALED = 3
IDX_EPB = 4


def build_capture():
    """A capture with two zero-payload records carrying the same comment."""
    shb = blocks.SectionHeader(options={"shb_userappl": "python-pcapng tests"})
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_name": "eth0"},
    )
    isb_approved = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        options={"opt_comment": [SHARED_COMMENT], "isb_usrdeliv": 42},
    )
    isb_sealed = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        options={"opt_comment": [SHARED_COMMENT]},
    )
    isb_sealed.options.data[UNKNOWN_OPTION_CODE] = [UNKNOWN_OPTION_RAW]
    epb = shb.new_member(
        blocks.EnhancedPacket, interface_id=0, packet_data=PACKET_PAYLOAD
    )

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for blk in (isb_approved, isb_sealed, epb):
        writer.write_block(blk)
    return stream.getvalue()


def run_redaction(policy):
    out_stream = io.BytesIO()
    evidence_stream = io.StringIO()
    evidence = redact_capture(
        io.BytesIO(build_capture()), out_stream, evidence_stream, policy
    )
    out_stream.seek(0)
    out_blocks = list(FileScanner(out_stream))
    records = [
        json.loads(line) for line in evidence_stream.getvalue().splitlines()
    ]
    return out_blocks, records, evidence


def find_option_record(records, block_index, option_code):
    for record in records:
        if (
            record["record"] == "option"
            and record["block_index"] == block_index
            and record["option_code"] == option_code
        ):
            return record
    raise AssertionError(
        "no evidence record for block {0} option {1}".format(
            block_index, option_code
        )
    )


def test_external_copy_discloses_only_the_approved_occurrence():
    policy = RedactionPolicy(approved_comments=[(IDX_ISB_APPROVED, SHARED_COMMENT)])
    out_blocks, _, _ = run_redaction(policy)

    # The file itself is retained: every block is still there.
    assert [type(b) for b in out_blocks] == [
        blocks.SectionHeader,
        blocks.InterfaceDescription,
        blocks.InterfaceStatistics,
        blocks.InterfaceStatistics,
        blocks.EnhancedPacket,
    ]

    # The same comment is disclosed in the approved place only.
    isb_approved, isb_sealed = out_blocks[2], out_blocks[3]
    assert isb_approved.options["opt_comment"] == SHARED_COMMENT
    assert "opt_comment" not in isb_sealed.options

    # The unknown option is not disclosed externally by default.
    assert UNKNOWN_OPTION_CODE not in isb_sealed.options.data

    # Known non-comment options pass through untouched.
    assert out_blocks[IDX_IDB].options["if_name"] == "eth0"
    assert isb_approved.options["isb_usrdeliv"] == 42

    # Packet payloads are copied verbatim, never parsed.
    assert out_blocks[IDX_EPB].packet_data == PACKET_PAYLOAD


def test_evidence_log_keeps_the_internal_cross_reference():
    policy = RedactionPolicy(approved_comments=[(IDX_ISB_APPROVED, SHARED_COMMENT)])
    _, records, evidence = run_redaction(policy)

    approved = find_option_record(records, IDX_ISB_APPROVED, 1)
    assert approved["block_type"] == "InterfaceStatistics"
    assert approved["option_name"] == "opt_comment"
    assert approved["action"] == DISCLOSE
    assert approved["value"] == SHARED_COMMENT

    sealed = find_option_record(records, IDX_ISB_SEALED, 1)
    assert sealed["action"] == SEAL
    assert sealed["value"] == SHARED_COMMENT

    # The unknown option is preserved raw, with its original location.
    unknown = find_option_record(records, IDX_ISB_SEALED, UNKNOWN_OPTION_CODE)
    assert unknown["option_name"] is None
    assert unknown["action"] == SEAL
    assert unknown["value_hex"] == UNKNOWN_OPTION_RAW.hex()

    retained = find_option_record(records, IDX_IDB, 2)
    assert retained["option_name"] == "if_name"
    assert retained["action"] == RETAIN

    # The summary proves the retention scope of the file itself.
    summary = [r for r in records if r["record"] == "summary"]
    assert len(summary) == 1
    assert summary[0]["blocks_scanned"] == 5
    assert summary[0]["options_disclose"] == 1
    assert summary[0]["options_seal"] == 2
    assert summary[0]["options_retain"] == 3
    assert dict(evidence.counters) == {
        "options_disclose": 1,
        "options_seal": 2,
        "options_retain": 3,
    }


def test_preservation_and_redaction_are_separate_actions():
    policy = RedactionPolicy()  # nothing approved
    shb = blocks.SectionHeader()
    isb = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        options={"opt_comment": [SHARED_COMMENT], "isb_usrdeliv": 7},
    )
    snapshot = {code: list(values) for code, values in isb.options.data.items()}

    evidence = EvidenceLog(io.StringIO())
    decisions = preserve_options(
        isb.options, 0, "InterfaceStatistics", policy, evidence
    )

    # Preservation only records; it must not modify the block.
    assert {code: list(values) for code, values in isb.options.data.items()} == snapshot
    assert decisions == [(1, 0, SEAL), (8, 0, RETAIN)]

    # Redaction only removes what preservation decided to seal.
    redact_options(isb.options, decisions)
    assert "opt_comment" not in isb.options
    assert isb.options["isb_usrdeliv"] == 7


def test_unknown_options_disclosed_only_when_policy_allows():
    policy = RedactionPolicy(
        approved_comments=lambda block_index, text: False,
        keep_unknown_options=True,
    )
    out_blocks, records, _ = run_redaction(policy)

    isb_sealed = out_blocks[IDX_ISB_SEALED]
    assert isb_sealed.options.data[UNKNOWN_OPTION_CODE] == [UNKNOWN_OPTION_RAW]
    assert "opt_comment" not in isb_sealed.options

    unknown = find_option_record(records, IDX_ISB_SEALED, UNKNOWN_OPTION_CODE)
    assert unknown["action"] == RETAIN
    assert unknown["value_hex"] == UNKNOWN_OPTION_RAW.hex()
