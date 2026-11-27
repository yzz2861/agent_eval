from __future__ import annotations

import copy
from pathlib import Path

from dissect.eventlog.evtx.proof import build_event_proofs, verify_event_proof


CHUNK_SIZE = 0x10000
HEADER_SIZE = 0x1000


def _micro_evtx(template_guid: bytes) -> bytes:
    source = Path(__file__).parent.joinpath("_data/TestLogX.evtx").read_bytes()
    source_chunk = source[HEADER_SIZE : HEADER_SIZE + CHUNK_SIZE]
    record_start = 512
    record_size = int.from_bytes(source_chunk[record_start + 4 : record_start + 8], "little")
    record = bytearray(source_chunk[record_start : record_start + record_size])
    template_offset = 38
    record[template_offset + 4 : template_offset + 20] = template_guid

    chunk = bytearray(CHUNK_SIZE)
    chunk[:8] = b"ElfChnk\x00"
    chunk[24:28] = (512).to_bytes(4, "little")
    chunk[28:32] = (512 + record_size).to_bytes(4, "little")
    chunk[32:36] = (512 + record_size).to_bytes(4, "little")
    chunk[record_start : record_start + record_size] = record

    header = bytearray(HEADER_SIZE)
    header[:8] = b"ElfFile\x00"
    header[32:36] = (128).to_bytes(4, "little")
    header[36:38] = (1).to_bytes(2, "little")
    header[38:40] = (1).to_bytes(2, "little")
    header[40:42] = HEADER_SIZE.to_bytes(2, "little")
    return bytes(header + chunk)


def test_evtx_proof_round_trip_and_differentiated_mismatches(tmp_path: Path) -> None:
    first_path = tmp_path / "first.evtx"
    second_path = tmp_path / "second.evtx"
    first_path.write_bytes(_micro_evtx(b"0123456789abcdef"))
    second_path.write_bytes(_micro_evtx(b"fedcba9876543210"))

    with first_path.open("rb") as first_fh, second_path.open("rb") as second_fh:
        first_proof = build_event_proofs(first_fh)[0]
        second_proof = build_event_proofs(second_fh)[0]

        assert first_proof.event == second_proof.event
        assert first_proof.chunk.sha256 != second_proof.chunk.sha256
        assert first_proof.record.sha256 != second_proof.record.sha256
        assert first_proof.templates[0].sha256 != second_proof.templates[0].sha256

        first_result = verify_event_proof(first_fh, first_proof.to_dict())
        assert first_result.valid
        read_ranges = {(item.offset, item.length) for item in first_result.read_ranges}
        assert (first_proof.chunk.offset, first_proof.chunk.length) not in read_ranges
        assert (0, first_proof.file_size) not in read_ranges
        assert all(item.offset >= first_proof.chunk.offset for item in first_result.read_ranges)
        assert all(
            item.offset + item.length <= first_proof.chunk.offset + first_proof.chunk.length
            for item in first_result.read_ranges
        )

        swapped = copy.deepcopy(first_proof.to_dict())
        swapped["record"]["sha256"] = second_proof.record.sha256
        swapped_result = verify_event_proof(first_fh, swapped)
        assert not swapped_result.valid
        assert {item.path for item in swapped_result.mismatches} == {"record.sha256"}

        changed_block = bytearray(first_path.read_bytes())
        free_space = first_proof.record.offset + first_proof.record.length
        changed_block[free_space] = 0x5A
        changed_block_path = tmp_path / "changed-block.evtx"
        changed_block_path.write_bytes(changed_block)

        with changed_block_path.open("rb") as changed_fh:
            changed_block_result = verify_event_proof(changed_fh, first_proof.to_dict())
        assert {item.path for item in changed_block_result.mismatches} == {"chunk.sha256"}

        changed_template = bytearray(first_path.read_bytes())
        template_offset = HEADER_SIZE + first_proof.templates[0].offset
        changed_template[template_offset : template_offset + 4] = b"\x12\x34\x56\x78"
        changed_template_path = tmp_path / "changed-template.evtx"
        changed_template_path.write_bytes(changed_template)

        with changed_template_path.open("rb") as changed_fh:
            changed_template_result = verify_event_proof(changed_fh, first_proof.to_dict())
        assert {item.path for item in changed_template_result.mismatches} == {
            "chunk.sha256",
            "record.sha256",
            "templates",
            "fields.Provider_Name",
            "fields.EventID",
            "fields.EventID_Qualifiers",
            "fields.Version",
            "fields.Level",
            "fields.Task",
            "fields.Opcode",
            "fields.Keywords",
            "fields.TimeCreated_SystemTime",
            "fields.EventRecordID",
            "fields.Correlation_ActivityID",
            "fields.Correlation_RelatedActivityID",
            "fields.Execution_ProcessID",
            "fields.Execution_ThreadID",
            "fields.Channel",
            "fields.Computer",
            "fields.Security_UserID",
        }
        assert changed_template_result.proof.event == first_proof.event
        assert not any(item.path in {"fields.Data", "fields.Binary"} for item in changed_template_result.mismatches)
