"""Layer reads must distinguish genuine zeroes from hole padding."""

import pytest

from volatility3.framework import contexts
from volatility3.framework.interfaces.layers import coalesce_evidence
from volatility3.framework.layers import physical, segmented

PAGE_SIZE = 0x1000
VIRTUAL_SIZE = 0x6000


class FixedSegmentedLayer(segmented.SegmentedLayer):
    """A segmented layer with a supplied, immutable segment table."""

    def __init__(self, context, config_path, name, segments):
        self._provided_segments = segments
        super().__init__(context, config_path, name)

    def _load_segments(self):
        self._segments = self._provided_segments


@pytest.fixture
def layered_context():
    buffer = bytearray(VIRTUAL_SIZE)
    buffer[0:PAGE_SIZE] = b"A" * PAGE_SIZE
    # The page at physical 0x1000 is deliberately left as genuine zeroes.
    buffer[0x4000:0x5000] = b"B" * PAGE_SIZE
    buffer[0x5000:0x6000] = b"C" * PAGE_SIZE

    context = contexts.Context()
    physical_layer = physical.BufferDataLayer(
        context,
        "physical",
        "physical",
        bytes(buffer),
        holes=[(0x2000, PAGE_SIZE)],
    )
    context.layers.add_layer(physical_layer)

    context.config["virtual.base_layer"] = "physical"
    segments = [
        (0x0000, 0x0000, PAGE_SIZE, PAGE_SIZE),
        (0x1000, 0x1000, PAGE_SIZE, PAGE_SIZE),
        # Two adjacent logical pages alias the same physical page.
        (0x2000, 0x4000, PAGE_SIZE, PAGE_SIZE),
        (0x3000, 0x4000, PAGE_SIZE, PAGE_SIZE),
        # This virtual page maps into the physical hole.
        (0x4000, 0x2000, PAGE_SIZE, PAGE_SIZE),
        (0x5000, 0x5000, PAGE_SIZE, PAGE_SIZE),
    ]
    virtual_layer = FixedSegmentedLayer(context, "virtual", "virtual", segments)
    context.layers.add_layer(virtual_layer)
    return physical_layer, virtual_layer


def test_real_zero_and_hole_padding_have_the_same_bytes_but_different_evidence(
    layered_context,
):
    physical_layer, _virtual_layer = layered_context
    report = physical_layer.read_with_evidence(PAGE_SIZE, PAGE_SIZE * 2, pad=True)

    assert report.data == b"\x00" * (PAGE_SIZE * 2)
    assert len(report.evidence) == 1
    actual = report.evidence[0]
    assert (actual.offset, actual.length, actual.mapped_offset) == (
        PAGE_SIZE,
        PAGE_SIZE,
        PAGE_SIZE,
    )
    assert actual.data == b"\x00" * PAGE_SIZE
    assert len(report.gaps) == 1
    assert (report.gaps[0].offset, report.gaps[0].length) == (
        PAGE_SIZE * 2,
        PAGE_SIZE,
    )


def test_segmented_aliases_keep_their_own_provenance(layered_context):
    _physical_layer, virtual_layer = layered_context
    report = virtual_layer.read_with_evidence(0, VIRTUAL_SIZE, pad=True)

    # The historical padding mode remains a byte-for-byte compatible output.
    assert report.data == virtual_layer.read(0, VIRTUAL_SIZE, pad=True)

    assert [
        (item.offset, item.length, item.mapped_offset, item.layer)
        for item in report.mappings
    ] == [
        (0x0000, 0x2000, 0x0000, "physical"),
        (0x2000, PAGE_SIZE, 0x4000, "physical"),
        (0x3000, PAGE_SIZE, 0x4000, "physical"),
        (0x4000, PAGE_SIZE, 0x2000, "physical"),
        (0x5000, PAGE_SIZE, 0x5000, "physical"),
    ]

    alias_evidence = [item for item in report.evidence if item.mapped_offset == 0x4000]
    assert [
        (item.offset, item.length, item.mapped_offset) for item in alias_evidence
    ] == [
        (0x2000, PAGE_SIZE, 0x4000),
        (0x3000, PAGE_SIZE, 0x4000),
    ]
    assert alias_evidence[0].data == b"B" * PAGE_SIZE
    assert alias_evidence[1].data == b"B" * PAGE_SIZE

    assert report.data[0x1000:0x2000] == b"\x00" * PAGE_SIZE
    assert report.evidence[0].data[PAGE_SIZE:] == b"\x00" * PAGE_SIZE
    assert [(gap.offset, gap.length) for gap in report.gaps] == [(0x4000, PAGE_SIZE)]


def test_whole_and_chunked_reads_produce_the_same_evidence_set(layered_context):
    _physical_layer, virtual_layer = layered_context
    whole = virtual_layer.read_with_evidence(0, VIRTUAL_SIZE, pad=True)

    split_evidence = []
    for start in range(0, VIRTUAL_SIZE, 0x700):
        length = min(0x700, VIRTUAL_SIZE - start)
        split_evidence.extend(
            virtual_layer.read_with_evidence(start, length, pad=True).evidence
        )

    assert coalesce_evidence(split_evidence) == whole.evidence
