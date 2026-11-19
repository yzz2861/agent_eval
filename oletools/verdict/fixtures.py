"""Deterministic, fully in-memory container-tree fixtures.

These fixtures need no real Office file on disk, so the composite verdict
logic can be exercised offline and deterministically. They model nested
containers with local encryption, an unrecognised embedded format, a corrupt
sub-document and a sub-object shared by two reference paths.
"""

from .model import (
    Capability,
    ContainerEdge,
    ContainerNode,
    DetectorResult,
    NodeKind,
    Outcome,
    Policy,
    Severity,
)

# Deterministic payloads; content_key hashing therefore stays reproducible.
PAYLOAD_ROOT = b"[ooxml] root package bytes"
PAYLOAD_MACRO = b"Attribute VB_Name + VBA macro stub"
PAYLOAD_ENCRYPTED = b"\x01\x02\x03 encrypted-agile-package"
PAYLOAD_SHARED = b"shared ole stream referenced twice"
PAYLOAD_DDE = b"DDE: cmd url"
PAYLOAD_UNKNOWN = b"\x9f\x8c unknown embedded blob"
PAYLOAD_CORRUPT = b"\x00broken ole stream"


def build_partial_encryption_tree():
    """Build a nested tree with local encryption and shared references.

    Layout::

        doc (OOXML root)
        |-- macro-part (OOXML_PART, contains a VBA macro)
        |-- encrypted-ole (OLE, encrypted=True, cannot be scanned)
        |    |-- shared-stream (OLE_STREAM, also referenced from doc)
        |-- dde-part (OOXML_PART, DDE link)
        |-- mystery-embed (UNKNOWN kind, unrecognised format)
        |-- corrupt-stream (OLE_STREAM, corrupt=True)
        |-- shared-stream (second reference path to the SAME node)

    Returns a tuple ``(roots, nodes, edges)`` ready for VerdictEngine.
    """
    root = ContainerNode(
        'doc', kind=NodeKind.OOXML, name='document.docm',
        payload=PAYLOAD_ROOT)
    macro_part = ContainerNode(
        'macro-part', kind=NodeKind.OOXML_PART, name='vbaProject.bin',
        payload=PAYLOAD_MACRO)
    encrypted_ole = ContainerNode(
        'encrypted-ole', kind=NodeKind.OLE, name='encrypted object',
        encrypted=True, payload=PAYLOAD_ENCRYPTED)
    shared_stream = ContainerNode(
        'shared-stream', kind=NodeKind.OLE_STREAM, name='shared',
        payload=PAYLOAD_SHARED)
    dde_part = ContainerNode(
        'dde-part', kind=NodeKind.OOXML_PART, name='document.xml',
        payload=PAYLOAD_DDE)
    mystery = ContainerNode(
        'mystery-embed', kind=NodeKind.UNKNOWN, name='blob.bin',
        payload=PAYLOAD_UNKNOWN)
    corrupt = ContainerNode(
        'corrupt-stream', kind=NodeKind.OLE_STREAM, name='broken',
        corrupt=True, parse_error="truncated OLE stream",
        payload=PAYLOAD_CORRUPT)
    nodes = [root, macro_part, encrypted_ole, shared_stream, dde_part,
             mystery, corrupt]
    edges = [
        ContainerEdge('doc', 'macro-part', label='word/vbaProject.bin'),
        ContainerEdge('doc', 'encrypted-ole', label='embeddings/enc.bin'),
        ContainerEdge('encrypted-ole', 'shared-stream',
                       label='inside-encrypted/ObjectPool'),
        ContainerEdge('doc', 'dde-part', label='word/document.xml'),
        ContainerEdge('doc', 'mystery-embed', label='embeddings/mystery'),
        ContainerEdge('doc', 'corrupt-stream', label='broken-stream'),
        ContainerEdge('doc', 'shared-stream',
                       label='direct-reference/ObjectPool'),
    ]
    return [root], nodes, edges

def strict_policy():
    """Policy requiring every standard capability used by the fixtures."""
    return Policy(required_capabilities=(
        Capability.MACRO,
        Capability.DDE,
        Capability.EMBEDDED_OBJECT,
        Capability.EXTERNAL_RELATIONSHIP,
        Capability.FLASH,
        Capability.OLE_STRUCTURE,
        Capability.OOXML_STRUCTURE,
        Capability.ENCRYPTION,
        Capability.UNKNOWN_EMBED,
        Capability.PARSER,
    ))


class SimulatedScanner(object):
    """Deterministic stand-in for olevba/msodde/oleid over the fixture tree.

    The scanner never touches the network or disk. ``fail_once`` maps a
    ``(node_id, capability)`` pair to the number of initial ERROR outcomes to
    emit before returning the real finding, which drives retry semantics.
    """

    # node_id -> {capability: (outcome, severity, detail, signature)}
    _SCRIPT = {
        'macro-part': {Capability.MACRO: (Outcome.RISK, Severity.HIGH,
                                          'VBA macro detected', 'vba:autoopen')},
        'dde-part': {Capability.DDE: (Outcome.RISK, Severity.HIGH,
                                      'DDE command link', 'dde:cmd')},
        'shared-stream': {Capability.OLE_STRUCTURE: (Outcome.CLEAN,
                                                     Severity.INFO, '', '')},
        'doc': {Capability.OOXML_STRUCTURE: (Outcome.CLEAN,
                                            Severity.INFO, '', '')},
    }

    def __init__(self, fail_once=None):
        # (node_id, capability_key) -> remaining forced failures
        self.fail_once = dict(fail_once or {})
        self.calls = []

    def _signature_for(self, node_id, cap_key):
        # Stable per (node, capability) signature so an ERROR then a retry
        # map to the same dedupe key and replace one another.
        return '{0}:{1}'.format(node_id, cap_key)

    def scan(self, node_id, capability, detector="simulated"):
        """Produce one DetectorResult, honouring injected transient errors."""
        cap_key = (capability.value if isinstance(capability, Capability)
                   else str(capability))
        self.calls.append((node_id, cap_key))
        failure_key = (node_id, cap_key)
        stable_signature = self._signature_for(node_id, cap_key)
        if self.fail_once.get(failure_key, 0) > 0:
            self.fail_once[failure_key] -= 1
            return DetectorResult(node_id, capability, Outcome.ERROR,
                                  detector, severity=Severity.MEDIUM,
                                  detail='transient scanner failure',
                                  signature=stable_signature)
        scripted = self._SCRIPT.get(node_id, {}).get(capability)
        if scripted is None:
            return DetectorResult(node_id, capability, Outcome.CLEAN,
                                  detector, severity=Severity.INFO,
                                  detail='no finding',
                                  signature=stable_signature)
        outcome, severity, detail, signature = scripted
        # Keep a stable identity so the retry replaces the failed record even
        # though the successful result carries a concrete signature.
        return DetectorResult(node_id, capability, outcome, detector,
                              severity=severity, detail=detail,
                              signature=stable_signature)

    def scan_all(self, engine, plan):
        """Run every (node_id, capability) entry in plan, in given order."""
        for node_id, capability in plan:
            engine.submit_result(self.scan(node_id, capability))
