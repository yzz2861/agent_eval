"""Finding model: collapse multi-plugin hits into one reviewable finding."""

from dataclasses import dataclass
from dataclasses import field
from typing import Dict
from typing import List
from typing import Tuple

DEFAULT_QUEUE = "unclassified"


@dataclass(frozen=True)
class Finding:
    """A distinct reviewable location.

    Several plugins can flag the same location; they are merged into one
    finding. ``detector_types`` keeps every plugin that fired, while
    ``primary_detector`` is the deterministic detector used for
    stratification. Plugin multiplicity never affects sampling weight.
    """

    finding_id: str
    filename: str
    line_number: int
    hashed_secret: str
    detector_types: List[str] = field(default_factory=list)
    source_queue: str = DEFAULT_QUEUE

    @property
    def primary_detector(self) -> str:
        # Deterministic, configuration-independent assignment so that a
        # finding always lands in the same stratum across reruns.
        return self.detector_types[0]

    @property
    def stratum_key(self) -> Tuple[str, str]:
        return (self.source_queue, self.primary_detector)

    @property
    def plugin_hit_count(self) -> int:
        return len(self.detector_types)


def make_finding_id(filename: str, line_number: int, hashed_secret: str) -> str:
    return "{}:{}:{}".format(filename, line_number, hashed_secret)
