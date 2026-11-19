# SPDX-License-Identifier: Apache-2.0
"""Loading helpers for policy documents and Bandit JSON reports.

The takeover layer reads YAML policy files (ownership, path moves, handoff
ledger, scan manifest).  JSON is accepted as an alternative serialization so
the layer stays usable in environments without PyYAML.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

from bandit.takeover.ledger import HandoffLedger
from bandit.takeover.ownership import OwnershipPolicy
from bandit.takeover.paths import PathMap

LOG = logging.getLogger(__name__)


class PolicyError(ValueError):
    """Raised when a policy document cannot be parsed or is incomplete."""


def _load_structured(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if path.endswith(".json"):
        return json.loads(text)
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised without PyYAML
        raise PolicyError(
            "PyYAML is required to read " + path + "; install the yaml extra "
            "or provide a .json policy instead"
        ) from exc
    loaded = yaml.safe_load(text)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise PolicyError("policy document " + path + " must be a mapping")
    return loaded


def load_policy(path: str):
    """Load the full policy bundle from one YAML/JSON document.

    Expected sections (all optional except ``ownership``):

    * ``ownership``: list of ``{directory, team}`` mappings,
    * ``path_moves``: mapping of old prefix -> new prefix,
    * ``handoffs``: list of accepted handoff records,
    * ``scan_manifest``: list of directories this scan intends to cover.
    """
    data = _load_structured(path)
    if "ownership" not in data:
        raise PolicyError("policy document " + path + " is missing ownership")
    path_map = PathMap.from_dict(data.get("path_moves", {}))
    policy = OwnershipPolicy.from_dict(data, path_map=path_map)
    ledger = HandoffLedger.from_dict({"handoffs": data.get("handoffs", [])})
    manifest = [str(item) for item in data.get("scan_manifest", [])]
    return PolicyBundle(
        ownership_policy=policy,
        handoff_ledger=ledger,
        path_map=path_map,
        scan_manifest=manifest,
        raw=data,
    )


def load_report(path: str) -> Dict[str, Any]:
    """Load a Bandit JSON report (current run or legacy backlog report)."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "results" not in data:
        raise PolicyError(
            "report " + path + " is not a Bandit JSON document (no results)"
        )
    data.setdefault("errors", [])
    return data


class PolicyBundle:
    """Container grouping the parsed policy inputs."""

    def __init__(
        self,
        ownership_policy: OwnershipPolicy,
        handoff_ledger: HandoffLedger,
        path_map: PathMap,
        scan_manifest: List[str],
        raw: Dict[str, Any],
    ) -> None:
        self.ownership_policy = ownership_policy
        self.handoff_ledger = handoff_ledger
        self.path_map = path_map
        self.scan_manifest = scan_manifest
        self.raw = raw

    def manifest_for(self, report: Dict[str, Any]) -> List[str]:
        explicit = report.get("scan_manifest")
        if explicit:
            return [str(item) for item in explicit]
        return list(self.scan_manifest)
