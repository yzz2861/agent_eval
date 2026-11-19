"""
Fuzzing campaign orchestration and artifact recording.

The campaign ties together the synthetic seed corpus, the structure-aware
mutators, the two differential oracles, the dual budget and the syntax-unit
reducer.  Every run is deterministic given its seed, and every finding records
the seed, the full transformation chain, the baseline/variant diagnostics and
the reduced minimal sample, so a discrepancy can be reproduced and audited
without re-running a random search.

Artifacts are plain JSON (binary blobs encoded as base64), which keeps them
diff-friendly and free of any Office dependency.
"""

import base64
import hashlib
import json
import os
import random

from . import model
from . import mutators
from . import oracle as oracle_module
from . import reducer as reducer_module
from . import seeds as seeds_module


def _b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def _md5(data):
    return hashlib.md5(bytes(data)).hexdigest()


class CampaignConfig(object):
    """Knobs controlling one campaign, including the dual budget."""

    def __init__(self, seed=20261119, valid_steps=40, invalid_steps=40,
                 max_bytes=2 * 1024 * 1024, reduce_findings=True):
        self.seed = seed
        self.valid_steps = int(valid_steps)
        self.invalid_steps = int(invalid_steps)
        self.max_bytes = int(max_bytes)
        self.reduce_findings = bool(reduce_findings)

    def to_record(self):
        return dict(self.__dict__)


class Campaign(object):
    """Runs a deterministic structure-aware fuzzing campaign."""

    def __init__(self, config=None):
        self.config = config or CampaignConfig()
        self.rng = random.Random(self.config.seed)
        self.findings = []
        self.records = []
        self.payload, self.seed_documents = seeds_module.default_seed_corpus()
        self.payload_md5 = _md5(self.payload)
        total_steps = self.config.valid_steps + self.config.invalid_steps
        self.budget = oracle_module.Budget(total_steps, self.config.max_bytes)

    def _record(self, entry):
        self.records.append(entry)

    def run(self):
        baseline_doc = self.seed_documents["hex_plain"]
        baseline = oracle_module.extract(baseline_doc)
        self._run_valid_pool(baseline)
        self._run_invalid_pool(baseline)
        return self.summary()

    def _run_valid_pool(self, baseline):
        names = sorted(self.seed_documents)
        for step in range(self.config.valid_steps):
            if self.budget.exhausted:
                break
            seed_name = names[step % len(names)]
            document = self.seed_documents[seed_name]
            tree = model.parse_rtf(document)
            chain = []
            current_tree = tree
            # one structural transformation keeps the chain easy to explain
            mutation = mutators.valid_mutation(current_tree, self.rng)
            if mutation is None:
                continue
            chain.append(mutation.as_record())
            variant_doc = model.render(mutation.tree)
            variant = oracle_module.run_with_budget(variant_doc, self.budget)
            if variant is None:
                break
            difference = oracle_module.compare_valid(
                baseline, variant, chain)
            entry = {
                "pool": "valid",
                "step": step,
                "seed": seed_name,
                "chain": chain,
                "variant_size": len(variant_doc),
                "difference": difference.kind if difference else None,
            }
            if difference is None:
                self._record(entry)
                continue
            self._handle_finding(entry, difference, mutation.tree,
                                 comparator=lambda doc: oracle_module.compare_valid(
                                     baseline, oracle_module.extract(doc), chain))

    def _run_invalid_pool(self, baseline):
        names = sorted(self.seed_documents)
        for step in range(self.config.invalid_steps):
            if self.budget.exhausted:
                break
            seed_name = names[step % len(names)]
            document = self.seed_documents[seed_name]
            tree = model.parse_rtf(document)
            mutation = mutators.invalid_mutation(tree, self.rng)
            if mutation is None:
                continue
            chain = [mutation.as_record()]
            variant_doc = model.render(mutation.tree)
            variant = oracle_module.run_with_budget(variant_doc, self.budget)
            if variant is None:
                break
            difference = oracle_module.compare_invalid(
                baseline, variant, chain, self.payload_md5)
            entry = {
                "pool": "invalid",
                "step": step,
                "seed": seed_name,
                "chain": chain,
                "variant_size": len(variant_doc),
                "diagnostics": list(variant.diagnostic_codes),
                "difference": difference.kind if difference else None,
            }
            if difference is None:
                self._record(entry)
                continue
            self._handle_finding(
                entry, difference, mutation.tree,
                comparator=lambda doc: oracle_module.compare_invalid(
                    baseline, oracle_module.extract(doc), chain,
                    self.payload_md5))


    def _handle_finding(self, entry, difference, tree, comparator):
        finding = {
            "id": "finding-%03d" % (len(self.findings) + 1),
            "entry": entry,
            "signature": difference.signature(),
            "baseline": difference.baseline.to_record(),
            "variant": difference.variant.to_record(),
            "variant_b64": _b64(model.render(tree)),
            "variant_md5": _md5(model.render(tree)),
        }
        if self.config.reduce_findings:
            outcome = reducer_module.reduce_finding(
                tree, difference, self.budget, comparator)
            finding["reduction"] = {
                "original_size": outcome.original_size,
                "reduced_size": outcome.reduced_size,
                "reducer_steps": outcome.steps,
                "signature_kept": outcome.signature_kept,
                "stop_reason": outcome.stop_reason,
                "minimal_b64": _b64(outcome.document),
                "minimal_md5": _md5(outcome.document),
            }
        self.findings.append(finding)
        self._record(entry)

    def summary(self):
        return {
            "config": self.config.to_record(),
            "payload_md5": self.payload_md5,
            "payload_size": len(self.payload),
            "seeds": sorted(self.seed_documents),
            "budget": self.budget.snapshot(),
            "records": self.records,
            "findings": self.findings,
            "finding_count": len(self.findings),
        }

    def write_artifacts(self, output_dir):
        """Persist the campaign summary and one RTF file per finding."""
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
        summary_path = os.path.join(output_dir, "campaign_summary.json")
        with open(summary_path, "w") as handle:
            json.dump(self.summary(), handle, indent=2, sort_keys=True)
        written = [summary_path]
        for finding in self.findings:
            rtf_path = os.path.join(output_dir, finding["id"] + ".rtf")
            if "reduction" in finding and finding["reduction"]["signature_kept"]:
                blob = base64.b64decode(finding["reduction"]["minimal_b64"])
            else:
                blob = base64.b64decode(finding["variant_b64"])
            with open(rtf_path, "wb") as handle:
                handle.write(blob)
            written.append(rtf_path)
        return written


def run_campaign(seed=20261119, valid_steps=40, invalid_steps=40,
                 max_bytes=2 * 1024 * 1024, output_dir=None,
                 reduce_findings=True):
    """Convenience entry point used by the CLI and the test-suite."""
    config = CampaignConfig(seed, valid_steps, invalid_steps, max_bytes,
                            reduce_findings)
    campaign = Campaign(config)
    campaign.run()
    if output_dir is not None:
        campaign.write_artifacts(output_dir)
    return campaign
