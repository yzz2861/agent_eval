#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module implements offline applicability assessment on top of the
CPE Applicability Language 2.3 evaluation layer.

Unlike the classic boolean language matching, an offline assessment must
distinguish three situations for every branch of an advisory expression:

- the branch is satisfied by the inventoried components (``match``);
- the branch is disproved because the relevant part of the deployment was
  fully inventoried and no satisfying component exists (``excluded``);
- the available inventory is not complete enough to decide
  (``insufficient_evidence``).

The three-valued logic used here is the Kleene logic defined by the
``Verdict`` enumeration. It keeps the original boolean semantics intact
(``match`` is the only "true" value) while allowing negation and nested
negation to be evaluated without turning unknown evidence into a hard
negative.
"""

from enum import Enum

from .cpe2_3_wfn import CPE2_3_WFN
from .cpeset2_3 import CPESet2_3


def _to_wfn(boundname):
    """Unbind any supported bound CPE name to a WFN."""
    from .cpelang2_3 import CPELanguage2_3
    return CPELanguage2_3._unbind(boundname)


def _wfn_part(wfn):
    """Return the unquoted CPE part (``a``, ``o`` or ``h``) of a WFN."""
    return wfn.get_attribute_values("part")[0].strip('"')


class Verdict(Enum):
    """
    Three-valued result of an offline applicability evaluation.
    """

    #: The branch is satisfied by at least one inventoried component.
    MATCH = "match"

    #: The branch is disproved by a complete inventory of the relevant part.
    EXCLUDED = "excluded"

    #: The inventory coverage is not complete enough to decide the branch.
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    @property
    def is_match(self):
        """Return True only for the affirmative verdict."""
        return self is Verdict.MATCH

    def negated(self):
        """
        Return the verdict obtained by applying a logical negation.

        A match becomes an exclusion and vice-versa. An unknown branch stays
        unknown because negating a statement that cannot be proved offline
        does not produce a proof either.
        """
        if self is Verdict.MATCH:
            return Verdict.EXCLUDED
        if self is Verdict.EXCLUDED:
            return Verdict.MATCH
        return Verdict.INSUFFICIENT_EVIDENCE


def _and(verdicts):
    """Kleene conjunction of a non-empty sequence of verdicts."""
    if any(verdict is Verdict.EXCLUDED for verdict in verdicts):
        return Verdict.EXCLUDED
    if all(verdict is Verdict.MATCH for verdict in verdicts):
        return Verdict.MATCH
    return Verdict.INSUFFICIENT_EVIDENCE


def _or(verdicts):
    """Kleene disjunction of a non-empty sequence of verdicts."""
    if any(verdict is Verdict.MATCH for verdict in verdicts):
        return Verdict.MATCH
    if all(verdict is Verdict.EXCLUDED for verdict in verdicts):
        return Verdict.EXCLUDED
    return Verdict.INSUFFICIENT_EVIDENCE


class ApplicabilityEvidence(object):
    """
    Evidence supporting a branch verdict.

    :ivar str kind: ``fact`` for an inventoried component, ``coverage`` when
        a missing component cannot be ruled out, or ``absence`` when a fully
        inventoried part rules it out.
    :ivar str asset_id: identifier of the deployment the evidence belongs to.
    :ivar str name: bound CPE name referenced by the branch.
    :ivar str component: inventoried CPE name backing the evidence, if any.
    :ivar str part: CPE part (``a``, ``o`` or ``h``) of the referenced fact.
    :ivar bool negated: whether the evidence was collected under a negation.
    """

    def __init__(self, kind, asset_id, name, component=None, part=None,
                 negated=False):
        self.kind = kind
        self.asset_id = asset_id
        self.name = name
        self.component = component
        self.part = part
        self.negated = negated

    def as_dict(self):
        """Return a plain dictionary representation of the evidence."""
        return {
            "kind": self.kind,
            "asset_id": self.asset_id,
            "name": self.name,
            "component": self.component,
            "part": self.part,
            "negated": self.negated,
        }


class BranchResult(object):
    """
    Verdict and supporting evidence for a single expression branch.

    A branch is identified by the bound CPE name of its ``fact-ref`` leaf;
    logical-test nodes aggregate the results of their child branches.
    """

    def __init__(self, verdict, name=None, evidence=None, children=None,
                 operator=None, negated=False):
        self.verdict = verdict
        self.name = name
        self.evidence = list(evidence or [])
        self.children = list(children or [])
        self.operator = operator
        self.negated = negated

    def as_dict(self):
        """Return a plain dictionary representation of the branch result."""
        data = {
            "verdict": self.verdict.value,
            "negated": self.negated,
        }
        if self.name is not None:
            data["name"] = self.name
        if self.operator is not None:
            data["operator"] = self.operator
        if self.evidence:
            data["evidence"] = [item.as_dict() for item in self.evidence]
        if self.children:
            data["children"] = [child.as_dict() for child in self.children]
        return data


class AssetInventory(object):
    """
    Component inventory of a single deployment (asset).

    Each component is tagged with the asset that owns it, so a product that
    appears in several deployments never satisfies a branch on behalf of
    another deployment.

    :ivar str asset_id: unique identifier of the deployment (asset number).
    :ivar list components: WFN CPE names inventoried on the deployment.
    :ivar set covered_parts: CPE parts (``a``, ``o``, ``h``) that have been
        fully inventoried. A fact referencing a part absent from this set can
        only be evaluated as insufficient evidence.
    """

    def __init__(self, asset_id, components=None, covered_parts=None):
        self.asset_id = asset_id
        self.components = []
        for component in components or []:
            self.add_component(component)
        self.covered_parts = set(covered_parts or [])

    def add_component(self, component):
        """Append a bound CPE name or WFN object to the inventory."""
        if not isinstance(component, CPE2_3_WFN):
            component = _to_wfn(component)
        self.components.append(component)

    def part_covered(self, part):
        """Return True if the given CPE part was fully inventoried."""
        return part in self.covered_parts


def _to_wfn(boundname):
    """Unbind any supported bound CPE name to a WFN."""
    from .cpelang2_3 import CPELanguage2_3
    return CPELanguage2_3._unbind(boundname)


def _wfn_part(wfn):
    value = wfn.get_attribute_values("part")[0]
    return value.strip('"')


class ApplicabilityAssessment(object):
    """
    Outcome of an offline applicability assessment.

    :ivar Verdict verdict: overall verdict across every supplied deployment.
    :ivar dict assets: mapping of asset identifier to its root
        :class:`BranchResult`.
    :ivar list matched_assets: identifiers of deployments that satisfy the
        advisory expression, in evaluation order.
    :ivar list unknown_assets: identifiers whose partial inventory prevents
        a definitive conclusion.
    """

    def __init__(self, verdict, assets):
        self.verdict = verdict
        self.assets = assets
        self.matched_assets = [
            asset_id for asset_id, result in assets.items()
            if result.verdict is Verdict.MATCH
        ]
        self.unknown_assets = [
            asset_id for asset_id, result in assets.items()
            if result.verdict is Verdict.INSUFFICIENT_EVIDENCE
        ]

    @property
    def is_applicable(self):
        """Return True when at least one deployment is affected."""
        return self.verdict.is_match

    def as_dict(self):
        """Return a plain dictionary representation of the assessment."""
        return {
            "verdict": self.verdict.value,
            "is_applicable": self.is_applicable,
            "matched_assets": list(self.matched_assets),
            "unknown_assets": list(self.unknown_assets),
            "assets": {
                asset_id: result.as_dict()
                for asset_id, result in self.assets.items()
            },
        }


class ApplicabilityEvaluator(object):
    """
    Offline evaluator for CPE Applicability Language 2.3 expressions.

    The evaluator walks the same DOM tree as the boolean language matcher but
    evaluates each deployment independently with three-valued logic, keeping
    track of the asset identifiers and components that justify every verdict.
    """

    TAG_ROOT = '#document'
    TAG_PLATSPEC = 'cpe:platform-specification'
    TAG_PLATFORM = 'cpe:platform'
    TAG_LOGITEST = 'cpe:logical-test'
    TAG_CPE = 'cpe:fact-ref'
    TAG_CHECK_CPE = 'check-fact-ref'

    ATT_NAME = 'name'
    ATT_OP = 'operator'
    ATT_NEGATE = 'negate'

    ATT_OP_AND = 'AND'
    ATT_NEGATE_TRUE = 'TRUE'

    def __init__(self, expression):
        #: Parsed CPE language expression (a CPELanguage2_3 instance).
        self.expression = expression

    def assess(self, inventories):
        """
        Evaluate the expression against one or more asset inventories.

        :param AssetInventory|list inventories: a single inventory or a list
            of inventories, each one representing a deployment.
        :returns: assessment with an overall verdict and per-asset branches.
        :rtype: ApplicabilityAssessment
        """
        if isinstance(inventories, AssetInventory):
            inventories = [inventories]

        platform = self._platform_node(self.expression.document)
        assets = {}
        for inventory in inventories:
            assets[inventory.asset_id] = self._evaluate(platform, inventory)

        verdicts = [result.verdict for result in assets.values()]
        if any(verdict is Verdict.MATCH for verdict in verdicts):
            overall = Verdict.MATCH
        elif any(verdict is Verdict.INSUFFICIENT_EVIDENCE
                 for verdict in verdicts):
            overall = Verdict.INSUFFICIENT_EVIDENCE
        else:
            overall = Verdict.EXCLUDED

        return ApplicabilityAssessment(overall, assets)

    def _platform_node(self, dom):
        if dom.nodeName in (self.TAG_ROOT, self.TAG_PLATSPEC):
            for node in dom.childNodes:
                if node.nodeName == self.TAG_PLATSPEC:
                    return self._platform_node(node)
                if node.nodeName == self.TAG_PLATFORM:
                    return self._platform_node(node)
        if dom.nodeName == self.TAG_PLATFORM:
            for node in dom.childNodes:
                if node.nodeName == self.TAG_LOGITEST:
                    return node
        return dom

    def _evaluate(self, dom, inventory, negated=False):
        node_name = dom.nodeName

        if node_name in (self.TAG_ROOT, self.TAG_PLATSPEC,
                         self.TAG_PLATFORM):
            return self._evaluate(self._platform_node(dom), inventory,
                                  negated)

        if node_name == self.TAG_CPE:
            return self._evaluate_fact(dom, inventory, negated)

        if node_name == self.TAG_LOGITEST:
            return self._evaluate_logical_test(dom, inventory, negated)

        # Unsupported check references cannot be resolved offline.
        return BranchResult(
            Verdict.INSUFFICIENT_EVIDENCE,
            evidence=[ApplicabilityEvidence(
                "coverage", inventory.asset_id,
                getattr(dom, "getAttribute", lambda *_: "")(self.ATT_NAME),
                negated=negated)],
            negated=negated)

    def _evaluate_fact(self, dom, inventory, negated):
        boundname = dom.getAttribute(self.ATT_NAME)
        wfn = _to_wfn(boundname)
        part = _wfn_part(wfn)

        for component in inventory.components:
            if CPESet2_3.cpe_superset(wfn, component):
                return BranchResult(
                    Verdict.MATCH,
                    name=boundname,
                    evidence=[ApplicabilityEvidence(
                        "fact", inventory.asset_id, boundname,
                        component=component.as_fs(), part=part,
                        negated=negated)],
                    negated=negated)

        if inventory.part_covered(part):
            kind = "absence"
            verdict = Verdict.EXCLUDED
        else:
            kind = "coverage"
            verdict = Verdict.INSUFFICIENT_EVIDENCE

        return BranchResult(
            verdict,
            name=boundname,
            evidence=[ApplicabilityEvidence(
                kind, inventory.asset_id, boundname, part=part,
                negated=negated)],
            negated=negated)

    def _evaluate_logical_test(self, dom, inventory, negated):
        operator = dom.getAttribute(self.ATT_OP).upper()
        is_negated = (dom.getAttribute(self.ATT_NEGATE).upper()
                      == self.ATT_NEGATE_TRUE)

        children = [
            self._evaluate(node, inventory, negated != is_negated)
            for node in dom.childNodes
            if not node.nodeName.startswith("#")
        ]

        if not children:
            verdict = Verdict.INSUFFICIENT_EVIDENCE
        elif operator == self.ATT_OP_AND:
            verdict = _and([child.verdict for child in children])
        else:
            verdict = _or([child.verdict for child in children])

        if is_negated:
            verdict = verdict.negated()

        return BranchResult(
            verdict,
            children=children,
            operator=operator,
            negated=negated or is_negated)
