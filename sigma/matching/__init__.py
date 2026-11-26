from typing import Any

from sigma.matching.event import Event, EventLogSource
from sigma.matching.match import SigmaMatch
from sigma.matching.matcher import SigmaMatcher
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.matching.correlation_matcher import SigmaCorrelationRuleMatcher

_DEPLOYMENT_EXPORTS = {
    "ConstraintViolation",
    "CoverageMatrix",
    "DeploymentConstraints",
    "DeploymentError",
    "DeploymentPlan",
    "DeploymentPlanner",
    "DeploymentScenario",
    "LabeledCase",
    "RuleCandidate",
    "UncoveredCase",
    "build_coverage_matrix",
    "select_deployment_plans",
}


def __getattr__(name: str) -> Any:
    if name in _DEPLOYMENT_EXPORTS:
        from sigma.matching import deployment

        return getattr(deployment, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Event",
    "EventLogSource",
    "SigmaMatch",
    "SigmaMatcher",
    "SigmaRuleMatcher",
    "SigmaCorrelationRuleMatcher",
    "ConstraintViolation",
    "CoverageMatrix",
    "DeploymentConstraints",
    "DeploymentError",
    "DeploymentPlan",
    "DeploymentPlanner",
    "DeploymentScenario",
    "LabeledCase",
    "RuleCandidate",
    "UncoveredCase",
    "build_coverage_matrix",
    "select_deployment_plans",
]
