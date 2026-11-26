"""Coverage-planning aliases for :mod:`sigma.matching.deployment`.

This module exists so callers that think in terms of coverage matrices can import the same
implementation without depending on the deployment-planning name.
"""

from sigma.matching.deployment import (
    ConstraintViolation,
    CoverageMatrix,
    DeploymentConstraints,
    DeploymentError,
    DeploymentPlan,
    DeploymentPlanner,
    DeploymentScenario,
    LabeledCase,
    RuleCandidate,
    UncoveredCase,
    build_coverage_matrix,
    main,
    select_deployment_plans,
)

__all__ = [
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
    "main",
    "select_deployment_plans",
]


if __name__ == "__main__":
    raise SystemExit(main())
