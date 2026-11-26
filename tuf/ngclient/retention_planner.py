"""Compatibility import path for retention planner callers."""

from tuf.retention import *  # noqa: F403
from tuf.retention import RetentionPlanner, plan_retention

__all__ = ["RetentionPlanner", "plan_retention"]
