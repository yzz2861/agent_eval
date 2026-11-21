"""Local replacement plugin package for the retired Bandit rule B102.

This package is intentionally local-only (never published or fetched from a
network index). It registers two checks under the ``bandit.plugins``
entry-point namespace:

* ``guard_exec_used`` (X901) - the replacement for built-in B102.
* ``guard_eval_used`` (X902) - an additional, newly introduced check.
"""

__version__ = "1.0.0"
