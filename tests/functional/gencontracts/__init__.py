"""Generative contract tests for team-owned Bandit rules.

This package builds tiny synthetic programs (a few scopes, ordinary
data-moving APIs) together with an explicit security-contract state.
Expected findings are derived from that contract state alone -- never
from Bandit's rule implementations -- so any divergence between the
oracle and a rule means the rule's conclusions genuinely changed.

Each program is rendered twice: once canonically and once as an
equivalent rewrite (renames, reordered independent statements, import
style, quote/blank-line formatting).  Comparing the two scans tells a
reviewer whether a conclusion really changed or only the layout did.

Generated source is only ever parsed and analysed statically; it is
never executed.
"""
