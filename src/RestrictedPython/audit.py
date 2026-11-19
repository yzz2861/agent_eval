"""
audit module:

Independent instrumentation audit for restricted compilation.

The audit does *not* trust the policy's own access classification.  It
re-parses the original source with a plain :class:`ast.NodeVisitor` to build
an expected list of the guard calls that must appear for attribute
read/write, subscript read/write, iteration and (star/keyword) call
spreading.  The transformed AST and every nested code object are then
checked against that list.
"""

from __future__ import annotations

import ast
import collections
import types
import typing

from RestrictedPython.transformer import RestrictingNodeTransformer


# Guard names inserted by ``RestrictingNodeTransformer`` to protect the
# operations audited here.
GETATTR_GUARD = '_getattr_'
GETITEM_GUARD = '_getitem_'
WRITE_GUARD = '_write_'
GETITER_GUARD = '_getiter_'
APPLY_GUARD = '_apply_'
UNPACK_GUARD = '_unpack_sequence_'
ITER_UNPACK_GUARD = '_iter_unpack_sequence_'

# Other guard-like names emitted by the transformer.  They are not part of
# the audited access set, but have to be recognised so their presence in
# the bytecode is not reported as unexplained.
INPLACE_GUARD = '_inplacevar_'
PRINT_GUARD = '_print_'

#: Guard calls protecting the operations in the user's source.
ACCESS_GUARDS: typing.Final = frozenset({
    GETATTR_GUARD,
    GETITEM_GUARD,
    WRITE_GUARD,
    GETITER_GUARD,
    APPLY_GUARD,
    UNPACK_GUARD,
    ITER_UNPACK_GUARD,
})

#: Every guard name the transformer is able to emit.
KNOWN_GUARDS: typing.Final = ACCESS_GUARDS | frozenset({
    INPLACE_GUARD,
    PRINT_GUARD,
})

#: Bytecode versions for which the checks below are known to be valid.
#: New CPython releases must be reviewed before being added: an unknown
#: version leads to an inconclusive result instead of a clean verdict.
SUPPORTED_BYTECODE_VERSIONS: typing.Final = frozenset(
    (3, minor) for minor in range(11, 16))

# Opcodes that load a global/builtin name onto the stack.  These are the
# instructions emitted for every guard call.
_LOAD_NAME_OPCODES: typing.Final = frozenset({
    'LOAD_GLOBAL',
    'LOAD_NAME',
})


class ExpectedGuardSite(typing.NamedTuple):
    """A guard required by a construct in the *original* source.

    ``guard`` is the expected guard name.  ``kind`` identifies the source
    construct (for example ``'attribute_load'``), ``node`` is the original
    AST node and ``span`` is the source range the transformed guard call
    reuses for its location.
    """

    guard: str
    kind: str
    node: ast.AST
    span: tuple[int, int, int, int]

    @property
    def location(self) -> str:
        """Human readable source location of the site."""
        start_line, start_col, _, _ = self.span
        return f'line {start_line} column {start_col}'


class GuardObservation(typing.NamedTuple):
    """A guard call found in the transformed AST."""

    guard: str
    node: ast.Call
    span: tuple[int, int, int, int]


class AuditResult:
    """Outcome of a guard audit.

    Attributes:
        expected: All sites required by the source oracle.
        observed: All guard calls found in the transformed AST.
        missing: Expected sites without a matching guard call.
        duplicate: Site keys that are protected more than once.
        unprovable: Guard calls that cannot be tied to an expected site.
        infrastructure: Non-access guard calls emitted by the transformer.
        bytecode_counts: Guard loads counted in every code object.
        inconclusive: ``True`` when no definitive verdict is possible.
        reasons: Explanations for an inconclusive result.
        errors: Policy/transformation errors encountered.
    """

    def __init__(self) -> None:
        self.expected: list[ExpectedGuardSite] = []
        self.observed: list[GuardObservation] = []
        self.missing: list[ExpectedGuardSite] = []
        self.duplicate: list[tuple[str, tuple[int, int, int, int], int]] = []
        self.unprovable: list[GuardObservation] = []
        self.infrastructure: list[GuardObservation] = []
        self.bytecode_counts: dict[str, int] = collections.Counter()
        self.inconclusive: bool = False
        self.reasons: list[str] = []
        self.errors: list[str] = []

    @property
    def ok(self) -> bool:
        """``True`` for a conclusive audit without findings."""
        return (
            not self.inconclusive
            and not self.missing
            and not self.duplicate
            and not self.unprovable
            and not self.errors)

    def assert_guarded(self) -> None:
        """Raise if the audit is inconclusive or found a problem."""
        if self.inconclusive:
            raise InconclusiveAuditError('; '.join(self.reasons))
        if not self.ok:
            raise GuardAuditError(self)


class GuardAuditError(AssertionError):
    """Raised when a required guard is missing or cannot be explained."""

    def __init__(self, result: AuditResult) -> None:
        self.result = result
        lines = ['RestrictedPython guard audit failed:']
        for site in result.missing:
            lines.append(
                f'  missing {site.guard} for {site.kind} '
                f'at {site.location}')
        for guard, span, count in result.duplicate:
            lines.append(
                f'  {guard} at line {span[0]} column {span[1]} '
                f'observed {count} times')
        for observation in result.unprovable:
            lines.append(
                f'  unexplained {observation.guard} call at '
                f'line {observation.span[0]} column {observation.span[1]}')
        super().__init__('\n'.join(lines))


class InconclusiveAuditError(RuntimeError):
    """Raised when the audit cannot produce a definitive verdict."""

    def __init__(self, reasons: str) -> None:
        self.reasons = reasons
        super().__init__(
            'RestrictedPython guard audit is inconclusive: ' + reasons)


def _span(node: ast.AST) -> tuple[int, int, int, int]:
    return (
        node.lineno,
        node.col_offset,
        node.end_lineno,
        node.end_col_offset,
    )


def _extract_guard_calls(tree: ast.AST) -> list[GuardObservation]:
    observations: list[GuardObservation] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ACCESS_GUARDS):
            observations.append(GuardObservation(
                node.func.id, node, _span(node)))
    return observations


def _extract_infrastructure_calls(
        tree: ast.AST) -> list[GuardObservation]:
    """Collect non-access guard calls (transformer infrastructure)."""
    observations: list[GuardObservation] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id not in ACCESS_GUARDS
                and node.func.id in KNOWN_GUARDS):
            observations.append(GuardObservation(
                node.func.id, node, _span(node)))
    return observations


def _match_sites(result: AuditResult) -> None:
    expected_by_key: dict[tuple[str, tuple[int, int, int, int]],
                         list[ExpectedGuardSite]] = {}
    for site in result.expected:
        expected_by_key.setdefault((site.guard, site.span), []).append(site)
    observed_by_key: dict[tuple[str, tuple[int, int, int, int]],
                          list[GuardObservation]] = {}
    for observation in result.observed:
        observed_by_key.setdefault((
            observation.guard, observation.span), []).append(observation)
    matched_observations: set[int] = set()
    matched_site_ids: set[int] = set()

    # First pass: exact span matches.  Each call satisfies one site.
    for key, sites in expected_by_key.items():
        observations = observed_by_key.get(key, ())
        for site, observation in zip(sites, observations):
            matched_site_ids.add(id(site))
            matched_observations.add(id(observation))
        if len(observations) > len(sites):
            result.duplicate.append(
                (key[0], key[1], len(observations)))

    # Second pass: start-position fallback for nested stores, where the
    # transformer copies the inner value location onto the _write_ call.
    for site in result.expected:
        if id(site) in matched_site_ids:
            continue
        start = (site.span[0], site.span[1])
        for observation in result.observed:
            if id(observation) in matched_observations:
                continue
            obs_start = (observation.span[0], observation.span[1])
            if observation.guard == site.guard and obs_start == start:
                matched_site_ids.add(id(site))
                matched_observations.add(id(observation))
                break
    result.missing = [
        site for site in result.expected
        if id(site) not in matched_site_ids]
    result.unprovable = [
        observation for observation in result.observed
        if id(observation) not in matched_observations]


def _verify_bytecode(result: AuditResult, code: types.CodeType | None) -> None:
    from RestrictedPython._bytecode import bytecode_version_supported
    from RestrictedPython._bytecode import count_guard_loads
    if not bytecode_version_supported():
        result.inconclusive = True
        result.reasons.append(
            "Unsupported or unreviewed Python bytecode version; refusing "
            "a definitive verdict.")
        return
    if code is None:
        result.inconclusive = True
        result.reasons.append("No code object was produced.")
        return
    counts, recognisable = count_guard_loads(code)
    result.bytecode_counts = counts
    if not recognisable:
        result.inconclusive = True
        result.reasons.append(
            "Unknown bytecode instruction encountered; audit rules do not "
            "cover this bytecode.")
    ast_counts: collections.Counter[str] = collections.Counter(
        observation.guard for observation in result.observed)
    for guard, expected_count in ast_counts.items():
        actual_count = counts.get(guard, 0)
        if actual_count < expected_count:
            result.inconclusive = True
            result.reasons.append(
                f"{guard}: transformed AST contains {expected_count} call(s) "
                f"but bytecode only loads it {actual_count} time(s).")


def audit_compiled_code(
        source: str | bytes,
        code: types.CodeType,
        transformed_tree: ast.AST,
        mode: str = "exec",
        filename: str = "<audit>",
) -> AuditResult:
    """Audit an already compiled restricted code object."

    ``source`` is re-parsed independently to derive the expected guard
    list; the policy transformer is not used as the oracle.
    """
    result = AuditResult()
    source_tree = ast.parse(source, filename, mode)
    from RestrictedPython._oracle import collect_expected_sites
    result.expected = collect_expected_sites(source_tree)
    result.observed = _extract_guard_calls(transformed_tree)
    result.infrastructure = _extract_infrastructure_calls(transformed_tree)
    _match_sites(result)
    _verify_bytecode(result, code)
    return result


def audit_restricted(
        source: str | bytes | ast.AST,
        filename: str = "<audit>",
        mode: str = "exec",
        policy: type[ast.NodeTransformer] = RestrictingNodeTransformer,
) -> AuditResult:
    """Transform and compile ``source`` and audit the resulting artefacts.

    The source is never executed.  The returned result reports missing,
    duplicate and unexplainable guard calls, or is marked inconclusive
    when the bytecode version is not supported.
    """
    result = AuditResult()
    if isinstance(source, ast.AST):
        source_tree = source
        raw_source = ast.unparse(source)
    else:
        raw_source = source
        source_tree = ast.parse(source, filename, mode)
    from RestrictedPython._oracle import collect_expected_sites
    result.expected = collect_expected_sites(source_tree)

    if not isinstance(policy, type) or not issubclass(
            policy, RestrictingNodeTransformer):
        raise TypeError("audit requires a RestrictingNodeTransformer policy")
    errors: list[str] = []
    _warnings: list[str] = []
    used_names: dict[str, bool] = {}
    transformed_tree = ast.parse(raw_source, filename, mode)
    policy_instance = policy(errors, _warnings, used_names)
    policy_instance.visit(transformed_tree)
    result.errors = list(errors)
    if errors:
        result.inconclusive = True
        result.reasons.append(
            "Policy reported errors; no defensible code object to audit.")
        result.observed = _extract_guard_calls(transformed_tree)
        result.infrastructure = _extract_infrastructure_calls(transformed_tree)
        _match_sites(result)
        return result
    result.observed = _extract_guard_calls(transformed_tree)
    result.infrastructure = _extract_infrastructure_calls(transformed_tree)
    _match_sites(result)
    code = compile(transformed_tree, filename, mode)
    _verify_bytecode(result, code)
    return result
