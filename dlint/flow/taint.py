#!/usr/bin/env python

# Reusable, configuration driven taint / validation path analysis.
#
# The analysis answers one narrow question: given a configured source of
# untrusted data, a configured validator and a configured dangerous sink, is
# there a reachable path on which the tainted value reaches the sink without
# being validated?
#
# It is built on top of dlint.flow.cfg and keeps two validator contracts
# separate:
#
# - RAISES: the validator raises on bad input. A straight-line call makes the
#   subsequent path safe, but an exception edge that bypasses the call is not.
# - BOOL: the validator returns a boolean. Merely calling it changes nothing;
#   only the true branch of an if/elif test that uses the result is considered
#   validated. An arbitrary if is therefore never treated as a sanitizer.
#
# Results carry the shortest reachable branch sequence as evidence. When the
# number of explored states exceeds a budget the verdict degrades to UNKNOWN
# rather than claiming the code is clean.

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import cfg


class ValidatorContract(object):
    RAISES = "raises"
    BOOL = "bool"


class FlowVerdict(object):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


class RuleSpec(object):
    # Declarative description of one source -> validator -> sink rule.

    def __init__(
        self,
        name,
        sources,
        validators,
        sinks,
        validator_contract=ValidatorContract.RAISES,
        max_states=20000,
    ):
        self.name = name
        self.sources = tuple(sources)
        self.validators = tuple(validators)
        self.sinks = tuple(sinks)
        self.validator_contract = validator_contract
        self.max_states = max_states


class FlowResult(object):
    # Outcome of analyzing a single function scope.

    def __init__(self, verdict, evidence=None, sink_lineno=None,
                 sink_name=None, reason=None):
        self.verdict = verdict
        self.evidence = list(evidence or [])
        self.sink_lineno = sink_lineno
        self.sink_name = sink_name
        self.reason = reason

    def __repr__(self):
        return "FlowResult(verdict={}, sink={}:{})".format(
            self.verdict, self.sink_name, self.sink_lineno
        )


class _State(object):
    # Immutable per-path taint state.

    __slots__ = ("tainted", "validated")

    def __init__(self, tainted, validated):
        self.tainted = frozenset(tainted)
        self.validated = frozenset(validated)

    def with_tainted(self, names):
        return _State(self.tainted | frozenset(names), self.validated)

    def without(self, names):
        names = frozenset(names)
        return _State(self.tainted - names, self.validated - names)

    def with_validated(self, names):
        return _State(self.tainted, self.validated | frozenset(names))

    def key(self):
        return self.tainted, self.validated

    def __eq__(self, other):
        return self.key() == other.key()

    def __hash__(self):
        return hash(self.key())


def _call_name(node):
    # Return the dotted callable name, e.g. open or os.path.join.
    func = getattr(node, "func", None)
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return None


def _matches(call, names):
    called = _call_name(call)
    if called is None:
        return False
    for name in names:
        if called == name or called.endswith("." + name):
            return True
    return False


def _store_names(target):
    names = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            names.update(_store_names(element))
    elif isinstance(target, ast.Starred):
        names.update(_store_names(target.value))
    return names


def _load_names(node):
    return {
        inner.id
        for inner in ast.walk(node)
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load)
    }


def _expr_taints(node, state):
    return _load_names(node) & set(state.tainted)


def _calls(node, names):
    return [
        inner
        for inner in ast.walk(node)
        if isinstance(inner, ast.Call) and _matches(inner, names)
    ]


def _call_argument_names(call):
    names = set()
    for arg in call.args:
        names.update(_load_names(arg))
    for keyword in call.keywords:
        names.update(_load_names(keyword.value))
    return names


def _header_expression(statement):
    # Only If/While carry a test expression that executes before branching.
    if isinstance(statement, (ast.If, ast.While)):
        return statement.test
    return None


def _expression_events(value, spec):
    events = []
    events.extend(("source", call) for call in _calls(value, spec.sources))
    events.extend(
        ("validator", call) for call in _calls(value, spec.validators)
    )
    events.extend(("sink", call) for call in _calls(value, spec.sinks))
    return events


def _apply_assignment(statement, state, spec):
    if isinstance(statement, ast.Assign):
        targets, value = statement.targets, statement.value
    elif isinstance(statement, ast.AnnAssign):
        targets = [statement.target] if statement.target else []
        value = statement.value
    elif isinstance(statement, ast.AugAssign):
        targets, value = [statement.target], statement.value
    else:
        return state, []

    events = _expression_events(value, spec) if value is not None else []
    stored = set()
    for target in targets:
        stored.update(_store_names(target))

    new_state = state.without(stored)
    rhs_is_source = any(kind == "source" for kind, _ in events)
    if value is not None and (_expr_taints(value, state) or rhs_is_source):
        new_state = new_state.with_tainted(stored)
    return new_state, events


class _FlowAnalyzer(object):
    def __init__(self, spec, scope_node):
        self.spec = spec
        self.scope_node = scope_node

    def initial_state(self):
        parameters = set()
        args = getattr(self.scope_node, "args", None)
        if args is not None:
            arg_nodes = list(getattr(args, "posonlyargs", []))
            arg_nodes += list(args.args)
            arg_nodes += list(getattr(args, "kwonlyargs", []))
            if args.vararg:
                arg_nodes.append(args.vararg)
            if args.kwarg:
                arg_nodes.append(args.kwarg)
            parameters = {arg.arg for arg in arg_nodes}

        # Free variables referenced but never bound inside the scope are
        # untrusted as well: they originate in an enclosing function whose
        # parameters are themselves treated as tainted entry points.
        free_variables = self._free_variable_names(parameters)
        return _State(parameters | free_variables, set())

    def _free_variable_names(self, parameters):
        if not isinstance(
            self.scope_node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            return set()

        bound = set(parameters)
        loaded = set()
        called = set()
        handler_types = set()
        for node in ast.walk(self.scope_node):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    bound.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    loaded.add(node.id)
            elif isinstance(node, ast.arg):
                bound.add(node.arg)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
            elif isinstance(node, ast.ExceptHandler) and node.type is not None:
                handler_types.update(_load_names(node.type))
        # Function and exception-class names resolve through imports rather
        # than enclosing-scope data, so they are not tainted free variables.
        excluded = called | handler_types
        return (loaded - bound) - excluded

    def analyze(self):
        # Monotonic dataflow over the CFG. Per-block entry states are joined
        # from all predecessors, so sequential branches merge instead of
        # exploding into an exponential number of paths. A worklist reaches a
        # fixpoint because the join is monotone in both directions.
        graph = cfg.build_cfg(self.scope_node.body)
        initial = self.initial_state()

        entry_states = {graph.entry.id: initial}
        evidence = {graph.entry.id: []}
        worklist = [graph.entry]
        queued = {graph.entry.id}
        explored = 0

        while worklist:
            block = worklist.pop(0)
            queued.discard(block.id)
            entry_state = entry_states[block.id]
            explored += 1
            if explored > self.spec.max_states:
                return FlowResult(
                    FlowVerdict.UNKNOWN,
                    evidence=list(evidence[block.id]),
                    reason="state budget exceeded",
                )

            unsafe, end_state = self._analyze_block(
                block, entry_state, []
            )
            if unsafe is not None:
                unsafe.evidence = list(evidence[block.id])
                return unsafe

            for target, edge in graph.successors(block):
                successor_state = self._edge_state(
                    block, edge, entry_state, end_state
                )
                previous = entry_states.get(target.id)
                merged = (
                    successor_state
                    if previous is None
                    else self._join(previous, successor_state)
                )
                label = self._edge_label(edge, block, target)
                candidate_evidence = evidence[block.id] + [label]
                if previous is None or merged.key() != previous.key():
                    entry_states[target.id] = merged
                self._update_evidence(
                    evidence, target.id, candidate_evidence, edge
                )
                if (
                    previous is None
                    or merged.key() != previous.key()
                ) and target.id not in queued:
                    queued.add(target.id)
                    worklist.append(target)

        return FlowResult(FlowVerdict.SAFE)

    @staticmethod
    def _update_evidence(evidence, target_id, candidate, edge):
        # Rank candidate paths lexicographically by (significance, -length):
        # significance counts meaningful control-transfer edges
        # (branch/except/finally), which identify how validation was bypassed.
        # A more explanatory path wins even if it is one edge longer, because
        # the plain fall-through path is precisely the validated, safe path.
        def rank(labels):
            significance = sum(
                1 for label in labels if not label.startswith("fall")
            )
            return (significance, -len(labels))

        incumbent = evidence.get(target_id)
        if incumbent is None or rank(candidate) > rank(incumbent):
            evidence[target_id] = candidate

    @staticmethod
    def _join(left, right):
        # Taint is a may-fact (union): a value is tainted if any reaching path
        # taints it. Validation is a must-fact (intersection): a value is
        # validated only when every reaching path validated it. Both
        # directions are monotone across worklist iterations - union only
        # grows taint and intersection only shrinks validation - so the
        # worklist still reaches a fixpoint.
        return _State(
            left.tainted | right.tainted,
            left.validated & right.validated,
        )

    def _analyze_block(self, block, state, evidence):
        current = state
        for statement in block.statements:
            if isinstance(
                statement,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                # Nested scopes are analyzed independently.
                continue

            if isinstance(
                statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)
            ):
                current, events = _apply_assignment(
                    statement, current, self.spec
                )
                sink = self._first_unsafe_sink(events, current)
                if sink is not None:
                    return self._unsafe(sink, evidence), current
                current = self._apply_raises_validator(events, current)
                continue

            if isinstance(statement, ast.For):
                # Iteration binds the loop target to values drawn from the
                # iterable; treat the target as untrusted on entry to the
                # loop body.
                target_names = _store_names(statement.target)
                iter_taint = _expr_taints(statement.iter, current)
                if iter_taint or target_names:
                    current = current.with_tainted(target_names)

            # Compound statements own nested blocks in the CFG, so only the
            # header expressions are inspected here; calls inside their
            # bodies belong to successor blocks and must not be pre-judged.
            header = _header_expression(statement)
            if header is not None:
                sink_calls = _calls(header, self.spec.sinks)
                validator_calls = _calls(header, self.spec.validators)
            elif isinstance(statement, ast.For):
                sink_calls = _calls(statement.iter, self.spec.sinks)
                validator_calls = _calls(
                    statement.iter, self.spec.validators
                )
            else:
                sink_calls = _calls(statement, self.spec.sinks)
                validator_calls = _calls(statement, self.spec.validators)

            for call in sink_calls:
                tainted = _call_argument_names(call) & set(current.tainted)
                if tainted - set(current.validated):
                    return self._unsafe(call, evidence), current

            current = self._apply_raises_validator(
                [("validator", call) for call in validator_calls], current
            )
        return None, current

    def _first_unsafe_sink(self, events, state):
        for kind, call in events:
            if kind != "sink":
                continue
            tainted = _call_argument_names(call) & set(state.tainted)
            if tainted - set(state.validated):
                return call
        return None

    def _apply_raises_validator(self, events, state):
        if self.spec.validator_contract != ValidatorContract.RAISES:
            return state
        validated = set()
        for kind, call in events:
            if kind != "validator":
                continue
            validated.update(
                _call_argument_names(call) & set(state.tainted)
            )
        return state.with_validated(validated)

    def _edge_state(self, block, edge, entry_state, end_state):
        if self._is_loop_back_edge(edge):
            # Validation is a per-iteration must-fact: a value validated at
            # the top of one iteration must not be assumed before the next
            # iteration runs its own validator. Carry taint forward only.
            return _State(end_state.tainted, set())

        if edge.kind == cfg.EXCEPTION:
            # The normal-path validator was skipped; validation is lost.
            return _State(entry_state.tainted, set())

        if (
            self.spec.validator_contract == ValidatorContract.BOOL
            and edge.kind == cfg.BRANCH
        ):
            tested = self._branch_validator_names(block, entry_state)
            if tested:
                if edge.label is True:
                    return end_state.with_validated(tested)
                # The rejecting branch did not validate the value.
                return _State(end_state.tainted, set())
        return end_state

    @staticmethod
    def _is_loop_back_edge(edge):
        # A fall/branch edge whose target block id is lower than its source
        # is a back edge created by a loop header re-entry.
        return (
            edge.kind in (cfg.FALL, cfg.BRANCH)
            and edge.target.id <= edge.source.id
        )

    def _branch_validator_names(self, block, entry_state):
        # Names passed as arguments to a BOOL validator inside the branch
        # condition. Only a recognized validator call counts; an arbitrary
        # if-test never validates anything.
        names = set()
        for statement in block.statements:
            test = getattr(statement, "test", None)
            if test is None:
                continue
            for call in _calls(test, self.spec.validators):
                names.update(
                    _call_argument_names(call) & set(entry_state.tainted)
                )
        return names

    @staticmethod
    def _edge_label(edge, source=None, target=None):
        lineno = edge.lineno
        if lineno is None and source is not None:
            lineno = source.lineno
        if lineno is None and target is not None:
            lineno = target.lineno
        if edge.kind == cfg.BRANCH:
            return "branch:{}@{}".format(edge.label, lineno)
        if edge.kind == cfg.EXCEPTION:
            return "except@{}".format(lineno)
        if edge.kind == cfg.FINALLY:
            return "finally@{}".format(lineno)
        return "fall@{}".format(lineno)

    def _unsafe(self, call, evidence):
        return FlowResult(
            FlowVerdict.UNSAFE,
            evidence=evidence,
            sink_lineno=call.lineno,
            sink_name=_call_name(call),
        )


def analyze_function(scope_node, spec):
    # Analyze one function (or module) node against a RuleSpec.
    return _FlowAnalyzer(spec, scope_node).analyze()
