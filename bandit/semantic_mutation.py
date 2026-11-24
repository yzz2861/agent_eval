import ast
import copy
import itertools
from dataclasses import dataclass, field
from enum import Enum


class SemanticStatus(str, Enum):
    PRESERVED = "preserved"
    CHANGED = "changed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Seed:
    name: str
    kind: str
    source: str
    test_id: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mutation:
    transform: str
    status: SemanticStatus
    preconditions: tuple[str, ...]
    expected: tuple[str, ...]
    source: str
    trajectory: tuple[dict[str, object], ...]
    seed_name: str
    seed_kind: str


class SemanticMutator:
    def __init__(self, node_budget=80):
        self.node_budget = node_budget
        self._name_counter = itertools.count(1)

    def generate(self, seed):
        tree = ast.parse(seed.source)
        target = self._find_target(tree, seed)
        if target is None:
            return ()

        mutations = []
        seen = set()
        builders = (
            self._reorder_keyword_arguments,
            self._reorder_positional_arguments,
            self._extract_argument,
            self._extract_call,
            self._alias_callable,
            self._alias_module,
            self._shadow_alias,
            self._wrap_branch,
        )
        for builder in builders:
            for candidate in builder(tree, target, seed):
                mutation = self._materialize(seed, candidate)
                if mutation is None or mutation.source in seen:
                    continue
                seen.add(mutation.source)
                mutations.append(mutation)
        return tuple(mutations)

    def _materialize(self, seed, candidate):
        transform, status, preconditions, expected, tree = candidate
        if self._count_nodes(tree) > self.node_budget:
            return None
        ast.fix_missing_locations(tree)
        try:
            source = ast.unparse(tree)
            compile(source, f"<{seed.name}-mutation>", "exec")
        except (SyntaxError, ValueError):
            return None
        trajectory = (
            {
                "transform": transform,
                "status": status.value,
                "preconditions": list(preconditions),
                "expected": list(expected),
            },
        )
        return Mutation(
            transform=transform,
            status=status,
            preconditions=preconditions,
            expected=expected,
            source=source,
            trajectory=trajectory,
            seed_name=seed.name,
            seed_kind=seed.kind,
        )

    def _find_target(self, tree, seed):
        names = {"load", "loads", "Unpickler"}
        if seed.kind == "command_injection":
            names = {"Popen", "call", "run", "check_output"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in names:
                return node
            if isinstance(func, ast.Attribute) and func.attr in names:
                return node
        return None

    def _reorder_keyword_arguments(self, tree, target, seed):
        if len(target.keywords) < 2:
            return ()
        original = tuple(keyword.arg for keyword in target.keywords)
        reordered = tuple(reversed(target.keywords))
        if tuple(keyword.arg for keyword in reordered) == original:
            return ()
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        candidate_target.keywords = reordered
        preconditions = (
            "all reordered arguments are passed by keyword",
            "keyword argument names remain bound to the same values",
        )
        return [
            (
                "argument_reorder_keyword",
                SemanticStatus.PRESERVED,
                preconditions,
                (seed.test_id,),
                candidate,
            )
        ]

    def _reorder_positional_arguments(self, tree, target, seed):
        if len(target.args) < 2 or target.keywords:
            return ()
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        candidate_target.args = list(reversed(candidate_target.args))
        preconditions = (
            "at least two positional arguments are present",
            "no keyword arguments participate in the call",
        )
        return [
            (
                "argument_reorder_positional",
                SemanticStatus.UNKNOWN,
                preconditions,
                (),
                candidate,
            )
        ]

    def _extract_argument(self, tree, target, seed):
        candidates = []
        expressions = [
            argument
            for argument in target.args
            if not isinstance(argument, ast.Name)
        ]
        for index, expression in enumerate(expressions):
            candidate = self._copied_tree(tree)
            candidate_target = self._matching_node(candidate, target)
            copied_expression = self._matching_node(candidate, expression)
            helper_name = self._unique_name("argument_value")
            helper = self._helper_function(
                helper_name, ast.Return(value=copy.deepcopy(copied_expression))
            )
            candidate.body.insert(0, helper)
            argument_index = target.args.index(expression)
            candidate_target.args[argument_index] = ast.Call(
                func=ast.Name(id=helper_name, ctx=ast.Load()),
                args=[],
                keywords=[],
            )
            preconditions = (
                "the extracted expression has no local-variable dependency",
                "the helper is invoked at the same evaluation point",
            )
            candidates.append(
                (
                    f"function_extract_argument_{index}",
                    SemanticStatus.PRESERVED,
                    preconditions,
                    (seed.test_id,),
                    candidate,
                )
            )
        return tuple(candidates)

    def _extract_call(self, tree, target, seed):
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        helper_name = self._unique_name("run_sink")
        helper = self._helper_function(
            helper_name, ast.Return(value=copy.deepcopy(candidate_target))
        )
        replacement = ast.Call(
            func=ast.Name(id=helper_name, ctx=ast.Load()),
            args=[],
            keywords=[],
        )
        self._replace_node(candidate, candidate_target, replacement)
        candidate.body.insert(0, helper)
        preconditions = (
            "the complete sink call is moved without argument changes",
            "the helper is invoked on the original execution path",
        )
        return [
            (
                "function_extract_call",
                SemanticStatus.PRESERVED,
                preconditions,
                (seed.test_id,),
                candidate,
            )
        ]

    def _alias_callable(self, tree, target, seed):
        call_name = self._callable_name(target)
        if call_name is None:
            return ()
        alias_name = self._unique_name("sink_alias")
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        candidate_target.func = ast.Name(id=alias_name, ctx=ast.Load())
        alias_node = ast.Assign(
            targets=[ast.Name(id=alias_name, ctx=ast.Store())],
            value=ast.Name(id=call_name, ctx=ast.Load()),
        )
        candidate.body.insert(0, alias_node)
        preconditions = (
            f"{alias_name} is not already bound in the module scope",
            f"{call_name} is not reassigned before the aliased call",
        )
        return [
            (
                "alias_shadow_callable",
                SemanticStatus.PRESERVED,
                preconditions,
                (seed.test_id,),
                candidate,
            )
        ]

    def _alias_module(self, tree, target, seed):
        if not isinstance(target.func, ast.Attribute):
            return ()
        module_name = target.func.value.id
        alias_name = self._unique_name("module_alias")
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        candidate_target.func.value = ast.Name(id=alias_name, ctx=ast.Load())
        alias_node = ast.Import(
            names=[ast.alias(name=module_name, asname=alias_name)]
        )
        candidate.body.insert(0, alias_node)
        preconditions = (
            f"{alias_name} is not already bound in the module scope",
            f"{module_name} resolves to the same imported module",
        )
        return [
            (
                "alias_shadow_module",
                SemanticStatus.PRESERVED,
                preconditions,
                (seed.test_id,),
                candidate,
            )
        ]

    def _shadow_alias(self, tree, target, seed):
        call_name = self._callable_name(target)
        if call_name is None:
            return ()
        safe_name = self._unique_name("safe_replacement")
        candidate = self._copied_tree(tree)
        candidate_target = self._matching_node(candidate, target)
        candidate_target.func = ast.Name(id=call_name, ctx=ast.Load())
        safe_function = self._helper_function(
            safe_name, ast.Return(value=ast.Constant(value=None))
        )
        shadow = ast.Assign(
            targets=[ast.Name(id=call_name, ctx=ast.Store())],
            value=ast.Name(id=safe_name, ctx=ast.Load()),
        )
        insert_at = self._target_statement_index(candidate, candidate_target)
        candidate.body.insert(insert_at, safe_function)
        candidate.body.insert(insert_at + 1, shadow)
        preconditions = (
            f"{call_name} is reassigned before the original call",
            "the replacement does not invoke the dangerous callee",
        )
        return [
            (
                "alias_shadow_rebinding",
                SemanticStatus.CHANGED,
                preconditions,
                (),
                candidate,
            )
        ]

    def _wrap_branch(self, tree, target, seed):
        candidates = []
        for condition, transform in (
            (ast.Constant(value=True), "branch_wrap_reachable"),
            (ast.Constant(value=False), "branch_wrap_unreachable"),
        ):
            candidate = self._copied_tree(tree)
            candidate_target = self._matching_node(candidate, target)
            statement = self._target_statement(candidate, candidate_target)
            index = candidate.body.index(statement)
            branch = ast.If(
                test=condition,
                body=[statement],
                orelse=[],
            )
            candidate.body[index] = branch
            preserved = condition.value is True
            preconditions = (
                "the branch condition is a compile-time constant",
                "the dangerous statement is the only wrapped statement",
            )
            candidates.append(
                (
                    transform,
                    SemanticStatus.PRESERVED
                    if preserved
                    else SemanticStatus.CHANGED,
                    preconditions,
                    (seed.test_id,) if preserved else (),
                    candidate,
                )
            )
        return tuple(candidates)

    def _helper_function(self, name, statement):
        return ast.FunctionDef(
            name=name,
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=[statement],
            decorator_list=[],
            returns=None,
        )

    def _unique_name(self, prefix):
        return f"{prefix}_{next(self._name_counter)}"

    def _copied_tree(self, tree):
        return copy.deepcopy(tree)

    def _matching_node(self, tree, original):
        for node in ast.walk(tree):
            if (node.lineno, node.col_offset) == (
                original.lineno,
                original.col_offset,
            ) and type(node) is type(original):
                return node
        raise ValueError("mutation target disappeared from copied tree")

    def _replace_node(self, tree, old_node, new_node):
        for parent in ast.walk(tree):
            for field_name, value in ast.iter_fields(parent):
                if isinstance(value, list) and old_node in value:
                    value[value.index(old_node)] = new_node
                    ast.fix_missing_locations(new_node)
                    return
                if value is old_node:
                    setattr(parent, field_name, new_node)
                    ast.fix_missing_locations(new_node)
                    return
        raise ValueError("mutation target cannot be replaced")

    def _target_statement(self, tree, target):
        for statement in tree.body:
            if target in ast.walk(statement):
                return statement
        raise ValueError("mutation target has no module statement")

    def _target_statement_index(self, tree, target):
        return tree.body.index(self._target_statement(tree, target))

    def _callable_name(self, target):
        if isinstance(target.func, ast.Name):
            return target.func.id
        if isinstance(target.func, ast.Attribute):
            return target.func.attr
        return None

    def _count_nodes(self, tree):
        return sum(1 for _ in ast.walk(tree))
