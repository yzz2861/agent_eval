#
# SPDX-License-Identifier: Apache-2.0
"""Limited, conservative lifecycle analysis for registered aggregates.

The analysis follows one aggregate object through aliases, local calls,
retry wrappers, generators and exception handlers.  It only reports exits at
which a concrete alias is still reachable and at least one identity-bearing
field has not been released.  Unknown control flow is treated conservatively,
but no finding is produced from a name that has merely gone out of scope.
"""
import ast
import copy
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from bandit.core import aggregate_registry as registry
from bandit.core import utils


_AGGREGATE_RE = re.compile(
    r"(?i)(aggregat|accumulat|statsaggregat|statsbuffer|statsaccumul|summarybuffer)"
)
_IDENTITY_RE = re.compile(
    r"(?i)(identity|identities|principal|subject|tenant|account|customer|"
    r"member|user|email|phone|ssn|token|secret|credential)"
)
_IDENTITY_ID_RE = re.compile(
    r"(?i)(^|_)(user|account|tenant|member|customer|principal|subject|"
    r"identity|session|request)_?id($|_)"
)
_RETRY_RE = re.compile(r"(?i)(retry|retrying|backoff|tenacity)")
_MUTATING_CONTAINER_METHODS = frozenset(
    {"add", "append", "extend", "insert", "setdefault", "update"}
)
_EMPTY_VALUES = (ast.Dict, ast.List, ast.Set, ast.Tuple)
_BENIGN_CALLS = frozenset(
    {
        "all",
        "any",
        "bool",
        "dict",
        "enumerate",
        "float",
        "format",
        "getattr",
        "hasattr",
        "id",
        "int",
        "isinstance",
        "len",
        "list",
        "max",
        "min",
        "open",
        "print",
        "range",
        "repr",
        "set",
        "sorted",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
    }
)

_PASS_DECORATORS = frozenset(
    {
        "aggregate",
        "aggregate_pass",
        "aggregation",
        "aggregation_pass",
        "pass_name",
        "synthesis",
        "synthesize",
    }
)

_EXIT_PRIORITY = {
    "publish": 100,
    "retry": 90,
    "return": 80,
    "yield": 75,
    "attribute": 70,
    "global": 65,
    "container": 60,
    "closure": 55,
    "exception": 50,
    "call-argument": 45,
    "generator": 40,
    "parameter-alias": 35,
    "module-global": 30,
}


@dataclass(frozen=True)
class AggregateType:
    name: str
    qualified_name: str
    identity_fields: frozenset = frozenset()
    release_methods: frozenset = frozenset()
    publish_methods: frozenset = frozenset()
    registered: bool = False
    class_node: ast.ClassDef = None


@dataclass
class ClassInfo:
    name: str
    qualname: str
    node: ast.ClassDef
    methods: dict = dataclass_field(default_factory=dict)
    identity_fields: frozenset = frozenset()
    release_methods: frozenset = frozenset()
    publish_methods: frozenset = frozenset()
    registered: bool = False


@dataclass
class FunctionInfo:
    node: ast.AST
    name: str
    qualname: str
    class_name: str = ""
    is_nested: bool = False
    is_async: bool = False
    is_generator: bool = False
    has_close_release: bool = False


@dataclass
class Value:
    obj_key: int = None
    contained: tuple = ()
    generator_of: FunctionInfo = None
    identity_owner: int = None
    identity_field: str = ""
    empty_literal: bool = False


@dataclass
class ObjState:
    key: int
    type_name: str
    aggregate: AggregateType
    active_fields: set = dataclass_field(default_factory=set)
    escaped: list = dataclass_field(default_factory=list)
    external: bool = False
    module_global: bool = False
    inferred: bool = False
    created_line: int = 0
    close_released: bool = False


@dataclass
class PendingExit:
    kind: str
    lineno: int
    obj_key: int
    note: str = ""
    fields: tuple = None


@dataclass
class State:
    vars: dict = dataclass_field(default_factory=dict)
    objs: dict = dataclass_field(default_factory=dict)
    containers: dict = dataclass_field(default_factory=dict)
    generators: dict = dataclass_field(default_factory=dict)
    pending: list = dataclass_field(default_factory=list)
    terminal: bool = False

    def clone(self):
        return copy.deepcopy(self)


@dataclass
class ExitFact:
    root: str
    pass_name: str
    type_name: str
    fields: tuple
    kind: str
    lineno: int
    function: str

    @property
    def priority(self):
        return _EXIT_PRIORITY.get(self.kind, 0)


@dataclass
class Finding:
    aggregate_type: str
    retained_identity_fields: tuple
    exit_kind: str
    lineno: int
    function: str
    pass_name: str
    message: str
    test_id: str = "B115"

    def as_dict(self):
        return {
            "test_id": self.test_id,
            "aggregate_type": self.aggregate_type,
            "pass": self.pass_name,
            "function": self.function,
            "exit": self.exit_kind,
            "line": self.lineno,
            "retained_identity_fields": list(
                self.retained_identity_fields
            ),
            "message": self.message,
        }


def _name_list(value):
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str)]
    return []


def _config_value(config, *names, default=None):
    for name in names:
        if name in config and config[name] is not None:
            return config[name]
    return default


class AggregateRegistry:
    """Resolves aggregate types from config, module metadata and defaults."""

    def __init__(self, module, config):
        self.config = config or {}
        self.classes = {}
        self.class_short_names = {}
        self.types = {}
        self.extra_identity_fields = set(
            _name_list(
                _config_value(
                    self.config,
                    "identity_fields",
                    "identity_field_names",
                )
            )
        )
        self._configured = self._normalise_types(
            _config_value(
                self.config,
                "aggregate_objects",
                "aggregate_types",
                "registered_objects",
                "objects",
                default=[],
            )
        )
        self._collect_classes(module)
        self._collect_module_registry(module)
        self._collect_defaults()

    def _normalise_types(self, value):
        result = {}
        if not value:
            return result
        if isinstance(value, str):
            value = [value]
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, dict):
                    entry = dict(item)
                    entry.setdefault("type", key)
                elif isinstance(item, (list, tuple, set)):
                    entry = {"type": key, "identity_fields": list(item)}
                else:
                    entry = {"type": key}
                result[key] = entry
            return result
        for item in value:
            if isinstance(item, str):
                result[item] = {"type": item}
            elif isinstance(item, dict):
                name = item.get("type") or item.get("name")
                if name:
                    result[name] = dict(item)
        return result

    def _collect_classes(self, module):
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            identity_fields = set()
            for item in ast.walk(node):
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        self._class_target(target, identity_fields)
                elif isinstance(item, ast.AnnAssign):
                    self._class_target(item.target, identity_fields)
            methods = {}
            release_methods = set()
            publish_methods = set()
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                info = FunctionInfo(
                    node=item,
                    name=item.name,
                    qualname=f"{node.name}.{item.name}",
                    class_name=node.name,
                    is_async=isinstance(item, ast.AsyncFunctionDef),
                    is_generator=self._contains_yield(item),
                    has_close_release=self._has_close_release(item),
                )
                methods[item.name] = info
                if self._is_release_method(item.name, identity_fields):
                    release_methods.add(item.name)
                if self._is_publish_method(item.name):
                    publish_methods.add(item.name)
            decorated = any(
                self._decorator_name(dec) in {
                    "register_aggregate",
                    "aggregate_object",
                    "bandit_aggregate",
                }
                for dec in node.decorator_list
            )
            looks_aggregate = bool(_AGGREGATE_RE.search(node.name))
            marker = any(
                isinstance(item, ast.Assign)
                and any(
                    isinstance(t, ast.Name)
                    and t.id
                    in {"__aggregate__", "__bandit_aggregate__"}
                    for t in item.targets
                )
                for item in node.body
            )
            info = ClassInfo(
                name=node.name,
                qualname=node.name,
                node=node,
                methods=methods,
                identity_fields=frozenset(identity_fields),
                registered=decorated or marker or looks_aggregate,
                release_methods=frozenset(release_methods),
                publish_methods=frozenset(publish_methods),
            )
            self.classes[node.name] = info
            self.class_short_names[node.name] = info

    @staticmethod
    def _class_target(target, identity_fields):
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
        else:
            return
        if _IDENTITY_RE.search(name) or _IDENTITY_ID_RE.search(name):
            identity_fields.add(name)

    def _collect_module_registry(self, module):
        for item in module.body:
            targets = []
            value = None
            if isinstance(item, ast.Assign):
                targets = item.targets
                value = item.value
            elif isinstance(item, ast.AnnAssign):
                targets = [item.target]
                value = item.value
            if value is None:
                continue
            for target in targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id in registry.REGISTRY_CONSTANT_NAMES
                ):
                    for name in self._registry_names(value):
                        if name:
                            self._configured.setdefault(name, {"type": name})

    def _registry_names(self, value):
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            names = []
            for element in value.elts:
                names.extend(self._registry_names(element))
            return names
        if isinstance(value, ast.Dict):
            names = []
            for key, item in zip(value.keys, value.values):
                key_name = self._constant_or_name(key)
                if key_name in {"type", "name"}:
                    names.append(self._constant_or_name(item))
                elif key_name:
                    names.append(key_name)
            return names
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return [value.value]
        if isinstance(value, ast.Name):
            return [value.id]
        return []

    @staticmethod
    def _constant_or_name(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _collect_defaults(self):
        for entry in registry.DEFAULT_AGGREGATE_OBJECTS:
            name = entry.get("type")
            if name:
                self._configured.setdefault(name, dict(entry))

    def _register(self, name, entry, class_info=None):
        identity_fields = set(_name_list(entry.get("identity_fields")))
        if class_info is not None:
            identity_fields.update(class_info.identity_fields)
        release_methods = set(_name_list(entry.get("release_methods")))
        if class_info is not None:
            release_methods.update(class_info.release_methods)
        publish_methods = set(_name_list(entry.get("publish_methods")))
        if class_info is not None:
            publish_methods.update(class_info.publish_methods)
        aggregate = AggregateType(
            name=name,
            qualified_name=entry.get("qualified_name", name),
            identity_fields=frozenset(identity_fields),
            release_methods=frozenset(release_methods),
            publish_methods=frozenset(publish_methods),
            registered=True,
            class_node=class_info.node if class_info is not None else None,
        )
        self.types[name] = aggregate
        return aggregate

    @staticmethod
    def _decorator_name(node):
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _contains_yield(node):
        return any(
            isinstance(item, (ast.Yield, ast.YieldFrom))
            for item in ast.walk(node)
        )

    def _has_close_release(self, node):
        class _Visitor(ast.NodeVisitor):
            def __init__(self, owner):
                self.owner = owner
                self.found = False

            def visit_Try(self, item):
                for statement in item.finalbody:
                    if self.owner._contains_release(statement):
                        self.found = True
                for handler in item.handlers:
                    close_handler = handler.type is not None and (
                        self.owner._type_name(handler.type)
                        == "GeneratorExit"
                    )
                    if close_handler and any(
                        self.owner._contains_release(statement)
                        for statement in handler.body
                    ):
                        self.found = True
                self.generic_visit(item)

        visitor = _Visitor(self)
        visitor.visit(node)
        return visitor.found

    def _contains_release(self, node):
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                if (
                    self._call_last_name(item)
                    in registry.DEFAULT_RELEASE_METHODS
                    | self._configured_release_methods()
                ):
                    return True
        return False

    def _configured_release_methods(self):
        return set(
            _name_list(
                _config_value(self.config, "release_methods", "clear_methods")
            )
        )

    def _configured_publish_methods(self):
        return set(
            _name_list(
                _config_value(
                    self.config, "publish_methods", "publish_functions"
                )
            )
        )

    def _is_release_method(self, name, identity_fields=()):
        methods = set(registry.DEFAULT_RELEASE_METHODS)
        methods.update(self._configured_release_methods())
        if name in methods:
            return True
        return bool(
            name.startswith("clear")
            and ("identity" in name or "cache" in name or "identit" in name)
        )

    def _is_publish_method(self, name):
        methods = set(registry.DEFAULT_PUBLISH_METHODS)
        methods.update(self._configured_publish_methods())
        return name in methods

    @staticmethod
    def _call_last_name(node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _type_name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def resolve_type(self, name):
        if not name:
            return None
        short = name.split(".")[-1]
        if short in self.classes:
            class_info = self.classes[short]
            if class_info.registered:
                entry = self._configured.get(short, {"type": short})
                return self._register(short, entry, class_info)
        for registered_name, entry in self._configured.items():
            registered_short = registered_name.split(".")[-1]
            if name == registered_name or short == registered_short:
                class_info = self.classes.get(registered_short)
                return self._register(registered_short, entry, class_info)
        if _AGGREGATE_RE.search(short):
            entry = self._configured.get(short, {"type": short})
            class_info = self.classes.get(short)
            return self._register(short, entry, class_info)
        return None

    def resolve_annotation(self, node):
        return self.resolve_type(self._type_name(node))

    def is_identity_field(self, name):
        return bool(
            name in self.extra_identity_fields
            or name in registry.DEFAULT_IDENTITY_FIELD_NAMES
            or _IDENTITY_RE.search(name)
            or _IDENTITY_ID_RE.search(name)
        )

    def is_release_method(self, name):
        return self._is_release_method(name)

    def is_publish_method(self, name):
        return self._is_publish_method(name)

    def class_for(self, type_name):
        short = (type_name or "").split(".")[-1]
        return self.classes.get(short)


@dataclass
class Frame:
    info: FunctionInfo
    depth: int = 0
    parent: object = None
    globals: set = dataclass_field(default_factory=set)
    nonlocals: set = dataclass_field(default_factory=set)

    @property
    def name(self):
        return self.info.name if self.info is not None else "<module>"

    @property
    def qualname(self):
        return self.info.qualname if self.info is not None else "<module>"


class AggregateLifecycleAnalyzer:
    """Analyze one root function without crossing registered object exits."""

    max_depth = 6
    max_states = 64

    def __init__(self, source, filename="", config=None):
        self.source = source
        self.filename = filename
        self.config = config or {}
        self.tree = ast.parse(source, filename=filename or "<unknown>")
        self.registry = AggregateRegistry(self.tree, self.config)
        self.import_aliases = {}
        self._collect_imports()
        self.functions = {}
        self.short_functions = {}
        self.methods_by_class = {}
        self.called_names = set()
        self.roots = []
        self._collect_functions()
        self._collect_calls()
        self.retry_wrappers = self._find_retry_wrappers()
        self.retry_lines = {}
        self._map_retry_decorators()
        self._next_key = 0
        self.exits = []
        self._active_root = None
        self._module_state = self._build_module_state()

    def _collect_imports(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.import_aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    qualified = f"{module}.{alias.name}" if module else alias.name
                    self.import_aliases[alias.asname or alias.name] = qualified

    def _collect_functions(self):
        for item in self.tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = self._function_info(item, "")
                self.functions[info.qualname] = info
                self.short_functions[info.name] = info
            elif isinstance(item, ast.ClassDef):
                for child in item.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        info = self._function_info(child, item.name)
                        self.functions[info.qualname] = info
                        self.methods_by_class.setdefault(item.name, {})[
                            info.name
                        ] = info
                        self.short_functions.setdefault(
                            info.name, info
                        )

    def _function_info(self, node, class_name):
        qualname = f"{class_name}.{node.name}" if class_name else node.name
        return FunctionInfo(
            node=node,
            name=node.name,
            qualname=qualname,
            class_name=class_name,
            is_nested=bool(class_name),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_generator=any(
                isinstance(item, (ast.Yield, ast.YieldFrom))
                for item in ast.walk(node)
            ),
            has_close_release=self.registry._has_close_release(node),
        )

    def _collect_calls(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._call_last_name(node)
                if name:
                    self.called_names.add(name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    name = self._decorator_name(decorator)
                    if name:
                        self.called_names.add(name)
        self.roots = [
            info
            for qualname, info in self.functions.items()
            if not info.class_name and info.name not in self.called_names
        ]

    @staticmethod
    def _call_last_name(node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _decorator_name(node):
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _call_name(self, node):
        return utils.get_call_name(node, self.import_aliases)

    def _find_retry_wrappers(self):
        wrappers = {}
        for info in self.functions.values():
            if info.class_name:
                continue
            for item in ast.walk(info.node):
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if item is info.node:
                    continue
                if not item.args.vararg:
                    continue
                has_loop = any(
                    isinstance(child, (ast.For, ast.AsyncFor, ast.While))
                    for child in ast.walk(item)
                )
                has_try = any(
                    isinstance(child, ast.Try)
                    and bool(child.handlers)
                    for child in ast.walk(item)
                )
                forwards_args = any(
                    isinstance(child, ast.Call)
                    and any(isinstance(arg, ast.Starred) for arg in child.args)
                    for child in ast.walk(item)
                )
                if has_loop and has_try and forwards_args:
                    line = self._retry_call_line(item)
                    wrappers[info.name] = {
                        "info": info,
                        "wrapper": item,
                        "line": line,
                    }
        return wrappers

    @staticmethod
    def _retry_call_line(wrapper):
        for item in ast.walk(wrapper):
            if isinstance(item, ast.Call) and any(
                isinstance(arg, ast.Starred) for arg in item.args
            ):
                return getattr(item, "lineno", wrapper.lineno)
        return wrapper.lineno

    def _map_retry_decorators(self):
        for info in self.functions.values():
            if info.class_name:
                continue
            for decorator in info.node.decorator_list:
                name = self._decorator_name(decorator)
                if name in self.retry_wrappers:
                    self.retry_lines[info.qualname] = self.retry_wrappers[
                        name
                    ]["line"]
                elif _RETRY_RE.search(name):
                    self.retry_lines[info.qualname] = getattr(
                        decorator, "lineno", info.node.lineno
                    )

    def _build_module_state(self):
        state = State()
        frame = Frame(info=None)
        for statement in self.tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                self._exec_assign(statement, state, frame, 0)
            elif isinstance(statement, ast.Expr):
                self._eval_expr(statement.value, state, frame, 0)
        for obj in state.objs.values():
            obj.external = True
            obj.module_global = True
            obj.escaped.append(
                ("module-global", obj.created_line)
            )
        return state

    def analyze_target(self, node):
        info = None
        for candidate in self.functions.values():
            if (
                candidate.node is node
                or (
                    candidate.name == getattr(node, "name", "")
                    and candidate.node.lineno == getattr(node, "lineno", -1)
                    and not candidate.class_name
                )
            ):
                info = candidate
                break
        if info is None or info.class_name:
            return []
        if info not in self.roots:
            return []
        return self._analyze_root(info)

    def analyze_all(self):
        findings = []
        for info in self.roots:
            findings.extend(self._analyze_root(info))
        return findings

    def _analyze_root(self, info):
        self._active_root = info
        self.exits = []
        state = self._module_state.clone()
        frame = Frame(info=info, depth=0)
        self._bind_params(info.node, state, frame)
        states = self._exec_block(info.node.body, state, frame, 0)
        end_line = self._function_end_line(info.node)
        for item in states:
            self._commit_pending(item, frame, include_returns=True)
            self._collect_end_state(item, frame, end_line)
        retry_line = self.retry_lines.get(info.qualname)
        if retry_line is not None and not info.has_close_release:
            for item in states:
                for obj in item.objs.values():
                    if obj.external and obj.active_fields:
                        self.exits.append(
                            ExitFact(
                                root=info.qualname,
                                pass_name=self._pass_name(info),
                                type_name=obj.type_name,
                                fields=tuple(sorted(obj.active_fields)),
                                kind="retry",
                                lineno=retry_line,
                                function=info.qualname,
                            )
                        )
        return self._findings_for_root(info)

    @staticmethod
    def _function_end_line(node):
        end = getattr(node, "end_lineno", None)
        if end:
            return end
        if node.body:
            return getattr(node.body[-1], "end_lineno", node.lineno)
        return node.lineno

    @staticmethod
    def _pass_name(info):
        for decorator in info.node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            name = AggregateLifecycleAnalyzer._decorator_name(decorator)
            if call is not None and name in _PASS_DECORATORS and call.args:
                first = call.args[0]
                if isinstance(first, ast.Constant) and isinstance(
                    first.value, str
                ):
                    return first.value
        return info.name

    def _bind_params(self, node, state, frame):
        parameters = list(node.args.posonlyargs) + list(node.args.args)
        parameters += list(node.args.kwonlyargs)
        for parameter in parameters:
            aggregate = None
            if parameter.annotation is not None:
                aggregate = self.registry.resolve_annotation(
                    parameter.annotation
                )
            if aggregate is None and self._looks_aggregate(parameter.arg):
                aggregate = self._inferred_type(parameter.arg)
            if aggregate is None:
                continue
            obj_key = self._new_object(
                aggregate,
                parameter,
                state,
                external=True,
                inferred=not aggregate.registered,
            )
            state.vars[parameter.arg] = obj_key

    @staticmethod
    def _looks_aggregate(name):
        return bool(
            _AGGREGATE_RE.search(name)
            or re.search(r"(?i)(^|_)(agg|stats|accumulator|buffer)($|_)", name)
        )

    def _inferred_type(self, name):
        return AggregateType(
            name=name,
            qualified_name=name,
            identity_fields=frozenset(),
            release_methods=frozenset(),
            publish_methods=frozenset(),
            registered=False,
        )

    def _new_object(
        self, aggregate, node, state, external=False, inferred=False
    ):
        key = self._next_key
        self._next_key += 1
        obj = ObjState(
            key=key,
            type_name=aggregate.name,
            aggregate=aggregate,
            active_fields=set(),
            external=external,
            inferred=inferred,
            created_line=getattr(node, "lineno", 1),
        )
        state.objs[key] = obj
        return key

    def _exec_block(self, statements, state, frame, depth):
        states = [state]
        for statement in statements:
            next_states = []
            for item in states:
                if item.terminal:
                    next_states.append(item)
                    continue
                next_states.extend(
                    self._exec_stmt(statement, item, frame, depth)
                )
            if len(next_states) > self.max_states:
                next_states = self._merge_states(next_states)
            states = next_states
            if not states:
                break
        return states

    def _merge_states(self, states):
        merged = states[0]
        for state in states[1:]:
            for key, obj in state.objs.items():
                if key not in merged.objs:
                    merged.objs[key] = obj
                else:
                    merged.objs[key].active_fields.update(obj.active_fields)
            for name, key in state.vars.items():
                merged.vars.setdefault(name, key)
            merged.pending.extend(state.pending)
            merged.terminal = merged.terminal and state.terminal
        merged.pending = self._dedupe_pending(merged.pending)
        return [merged]

    @staticmethod
    def _dedupe_pending(pending):
        seen = set()
        result = []
        for item in pending:
            key = (item.kind, item.lineno, item.obj_key)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def _exec_stmt(self, node, state, frame, depth):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            self._exec_assign(node, state, frame, depth)
            return [state]
        if isinstance(node, ast.AugAssign):
            self._exec_augassign(node, state, frame, depth)
            return [state]
        if isinstance(node, ast.Expr):
            if isinstance(node.value, (ast.Yield, ast.YieldFrom)):
                self._exec_yield(node.value, state, frame, depth)
            else:
                self._eval_expr(node.value, state, frame, depth)
            return [state]
        if isinstance(node, ast.Return):
            return self._exec_return(node, state, frame, depth)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            self._exec_yield(node, state, frame, depth)
            return [state]
        if isinstance(node, ast.Raise):
            self._exec_raise(node, state, frame, depth)
            return [state]
        if isinstance(node, ast.If):
            return self._exec_if(node, state, frame, depth)
        if isinstance(node, (ast.Try,)):
            return self._exec_try(node, state, frame, depth)
        if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
            return self._exec_try(node, state, frame, depth)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            return self._exec_loop(node, state, frame, depth)
        if isinstance(node, ast.While):
            return self._exec_loop(node, state, frame, depth)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._exec_block(node.body, state, frame, depth)
        if isinstance(node, ast.Global):
            frame.globals.update(node.names)
            return [state]
        if isinstance(node, ast.Nonlocal):
            frame.nonlocals.update(node.names)
            return [state]
        if isinstance(node, ast.Delete):
            self._exec_delete(node, state, frame)
            return [state]
        if isinstance(node, ast.Match):
            return self._exec_match(node, state, frame, depth)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [state]
        if isinstance(node, (ast.ClassDef, ast.Import, ast.ImportFrom)):
            return [state]
        if isinstance(node, (ast.Assert, ast.Pass, ast.Break, ast.Continue)):
            return [state]
        return [state]

    def _exec_return(self, node, state, frame, depth):
        value = (
            self._eval_expr(node.value, state, frame, depth)
            if node.value is not None
            else Value()
        )
        line = getattr(node, "lineno", self._function_end_line(frame.info.node))
        if value.obj_key is not None:
            state.pending.append(PendingExit("return", line, value.obj_key))
        for key in value.contained:
            state.pending.append(PendingExit("return", line, key))
        for key, obj in state.objs.items():
            if key in state.vars.values() or obj.external:
                if value.obj_key != key and key not in value.contained:
                    state.pending.append(
                        PendingExit("parameter-alias", line, key)
                    )
        state.terminal = True
        return [state]

    def _exec_yield(self, node, state, frame, depth):
        value = (
            self._eval_expr(node.value, state, frame, depth)
            if getattr(node, "value", None) is not None
            else Value()
        )
        line = getattr(node, "lineno", frame.info.node.lineno)
        if value.obj_key is not None:
            self._add_pending_fact(state, "yield", line, value.obj_key)
        for key in value.contained:
            self._add_pending_fact(state, "yield", line, key)
        if not frame.info.has_close_release:
            for key, obj in state.objs.items():
                if obj.active_fields:
                    self._add_pending_fact(state, "generator", line, key)

    def _exec_raise(self, node, state, frame, depth):
        line = getattr(node, "lineno", frame.info.node.lineno)
        for key, obj in list(state.objs.items()):
            if obj.external or obj.escaped:
                state.pending.append(
                        PendingExit(
                            "exception",
                            line,
                            key,
                            fields=tuple(sorted(obj.active_fields)),
                        )
                )
        retry_line = self.retry_lines.get(frame.qualname)
        if retry_line is not None:
            for key, obj in list(state.objs.items()):
                if obj.external and obj.active_fields:
                    state.pending.append(
                        PendingExit(
                            "retry",
                            retry_line,
                            key,
                            fields=tuple(sorted(obj.active_fields)),
                        )
                    )
        state.pending = self._dedupe_pending(state.pending)
        state.terminal = True

    def _exec_if(self, node, state, frame, depth):
        test = self._eval_expr(node.test, state, frame, depth)
        branches = [
            self._exec_block(node.body, state.clone(), frame, depth)
        ]
        if node.orelse:
            branches.append(
                self._exec_block(node.orelse, state.clone(), frame, depth)
            )
        else:
            branches.append([state.clone()])
        if test.obj_key is not None:
            # A condition value is observed by the branch test.
            self._mark_escape(state, test.obj_key, "call-argument", node.lineno)
        return self._join(branches)

    def _exec_try(self, node, state, frame, depth):
        body_states = self._exec_block(node.body, state, frame, depth)
        exception_states = [
            item
            for item in body_states
            if any(pending.kind == "exception" for pending in item.pending)
        ]
        other_states = [
            item for item in body_states if item not in exception_states
        ]
        handled = []
        for handler in node.handlers:
            for item in exception_states:
                clone = item.clone()
                clone.terminal = False
                clone.pending = []
                handled.extend(
                    self._exec_block(handler.body, clone, frame, depth)
                )
        if node.handlers:
            normal = other_states + handled
        else:
            normal = body_states
        if not normal:
            normal = body_states
        if node.orelse:
            success = [item for item in normal if not item.terminal]
            else_states = []
            for item in success:
                else_states.extend(
                    self._exec_block(node.orelse, item.clone(), frame, depth)
                )
            if else_states:
                normal = else_states + [
                    item for item in normal if item.terminal
                ]
        if node.finalbody:
            final_states = []
            for item in normal:
                was_terminal = item.terminal
                item.terminal = False
                execution = self._exec_block(
                    node.finalbody, item, frame, depth
                )
                if was_terminal:
                    for final_item in execution:
                        final_item.terminal = True
                final_states.extend(execution)
            return final_states
        return normal

    def _exec_loop(self, node, state, frame, depth):
        entry = state.clone()
        body = self._exec_block(node.body, state, frame, depth)
        finals = body + [entry]
        if node.orelse:
            for item in body:
                if not item.terminal:
                    finals.extend(
                        self._exec_block(node.orelse, item.clone(), frame, depth)
                    )
        return finals

    def _exec_match(self, node, state, frame, depth):
        states = [state.clone()]
        for case in node.cases:
            branch = []
            for item in states:
                branch.extend(
                    self._exec_block(case.body, item.clone(), frame, depth)
                )
            states.extend(branch)
        return states

    @staticmethod
    def _join(branches):
        result = []
        for branch in branches:
            result.extend(branch)
        return result

    def _exec_assign(self, node, state, frame, depth):
        if isinstance(node, ast.AnnAssign):
            if node.value is None:
                return
            value = self._eval_expr(node.value, state, frame, depth)
            self._assign_target(node.target, value, state, frame, depth)
            return
        value = self._eval_expr(node.value, state, frame, depth)
        for target in node.targets:
            self._assign_target(target, value, state, frame, depth)

    def _assign_target(self, target, value, state, frame, depth):
        if isinstance(target, ast.Name):
            name = target.id
            if value.obj_key is not None:
                state.vars[name] = value.obj_key
                state.containers.pop(name, None)
                if name in frame.globals:
                    self._mark_escape(
                        state, value.obj_key, "global", target.lineno
                    )
            elif value.contained:
                state.vars.pop(name, None)
                state.containers[name] = tuple(value.contained)
                if name in frame.globals:
                    for key in value.contained:
                        self._mark_escape(
                            state, key, "global", target.lineno
                        )
            else:
                state.vars.pop(name, None)
                state.containers.pop(name, None)
            return
        if isinstance(target, ast.Attribute):
            base = self._eval_expr(target.value, state, frame, depth)
            if base.obj_key is not None and self._is_identity_field(target.attr):
                if value.empty_literal:
                    self._clear_identity_field(state, base.obj_key, target.attr)
                else:
                    self._write_identity_field(
                        state,
                        base.obj_key,
                        target.attr,
                        getattr(target, "lineno", 0),
                    )
                if value.obj_key is not None:
                    self._mark_escape(
                        state,
                        value.obj_key,
                        "container",
                        getattr(target, "lineno", 0),
                    )
                return
            if value.obj_key is not None:
                self._mark_escape(
                    state, value.obj_key, "attribute", getattr(target, "lineno", 0)
                )
            for key in value.contained:
                self._mark_escape(
                    state, key, "attribute", getattr(target, "lineno", 0)
                )
            return
        if isinstance(target, ast.Subscript):
            owner, identity_field = self._identity_owner(target.value, state)
            if owner is not None:
                if value.empty_literal:
                    self._clear_identity_field(state, owner, identity_field)
                else:
                    self._write_identity_field(
                        state,
                        owner,
                        identity_field,
                        getattr(target, "lineno", 0),
                    )
            if value.obj_key is not None:
                self._mark_escape(
                    state, value.obj_key, "container", getattr(target, "lineno", 0)
                )
            for key in value.contained:
                self._mark_escape(
                    state, key, "container", getattr(target, "lineno", 0)
                )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, Value(), state, frame, depth)
            for key in value.contained:
                self._mark_escape(
                    state, key, "container", getattr(target, "lineno", 0)
                )

    def _identity_owner(self, node, state):
        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, state, Frame(info=None), 0)
            if base.obj_key is not None and self._is_identity_field(node.attr):
                return base.obj_key, node.attr
        return None, ""

    def _exec_augassign(self, node, state, frame, depth):
        if isinstance(node.target, ast.Attribute):
            base = self._eval_expr(node.target.value, state, frame, depth)
            if base.obj_key is not None and self._is_identity_field(
                node.target.attr
            ):
                self._write_identity_field(
                    state, base.obj_key, node.target.attr, node.lineno
                )
                return
        self._eval_expr(node.value, state, frame, depth)

    def _exec_delete(self, node, state, frame):
        for target in node.targets:
            if isinstance(target, ast.Name):
                state.vars.pop(target.id, None)
                state.containers.pop(target.id, None)
            elif isinstance(target, ast.Attribute):
                base = self._eval_expr(target.value, state, frame, 0)
                if base.obj_key is not None and self._is_identity_field(
                    target.attr
                ):
                    self._clear_identity_field(
                        state, base.obj_key, target.attr
                    )

    def _is_identity_field(self, name):
        return self.registry.is_identity_field(name)

    def _write_identity_field(self, state, obj_key, field_name, lineno):
        obj = state.objs.get(obj_key)
        if obj is None:
            return
        obj.active_fields.add(field_name)

    @staticmethod
    def _clear_identity_field(state, obj_key, field_name):
        obj = state.objs.get(obj_key)
        if obj is not None:
            obj.active_fields.discard(field_name)

    def _mark_escape(self, state, obj_key, kind, lineno):
        obj = state.objs.get(obj_key)
        if obj is not None:
            obj.escaped.append((kind, lineno))

    def _eval_expr(self, node, state, frame, depth):
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return Value(empty_literal=node.value is None)
        if isinstance(node, ast.Name):
            key = state.vars.get(node.id)
            if key is not None:
                return Value(obj_key=key)
            if node.id in state.containers:
                return Value(contained=tuple(state.containers[node.id]))
            if node.id in state.generators:
                return Value(generator_of=state.generators[node.id])
            return Value()
        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, state, frame, depth)
            if base.obj_key is not None and self._is_identity_field(node.attr):
                return Value(
                    identity_owner=base.obj_key,
                    identity_field=node.attr,
                )
            return Value()
        if isinstance(node, ast.Call):
            return self._eval_call(node, state, frame, depth)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            self._exec_yield(node, state, frame, depth)
            return Value()
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._eval_container(node, node.elts, state, frame, depth)
        if isinstance(node, ast.Dict):
            elements = list(node.keys) + list(node.values)
            return self._eval_container(node, elements, state, frame, depth)
        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, state, frame, depth)
            index = self._eval_expr(node.slice, state, frame, depth)
            contained = list(base.contained)
            if index.obj_key is not None:
                contained.append(index.obj_key)
            return Value(contained=tuple(contained))
        if isinstance(node, ast.IfExp):
            condition = self._eval_expr(node.test, state, frame, depth)
            left = self._eval_expr(node.body, state, frame, depth)
            right = self._eval_expr(node.orelse, state, frame, depth)
            return self._merge_values(condition, left, right)
        if isinstance(node, ast.BoolOp):
            values = [
                self._eval_expr(value, state, frame, depth)
                for value in node.values
            ]
            return self._merge_values(*values)
        if isinstance(node, ast.NamedExpr):
            value = self._eval_expr(node.value, state, frame, depth)
            self._assign_target(node.target, value, state, frame, depth)
            return value
        if isinstance(node, (ast.Await, ast.Starred, ast.UnaryOp)):
            return self._eval_expr(
                getattr(node, "value", None)
                or getattr(node, "operand", None),
                state,
                frame,
                depth,
            )
        if isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left, state, frame, depth)
            right = self._eval_expr(node.right, state, frame, depth)
            return self._merge_values(left, right)
        if isinstance(node, ast.Compare):
            values = [self._eval_expr(node.left, state, frame, depth)]
            for comparator in node.comparators:
                values.append(
                    self._eval_expr(comparator, state, frame, depth)
                )
            return self._merge_values(*values)
        if isinstance(node, ast.JoinedStr):
            values = [
                self._eval_expr(value.value, state, frame, depth)
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            ]
            return self._merge_values(*values)
        if isinstance(node, ast.Lambda):
            return Value()
        return Value()

    def _eval_container(self, node, elements, state, frame, depth):
        keys = []
        empty = not elements
        for element in elements:
            if element is None:
                continue
            value = self._eval_expr(element, state, frame, depth)
            if value.obj_key is not None:
                keys.append(value.obj_key)
            keys.extend(value.contained)
        return Value(contained=tuple(keys), empty_literal=empty)

    @staticmethod
    def _merge_values(*values):
        keys = []
        owners = []
        generator = None
        for value in values:
            if value is None:
                continue
            if value.obj_key is not None:
                keys.append(value.obj_key)
            keys.extend(value.contained)
            if value.identity_owner is not None:
                owners.append(value.identity_owner)
            generator = generator or value.generator_of
        if owners and not keys:
            return Value(identity_owner=owners[0])
        if generator is not None:
            return Value(generator_of=generator)
        return Value(contained=tuple(keys))

    def _eval_call(self, node, state, frame, depth):
        if isinstance(node.func, ast.Attribute):
            return self._eval_method_call(node, state, frame, depth)
        full_name = self._call_name(node)
        short_name = full_name.split(".")[-1]
        aggregate = self.registry.resolve_type(full_name)
        if aggregate is None:
            aggregate = self.registry.resolve_type(short_name)
        args = [
            self._eval_expr(argument, state, frame, depth)
            for argument in node.args
        ]
        args.extend(
            self._eval_expr(keyword.value, state, frame, depth)
            for keyword in node.keywords
        )
        if aggregate is not None:
            key = self._new_object(aggregate, node, state)
            for value in args:
                for item in (value.obj_key,) + value.contained:
                    if item is not None:
                        self._mark_escape(
                            state, item, "container", node.lineno
                        )
            return Value(obj_key=key)

        if self.registry.is_publish_method(short_name):
            for value in args:
                self._record_publish(state, value, node.lineno)
        if self.registry.is_release_method(short_name):
            for value in args:
                self._record_release(state, value)

        info = self.functions.get(full_name) or self.short_functions.get(
            short_name
        )
        if info is not None:
            if info.is_generator:
                for value in args:
                    for item in (value.obj_key,) + value.contained:
                        if item is not None and not info.has_close_release:
                            self._mark_escape(
                                state, item, "generator", node.lineno
                            )
                return Value(generator_of=info)
            return self._invoke_function(info, node, state, frame, depth)
        if short_name not in _BENIGN_CALLS:
            for value in args:
                for item in (value.obj_key,) + value.contained:
                    if item is not None:
                        self._mark_escape(
                            state, item, "call-argument", node.lineno
                        )
        return self._merge_values(*args)

    def _eval_method_call(self, node, state, frame, depth):
        method = node.func.attr
        base = self._eval_expr(node.func.value, state, frame, depth)
        args = [
            self._eval_expr(argument, state, frame, depth)
            for argument in node.args
        ]
        args.extend(
            self._eval_expr(keyword.value, state, frame, depth)
            for keyword in node.keywords
        )
        if base.identity_owner is not None:
            field_name = base.identity_field
            if method in _MUTATING_CONTAINER_METHODS | {"add", "append"}:
                self._write_identity_field(
                    state, base.identity_owner, field_name, node.lineno
                )
            elif self.registry.is_release_method(method) or method in {
                "clear",
                "discard",
                "pop",
                "remove",
            }:
                self._clear_identity_field(
                    state, base.identity_owner, field_name
                )
            return Value()
        if base.obj_key is not None:
            obj = state.objs.get(base.obj_key)
            if obj is None:
                return Value()
            if (
                self.registry.is_release_method(method)
                or method in obj.aggregate.release_methods
            ):
                obj.active_fields.clear()
                obj.close_released = True
                return Value()
            if (
                self.registry.is_publish_method(method)
                or method in obj.aggregate.publish_methods
            ):
                self._record_publish(
                    state, Value(obj_key=base.obj_key), node.lineno
                )
                return Value()
            if self._is_identity_field(method):
                self._write_identity_field(
                    state, base.obj_key, method, node.lineno
                )
                return Value()
            if method in {"add", "append", "extend", "merge", "update"}:
                for value in args:
                    for item in (value.obj_key,) + value.contained:
                        if item is not None:
                            self._mark_escape(
                                state, item, "attribute", node.lineno
                            )
            class_info = self.registry.class_for(obj.type_name)
            method_info = None
            if class_info is not None:
                method_info = self.methods_by_class.get(
                    class_info.name, {}
                ).get(method)
            if method_info is not None:
                return self._invoke_function(
                    method_info,
                    node,
                    state,
                    frame,
                    depth,
                    bound_self=base.obj_key,
                )
            return Value()
        if base.generator_of is not None and method == "close":
            return Value()
        for value in args:
            for item in (value.obj_key,) + value.contained:
                if item is not None:
                    self._mark_escape(
                        state, item, "call-argument", node.lineno
                    )
        return Value()

    def _record_publish(self, state, value, lineno):
        if value.obj_key is not None:
            obj = state.objs.get(value.obj_key)
            if obj is not None and obj.active_fields:
                state.pending.append(
                    PendingExit(
                        "publish",
                        lineno,
                        value.obj_key,
                        fields=tuple(sorted(obj.active_fields)),
                    )
                )
        if value.identity_owner is not None:
            obj = state.objs.get(value.identity_owner)
            if obj is not None and obj.active_fields:
                state.pending.append(
                    PendingExit(
                        "publish",
                        lineno,
                        value.identity_owner,
                        fields=tuple(sorted(obj.active_fields)),
                    )
                )
        for key in value.contained:
            obj = state.objs.get(key)
            if obj is not None and obj.active_fields:
                state.pending.append(
                    PendingExit(
                        "publish",
                        lineno,
                        key,
                        fields=tuple(sorted(obj.active_fields)),
                    )
                )

    def _record_release(self, state, value):
        if value.obj_key is not None:
            obj = state.objs.get(value.obj_key)
            if obj is not None:
                obj.active_fields.clear()
                obj.close_released = True
        if value.identity_owner is not None:
            self._clear_identity_field(
                state, value.identity_owner, value.identity_field
            )
        for key in value.contained:
            obj = state.objs.get(key)
            if obj is not None:
                obj.active_fields.clear()
                obj.close_released = True

    def _invoke_function(
        self, info, call, state, frame, depth, bound_self=None
    ):
        if depth >= self.max_depth:
            return Value()
        arguments = [
            self._eval_expr(argument, state, frame, depth)
            for argument in call.args
        ]
        keywords = {
            keyword.arg: self._eval_expr(
                keyword.value, state, frame, depth
            )
            for keyword in call.keywords
            if keyword.arg is not None
        }
        callee_state = state.clone()
        callee_frame = Frame(info=info, depth=depth + 1, parent=frame)
        self._bind_call_arguments(
            info,
            callee_state,
            arguments,
            keywords,
            state,
            bound_self=bound_self,
        )
        return_states = self._exec_block(
            info.node.body, callee_state, callee_frame, depth + 1
        )
        returned_key = self._common_return_key(return_states)
        self._merge_call_effects(state, return_states)
        for item in return_states:
            self._commit_pending(item, callee_frame, include_returns=False)
        if returned_key is not None:
            return Value(obj_key=returned_key)
        return Value()

    @staticmethod
    def _common_return_key(states):
        keys = set()
        for state in states:
            for pending in state.pending:
                if pending.kind == "return":
                    keys.add(pending.obj_key)
        return keys.pop() if len(keys) == 1 else None

    def _caller_retains(self, caller_state, obj_key):
        if obj_key in caller_state.vars.values():
            return True
        if obj_key in caller_state.containers.values():
            return True
        obj = caller_state.objs.get(obj_key)
        return bool(obj is not None and (obj.external or obj.escaped))

    def _bind_call_arguments(
        self,
        info,
        state,
        arguments,
        keywords,
        caller_state,
        bound_self=None,
    ):
        parameters = list(info.node.args.posonlyargs)
        parameters += list(info.node.args.args)
        if bound_self is not None and parameters:
            state.vars[parameters[0].arg] = bound_self
            parameters = parameters[1:]
        for index, parameter in enumerate(parameters):
            value = (
                arguments[index]
                if index < len(arguments)
                else keywords.get(parameter.arg)
            )
            if value is not None:
                self._bind_argument(
                    parameter, value, state, caller_state
                )
        for parameter in info.node.args.kwonlyargs:
            value = keywords.get(parameter.arg)
            if value is not None:
                self._bind_argument(
                    parameter, value, state, caller_state
                )
        if info.node.args.vararg is not None:
            for value in arguments[len(parameters):]:
                if value.obj_key is not None:
                    state.vars.setdefault(
                        info.node.args.vararg.arg, value.obj_key
                    )

    def _bind_argument(self, parameter, value, state, caller_state):
        if value.obj_key is None:
            return
        state.vars[parameter.arg] = value.obj_key
        obj = state.objs.get(value.obj_key)
        if obj is not None:
            obj.external = self._caller_retains(caller_state, value.obj_key)

    @staticmethod
    def _merge_call_effects(caller_state, callee_states):
        if not callee_states:
            return
        for key in list(caller_state.objs):
            matching = [
                state.objs[key]
                for state in callee_states
                if key in state.objs
            ]
            if not matching:
                continue
            if all(not obj.active_fields for obj in matching):
                caller_state.objs[key].active_fields.clear()
            else:
                caller_state.objs[key].active_fields.update(
                    field
                    for obj in matching
                    for field in obj.active_fields
                )
        for state in callee_states:
            for key, obj in state.objs.items():
                if key not in caller_state.objs:
                    caller_state.objs[key] = obj
                elif obj.escaped:
                    caller_state.objs[key].escaped.extend(obj.escaped)

    def _add_pending_fact(self, state, kind, lineno, obj_key):
        obj = state.objs.get(obj_key)
        if obj is not None and obj.active_fields:
            state.pending.append(
                PendingExit(
                    kind,
                    lineno,
                    obj_key,
                    fields=tuple(sorted(obj.active_fields)),
                )
            )

    def _commit_pending(self, state, frame, include_returns=False):
        for pending in state.pending:
            if pending.kind in {"return", "parameter-alias", "yield"}:
                if not include_returns:
                    continue
            obj = state.objs.get(pending.obj_key)
            if obj is None:
                continue
            fields = (
                pending.fields
                if pending.fields is not None
                else tuple(sorted(obj.active_fields))
            )
            if not fields:
                continue
            self.exits.append(
                ExitFact(
                    root=self._active_root.qualname,
                    pass_name=self._pass_name(self._active_root),
                    type_name=obj.type_name,
                    fields=fields,
                    kind=pending.kind,
                    lineno=pending.lineno,
                    function=frame.qualname,
                )
            )
        state.pending = []

    def _collect_end_state(self, state, frame, end_line):
        for key, obj in state.objs.items():
            if not obj.active_fields:
                continue
            if obj.escaped:
                candidates = [
                    item for item in obj.escaped if item[0] != "identity-write"
                ]
                if candidates:
                    best = max(
                        candidates,
                        key=lambda item: _EXIT_PRIORITY.get(item[0], 0),
                    )
                    self.exits.append(
                        ExitFact(
                            root=self._active_root.qualname,
                            pass_name=self._pass_name(self._active_root),
                            type_name=obj.type_name,
                            fields=tuple(sorted(obj.active_fields)),
                            kind=best[0],
                            lineno=best[1],
                            function=frame.qualname,
                        )
                    )
            if obj.external and not obj.module_global:
                self.exits.append(
                    ExitFact(
                        root=self._active_root.qualname,
                        pass_name=self._pass_name(self._active_root),
                        type_name=obj.type_name,
                        fields=tuple(sorted(obj.active_fields)),
                        kind="parameter-alias",
                        lineno=end_line,
                        function=frame.qualname,
                    )
                )
            elif obj.module_global:
                self.exits.append(
                    ExitFact(
                        root=self._active_root.qualname,
                        pass_name=self._pass_name(self._active_root),
                        type_name=obj.type_name,
                        fields=tuple(sorted(obj.active_fields)),
                        kind="module-global",
                        lineno=obj.created_line,
                        function=frame.qualname,
                    )
                )

    def _findings_for_root(self, info):
        facts = [
            item for item in self.exits if item.root == info.qualname
        ]
        facts.sort(key=lambda item: (-item.priority, item.lineno))
        findings = []
        seen = set()
        for fact in facts:
            registered = self.registry.resolve_type(fact.type_name)
            eligible = bool(
                registered
                or fact.kind in {"publish", "call-argument", "exception"}
            )
            if not eligible:
                continue
            key = (
                fact.type_name,
                fact.fields,
                fact.pass_name,
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._make_finding(fact))
        return findings

    def _make_finding(self, fact):
        fields = ", ".join(fact.fields)
        message = (
            f"Aggregate lifecycle: '{fact.type_name}' keeps identity "
            f"field(s) {fields} set and remains live at {fact.kind} "
            f"exit in pass '{fact.pass_name}' (line {fact.lineno})."
        )
        return Finding(
            aggregate_type=fact.type_name,
            retained_identity_fields=tuple(fact.fields),
            exit_kind=fact.kind,
            lineno=fact.lineno,
            function=fact.function,
            pass_name=fact.pass_name,
            message=message,
        )


def analyze_source(source, filename="", config=None):
    """Return lifecycle findings for every root in *source*."""
    analyzer = AggregateLifecycleAnalyzer(source, filename, config)
    return analyzer.analyze_all()


def analyze_target(source, node, filename="", config=None):
    """Return lifecycle findings for one Bandit FunctionDef target."""
    analyzer = AggregateLifecycleAnalyzer(source, filename, config)
    return analyzer.analyze_target(node)
