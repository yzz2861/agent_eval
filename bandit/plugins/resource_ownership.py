# SPDX-License-Identifier: Apache-2.0
r"""
===========================================
B616: Test for unreleased temporary resources
===========================================

Temporary credentials and other short-lived resources must be returned on
every exit path, including early returns, exceptions and coroutine
cancellation.  This plugin follows configured factory calls within one
function and reports factories whose result can escape the function without
being released or explicitly handed to a configured managed call.

Assigning a resource to another name does not transfer ownership.  The
following all leave the resource owned by the same function:

.. code-block:: python

    credential = issue_credential()
    alias = credential
    holder.credential = alias

Configured releases, configured managed calls, ``with``/``async with`` and
``try``/``finally`` are modelled using their normal Python lifetimes.  When a
resource is passed to a call that is not declared in the configuration, the
plugin cannot prove whether ownership moved, so that resource is left in an
unknown state instead of being reported.

**Config Options:**

Factories can be paired with one or more release calls.  Global
``release_calls`` and ``managed_calls`` may also be used when all configured
factories share the same interfaces.

.. code-block:: yaml

    resource_ownership:
      resources:
        - factory: auth.issue_temporary_credential
          release: auth.return_temporary_credential
          managed_calls:
            - auth.upload_with_temporary_credential
      release_calls: []
      managed_calls: []

The shorthand mapping form is also accepted:

.. code-block:: yaml

    resource_ownership:
      factories:
        auth.issue_temporary_credential:
          release: auth.return_temporary_credential
      managed_calls:
        - auth.upload_with_temporary_credential

:Example:

.. code-block:: none

    >> Issue: [B616:resource_ownership] Resource from
       'auth.issue_temporary_credential' acquired at line 4 is not released
       on exit path: 4 -> 6 -> 7 (return at line 7).
       Severity: Medium   Confidence: High
       CWE: CWE-772 (https://cwe.mitre.org/data/definitions/772.html)
       Location: examples/resource_ownership.py:4:4

.. seealso::

 - https://cwe.mitre.org/data/definitions/772.html

.. versionadded:: 1.9.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core.utils import get_call_name


_FACTORY_KEYS = (
    "factory",
    "factories",
    "acquire",
    "create",
    "qualname",
    "name",
)
_RELEASE_KEYS = (
    "release",
    "releases",
    "release_call",
    "release_calls",
    "release_api",
    "release_with",
    "release_interface",
    "release_interfaces",
    "return",
    "return_call",
    "return_calls",
    "return_interface",
    "return_interfaces",
    "return_with",
)
_MANAGED_KEYS = (
    "handoff_to",
    "handoff",
    "handoffs",
    "handoff_call",
    "handoff_calls",
    "managed",
    "managed_call",
    "managed_calls",
    "managed_functions",
    "owner",
    "takes_ownership",
    "transfer",
    "transfers",
    "transfer_call",
    "transfer_calls",
    "consumer",
    "consumers",
)
_RESOURCE_CONTAINER_KEYS = (
    "resources",
    "resource_factories",
    "resource_pairs",
    "factory_calls",
    "factory_release_pairs",
    "pairs",
    "factories",
    "leases",
)
_GLOBAL_RELEASE_KEYS = (
    "release_calls",
    "releases",
    "release_interfaces",
    "return_calls",
    "return_interfaces",
)
_GLOBAL_MANAGED_KEYS = (
    "managed",
    "managed_calls",
    "managed_call",
    "managed_functions",
    "handoff_calls",
    "handoff_call",
    "handoff",
    "handoffs",
    "transfer_calls",
    "transfer_call",
    "consumers",
)


def gen_config(name):
    if name in ("resource_ownership", "resource_lifecycle"):
        return {
            "resources": [],
            "release_calls": [],
            "managed_calls": [],
        }


def _names(value):
    """Return call names from the flexible config value forms."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        if any(key in value for key in ("name", "qualname", "call")):
            result = []
            for key in ("name", "qualname", "call"):
                result.extend(_names(value.get(key)))
            return result
        result = []
        for key, item in value.items():
            if isinstance(key, str):
                result.append(key)
            result.extend(_names(item))
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for item in value:
            result.extend(_names(item))
        return result
    return []


def _looks_like_resource(value):
    if not isinstance(value, dict):
        return False
    if any(key in value for key in _RESOURCE_CONTAINER_KEYS):
        return False
    if any(key in value for key in ("factory", "qualname", "name")):
        return True
    return any(key in value for key in ("acquire", "create")) and any(
        key in value for key in _RELEASE_KEYS + _MANAGED_KEYS
    )


def _resource_entries(value):
    """Yield normalized resource dictionaries from several config shapes."""
    if value is None:
        return
    if isinstance(value, str):
        yield {"factory": value}
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _resource_entries(item)
    elif isinstance(value, dict):
        if _looks_like_resource(value):
            yield value
            return
        for key, item in value.items():
            if not isinstance(key, str):
                continue
            if isinstance(item, str):
                yield {"factory": key, "release": item}
            elif isinstance(item, (list, tuple, set)):
                yield {"factory": key, "release": item}
            elif isinstance(item, dict):
                entry = dict(item)
                entry.setdefault("factory", key)
                yield entry
            else:
                yield {"factory": key}


class _Policy:
    def __init__(self):
        self.factories = {}
        self.release_calls = set()
        self.managed_calls = set()


def _add_policy_entry(policy, entry, global_releases, global_managed):
    factory_names = []
    for key in _FACTORY_KEYS:
        if key in entry:
            factory_names.extend(_names(entry.get(key)))

    releases = set(global_releases)
    for key in _RELEASE_KEYS:
        if key in entry:
            releases.update(_names(entry.get(key)))

    managed = set(global_managed)
    for key in _MANAGED_KEYS:
        if key in entry:
            managed.update(_names(entry.get(key)))

    for factory in factory_names:
        current = policy.factories.setdefault(
            factory, {"releases": set(), "managed": set()}
        )
        current["releases"].update(releases)
        current["managed"].update(managed)


def _normalise_config(config):
    policy = _Policy()
    if not config:
        return policy

    if isinstance(config, dict):
        global_releases = set()
        for key in _GLOBAL_RELEASE_KEYS:
            global_releases.update(_names(config.get(key)))
        global_managed = set()
        for key in _GLOBAL_MANAGED_KEYS:
            global_managed.update(_names(config.get(key)))

        policy.release_calls.update(global_releases)
        policy.managed_calls.update(global_managed)

        for container_key in _RESOURCE_CONTAINER_KEYS:
            for entry in _resource_entries(config.get(container_key)):
                _add_policy_entry(
                    policy, entry, global_releases, global_managed
                )

        if _looks_like_resource(config):
            _add_policy_entry(
                policy, config, global_releases, global_managed
            )
        else:
            known_options = (
                set(_RESOURCE_CONTAINER_KEYS)
                | set(_GLOBAL_RELEASE_KEYS)
                | set(_GLOBAL_MANAGED_KEYS)
                | {"factory", "qualname", "name"}
            )
            for key, value in config.items():
                if key in known_options or not isinstance(key, str):
                    continue
                for entry in _resource_entries({key: value}):
                    _add_policy_entry(
                        policy, entry, global_releases, global_managed
                    )
    else:
        for entry in _resource_entries(config):
            _add_policy_entry(policy, entry, set(), set())

    return policy


def _last_name(name):
    return name.rsplit(".", 1)[-1]


def _name_matches(configured, actual):
    if not configured or not actual:
        return False
    if configured == actual:
        return True
    if "." not in configured:
        return _last_name(configured) == _last_name(actual)

    configured_parts = configured.split(".")
    actual_parts = actual.split(".")
    if len(configured_parts) == 2 and configured_parts[0][:1].isupper():
        return configured_parts[-1] == actual_parts[-1]
    return False


def _matches(names, actual):
    return any(_name_matches(name, actual) for name in names)


def _key(node):
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return f"{type(node).__name__}@{getattr(node, 'lineno', 0)}"


def _new_state():
    return {"owners": {}, "bindings": {}, "path": ()}


def _clone_state(state):
    owners = {}
    for owner_id, owner in state["owners"].items():
        copied = dict(owner)
        copied["releases"] = set(owner["releases"])
        copied["managed"] = set(owner["managed"])
        owners[owner_id] = copied
    return {
        "owners": owners,
        "bindings": dict(state["bindings"]),
        "path": state["path"],
    }


def _advance(state, lineno):
    state = _clone_state(state)
    if lineno and (not state["path"] or state["path"][-1] != lineno):
        state["path"] = state["path"] + (lineno,)
    return state


def _state_key(state):
    owners = tuple(
        sorted(
            (
                owner_id,
                owner["status"],
                owner["factory"],
                owner["lineno"],
            )
            for owner_id, owner in state["owners"].items()
        )
    )
    bindings = tuple(sorted(state["bindings"].items()))
    return owners, bindings, state["path"]


class _Exit:
    def __init__(self, kind, state, lineno):
        self.kind = kind
        self.state = state
        self.lineno = lineno


class _Flow:
    def __init__(self, normal=None, exits=None):
        self.normal = list(normal or [])
        self.exits = list(exits or [])

    def add(self, other):
        self.normal.extend(other.normal)
        self.exits.extend(other.exits)

    def dedupe(self):
        normal = {}
        for state in self.normal:
            normal[_state_key(state)] = state
        exits = {}
        for exit_item in self.exits:
            key = (
                exit_item.kind,
                exit_item.lineno,
                _state_key(exit_item.state),
            )
            exits[key] = exit_item
        return _Flow(normal.values(), exits.values())


class _Value:
    def __init__(self, owners=None, unknown=False):
        self.owners = set(owners or ())
        self.unknown = unknown


class _Analyzer:
    def __init__(self, node, config, aliases):
        self.node = node
        self.aliases = aliases or {}
        self.policy = _normalise_config(config)
        self._next_owner = 0

    def run(self):
        if not self.policy.factories:
            return None

        start = _new_state()
        flow = self._exec_block(self.node.body, [start]).dedupe()
        end_line = getattr(self.node, "end_lineno", self.node.lineno)
        flow.exits.extend(
            _Exit("fall-through", state, end_line) for state in flow.normal
        )
        return self._issue(flow.exits)

    def _factory_for(self, call_name):
        for factory in self.policy.factories:
            if _name_matches(factory, call_name):
                return factory
        return None

    def _is_release(self, call_name, owners=()):
        if _matches(self.policy.release_calls, call_name):
            return True
        for owner in owners:
            if _matches(owner["releases"], call_name):
                return True
        return False

    def _is_managed(self, call_name, owners=()):
        if _matches(self.policy.managed_calls, call_name):
            return True
        for owner in owners:
            if _matches(owner["managed"], call_name):
                return True
        return False

    def _new_owner(self, state, factory, call):
        self._next_owner += 1
        owner_id = self._next_owner
        policy = self.policy.factories[factory]
        state["owners"][owner_id] = {
            "id": owner_id,
            "factory": factory,
            "lineno": getattr(call, "lineno", self.node.lineno),
            "col_offset": getattr(call, "col_offset", 0),
            "releases": set(policy["releases"]),
            "managed": set(policy["managed"]),
            "status": "owned",
            "entry_path": state["path"],
        }
        return owner_id

    def _owners_in(self, state, owner_ids):
        return [
            state["owners"][owner_id]
            for owner_id in owner_ids
            if owner_id in state["owners"]
        ]

    def _forget_owner(self, state, owner_id):
        state["owners"].pop(owner_id, None)
        state["bindings"] = {
            key: value
            for key, value in state["bindings"].items()
            if value != owner_id
        }

    def _consume(self, state, owner_ids):
        for owner_id in list(owner_ids):
            self._forget_owner(state, owner_id)

    def _unknown(self, state, owner_ids):
        for owner_id in owner_ids:
            owner = state["owners"].get(owner_id)
            if owner is not None:
                owner["status"] = "unknown"

    def _binding_owners(self, state, node):
        owner_id = state["bindings"].get(_key(node))
        return {owner_id} if owner_id is not None else set()

    def _bind(self, state, target, value):
        if isinstance(target, (ast.Tuple, ast.List)):
            owners = list(value.owners)
            if len(owners) == len(target.elts):
                for child, owner_id in zip(target.elts, owners):
                    self._bind(state, child, _Value({owner_id}))
            return
        if isinstance(target, ast.Starred):
            return
        if not isinstance(target, (ast.Name, ast.Attribute, ast.Subscript)):
            return

        key = _key(target)
        state["bindings"].pop(key, None)
        if len(value.owners) == 1:
            owner_id = next(iter(value.owners))
            if owner_id in state["owners"]:
                state["bindings"][key] = owner_id

    def _eval_expr(self, state, node, suppress_factory=False):
        if node is None:
            return _Value()

        if isinstance(node, ast.Call):
            receiver = _Value()
            if isinstance(node.func, ast.Attribute):
                receiver = self._eval_expr(state, node.func.value)
            elif not isinstance(node.func, ast.Name):
                receiver = self._eval_expr(state, node.func)

            argument_owners = set()
            for arg in node.args:
                value = self._eval_expr(state, arg)
                argument_owners.update(value.owners)
            for keyword in node.keywords:
                value = self._eval_expr(state, keyword.value)
                argument_owners.update(value.owners)

            call_name = get_call_name(node, self.aliases)
            factory = self._factory_for(call_name)
            if factory is not None:
                if suppress_factory:
                    return _Value()
                return _Value({self._new_owner(state, factory, node)})

            all_owners = set(argument_owners)
            if _matches(
                self.policy.release_calls | self.policy.managed_calls,
                call_name,
            ):
                all_owners.update(receiver.owners)
            else:
                for owner in self._owners_in(state, receiver.owners):
                    if _matches(
                        owner["releases"] | owner["managed"], call_name
                    ):
                        all_owners.update(receiver.owners)
                        break

            owners = self._owners_in(state, all_owners)
            if self._is_release(call_name, owners):
                self._consume(state, all_owners)
                return _Value()
            if self._is_managed(call_name, owners):
                self._consume(state, all_owners)
                return _Value()
            if all_owners:
                self._unknown(state, all_owners)
            return _Value()

        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            owners = self._binding_owners(state, node)
            if owners:
                return _Value(owners)
            if isinstance(node, ast.Attribute):
                return self._eval_expr(state, node.value)
            if isinstance(node, ast.Subscript):
                value = self._eval_expr(state, node.value)
                value.owners.update(self._eval_expr(state, node.slice).owners)
                return value
            return _Value()

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            owners = set()
            for item in node.elts:
                owners.update(self._eval_expr(state, item).owners)
            return _Value(owners)

        if isinstance(node, ast.Dict):
            owners = set()
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    owners.update(self._eval_expr(state, key).owners)
                owners.update(self._eval_expr(state, value).owners)
            return _Value(owners)

        if isinstance(
            node, (ast.Await, ast.Yield, ast.YieldFrom, ast.Starred)
        ):
            return self._eval_expr(state, node.value, suppress_factory)

        if isinstance(node, ast.NamedExpr):
            value = self._eval_expr(state, node.value, suppress_factory)
            self._bind(state, node.target, value)
            return value

        owners = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                owners.update(
                    self._eval_expr(state, child, suppress_factory).owners
                )
        return _Value(owners)

    def _contains_call(self, node):
        return any(isinstance(child, ast.Call) for child in ast.walk(node))

    def _contains_release(self, node):
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = get_call_name(child, self.aliases)
            if _matches(
                self.policy.release_calls | self.policy.managed_calls,
                call_name,
            ):
                return True
            for factory in self.policy.factories.values():
                if _matches(
                    factory["releases"] | factory["managed"], call_name
                ):
                    return True
        return False

    def _exception_flow(self, node, before, normal):
        if not self._contains_call(node):
            return _Flow()
        state = _advance(before, getattr(node, "lineno", None))
        if normal:
            after = normal[0]
            for owner_id in list(state["owners"]):
                if owner_id not in after["owners"]:
                    state["owners"].pop(owner_id)
                else:
                    status = after["owners"][owner_id]["status"]
                    state["owners"][owner_id]["status"] = status
        return _Flow(exits=[_Exit("exception", state, node.lineno)])

    def _exec_simple(self, node, state):
        before = _clone_state(state)
        state = _advance(state, getattr(node, "lineno", None))
        flow = _Flow(normal=[state])

        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value_node = node.value
            value = self._eval_expr(state, value_node)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(state, target, value)
            else:
                self._bind(state, node.target, value)
        elif isinstance(node, ast.Return):
            value = self._eval_expr(state, node.value)
            self._unknown(state, value.owners)
            flow.normal = []
            flow.exits.append(
                _Exit("return", state, getattr(node, "lineno", 0))
            )
        elif isinstance(node, ast.Raise):
            self._eval_expr(state, node.exc)
            flow.normal = []
            flow.exits.append(
                _Exit("raise", state, getattr(node, "lineno", 0))
            )
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                state["bindings"].pop(_key(target), None)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            pass
        elif isinstance(node, ast.Pass):
            pass
        elif isinstance(node, ast.Expr):
            self._eval_expr(state, node.value)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._eval_expr(state, child)

        if isinstance(node, (ast.Return, ast.Raise)):
            return flow

        if isinstance(node, ast.Assert):
            flow.exits.append(
                _Exit("assert", _clone_state(state), node.lineno)
            )
        exception = self._exception_flow(node, before, flow.normal)
        flow.add(exception)
        return flow

    def _exec_if(self, node, state):
        before = _clone_state(state)
        test_state = _advance(state, node.lineno)
        self._eval_expr(test_state, node.test)
        result = _Flow()
        result.add(self._exec_block(node.body, [test_state]))
        result.add(self._exec_block(node.orelse, [_clone_state(test_state)]))
        result.add(self._exception_flow(node.test, before, [test_state]))
        return result

    def _exec_loop(self, node, state):
        before = _clone_state(state)
        loop_state = _advance(state, node.lineno)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._eval_expr(loop_state, node.iter)
        else:
            self._eval_expr(loop_state, node.test)

        body_flow = self._exec_block(node.body, [_clone_state(loop_state)])
        result = _Flow(normal=[loop_state])
        result.normal.extend(body_flow.normal)
        for exit_item in body_flow.exits:
            if exit_item.kind in ("break", "continue"):
                result.normal.append(exit_item.state)
            else:
                result.exits.append(exit_item)
        result.add(self._exec_block(node.orelse, [_clone_state(loop_state)]))
        test_node = node.iter if isinstance(
            node, (ast.For, ast.AsyncFor)
        ) else node.test
        result.add(self._exception_flow(test_node, before, [loop_state]))
        return result

    def _exec_with(self, node, state):
        result_state = _advance(state, node.lineno)
        for item in node.items:
            value = self._eval_expr(
                result_state, item.context_expr, suppress_factory=True
            )
            self._consume(result_state, value.owners)
        return self._exec_block(node.body, [result_state])

    def _handler_catches_all(self, handler):
        if handler.type is None:
            return True
        names = []
        if isinstance(handler.type, ast.Tuple):
            candidates = handler.type.elts
        else:
            candidates = [handler.type]
        for candidate in candidates:
            try:
                names.append(ast.unparse(candidate))
            except (AttributeError, ValueError):
                pass
        return any(_last_name(name) == "BaseException" for name in names)

    def _handler_catches_any(self, handler):
        return handler.type is None or not isinstance(
            handler.type, ast.Constant
        )

    def _apply_finally(self, finalbody, normal, exits):
        if not finalbody:
            return _Flow(normal, exits)

        result = _Flow()
        for state in normal:
            final_flow = self._exec_block(finalbody, [state])
            result.normal.extend(final_flow.normal)
            result.exits.extend(final_flow.exits)
        for exit_item in exits:
            final_flow = self._exec_block(finalbody, [exit_item.state])
            result.exits.extend(
                _Exit(exit_item.kind, state, exit_item.lineno)
                for state in final_flow.normal
            )
            result.exits.extend(final_flow.exits)
        return result

    def _exec_try(self, node, state):
        body = self._exec_block(node.body, [_advance(state, node.lineno)])
        body_raises = [
            exit_item for exit_item in body.exits
            if exit_item.kind in ("raise", "exception", "assert")
        ]
        body_other = [
            exit_item for exit_item in body.exits
            if exit_item.kind not in ("raise", "exception", "assert")
        ]

        normal = self._exec_block(node.orelse, body.normal)
        exits = body_other + normal.exits
        normal_states = normal.normal

        catch_all = False
        has_handler = False
        for handler in node.handlers:
            has_handler = True
            catch_all = catch_all or self._handler_catches_all(handler)
            if not self._handler_catches_any(handler) and not body_raises:
                continue
            handler_inputs = [
                _advance(exit_item.state, handler.lineno)
                for exit_item in body_raises
            ]
            handler_flow = self._exec_block(handler.body, handler_inputs)
            normal_states.extend(handler_flow.normal)
            exits.extend(handler_flow.exits)

        if body_raises and (not has_handler or not catch_all):
            exits.extend(body_raises)

        return self._apply_finally(
            node.finalbody, normal_states, exits
        ).dedupe()

    def _exec_match(self, node, state):
        before = _clone_state(state)
        subject_state = _advance(state, node.lineno)
        self._eval_expr(subject_state, node.subject)
        result = _Flow(normal=[_clone_state(subject_state)])
        for case in node.cases:
            case_state = _clone_state(subject_state)
            self._eval_expr(case_state, case.guard)
            body_flow = self._exec_block(case.body, [case_state])
            result.normal.extend(body_flow.normal)
            result.exits.extend(body_flow.exits)
        result.add(self._exception_flow(node.subject, before, [subject_state]))
        return result

    def _exec_stmt(self, node, state):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            return _Flow(normal=[_advance(state, node.lineno)])
        if isinstance(node, ast.If):
            return self._exec_if(node, state)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self._exec_loop(node, state)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._exec_with(node, state)
        if isinstance(node, ast.Try):
            return self._exec_try(node, state)
        if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
            return self._exec_try(node, state)
        if hasattr(ast, "Match") and isinstance(node, ast.Match):
            return self._exec_match(node, state)
        if isinstance(node, ast.Break):
            return _Flow(
                exits=[
                    _Exit(
                        "break", _advance(state, node.lineno), node.lineno
                    )
                ]
            )
        if isinstance(node, ast.Continue):
            return _Flow(
                exits=[
                    _Exit(
                        "continue", _advance(state, node.lineno), node.lineno
                    )
                ]
            )
        return self._exec_simple(node, state)

    def _exec_block(self, statements, states):
        flow = _Flow(normal=states)
        for statement in statements:
            next_flow = _Flow()
            for state in flow.normal:
                next_flow.add(self._exec_stmt(statement, state))
            flow.normal = next_flow.normal
            flow.exits.extend(next_flow.exits)
        return flow.dedupe()

    def _format_path(self, state, owner):
        entry_path = owner.get("entry_path", ())
        path = list(state["path"])
        if entry_path:
            start = path.index(entry_path[-1]) if entry_path[-1] in path else 0
            path = path[start:]
        values = []
        for item in path:
            if not values or values[-1] != item:
                values.append(item)
        return " -> ".join(str(item) for item in values)

    def _issue(self, exits):
        leaks = {}
        for exit_item in exits:
            for owner_id, owner in exit_item.state["owners"].items():
                if owner["status"] != "owned":
                    continue
                leak = leaks.setdefault(
                    owner_id,
                    {"owner": owner, "paths": []},
                )
                path = self._format_path(exit_item.state, owner)
                description = f"{exit_item.kind} at line {exit_item.lineno}"
                text = f"{path} ({description})" if path else description
                if text not in leak["paths"]:
                    leak["paths"].append(text)

        if not leaks:
            return None

        first_id = min(leaks)
        leak = leaks[first_id]
        owner = leak["owner"]
        shown_paths = leak["paths"][:6]
        message = (
            f"Resource from '{owner['factory']}' acquired at line "
            f"{owner['lineno']} is not released on exit path"
        )
        if len(shown_paths) != 1:
            message += "s"
        message += ": " + "; ".join(shown_paths)
        if len(leak["paths"]) > len(shown_paths):
            message += "; ..."
        if len(leaks) > 1:
            message += (
                f" ({len(leaks)} unreleased resources detected in this "
                "function)"
            )

        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.MISSING_RELEASE_OF_RESOURCE,
            text=message,
            lineno=owner["lineno"],
            col_offset=owner["col_offset"],
        )


@test.takes_config("resource_ownership")
@test.checks("FunctionDef", "AsyncFunctionDef")
@test.test_id("B616")
def resource_ownership(context, config):
    node = context.node
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    return _Analyzer(node, config, context.import_aliases).run()
