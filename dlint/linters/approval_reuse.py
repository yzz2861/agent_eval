#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import fnmatch

from . import base


DEFAULT_ISSUANCE_APIS = (
    'issue',
    'issue_ticket',
    'issue_approval',
    'issue_token',
    'issue_permit',
    'acquire',
    'acquire_ticket',
    'acquire_approval',
    'acquire_token',
    'grant',
    'grant_ticket',
    'grant_approval',
    'obtain_ticket',
    'request_ticket',
    'new_ticket',
    'create_ticket',
    'reserve_ticket',
    'mint_ticket',
    'allocate_ticket',
)

DEFAULT_BORROW_APIS = (
    'borrow',
    'borrow_ticket',
    'borrow_approval',
    'peek',
    'peek_ticket',
    'peek_approval',
    'check_ticket',
    'check_approval',
    'inspect_ticket',
    'inspect_approval',
    'validate_ticket',
    'validate_approval',
    'verify_ticket',
    'verify_approval',
    'read_ticket',
    'read_approval',
    'ticket_status',
    'approval_status',
    'get_ticket',
    'get_approval',
    'lookup_ticket',
    'lookup_approval',
    'find_ticket',
    'find_approval',
)

DEFAULT_CONSUMPTION_APIS = (
    'consume',
    'consume_ticket',
    'consume_approval',
    'consume_token',
    'redeem',
    'redeem_ticket',
    'redeem_approval',
    'redeem_token',
    'spend',
    'spend_ticket',
    'spend_approval',
    'use_ticket',
    'use_approval',
    'claim_ticket',
    'claim_approval',
    'mark_used',
    'burn_ticket',
    'invalidate_ticket',
    'revoke_ticket',
    'finalize_ticket',
    'complete_ticket',
    'apply_ticket',
)

MAX_PATH_STATES = 128
MAX_HELPER_DEPTH = 6
MAX_HELPER_CALLS = 256
MAX_LOOP_ITERATIONS = 3


class _Ticket(object):
    __slots__ = ('ticket_id', 'site')

    def __init__(self, ticket_id, site):
        self.ticket_id = ticket_id
        self.site = site


class _Unknown(object):
    __slots__ = ('reason',)

    def __init__(self, reason):
        self.reason = reason


class _Const(object):
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value


class _Container(object):
    __slots__ = ('kind', 'items')

    def __init__(self, kind, items):
        self.kind = kind
        self.items = items


class _ApiRef(object):
    __slots__ = ('path',)

    def __init__(self, path):
        self.path = path


class _Site(object):
    __slots__ = ('lineno', 'col_offset', 'path', 'key')

    def __init__(self, call_node, path):
        self.lineno = call_node.lineno
        self.col_offset = call_node.col_offset
        self.path = path
        self.key = (self.lineno, self.col_offset, path)


class _State(object):
    __slots__ = ('env', 'aliases', 'consumed', 'returns', 'terminated')

    def __init__(self, env=None, aliases=None, consumed=None, returns=None,
                 terminated=None):
        self.env = env if env is not None else {}
        self.aliases = aliases if aliases is not None else {}
        self.consumed = consumed if consumed is not None else {}
        self.returns = returns if returns is not None else []
        self.terminated = terminated

    def clone(self):
        return _State(
            env=dict(self.env),
            aliases=dict(self.aliases),
            consumed=dict(self.consumed),
            returns=list(self.returns),
            terminated=self.terminated,
        )


class _BlockResult(object):
    __slots__ = ('normal', 'terminated')

    def __init__(self, normal, terminated):
        self.normal = normal
        self.terminated = terminated


class _Context(object):
    __slots__ = ('depth', 'stack', 'budget', 'collector')

    def __init__(self, depth=0, stack=None, budget=None, collector=None):
        self.depth = depth
        self.stack = stack if stack is not None else ()
        self.budget = budget if budget is not None else [0]
        self.collector = collector

    def clone(self, **kwargs):
        return _Context(
            depth=kwargs.get('depth', self.depth),
            stack=kwargs.get('stack', self.stack),
            budget=self.budget,
            collector=kwargs.get('collector', self.collector),
        )


class ApprovalReuseLinter(base.BaseLinter):
    """This linter tracks one-time approval tickets through issue, borrow and
    consumption APIs. A ticket consumed on more than one reachable path is
    reported, while tickets returned by unanalyzable external calls are
    reported separately with an unknown status.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 one-time approval consumed more than once'
    _unknown_tmpl = 'DUO139 approval status unknown'

    issuance_apis = DEFAULT_ISSUANCE_APIS
    borrow_apis = DEFAULT_BORROW_APIS
    consumption_apis = DEFAULT_CONSUMPTION_APIS

    def __init__(self, *args, **kwargs):
        self._apply_config(kwargs)

        super(ApprovalReuseLinter, self).__init__(*args, **kwargs)

        self._active_context = None
        self._ticket_counter = 0
        self._reuse_edges = set()
        self._unknown_findings = set()
        self._functions = {}
        self._affects = {}
        self._analyzed_functions = set()
        self._module_aliases = {}
        self._module_env = {}
        self._current_module = None

    def _apply_config(self, kwargs):
        api_config = kwargs.pop('api_config', None)
        apis = kwargs.pop('apis', None)
        if api_config is None:
            api_config = getattr(type(self), 'api_config', None)
        if apis is None:
            apis = getattr(type(self), 'apis', None)

        issue_apis = self._pop_first(
            kwargs,
            'issuance_apis', 'issue_apis', 'issuers', 'issuance_api',
            'issue', 'ticket_issue_apis',
        )
        borrow_apis = self._pop_first(
            kwargs,
            'borrow_apis', 'borrowers', 'borrow_api', 'borrow',
            'ticket_borrow_apis',
        )
        consumption_apis = self._pop_first(
            kwargs,
            'consumption_apis', 'consume_apis', 'consumers', 'consumption_api',
            'consume', 'ticket_consume_apis',
        )

        if apis is not None:
            if isinstance(apis, dict):
                issue_apis = issue_apis or apis.get(
                    'issue', apis.get('issuance', apis.get('issuers')))
                borrow_apis = borrow_apis or apis.get(
                    'borrow', apis.get('borrowing', apis.get('borrowers')))
                consumption_apis = consumption_apis or apis.get(
                    'consume', apis.get('consumption', apis.get('consumers')))
            else:
                issue_apis = issue_apis or apis

        if api_config is not None:
            issue_apis = issue_apis or api_config.get(
                'issue', api_config.get('issuance'))
            borrow_apis = borrow_apis or api_config.get('borrow')
            consumption_apis = consumption_apis or api_config.get(
                'consume', api_config.get('consumption'))

        if issue_apis is None:
            issue_apis = self._class_api_config(
                ('issue_apis', 'issuers', 'issue'),
                'issuance_apis',
                DEFAULT_ISSUANCE_APIS)
        if borrow_apis is None:
            borrow_apis = self._class_api_config(
                ('borrowers', 'borrow'),
                'borrow_apis',
                DEFAULT_BORROW_APIS)
        if consumption_apis is None:
            consumption_apis = self._class_api_config(
                ('consume_apis', 'consumers', 'consume'),
                'consumption_apis',
                DEFAULT_CONSUMPTION_APIS)

        self.issuance_apis = self._normalize_specs(issue_apis)
        self.borrow_apis = self._normalize_specs(borrow_apis)
        self.consumption_apis = self._normalize_specs(consumption_apis)

    def _class_api_config(self, aliases, canonical, default):
        instance_type = type(self)
        for alias in aliases:
            if alias in instance_type.__dict__:
                return instance_type.__dict__[alias]
        return getattr(instance_type, canonical, default)

    @staticmethod
    def _pop_first(kwargs, *names):
        for name in names:
            if name in kwargs:
                return kwargs.pop(name)
        return None

    @staticmethod
    def _normalize_specs(specs):
        if specs is None:
            return ()
        if callable(specs):
            return (specs,)
        if isinstance(specs, str):
            specs = [
                spec.strip()
                for spec in specs.replace(',', ' ').split()
                if spec.strip()
            ]
        return tuple(specs)

    def configure(self, issuance_apis=None, borrow_apis=None,
                  consumption_apis=None, **kwargs):
        if (
            isinstance(issuance_apis, dict)
            and borrow_apis is None
            and consumption_apis is None
        ):
            config = issuance_apis
            issuance_apis = config.get('issue', config.get('issuance'))
            borrow_apis = config.get('borrow')
            consumption_apis = config.get('consume', config.get('consumption'))

        issue_value = kwargs.get(
            'issue_apis', kwargs.get('issue', self.issuance_apis))
        borrow_value = kwargs.get(
            'borrow_apis', kwargs.get('borrow', self.borrow_apis))
        consume_value = kwargs.get(
            'consume_apis', kwargs.get('consume', self.consumption_apis))

        self.issuance_apis = self._normalize_specs(
            issuance_apis if issuance_apis is not None else issue_value)
        self.borrow_apis = self._normalize_specs(
            borrow_apis if borrow_apis is not None else borrow_value)
        self.consumption_apis = self._normalize_specs(
            consumption_apis
            if consumption_apis is not None
            else consume_value)
        return self

    def visit_Module(self, node):
        self._current_module = node
        self._ticket_counter = 0
        self._reuse_edges = set()
        self._unknown_findings = set()
        self._functions = {}
        self._affects = {}
        self._analyzed_functions = set()
        self._module_aliases = {}
        self._module_env = {}
        self._collect_functions(node)
        self._collect_module_aliases(node)

        context = _Context()
        module_block = self._exec_block(node.body, [_State()], context)
        for module_state in module_block.normal:
            self._module_env.update(module_state.env)
        self._analyze_uncalled_functions(node)

        self._emit_results()

    def _analyze_uncalled_functions(self, node):
        relevance = {}
        called_functions = set()
        for function in self._functions.values():
            for candidate in function:
                for child in ast.walk(candidate):
                    if not isinstance(child, ast.Call):
                        continue
                    path = self._canonical_static_path(
                        self._static_expr_path(child.func))
                    terminal = path.rsplit('.', 1)[-1] if path else ''
                    for callee in self._functions.get(terminal, ()):
                        if callee is not candidate:
                            called_functions.add(callee)

        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (
                    statement not in called_functions
                    and self._function_is_relevant(
                        statement, relevance, set())
                ):
                    self._analyze_uncalled_function(statement)
            elif isinstance(statement, ast.ClassDef):
                for child in statement.body:
                    if isinstance(child, (ast.FunctionDef,
                                          ast.AsyncFunctionDef)):
                        if (
                            child not in called_functions
                            and self._function_is_relevant(
                                child, relevance, set())
                        ):
                            self._analyze_uncalled_function(child)

    def _function_is_relevant(self, function, cache, visiting):
        if function in cache:
            return cache[function]
        if function in visiting:
            return False
        visiting.add(function)

        relevant = False
        callees = set()
        for child in ast.walk(function):
            if not isinstance(child, ast.Call):
                continue
            path = self._canonical_static_path(
                self._static_expr_path(child.func))
            terminal = path.rsplit('.', 1)[-1] if path else ''
            if (
                self._matches(self.issuance_apis, path)
                or self._matches(self.borrow_apis, path)
                or self._matches(self.consumption_apis, path)
            ):
                relevant = True
            if terminal:
                callees.add(terminal)

        if not relevant:
            for callee_name in callees:
                for callee in self._functions.get(callee_name, ()):
                    if callee is function:
                        continue
                    if self._function_is_relevant(callee, cache, visiting):
                        relevant = True
                        break
                if relevant:
                    break

        visiting.discard(function)
        cache[function] = relevant
        return relevant

    def _analyze_uncalled_function(self, function):
        if function in self._analyzed_functions:
            return

        local_state = _State(
            env=dict(self._module_env),
            aliases=dict(self._module_aliases),
        )
        parameters = list(
            getattr(function.args, 'posonlyargs', ())) + list(
                function.args.args)
        for index, parameter in enumerate(parameters):
            name = self._name_of(parameter)
            if index == 0 and name in ('self', 'cls'):
                local_state.env[name] = _Unknown('instance receiver')
            else:
                local_state.env[name] = _Unknown(
                    'unresolved parameter {}'.format(name))

        for parameter in getattr(function.args, 'kwonlyargs', ()):
            name = self._name_of(parameter)
            local_state.env[name] = _Unknown(
                'unresolved parameter {}'.format(name))

        vararg = getattr(function.args, 'vararg', None)
        if vararg is not None:
            local_state.env[self._name_of(vararg)] = _Container('tuple', [])

        kwarg = getattr(function.args, 'kwarg', None)
        if kwarg is not None:
            local_state.env[self._name_of(kwarg)] = _Container('dict', {})

        self._analyzed_functions.add(function)
        context = _Context()
        self._exec_block(function.body, [local_state], context)

    def _collect_module_aliases(self, node):
        for statement in node.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.asname:
                        self._module_aliases[alias.asname] = alias.name
                    else:
                        root = alias.name.split('.')[0]
                        self._module_aliases[root] = root
            elif isinstance(statement, ast.ImportFrom):
                module = statement.module or ''
                for alias in statement.names:
                    if alias.name == '*':
                        continue
                    local_name = alias.asname or alias.name
                    self._module_aliases[local_name] = (
                        '{}.{}'.format(module, alias.name)
                        if module else alias.name
                    )

    def _canonical_static_path(self, path):
        if not path:
            return path
        parts = path.split('.')
        if parts[0] in self._module_aliases:
            return '.'.join([self._module_aliases[parts[0]]] + parts[1:])
        return path

    def _collect_functions(self, node):
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._functions.setdefault(child.name, []).append(child)

    def _next_ticket(self, site):
        self._ticket_counter += 1
        return _Ticket(self._ticket_counter, site)

    def _record_reuse(self, ticket, previous_site, site):
        self._reuse_edges.add(
            (ticket.ticket_id, previous_site.key, site.key)
        )

    def _record_unknown(self, site, reason):
        self._unknown_findings.add((site.key, reason))

    def _emit_results(self):
        results = []

        graph = {}
        for _, first, second in self._reuse_edges:
            graph.setdefault(first, set()).add(second)
            graph.setdefault(second, set()).add(first)

        seen_components = set()
        for start in sorted(graph):
            if start in seen_components:
                continue

            component = set()
            stack = [start]
            while stack:
                current = stack.pop()
                if current in component:
                    continue
                component.add(current)
                stack.extend(graph.get(current, ()))
            seen_components.update(component)

            lines = sorted(set(site[0] for site in component))
            if len(lines) == 1:
                detail = (
                    'call at line {} can consume the same approval more than '
                    'once when repeated'.format(lines[0])
                )
            elif len(lines) == 2:
                detail = (
                    'first call at line {}, repeated at line {}'.format(
                        lines[0], lines[1])
                )
            else:
                detail = 'calls at lines {} reuse the same approval'.format(
                    ', '.join(str(line) for line in lines))

            message = '{}: {}'.format(self._error_tmpl, detail)
            for lineno, col_offset, _ in sorted(component):
                results.append(
                    base.Flake8Result(
                        lineno=lineno,
                        col_offset=col_offset,
                        message=message,
                    )
                )

        for (lineno, col_offset, _), reason in sorted(self._unknown_findings):
            results.append(
                base.Flake8Result(
                    lineno=lineno,
                    col_offset=col_offset,
                    message='{}: cannot determine whether the approval from {} '
                            'was already consumed'.format(
                                self._unknown_tmpl, reason),
                )
            )

        unique = {}
        for result in results:
            unique[(result.lineno, result.col_offset, result.message)] = result

        self.results.extend(
            unique[key] for key in sorted(unique)
        )

    def _exec_block(self, statements, states, context):
        normal = []
        terminated = []
        current = list(states)

        for statement in statements:
            next_states = []
            for state in current:
                for result_state in self._exec_stmt(statement, state, context):
                    if result_state.terminated is None:
                        next_states.append(result_state)
                    else:
                        terminated.append(result_state)
            current = self._dedupe_states(next_states)
            if not current:
                break

        return _BlockResult(current, terminated)

    def _exec_stmt(self, statement, state, context):
        capture = (
            context.collector is not None
            and self._may_raise(statement)
        )
        if capture:
            context.collector.append(state.clone())

        previous_context = self._active_context
        self._active_context = context
        try:
            results = self._exec_stmt_inner(statement, state, context)
        finally:
            self._active_context = previous_context

        if capture:
            for result in results:
                if result.terminated in (None, 'raise'):
                    context.collector.append(result.clone())

        return results

    def _exec_stmt_inner(self, statement, state, context):
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            return [self._exec_import(statement, state)]
        if isinstance(statement, ast.Assign):
            return self._exec_assign(statement, state)
        if isinstance(statement, ast.AnnAssign):
            if statement.value is None:
                return [state]
            return self._exec_assign(statement, state)
        if isinstance(statement, ast.AugAssign):
            return self._exec_aug_assign(statement, state)
        if isinstance(statement, ast.Expr):
            return [
                result_state
                for _, result_state in self._exec_expr(statement.value, state)
            ]
        if isinstance(statement, ast.If):
            return self._exec_if(statement, state, context)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            return self._exec_for(statement, state, context)
        if isinstance(statement, ast.While):
            return self._exec_while(statement, state, context)
        if isinstance(statement, ast.Try):
            return self._exec_try(statement, state, context)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return self._exec_with(statement, state, context)
        if isinstance(statement, ast.Return):
            return self._exec_return(statement, state)
        if isinstance(statement, ast.Raise):
            return self._exec_raise(statement, state)
        if isinstance(statement, ast.Break):
            result = state.clone()
            result.terminated = 'break'
            return [result]
        if isinstance(statement, ast.Continue):
            result = state.clone()
            result.terminated = 'continue'
            return [result]
        if isinstance(statement, ast.Assert):
            return [
                result_state
                for _, result_state in self._exec_expr(statement.test, state)
            ]
        if isinstance(statement, ast.Delete):
            return [self._exec_delete(statement, state)]
        match_type = getattr(ast, 'Match', None)
        if match_type is not None and isinstance(statement, match_type):
            return self._exec_match(statement, state, context)

        return [state]

    def _exec_import(self, statement, state):
        result = state.clone()
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname:
                    result.aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split('.')[0]
                    result.aliases[root] = root
        else:
            module = statement.module or ''
            for alias in statement.names:
                if alias.name == '*':
                    continue
                local_name = alias.asname or alias.name
                if module:
                    result.aliases[local_name] = '{}.{}'.format(
                        module, alias.name)
                else:
                    result.aliases[local_name] = alias.name
        return result

    def _exec_assign(self, statement, state):
        results = []
        for value, result_state in self._exec_expr(statement.value, state):
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            else:
                targets = [statement.target]

            bound_state = result_state
            for target in targets:
                bound_state = self._bind_target(
                    target, value, bound_state)
            results.append(bound_state)
        return results

    def _exec_aug_assign(self, statement, state):
        results = []
        for value, result_state in self._exec_expr(statement.value, state):
            current = self._eval_single(statement.target, result_state)
            combined = self._aug_assign_value(statement.op, current, value)
            results.append(
                self._bind_target(statement.target, combined, result_state)
            )
        return results

    @staticmethod
    def _aug_assign_value(operator, current, value):
        if isinstance(operator, ast.Add):
            if isinstance(current, _Const) and isinstance(value, _Const):
                try:
                    return _Const(current.value + value.value)
                except TypeError:
                    return _Unknown('augmented assignment')
            if isinstance(current, _Container) and isinstance(
                    value, _Container):
                current_items = ApprovalReuseLinter._container_values(
                    current)
                value_items = ApprovalReuseLinter._container_values(value)
                return _Container(current.kind, current_items + value_items)
        return _Unknown('augmented assignment')

    def _exec_return(self, statement, state):
        results = []
        if statement.value is None:
            value_results = [(_Const(None), state)]
        else:
            value_results = self._exec_expr(statement.value, state)

        for value, result_state in value_results:
            returned = result_state.clone()
            returned.returns.append(value)
            returned.terminated = 'return'
            results.append(returned)
        return results

    def _exec_raise(self, statement, state):
        results = []
        if statement.exc is None:
            value_results = [(_Const(None), state)]
        else:
            value_results = self._exec_expr(statement.exc, state)

        for _, result_state in value_results:
            raised = result_state.clone()
            raised.terminated = 'raise'
            results.append(raised)
        return results

    def _exec_delete(self, statement, state):
        result = state.clone()
        for target in statement.targets:
            key = self._target_key(target)
            if key is not None:
                result.env.pop(key, None)
        return result

    def _exec_if(self, statement, state, context):
        results = []
        for value, test_state in self._exec_expr(statement.test, state):
            truth = self._truth(value)
            if truth is False:
                branches = [(statement.orelse, test_state)]
            elif truth is True:
                branches = [(statement.body, test_state)]
            else:
                branches = [
                    (statement.body, test_state.clone()),
                    (statement.orelse, test_state.clone()),
                ]

            for body, branch_state in branches:
                block = self._exec_block(body, [branch_state], context)
                results.extend(block.normal)
                results.extend(block.terminated)

        return self._dedupe_states(results)

    def _exec_for(self, statement, state, context):
        results = []
        for iterable, iter_state in self._exec_expr(statement.iter, state):
            items = self._iter_values(iterable)
            known_length = self._iter_length(iterable)

            entries = [iter_state.clone()] if known_length != 1 else []
            exits = []
            current = [iter_state.clone()]

            limit = min(len(items), MAX_LOOP_ITERATIONS)
            for item in items[:limit]:
                next_iteration = []
                for loop_state in current:
                    bound = self._bind_target(
                        statement.target, item, loop_state.clone())
                    block = self._exec_block(statement.body, [bound], context)
                    next_iteration.extend(block.normal)
                    for terminated in block.terminated:
                        if terminated.terminated == 'break':
                            terminated = terminated.clone()
                            terminated.terminated = None
                            exits.append(terminated)
                        elif terminated.terminated == 'continue':
                            terminated = terminated.clone()
                            terminated.terminated = None
                            next_iteration.append(terminated)
                        else:
                            exits.append(terminated)
                current = self._dedupe_states(next_iteration)
                if not current:
                    break

            exits.extend(current)
            if known_length != 1:
                exits.extend(entries)

            if statement.orelse:
                orelse_exits = []
                for exit_state in self._dedupe_states(exits):
                    if exit_state.terminated is None:
                        block = self._exec_block(
                            statement.orelse, [exit_state], context)
                        orelse_exits.extend(block.normal)
                        orelse_exits.extend(block.terminated)
                    else:
                        orelse_exits.append(exit_state)
                exits = orelse_exits

            results.extend(exits)

        return self._dedupe_states(results)

    def _exec_while(self, statement, state, context):
        exits = []
        current = [state.clone()]

        for _ in range(MAX_LOOP_ITERATIONS):
            next_iteration = []
            for loop_state in current:
                for value, test_state in self._exec_expr(
                        statement.test, loop_state):
                    truth = self._truth(value)
                    if truth is False:
                        exits.append(test_state)
                        continue
                    if truth is not True:
                        exits.append(test_state.clone())

                    block = self._exec_block(
                        statement.body, [test_state.clone()], context)
                    next_iteration.extend(block.normal)
                    for terminated in block.terminated:
                        if terminated.terminated == 'break':
                            terminated = terminated.clone()
                            terminated.terminated = None
                            exits.append(terminated)
                        elif terminated.terminated == 'continue':
                            terminated = terminated.clone()
                            terminated.terminated = None
                            next_iteration.append(terminated)
                        else:
                            exits.append(terminated)

            current = self._dedupe_states(next_iteration)
            if not current:
                break

        exits.extend(current)

        if statement.orelse:
            orelse_exits = []
            for exit_state in self._dedupe_states(exits):
                if exit_state.terminated is None:
                    block = self._exec_block(
                        statement.orelse, [exit_state], context)
                    orelse_exits.extend(block.normal)
                    orelse_exits.extend(block.terminated)
                else:
                    orelse_exits.append(exit_state)
            exits = orelse_exits

        return self._dedupe_states(exits)

    def _exec_try(self, statement, state, context):
        saved_collector = context.collector
        exceptions = []
        context.collector = exceptions
        try:
            body = self._exec_block(statement.body, [state], context)
        finally:
            context.collector = saved_collector

        normal = list(body.normal)
        terminated = [
            item for item in body.terminated
            if item.terminated != 'raise'
        ]

        if statement.orelse:
            block = self._exec_block(
                statement.orelse, normal, context)
            normal = block.normal
            terminated.extend(block.terminated)

        exception_states = self._dedupe_states(exceptions)
        if statement.handlers:
            handler_normal = []
            handler_terminated = []
            for handler in statement.handlers:
                start_states = []
                for exception_state in exception_states:
                    handler_state = exception_state.clone()
                    handler_state.terminated = None
                    if handler.name is not None:
                        handler_state.env[self._name_of(handler.name)] = (
                            _Unknown('caught exception'))
                    start_states.append(handler_state)

                block = self._exec_block(
                    handler.body, self._dedupe_states(start_states), context)
                handler_normal.extend(block.normal)
                handler_terminated.extend(block.terminated)

            normal.extend(handler_normal)
            terminated.extend(handler_terminated)
        else:
            terminated.extend(exception_states)

        if statement.finalbody:
            normal, terminated = self._run_finally(
                statement.finalbody, normal, terminated, context)

        return self._dedupe_states(normal + terminated)

    def _run_finally(self, finalbody, normal, terminated, context):
        normal_out = []
        terminated_out = []

        incoming = [(item, None) for item in normal]
        incoming.extend((item, item.terminated) for item in terminated)

        for incoming_state, original_termination in incoming:
            block = self._exec_block(
                finalbody, [incoming_state.clone()], context)
            for item in block.normal:
                if original_termination is None:
                    normal_out.append(item)
                else:
                    item = item.clone()
                    item.terminated = original_termination
                    terminated_out.append(item)
            terminated_out.extend(block.terminated)

        return self._dedupe_states(normal_out), self._dedupe_states(
            terminated_out)

    def _exec_with(self, statement, state, context):
        states = [state]
        for item in statement.items:
            next_states = []
            for current_state in states:
                for value, result_state in self._exec_expr(
                        item.context_expr, current_state):
                    if item.optional_vars is not None:
                        result_state = self._bind_target(
                            item.optional_vars, value, result_state)
                    next_states.append(result_state)
            states = self._dedupe_states(next_states)

        block = self._exec_block(statement.body, states, context)
        return self._dedupe_states(block.normal + block.terminated)

    def _exec_match(self, statement, state, context):
        subject_results = self._exec_expr(statement.subject, state)
        results = []

        for _, subject_state in subject_results:
            results.append(subject_state.clone())
            for case in statement.cases:
                case_state = subject_state.clone()
                for name in self._pattern_names(case.pattern):
                    case_state.env[name] = _Unknown('match binding')
                if case.guard is not None:
                    guards = self._exec_expr(case.guard, case_state)
                    case_states = [
                        guarded_state
                        for value, guarded_state in guards
                        if self._truth(value) is not False
                    ]
                else:
                    case_states = [case_state]

                for guarded_state in case_states:
                    block = self._exec_block(
                        case.body, [guarded_state], context)
                    results.extend(block.normal)
                    results.extend(block.terminated)

        return self._dedupe_states(results)

    def _pattern_names(self, pattern):
        names = []
        for child in ast.walk(pattern):
            name = getattr(child, 'name', None)
            if isinstance(name, str):
                names.append(name)
            rest = getattr(child, 'rest', None)
            if isinstance(rest, str):
                names.append(rest)
        return names

    def _exec_expr(self, expression, state):
        if expression is None:
            return [(_Const(None), state)]
        if hasattr(ast, 'Constant') and isinstance(
                expression, ast.Constant):
            return [(_Const(expression.value), state)]
        if not hasattr(ast, 'Constant'):
            if isinstance(expression, ast.Num):
                return [(_Const(expression.n), state)]
            if isinstance(expression, ast.Str):
                return [(_Const(expression.s), state)]
            if isinstance(expression, ast.NameConstant):
                return [(_Const(expression.value), state)]
        if isinstance(expression, ast.Name):
            return [(self._eval_name(expression, state), state)]
        if isinstance(expression, ast.Attribute):
            return [(self._eval_attribute(expression, state), state)]
        if isinstance(expression, ast.Subscript):
            return self._exec_subscript(expression, state)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return self._exec_container_literal(expression, state)
        if isinstance(expression, ast.Dict):
            return self._exec_dict_literal(expression, state)
        if isinstance(expression, ast.Call):
            return self._exec_call(expression, state)
        if isinstance(expression, ast.IfExp):
            return self._exec_if_exp(expression, state)
        if isinstance(expression, ast.BoolOp):
            return self._exec_bool_op(expression, state)
        if isinstance(expression, ast.NamedExpr):
            results = []
            for value, result_state in self._exec_expr(
                    expression.value, state):
                results.append(
                    (value, self._bind_target(
                        expression.target, value, result_state)))
            return results
        if isinstance(expression, ast.Starred):
            return self._exec_expr(expression.value, state)
        if isinstance(expression, (ast.Await, ast.Yield, ast.YieldFrom)):
            return self._exec_expr(expression.value, state)
        if isinstance(expression, (ast.BinOp, ast.UnaryOp, ast.Compare)):
            return self._exec_operator(expression, state)
        if isinstance(expression, ast.Lambda):
            return [(_Unknown('lambda result'), state)]
        if isinstance(expression, ast.JoinedStr):
            return self._exec_joined_str(expression, state)

        return [(_Unknown('unsupported expression'), state)]

    def _exec_operator(self, expression, state):
        children = [
            child for child in ast.iter_child_nodes(expression)
            if isinstance(child, ast.expr)
        ]
        results = [(None, state)]
        for child in children:
            next_results = []
            for _, result_state in results:
                next_results.extend(self._exec_expr(child, result_state))
            results = next_results
        return [
            (_Unknown('operator result'), result_state)
            for _, result_state in results
        ]

    def _exec_joined_str(self, expression, state):
        results = [(_Const(''), state)]
        for value in expression.values:
            next_results = []
            for _, result_state in results:
                if isinstance(value, ast.FormattedValue):
                    values = self._exec_expr(value.value, result_state)
                else:
                    values = self._exec_expr(value, result_state)
                next_results.extend(
                    (_Const(''), inner_state) for _, inner_state in values)
            results = next_results
        return results

    def _exec_if_exp(self, expression, state):
        results = []
        for value, test_state in self._exec_expr(expression.test, state):
            truth = self._truth(value)
            branches = []
            if truth is not False:
                branches.append((expression.body, test_state.clone()))
            if truth is not True:
                branches.append((expression.orelse, test_state.clone()))
            for branch, branch_state in branches:
                results.extend(self._exec_expr(branch, branch_state))
        return results

    def _exec_bool_op(self, expression, state):
        current = [(_Unknown('boolean expression'), state)]
        for value in expression.values:
            next_values = []
            for _, current_state in current:
                next_values.extend(self._exec_expr(value, current_state))
            current = next_values
        return current

    def _exec_container_literal(self, expression, state):
        results = [([], state)]
        for element in expression.elts:
            next_results = []
            for values, result_state in results:
                for value, inner_state in self._exec_expr(
                        element, result_state):
                    next_results.append((values + [value], inner_state))
            results = next_results

        kind = (
            'tuple' if isinstance(expression, ast.Tuple)
            else 'set' if isinstance(expression, ast.Set)
            else 'list'
        )
        return [
            (_Container(kind, values), result_state)
            for values, result_state in results
        ]

    def _exec_dict_literal(self, expression, state):
        results = [([], state)]
        for key_node, value_node in zip(expression.keys, expression.values):
            next_results = []
            for pairs, result_state in results:
                if key_node is None:
                    for value, inner_state in self._exec_expr(
                            value_node, result_state):
                        inner_pairs = list(pairs)
                        if isinstance(value, _Container):
                            inner_pairs.extend(
                                value.items.items()
                                if isinstance(value.items, dict)
                                else [(index, item) for index, item in
                                      enumerate(value.items)]
                            )
                        next_results.append((inner_pairs, inner_state))
                else:
                    for key, key_state in self._exec_expr(
                            key_node, result_state):
                        for value, inner_state in self._exec_expr(
                                value_node, key_state):
                            next_results.append(
                                (pairs + [(self._key_of(key), value)],
                                 inner_state))
            results = next_results

        return [
            (_Container('dict', dict(pairs)), result_state)
            for pairs, result_state in results
        ]

    def _exec_subscript(self, expression, state):
        results = []
        for container, container_state in self._exec_expr(
                expression.value, state):
            for index, index_state in self._exec_expr(
                    expression.slice, container_state):
                results.append(
                    (self._subscript_value(container, index), index_state)
                )
        return results

    def _exec_call(self, call, state):
        if isinstance(call.func, ast.Attribute):
            receiver_results = self._exec_expr(call.func.value, state)
        else:
            receiver_results = [(None, state)]

        results = []
        for receiver, receiver_state in receiver_results:
            path = self._callee_path(call.func, receiver_state)

            arg_states = self._eval_arguments(call, receiver_state)
            for arg_values, kw_values, arg_state in arg_states:
                results.extend(
                    self._apply_call(
                        call, path, receiver, arg_values, kw_values,
                        arg_state))

        return results

    def _eval_arguments(self, call, state):
        results = [([], {}, state)]

        for argument in call.args:
            next_results = []
            for values, keywords, result_state in results:
                if isinstance(argument, ast.Starred):
                    expr_results = self._exec_expr(
                        argument.value, result_state)
                else:
                    expr_results = self._exec_expr(argument, result_state)

                for value, inner_state in expr_results:
                    expanded = (
                        self._container_values(value)
                        if isinstance(argument, ast.Starred)
                        else [value]
                    )
                    next_results.append(
                        (values + expanded, keywords, inner_state))
            results = next_results

        for keyword in call.keywords:
            next_results = []
            for values, keywords, result_state in results:
                for value, inner_state in self._exec_expr(
                        keyword.value, result_state):
                    if keyword.arg is None and isinstance(value, _Container) \
                            and isinstance(value.items, dict):
                        updated = dict(keywords)
                        for key, inner_value in value.items.items():
                            updated[str(key)] = inner_value
                    else:
                        updated = dict(keywords)
                        updated[keyword.arg] = value
                    next_results.append((values, updated, inner_state))
            results = next_results

        return [
            (values, keywords, result_state)
            for values, keywords, result_state in results
        ]

    def _apply_call(self, call, path, receiver, args, kwargs, state):
        site = _Site(call, path)
        functions = self._functions.get(path.rsplit('.', 1)[-1], ())

        if functions and self._should_inline_function(
                call, path, receiver, state):
            return self._call_user_function(
                call, functions, receiver, args, kwargs, state)

        if self._matches(self.issuance_apis, path):
            return [(self._next_ticket(site), state)]

        if self._matches(self.consumption_apis, path):
            return self._consume(site, receiver, args, kwargs, state)

        if self._matches(self.borrow_apis, path):
            return self._borrow(site, receiver, args, kwargs, state)

        container_result = self._container_method(
            call, path, receiver, args, kwargs, state)
        if container_result is not None:
            return container_result

        if functions:
            return self._call_user_function(
                call, functions, receiver, args, kwargs, state)

        if path.rsplit('.', 1)[-1] == 'range' and all(
                isinstance(argument, _Const) and
                isinstance(argument.value, int)
                for argument in args):
            try:
                return [(_Const(list(range(*[
                    argument.value for argument in args
                ]))), state)]
            except (TypeError, ValueError):
                pass

        reason = (
            'external call "{}"'.format(path)
            if path else 'an unanalyzable call result'
        )
        return [(_Unknown(reason), state)]

    def _should_inline_function(self, call, path, receiver, state):
        if not path:
            return False
        if '.' not in path:
            return True
        if path.startswith('self.'):
            return True
        if isinstance(call.func, ast.Attribute):
            base = call.func.value
            if isinstance(base, ast.Name) and base.id in state.env:
                return not isinstance(state.env.get(base.id), _ApiRef)
        return False

    def _consume(self, site, receiver, args, kwargs, state):
        values = self._call_ticket_values(receiver, args, kwargs)

        result_state = state.clone()
        for value in values:
            if isinstance(value, _Ticket):
                previous = result_state.consumed.get(value.ticket_id)
                if previous is not None:
                    self._record_reuse(value, previous, site)
                result_state.consumed[value.ticket_id] = site
            elif isinstance(value, _Unknown):
                self._record_unknown(site, value.reason)
            elif isinstance(value, _ApiRef):
                self._record_unknown(
                    site, 'attribute "{}"'.format(value.path))

        return [(_Const(None), result_state)]

    def _borrow(self, site, receiver, args, kwargs, state):
        values = self._call_ticket_values(receiver, args, kwargs)

        if len(values) == 1:
            result = values[0]
        elif values:
            result = _Container('tuple', values)
        else:
            result = _Unknown(
                'borrow API "{}" returned an untracked value'.format(
                    site.path))
        return [(result, state)]

    def _call_ticket_values(self, receiver, args, kwargs):
        argument_values = []
        for argument in args:
            argument_values.extend(self._ticket_like_values(argument))
        for argument in kwargs.values():
            argument_values.extend(self._ticket_like_values(argument))

        receiver_values = []
        if receiver is not None:
            receiver_values.extend(self._ticket_like_values(receiver))

        direct_receiver = [
            value for value in receiver_values
            if isinstance(value, _Ticket)
        ]
        if direct_receiver:
            return direct_receiver + argument_values
        if argument_values:
            return argument_values
        return receiver_values

    def _container_method(self, call, path, receiver, args, kwargs, state):
        if not isinstance(call.func, ast.Attribute):
            return None

        method = call.func.attr
        if method == 'get' and isinstance(receiver, _Container):
            key = self._key_of(args[0]) if args else None
            return [(self._subscript_value(receiver, _Const(key)), state)]
        if method == 'pop' and isinstance(receiver, _Container):
            key = self._key_of(args[0]) if args else None
            value = self._subscript_value(receiver, _Const(key))
            updated = self._container_without(receiver, key)
            return [
                (value, self._store_expr(call.func.value, updated, state))
            ]
        if method in ('append', 'add') and isinstance(receiver, _Container):
            updated = self._container_append(receiver, args[0] if args else None)
            return [
                (_Const(None),
                 self._store_expr(call.func.value, updated, state))
            ]
        if method == 'extend' and isinstance(receiver, _Container):
            additions = self._container_values(args[0]) if args else []
            updated = receiver
            for addition in additions:
                updated = self._container_append(updated, addition)
            return [
                (_Const(None),
                 self._store_expr(call.func.value, updated, state))
            ]
        if method == 'insert' and isinstance(receiver, _Container):
            value = args[1] if len(args) > 1 else None
            updated = self._container_append(receiver, value)
            return [
                (_Const(None),
                 self._store_expr(call.func.value, updated, state))
            ]
        if method == 'setdefault' and isinstance(receiver, _Container):
            key = self._key_of(args[0]) if args else None
            default = args[1] if len(args) > 1 else _Const(None)
            existing = receiver.items.get(key) if isinstance(
                receiver.items, dict) else None
            if existing is not None:
                return [(existing, state)]
            updated_items = dict(receiver.items)
            updated_items[key] = default
            updated = _Container('dict', updated_items)
            return [
                (default, self._store_expr(call.func.value, updated, state))
            ]

        return None

    def _call_user_function(self, call, functions, receiver, args, kwargs,
                            state):
        context = self._active_context or _Context()
        name = self._callee_path(call.func, state)

        if context.depth >= MAX_HELPER_DEPTH:
            return [(
                _Unknown(
                    'local call "{}" exceeded the analysis depth limit'.format(
                        name)),
                state,
            )]
        if context.budget[0] >= MAX_HELPER_CALLS:
            return [(
                _Unknown(
                    'local call "{}" exceeded the analysis call limit'.format(
                        name)),
                state,
            )]

        results = []
        for function in functions:
            if function in context.stack:
                results.append((
                    _Unknown('recursive call "{}"'.format(name)),
                    state,
                ))
                continue

            context.budget[0] += 1
            self._analyzed_functions.add(function)
            child_context = context.clone(
                depth=context.depth + 1,
                stack=context.stack + (function,),
            )
            previous_context = self._active_context
            self._active_context = child_context
            try:
                local_state = self._bind_function_arguments(
                    function, receiver, args, kwargs, state)
                bindings = self._argument_bindings(
                    function, receiver, call)
                block = self._exec_block(
                    function.body, [local_state], child_context)
            finally:
                self._active_context = previous_context

            for result_state in block.normal:
                results.append((
                    _Const(None),
                    self._return_to_caller(
                        state, local_state, result_state, bindings),
                ))

            for result_state in block.terminated:
                if result_state.terminated != 'return':
                    continue
                value = (
                    result_state.returns[-1]
                    if result_state.returns
                    else _Const(None)
                )
                results.append((
                    value,
                    self._return_to_caller(
                        state, local_state, result_state, bindings),
                ))

        return results

    def _argument_bindings(self, function, receiver, call):
        parameters = list(
            getattr(function.args, 'posonlyargs', ())) + list(
                function.args.args)
        if (
            receiver is not None
            and parameters
            and self._name_of(parameters[0]) in ('self', 'cls')
        ):
            parameters = parameters[1:]

        bindings = []
        for index, parameter in enumerate(parameters):
            if index >= len(call.args):
                break
            argument = call.args[index]
            if isinstance(argument, ast.Starred):
                continue
            bindings.append((self._name_of(parameter), argument))

        for keyword in call.keywords:
            if keyword.arg is not None:
                bindings.append((keyword.arg, keyword.value))
        return bindings

    def _bind_function_arguments(self, function, receiver, args, kwargs,
                                 state):
        local_state = state.clone()
        local_state.returns = []
        local_state.terminated = None

        arguments = function.args
        positional_params = list(
            getattr(arguments, 'posonlyargs', ())) + list(arguments.args)
        positional_values = list(args)

        if (
            receiver is not None
            and positional_params
            and self._name_of(positional_params[0]) in ('self', 'cls')
        ):
            local_state.env[
                self._name_of(positional_params[0])
            ] = receiver
            positional_params = positional_params[1:]

        defaults = list(getattr(arguments, 'defaults', ()))
        first_default = len(positional_params) - len(defaults)

        remaining_keywords = dict(kwargs)
        for index, parameter in enumerate(positional_params):
            parameter_name = self._name_of(parameter)
            if index < len(positional_values):
                value = positional_values[index]
            elif parameter_name in remaining_keywords:
                value = remaining_keywords.pop(parameter_name)
            elif index >= first_default and defaults:
                default = defaults[index - first_default]
                value = self._eval_single(default, local_state)
            else:
                value = _Unknown('missing argument "{}"'.format(
                    parameter_name))
            local_state.env[parameter_name] = value

        vararg = getattr(arguments, 'vararg', None)
        if vararg is not None:
            local_state.env[self._name_of(vararg)] = _Container(
                'tuple', positional_values[len(positional_params):])

        keyword_values = remaining_keywords
        for parameter in getattr(arguments, 'kwonlyargs', ()):
            parameter_name = self._name_of(parameter)
            if parameter_name in keyword_values:
                value = keyword_values.pop(parameter_name)
            else:
                value = _Unknown('missing keyword argument "{}"'.format(
                    parameter_name))
            local_state.env[parameter_name] = value

        kwarg = getattr(arguments, 'kwarg', None)
        if kwarg is not None:
            local_state.env[self._name_of(kwarg)] = _Container(
                'dict', dict((key, value) for key, value in
                             keyword_values.items()))

        return local_state

    def _return_to_caller(self, caller_state, local_state, function_state,
                          bindings):
        result_state = caller_state.clone()
        result_state.consumed = dict(function_state.consumed)
        for key, value in function_state.env.items():
            if '.' in key:
                result_state.env[key] = value

        for parameter_name, argument in bindings:
            before = local_state.env.get(parameter_name)
            after = function_state.env.get(parameter_name)
            if (
                isinstance(before, _Container)
                and isinstance(after, _Container)
                and ApprovalReuseLinter._value_sig(before)
                != ApprovalReuseLinter._value_sig(after)
            ):
                result_state = self._bind_target(
                    argument, after, result_state)
        return result_state

    def _eval_name(self, expression, state):
        name = expression.id
        if name in state.env:
            return state.env[name]
        if name in state.aliases:
            return _ApiRef(state.aliases[name])
        return _Unknown('name "{}"'.format(name))

    def _eval_attribute(self, expression, state):
        key = self._target_key(expression)
        if key is not None and key in state.env:
            return state.env[key]

        path = self._expr_path(expression, state)
        if path:
            return _ApiRef(path)
        return _Unknown('attribute access')

    def _callee_path(self, expression, state):
        if isinstance(expression, ast.Name):
            name = expression.id
            value = state.env.get(name)
            if isinstance(value, _ApiRef):
                return value.path
            if name in state.aliases:
                return state.aliases[name]
            return name
        if isinstance(expression, ast.Attribute):
            base = self._expr_path(expression.value, state)
            if base:
                return '{}.{}'.format(base, expression.attr)
            return expression.attr
        if isinstance(expression, ast.Call):
            return ''
        return ''

    def _expr_path(self, expression, state):
        if isinstance(expression, ast.Name):
            name = expression.id
            value = state.env.get(name)
            if isinstance(value, _ApiRef):
                return value.path
            return state.aliases.get(name, name)
        if isinstance(expression, ast.Attribute):
            base = self._expr_path(expression.value, state)
            if base:
                return '{}.{}'.format(base, expression.attr)
            return expression.attr
        return ''

    @staticmethod
    def _target_key(target):
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            base = ApprovalReuseLinter._static_expr_path(target.value)
            if base:
                return '{}.{}'.format(base, target.attr)
        return None

    @staticmethod
    def _static_expr_path(expression):
        if isinstance(expression, ast.Name):
            return expression.id
        if isinstance(expression, ast.Attribute):
            base = ApprovalReuseLinter._static_expr_path(expression.value)
            if base:
                return '{}.{}'.format(base, expression.attr)
        return ''

    def _bind_target(self, target, value, state):
        if isinstance(target, ast.Name):
            result = state.clone()
            result.env[target.id] = value
            return result
        if isinstance(target, ast.Attribute):
            key = self._target_key(target)
            result = state.clone()
            if key is not None:
                result.env[key] = value
            return result
        if isinstance(target, ast.Subscript):
            return self._store_subscript(target, value, state)
        if isinstance(target, (ast.Tuple, ast.List)):
            return self._unpack_targets(target.elts, value, state)
        if isinstance(target, ast.Starred):
            return self._bind_target(target.value, value, state)
        return state

    def _unpack_targets(self, targets, value, state):
        values = self._container_values(value)
        result = state
        has_star = any(isinstance(target, ast.Starred) for target in targets)

        if has_star:
            for index, target in enumerate(targets):
                if isinstance(target, ast.Starred):
                    result = self._bind_target(
                        target.value, _Container('list', values[index:]),
                        result)
                    break
                item = values[index] if index < len(values) else _Unknown(
                    'container item')
                result = self._bind_target(target, item, result)
            return result

        for index, target in enumerate(targets):
            item = values[index] if index < len(values) else _Unknown(
                'container item')
            result = self._bind_target(target, item, result)
        return result

    def _store_subscript(self, target, value, state):
        container_key = self._target_key(target.value)
        container = self._eval_single(target.value, state)
        index = self._eval_single(target.slice, state)
        key = self._key_of(index)

        if isinstance(container, _Container):
            if isinstance(container.items, dict):
                items = dict(container.items)
                items[key] = value
            else:
                items = list(container.items)
                if isinstance(key, int) and -len(items) <= key < len(items):
                    items[key] = value
                else:
                    items.append(value)
            updated = _Container(container.kind, items)
        else:
            updated = _Container('dict', {key: value})

        if container_key is not None:
            result = state.clone()
            result.env[container_key] = updated
            return result

        return self._store_expr(target.value, updated, state)

    def _store_expr(self, expression, value, state):
        key = self._target_key(expression)
        if key is not None:
            result = state.clone()
            result.env[key] = value
            return result
        if isinstance(expression, ast.Subscript):
            return self._store_subscript(expression, value, state)
        return state

    def _eval_single(self, expression, state):
        results = self._exec_expr(expression, state)
        if not results:
            return _Unknown('unresolved expression')
        return results[0][0]

    def _subscript_value(self, container, index):
        if isinstance(container, _Container):
            key = self._key_of(index)
            if isinstance(container.items, dict):
                if key in container.items:
                    return container.items[key]
                values = list(container.items.values())
            else:
                values = container.items
                if isinstance(key, int):
                    try:
                        return values[key]
                    except IndexError:
                        return _Unknown('container index')

            unique = {}
            for value in values:
                unique[self._value_sig(value)] = value
            if len(unique) == 1:
                return list(unique.values())[0]
            return _Unknown('ambiguous container value')

        if isinstance(container, _Unknown):
            return _Unknown(container.reason)
        if isinstance(container, _ApiRef):
            return _Unknown('attribute "{}"'.format(container.path))
        return _Unknown('subscript of an untracked value')

    def _container_values(self, value):
        if isinstance(value, _Container):
            if isinstance(value.items, dict):
                return list(value.items.values())
            return list(value.items)
        return [value]

    def _container_append(self, container, value):
        if isinstance(container.items, dict):
            items = dict(container.items)
            items[self._key_of(value)] = value
        else:
            items = list(container.items)
            items.append(value)
        return _Container(container.kind, items)

    def _container_without(self, container, key):
        if isinstance(container.items, dict):
            items = dict(container.items)
            items.pop(key, None)
        else:
            items = list(container.items)
            if isinstance(key, int):
                try:
                    items.pop(key)
                except IndexError:
                    pass
        return _Container(container.kind, items)

    def _ticket_like_values(self, value):
        if isinstance(value, (_Ticket, _Unknown, _ApiRef)):
            return [value]
        if isinstance(value, _Container):
            results = []
            for item in self._container_values(value):
                results.extend(self._ticket_like_values(item))
            return results
        return []

    def _iter_values(self, value):
        if isinstance(value, _Container):
            if isinstance(value.items, dict):
                return [_Const(key) for key in value.items.keys()]
            return list(value.items)
        if isinstance(value, _Const) and isinstance(
                value.value, (list, tuple, set)):
            return [_Const(item) for item in value.value]
        return [
            _Unknown('loop item')
            for _ in range(MAX_LOOP_ITERATIONS)
        ]

    def _iter_length(self, value):
        if isinstance(value, _Container):
            if isinstance(value.items, dict):
                return len(value.items)
            if value.kind in ('list', 'tuple', 'set'):
                return len(value.items)
        if isinstance(value, _Const) and isinstance(
                value.value, (list, tuple, set)):
            return len(value.value)
        return None

    @staticmethod
    def _key_of(value):
        if isinstance(value, _Const):
            try:
                hash(value.value)
            except TypeError:
                return repr(value.value)
            return value.value
        if isinstance(value, _ApiRef):
            return value.path
        return repr(ApprovalReuseLinter._value_sig(value))

    @staticmethod
    def _truth(value):
        if isinstance(value, _Const):
            return bool(value.value)
        return None

    @staticmethod
    def _name_of(name):
        if isinstance(name, str):
            return name
        if isinstance(name, ast.arg):
            return name.arg
        if isinstance(name, ast.Name):
            return name.id
        return str(name)

    @staticmethod
    def _may_raise(statement):
        if isinstance(statement, (ast.Raise, ast.Assert)):
            return True
        for child in ast.walk(statement):
            if isinstance(child, (ast.Call, ast.Subscript)):
                return True
            if isinstance(child, ast.BinOp) and isinstance(
                    child.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                return True
        return False

    @staticmethod
    def _matches(specs, path):
        terminal = path.rsplit('.', 1)[-1] if path else ''
        for spec in specs:
            if callable(spec):
                try:
                    matched = spec(path)
                except TypeError:
                    matched = spec(terminal)
                if matched:
                    return True
                continue

            spec = spec.strip()
            if not spec:
                continue
            if any(char in spec for char in '*?['):
                if fnmatch.fnmatch(path, spec) or fnmatch.fnmatch(
                        terminal, spec):
                    return True
            elif '.' in spec:
                if path == spec or path.endswith('.' + spec):
                    return True
            elif terminal == spec:
                return True
        return False

    def _dedupe_states(self, states):
        seen = set()
        results = []
        for state in states:
            signature = self._state_sig(state)
            if signature in seen:
                continue
            seen.add(signature)
            results.append(state)
            if len(results) >= MAX_PATH_STATES:
                break
        return results

    def _state_sig(self, state):
        return (
            tuple(sorted(
                (key, self._value_sig(value))
                for key, value in state.env.items()
            )),
            tuple(sorted(state.aliases.items())),
            tuple(sorted(
                (ticket_id, site)
                for ticket_id, site in state.consumed.items()
            )),
            tuple(self._value_sig(value) for value in state.returns),
            state.terminated,
        )

    @staticmethod
    def _value_sig(value):
        if isinstance(value, _Ticket):
            return ('ticket', value.ticket_id)
        if isinstance(value, _Unknown):
            return ('unknown', value.reason)
        if isinstance(value, _Const):
            return ('const', repr(value.value))
        if isinstance(value, _Container):
            if isinstance(value.items, dict):
                items = tuple(sorted(
                    (repr(key), ApprovalReuseLinter._value_sig(item))
                    for key, item in value.items.items()
                ))
            else:
                items = tuple(
                    ApprovalReuseLinter._value_sig(item)
                    for item in value.items
                )
            return ('container', value.kind, items)
        if isinstance(value, _ApiRef):
            return ('api', value.path)
        return ('other', repr(value))


BadApprovalReuseLinter = ApprovalReuseLinter
TicketReuseLinter = ApprovalReuseLinter
OneTimeApprovalReuseLinter = ApprovalReuseLinter
