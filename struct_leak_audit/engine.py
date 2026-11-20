"""
Intra-procedural engine that turns the AST into FunctionReport objects.
"""
from __future__ import annotations

from pycparser import c_ast

from .analyzer import (
    AuditConfig,
    _VarInfo,
    render,
    root_identifier,
    struct_name_of,
)
from .exprclass import classify_rhs
from .model import (
    CONSTANT_FIELD,
    FIELD_FROM_SOURCE,
    FIELD_INIT,
    INTERNAL,
    KNOWN_PROJECTION,
    MEMCPY_COPY,
    Severity,
    UNBOUND_INDIRECT,
    UNBOUND_PROJECTION,
    UNKNOWN,
    WHOLE_COPY,
    WHOLE_STRUCT_COPY,
    Finding,
    FunctionReport,
)


class AuditEngine:
    def __init__(self, ast: c_ast.FileAST, config: AuditConfig):
        self.ast = ast
        self.config = config
        self.declared_functions = self._collect_function_names(ast)
        self.findings: list[Finding] = []
        self.variables: dict[str, _VarInfo] = {}
        self.parameters: set[str] = set()
        self.current_function = ""

    @staticmethod
    def _collect_function_names(ast: c_ast.FileAST) -> set[str]:
        names = set()
        for node in ast.ext:
            decl = node.decl if isinstance(node, c_ast.FuncDef) else node
            if isinstance(decl, c_ast.Decl) and isinstance(decl.type, c_ast.FuncDecl):
                if decl.name:
                    names.add(decl.name)
        return names

    def run(self) -> list[FunctionReport]:
        reports = []
        for node in self.ast.ext:
            if not isinstance(node, c_ast.FuncDef):
                continue
            reports.append(self._analyze_function(node))
        return reports

    def _analyze_function(self, func: c_ast.FuncDef) -> FunctionReport:
        self.findings = []
        self.variables = {}
        self.parameters = set()
        self.current_function = func.decl.name
        coord = str(func.coord)
        self._register_parameters(func.decl.type)
        self._register_local_declarations(func.body)
        self._walk_statement(func.body)
        return FunctionReport(
            name=self.current_function,
            coord=coord,
            findings=list(self.findings),
        )

    def _register_parameters(self, func_decl: c_ast.FuncDecl) -> None:
        if not func_decl.args:
            return
        for arg in func_decl.args.params:
            if isinstance(arg, c_ast.Decl) and arg.name:
                info = self._build_var_info(arg, param=True)
                self.variables[arg.name] = info
                self.parameters.add(arg.name)
            elif isinstance(arg, c_ast.EllipsisParam):
                continue

    def _register_local_declarations(self, body: c_ast.Compound) -> None:
        for stmt in body.block_items or []:
            if isinstance(stmt, c_ast.Decl) and stmt.name:
                self.variables[stmt.name] = self._build_var_info(stmt)

    def _build_var_info(self, decl: c_ast.Decl, param: bool = False) -> _VarInfo:
        tag = struct_name_of(decl.type)
        return _VarInfo(
            name=decl.name,
            struct_name=tag,
            is_pointer=isinstance(decl.type, c_ast.PtrDecl),
            is_target=tag == self.config.public_struct,
            param=param,
        )

    def _walk_statement(self, node: c_ast.Node) -> None:
        if isinstance(node, c_ast.Compound):
            for item in node.block_items or []:
                self._walk_statement(item)
        elif isinstance(node, c_ast.If):
            self._walk_statement(node.iftrue)
            if node.iffalse:
                self._walk_statement(node.iffalse)
        elif isinstance(node, (c_ast.While, c_ast.DoWhile, c_ast.For)):
            body = getattr(node, "stmt", None)
            if body is not None:
                self._walk_statement(body)
        elif isinstance(node, c_ast.Switch):
            self._walk_statement(node.stmt)
        elif isinstance(node, c_ast.Case):
            for stmt in node.stmts or []:
                self._walk_statement(stmt)
        elif isinstance(node, c_ast.Label):
            self._walk_statement(node.stmt)
        elif isinstance(node, c_ast.Decl):
            self._process_declaration(node)
        elif isinstance(node, c_ast.Assignment):
            self._process_assignment(node)
        elif isinstance(node, c_ast.FuncCall):
            self._process_call(node)
        # Every expression statement carrying a call is reached via the
        # Compound loop; nested calls are revisited through expression walks.

    def _process_declaration(self, decl: c_ast.Decl) -> None:
        if decl.name and decl.name not in self.variables:
            self.variables[decl.name] = self._build_var_info(decl)
        if decl.init is None or not self._is_target_lvalue_name(decl.name):
            return
        info = self.variables[decl.name]
        if isinstance(decl.init, c_ast.InitList):
            self._process_init_list(info, decl.init, str(decl.coord))
        else:
            if self._is_projection_call(decl.init):
                self._note_projection_result(decl.init, str(decl.coord), info.name)
                info.whole = (FIELD_INIT, render(decl.init))
                return
            category, source = classify_rhs(decl.init, self.parameters,
                                            self.variables, self.config)
            self._apply_single_init(info, category, source, decl.init,
                                    str(decl.coord))

    def _process_init_list(self, info: _VarInfo, init_list: c_ast.InitList,
                           coord: str) -> None:
        for initializer in init_list.exprs:
            if isinstance(initializer, c_ast.NamedInitializer):
                field_name = self._named_initializer_field(initializer)
                value = initializer.expr
            else:
                field_name = "<aggregate>"
                value = initializer
            category, source = classify_rhs(value, self.parameters,
                                            self.variables, self.config)
            self._record_field(info, field_name, category, source, value, coord)

    def _process_assignment(self, node: c_ast.Assignment) -> None:
        target = node.lvalue
        base = root_identifier(target)
        if base is None or base.name not in self.variables:
            self._scan_for_calls(node.rvalue)
            return
        info = self.variables[base.name]
        if not info.is_target:
            self._scan_for_calls(node.rvalue)
            return
        coord = str(node.coord)
        if isinstance(target, c_ast.StructRef):
            category, source = classify_rhs(node.rvalue, self.parameters,
                                            self.variables, self.config)
            self._record_field(info, target.field.name, category, source,
                               node.rvalue, coord)
            return
        category, source = classify_rhs(node.rvalue, self.parameters,
                                        self.variables, self.config)
        self._record_whole(info, category, source, node.rvalue, coord)

    def _record_field(self, info: _VarInfo, field_name: str, category: str,
                      source: str, value: c_ast.Node, coord: str) -> None:
        info.fields[field_name] = (category, source)
        if category == FIELD_INIT:
            self.findings.append(Finding(
                Severity.SAFE, CONSTANT_FIELD,
                f"field {field_name!r} is initialized from a safe constant",
                coord, self.current_function, info.name,
                expression=render(value), source=source))
        elif category == INTERNAL:
            self.findings.append(Finding(
                Severity.REVIEW, FIELD_FROM_SOURCE,
                f"field {field_name!r} is copied from an internal source field",
                coord, self.current_function, info.name,
                expression=render(value), source=source))
        elif category in (WHOLE_COPY, UNKNOWN):
            severity = Severity.UNSAFE if category == WHOLE_COPY else Severity.REVIEW
            code = WHOLE_STRUCT_COPY if category == WHOLE_COPY else UNBOUND_PROJECTION
            self.findings.append(Finding(
                severity, code,
                f"field {field_name!r} takes its value from {source}",
                coord, self.current_function, info.name,
                expression=render(value), source=source))
        else:
            self.findings.append(Finding(
                Severity.REVIEW, FIELD_FROM_SOURCE,
                f"field {field_name!r} is copied from an internal source field",
                coord, self.current_function, info.name,
                expression=render(value), source=source))

    def _record_whole(self, info: _VarInfo, category: str, source: str,
                      value: c_ast.Node, coord: str) -> None:
        info.whole = (category, source)
        if category == FIELD_INIT:
            return
        if category == WHOLE_COPY:
            self.findings.append(Finding(
                Severity.UNSAFE, WHOLE_STRUCT_COPY,
                "whole public structure is assigned from an internal object",
                coord, self.current_function, info.name,
                expression=render(value), source=source))
        else:
            self.findings.append(Finding(
                Severity.REVIEW, UNBOUND_PROJECTION,
                "whole public structure is assigned from an unbound expression",
                coord, self.current_function, info.name,
                expression=render(value), source=source))

    def _scan_for_calls(self, node: c_ast.Node | None) -> None:
        for child in node or []:
            if isinstance(child, c_ast.FuncCall):
                self._process_call(child)
            self._scan_for_calls(child)

    def _process_call(self, call: c_ast.FuncCall) -> None:
        callee = self._callee_name(call)
        coord = str(call.coord)
        if callee in self.config.copy_functions:
            self._process_copy_call(call, callee, coord)
            return
        if callee in self.config.report_functions:
            self._process_report_call(call, coord)
            return
        if callee is None or callee not in self.declared_functions:
            self._process_indirect(call, callee, coord)
            return
        if callee in self.config.projection_functions:
            self._note_projection_result(call, coord)

    def _process_copy_call(self, call: c_ast.FuncCall, name: str,
                           coord: str) -> None:
        args = call.args.exprs if call.args else []
        if len(args) < 2:
            return
        destination = root_identifier(args[0])
        if destination is None or destination.name not in self.variables:
            return
        info = self.variables[destination.name]
        if not info.is_target:
            return
        source = render(args[1])
        info.whole = (WHOLE_COPY, source)
        self.findings.append(Finding(
            Severity.UNSAFE, MEMCPY_COPY,
            f"{name}() overwrites the whole public structure from {source}",
            coord, self.current_function, info.name,
            expression=render(call), source=source))

    def _process_report_call(self, call: c_ast.FuncCall, coord: str) -> None:
        args = call.args.exprs if call.args else []
        for argument in args:
            base = root_identifier(argument)
            if base is None or base.name not in self.variables:
                continue
            info = self.variables[base.name]
            if not info.is_target:
                continue
            if info.whole is not None:
                category, source = info.whole
                if category == WHOLE_COPY:
                    continue
                elif category not in (FIELD_INIT,):
                    self.findings.append(Finding(
                        Severity.REVIEW, UNBOUND_PROJECTION,
                        "reported structure has an unbound whole-object origin",
                        coord, self.current_function, info.name,
                        expression=render(argument), source=source))

    def _process_indirect(self, call: c_ast.FuncCall, callee: str | None,
                          coord: str) -> None:
        rendered = render(call.name)
        target_var = self._target_argument(call)
        self.findings.append(Finding(
            Severity.REVIEW, UNBOUND_INDIRECT,
            "indirect call callee cannot be bound to a declared function",
            coord, self.current_function, target_var,
            expression=rendered, source=rendered))

    def _is_projection_call(self, node: c_ast.Node) -> bool:
        if not isinstance(node, c_ast.FuncCall):
            return False
        callee = self._callee_name(node)
        return callee in self.config.projection_functions

    def _note_projection_result(self, call: c_ast.FuncCall, coord: str,
                                variable: str = "") -> None:
        self.findings.append(Finding(
            Severity.SAFE, KNOWN_PROJECTION,
            "value produced by a configured safe projection function",
            coord, self.current_function, variable,
            expression=render(call), source=render(call)))

    def _target_argument(self, call: c_ast.FuncCall) -> str:
        if not call.args:
            return ""
        for argument in call.args.exprs:
            base = root_identifier(argument)
            if base and base.name in self.variables:
                info = self.variables[base.name]
                if info.is_target:
                    return base.name
        first = root_identifier(call.args.exprs[0])
        return first.name if first else ""

    @staticmethod
    def _callee_name(call: c_ast.FuncCall) -> str | None:
        name = call.name
        if isinstance(name, c_ast.ID):
            return name.name
        if isinstance(name, c_ast.UnaryOp) and name.op == "*":
            inner = name.expr
            if isinstance(inner, c_ast.ID):
                return inner.name
        return None

    @staticmethod
    def _named_initializer_field(node: c_ast.NamedInitializer) -> str:
        return ".".join(part.name for part in node.name)

    def _is_target_lvalue_name(self, name: str | None) -> bool:
        return bool(name and name in self.variables
                    and self.variables[name].is_target)

    def _apply_single_init(self, info: _VarInfo, category: str, source: str,
                           value: c_ast.Node, coord: str) -> None:
        if category == FIELD_INIT:
            info.whole = (FIELD_INIT, source)
            return
        self._record_whole(info, category, source, value, coord)
