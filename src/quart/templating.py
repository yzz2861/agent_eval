from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterable
from collections.abc import AsyncIterator
from contextvars import ContextVar
from io import StringIO
from typing import Any
from typing import TYPE_CHECKING

from flask.templating import (
    DispatchingJinjaLoader as DispatchingJinjaLoader,  # noqa: F401
)
from jinja2 import Environment as BaseEnvironment
from jinja2 import nodes
from jinja2 import pass_context
from jinja2 import Template
from jinja2 import TemplateNotFound
from jinja2 import TemplateRuntimeError
from jinja2.runtime import AsyncLoopContext
from jinja2.runtime import Context

from .ctx import has_app_context
from .ctx import has_request_context
from .globals import app_ctx
from .globals import current_app
from .helpers import stream_with_context
from .signals import before_render_template
from .signals import template_rendered

if TYPE_CHECKING:
    from .app import Quart  # noqa
    from .ctx import _AppCtxGlobals
    from .sessions import SessionMixin
    from .wrappers import Request


_SETUP_PARENT_NAME = "_quart_setup_template_parent"
_SETUP_INCLUDE_NAME = "_quart_setup_template_include"
_AUTO_ITER_NAME = "_quart_auto_aiter"
_active_async_iterators: ContextVar[list[Any] | None] = ContextVar(
    "quart-block-async-iterators",
    default=None,
)


class _SyncAsyncIterator:
    def __init__(self, iterator: Any) -> None:
        self._iterator = iterator

    def __aiter__(self) -> _SyncAsyncIterator:
        return self

    async def __anext__(self) -> Any:
        try:
            return next(self._iterator)
        except StopIteration as error:
            raise StopAsyncIteration(error.value) from error

    async def aclose(self) -> None:
        close = getattr(self._iterator, "close", None)
        if close is not None:
            close()


def _auto_aiter(iterable: AsyncIterable[Any] | Any) -> Any:
    registry = _active_async_iterators.get()
    if hasattr(iterable, "__aiter__"):
        iterator = iterable.__aiter__()
        if registry is not None:
            registry.append(iterator)
        return iterator

    iterator = _SyncAsyncIterator(iter(iterable))
    if registry is not None:
        registry.append(iterator)
    return iterator


class _BlockAsyncLoopContext(AsyncLoopContext):
    @staticmethod
    def _to_iterator(iterable: AsyncIterable[Any] | Any) -> Any:
        return _auto_aiter(iterable)


async def _close_block_async_iterators(iterators: list[Any]) -> None:
    closers = [getattr(iterator, "aclose", None) for iterator in reversed(iterators)]
    tasks = [close() for close in closers if close is not None]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result


def _generate_block_code(
    source: nodes.Template,
    environment: BaseEnvironment,
    name: str | None,
    filename: str | None,
) -> str:
    stream = StringIO()
    from jinja2.compiler import CodeGenerator

    generator = CodeGenerator(
        environment, name, filename, stream, optimized=environment.optimized
    )
    generator.visit(source)
    code = stream.getvalue()
    code = re.sub(r"\bauto_aiter\(", f"{_AUTO_ITER_NAME}(", code)
    code = re.sub(r"\bAsyncLoopContext\(", "_quart_async_loop_context(", code)
    return code.replace(
        "name = ",
        f"_quart_async_loop_context = environment.context_class."
        f"__quart_loop_context__\n{_AUTO_ITER_NAME} = environment.globals"
        f"[{_AUTO_ITER_NAME!r}]\nname = ",
        1,
    )


def _dead_if(statement: nodes.Stmt) -> nodes.If:
    return nodes.If(
        nodes.Const(False),
        [statement],
        [],
        [],
        lineno=statement.lineno,
    )


def _has_statements(statements: list[nodes.Node]) -> bool:
    return bool(statements)


def _has_if_statements(statement: nodes.If) -> bool:
    return (
        _has_statements(statement.body)
        or _has_statements(statement.else_)
        or any(_has_if_statements(branch) for branch in statement.elif_)
    )


_COLLECTABLE_WRAPPERS = (nodes.FilterBlock, nodes.CallBlock)
_EXECUTABLE_CONTAINERS = (nodes.For, nodes.If, nodes.With)


def _collect_blocks(statements: list[nodes.Node]) -> list[nodes.Block]:
    blocks: list[nodes.Block] = []
    for statement in statements:
        if isinstance(statement, nodes.Block):
            blocks.append(statement)
        elif isinstance(statement, _COLLECTABLE_WRAPPERS):
            blocks.extend(_collect_blocks(statement.body))
        elif isinstance(statement, (nodes.For, nodes.If)):
            blocks.extend(_collect_blocks(statement.body))
            blocks.extend(_collect_blocks(statement.else_))
            if isinstance(statement, nodes.If):
                blocks.extend(
                    block
                    for branch in statement.elif_
                    for block in _collect_blocks([branch])
                )
        elif isinstance(statement, nodes.With):
            blocks.extend(_collect_blocks(statement.body))
    return blocks


def _has_static_extends(statements: list[nodes.Node]) -> bool:
    for statement in statements:
        if isinstance(statement, nodes.Extends) and isinstance(
            statement.template, nodes.Const
        ):
            return True
        if isinstance(statement, nodes.For) and (
            _has_static_extends(statement.body) or _has_static_extends(statement.else_)
        ):
            return True
        if isinstance(statement, nodes.If) and (
            _has_static_extends(statement.body)
            or _has_static_extends(statement.else_)
            or any(_has_static_extends([branch]) for branch in statement.elif_)
        ):
            return True
        if isinstance(statement, nodes.With) and _has_static_extends(statement.body):
            return True
    return False


def _strip_setup_body(
    statements: list[nodes.Node],
    *,
    top_level: bool = False,
    inherited_extends: bool = False,
) -> list[nodes.Node]:
    result: list[nodes.Node] = []
    static_extends = inherited_extends or _has_static_extends(statements)
    for statement in statements:
        if top_level and isinstance(statement, (nodes.For, nodes.With)):
            continue
        if (
            top_level
            and isinstance(statement, nodes.If)
            and not _has_static_extends([statement])
        ):
            continue
        if isinstance(
            statement,
            (
                nodes.Output,
                nodes.Block,
                nodes.FilterBlock,
                nodes.CallBlock,
                nodes.AssignBlock,
            ),
        ):
            continue

        if (
            static_extends
            and top_level
            and not isinstance(
                statement,
                (
                    nodes.Extends,
                    nodes.If,
                ),
            )
        ):
            continue

        if isinstance(statement, nodes.Extends):
            statement = nodes.ExprStmt(
                nodes.Call(
                    nodes.Name(_SETUP_PARENT_NAME, "load"),
                    [statement.template],
                    [],
                    None,
                    None,
                    lineno=statement.lineno,
                ),
                lineno=statement.lineno,
            )
        elif isinstance(statement, nodes.Include):
            statement = nodes.ExprStmt(
                nodes.Call(
                    nodes.Name(_SETUP_INCLUDE_NAME, "load"),
                    [statement.template],
                    [],
                    None,
                    None,
                    lineno=statement.lineno,
                ),
                lineno=statement.lineno,
            )
        elif isinstance(statement, nodes.For):
            statement.body = _strip_setup_body(statement.body)
            statement.else_ = _strip_setup_body(statement.else_)
            if not statement.body and not statement.else_:
                continue
        elif isinstance(statement, nodes.If):
            statement.body = _strip_setup_body(
                statement.body, inherited_extends=static_extends
            )
            statement.elif_ = [
                _strip_setup_elif(branch, static_extends) for branch in statement.elif_
            ]
            statement.else_ = _strip_setup_body(
                statement.else_, inherited_extends=static_extends
            )
            if not _has_if_statements(statement):
                continue
        elif isinstance(statement, nodes.With):
            statement.body = _strip_setup_body(statement.body)
            if not statement.body:
                continue

        result.append(statement)
    return result


def _strip_setup_elif(statement: nodes.If, has_extends: bool = False) -> nodes.If:
    statement.body = _strip_setup_body(statement.body, inherited_extends=has_extends)
    statement.elif_ = [
        _strip_setup_elif(branch, has_extends) for branch in statement.elif_
    ]
    statement.else_ = _strip_setup_body(statement.else_, inherited_extends=has_extends)
    return statement


def _prepare_setup_template(
    environment: BaseEnvironment,
    template: Template,
) -> Template:
    if template.name is None or template.environment.loader is None:
        raise TemplateNotFound(str(template.name))
    source, filename, _ = environment.loader.get_source(environment, template.name)
    ast = environment.parse(source)
    blocks = _collect_blocks(ast.body)
    ast.body = _strip_setup_body(ast.body, top_level=True)
    ast.body.extend(_dead_if(block) for block in blocks)
    code = environment.compile(ast, template.name, filename)
    return Template.from_code(environment, code, environment.make_globals(None))


def _create_block_context(
    environment: BaseEnvironment,
    template: Template,
    context: dict[str, Any],
) -> tuple[Context, Any]:
    setup_environment = environment.overlay(
        loader=environment.loader,
        cache_size=0,
    )

    def generate_setup_code(
        source: nodes.Template,
        name: str | None,
        filename: str | None,
        defer_init: bool = False,
    ) -> str:
        return _generate_block_code(source, setup_environment, name, filename)

    setup_environment._generate = (  # type: ignore[attr-defined, method-assign]
        generate_setup_code
    )

    class BlockContext(setup_environment.context_class):
        __quart_loop_context__ = _BlockAsyncLoopContext

    setup_environment.context_class = BlockContext
    setup_environment.globals[_AUTO_ITER_NAME] = _auto_aiter

    @pass_context
    async def setup_parent(context: Context, parent: Any) -> None:
        parent_template = setup_environment.get_or_select_template(parent)
        parent_blocks = parent_template.blocks.items()
        for name, block in parent_blocks:
            context.blocks.setdefault(name, []).append(block)
        parent_setup = _prepare_setup_template(setup_environment, parent_template)
        async for _ in parent_setup.root_render_func(context):  # type: ignore
            pass

    @pass_context
    async def setup_include(context: Context, included: Any) -> None:
        included_template = setup_environment.get_or_select_template(included)
        included_setup = _prepare_setup_template(setup_environment, included_template)
        async for _ in included_setup.root_render_func(context):  # type: ignore
            pass

    setup_environment.globals[_SETUP_PARENT_NAME] = setup_parent
    setup_environment.globals[_SETUP_INCLUDE_NAME] = setup_include
    setup_template = _prepare_setup_template(setup_environment, template)
    block_context = setup_template.new_context(context)

    async def initialize() -> None:
        async for _ in setup_template.root_render_func(block_context):  # type: ignore
            pass

    return block_context, initialize


def _get_block(context: Context, template: Template, block_name: str) -> Any:
    try:
        return context.blocks[block_name][0]
    except LookupError:
        available = ", ".join(sorted(context.blocks))
        if available:
            message = (
                f"Block {block_name!r} not found in template "
                f"{template.name!r}. Available blocks: {available}."
            )
        else:
            message = f"Block {block_name!r} not found in template {template.name!r}."
        raise TemplateRuntimeError(message) from None


class Environment(BaseEnvironment):
    """Quart specific Jinja Environment.

    This changes the default Jinja loader to use the
    DispatchingJinjaLoader, and enables async Jinja by default.
    """

    def __init__(self, app: Quart, **options: Any) -> None:
        """Create a Quart specific Jinja Environment.

        Arguments:
            app: The Quart app to bind to.
            options: The standard Jinja Environment options.
        """
        if "loader" not in options:
            options["loader"] = app.create_global_jinja_loader()
        options["enable_async"] = True
        super().__init__(**options)


async def render_template(
    template_name_or_list: str | list[str], **context: Any
) -> str:
    """Render the template with the context given.

    Arguments:
        template_name_or_list: Template name to render of a list of
            possible template names.
        context: The variables to pass to the template.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.get_or_select_template(template_name_or_list)  # type: ignore
    return await _render(template, context, current_app._get_current_object())


async def render_template_string(source: str, **context: Any) -> str:
    """Render the template source with the context given.

    Arguments:
        source: The template source code.
        context: The variables to pass to the template.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.from_string(source)
    return await _render(template, context, current_app._get_current_object())


async def render_template_block(
    template_name_or_list: str | Template | list[str | Template],
    block_name: str,
    **context: Any,
) -> str:
    """Render one block from the selected template.

    Only statements required to establish template inheritance and the
    selected block are evaluated. Content outside the block is not
    rendered.

    Arguments:
        template_name_or_list: The name of the template containing the
            block. If a list is given, the first existing template is
            used.
        block_name: The name of the block to render.
        context: The variables to make available in the block.
    """
    app = current_app._get_current_object()
    ctx = app_ctx._get_current_object()
    await app.update_template_context(ctx, context)
    template = app.jinja_env.get_or_select_template(template_name_or_list)
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    block_context, initialize = _create_block_context(app.jinja_env, template, context)
    await initialize()
    block = _get_block(block_context, template, block_name)
    iterators: list[Any] = []
    token = _active_async_iterators.set(iterators)
    generator = block(block_context)
    try:
        rendered = "".join([chunk async for chunk in generator])
    finally:
        await generator.aclose()
        await _close_block_async_iterators(iterators)
        try:
            await template_rendered.send_async(
                app,
                _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
                template=template,
                context=context,
            )
        finally:
            _active_async_iterators.reset(token)
    return rendered


async def stream_template_block(
    template_name_or_list: str | Template | list[str | Template],
    block_name: str,
    **context: Any,
) -> AsyncIterator[str]:
    """Render one block from a template as an async stream.

    Arguments:
        template_name_or_list: The name of the template containing the
            block. If a list is given, the first existing template is
            used.
        block_name: The name of the block to render.
        context: The variables to make available in the block.
    """
    app = current_app._get_current_object()
    ctx = app_ctx._get_current_object()
    await app.update_template_context(ctx, context)
    template = app.jinja_env.get_or_select_template(template_name_or_list)
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    block_context, initialize = _create_block_context(app.jinja_env, template, context)
    await initialize()
    _get_block(block_context, template, block_name)
    return await _stream_block(app, template, block_name, context, block_context)


async def _render(template: Template, context: dict, app: Quart) -> str:
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    rendered_template = await template.render_async(context)
    await template_rendered.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    return rendered_template


async def _default_template_ctx_processor() -> dict[str, Any]:
    context: dict[str, _AppCtxGlobals | Request | SessionMixin] = {}
    ctx = app_ctx._get_current_object()
    if has_app_context():
        context["g"] = ctx.g
    if has_request_context():
        context["request"] = ctx.request
        context["session"] = ctx.session
    return context


async def stream_template(
    template_name_or_list: str | Template | list[str | Template], **context: Any
) -> AsyncIterator[str]:
    """Render a template by name with the given context as a stream.

    This returns an iterator of strings, which can be used as a
    streaming response from a view.

    Arguments:
        template_name_or_list: The name of the template to render. If a
            list is given, the first name to exist will be rendered.
        context: The variables to make available in the template.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.get_or_select_template(template_name_or_list)
    return await _stream(current_app._get_current_object(), template, context)


async def stream_template_string(source: str, **context: Any) -> AsyncIterator[str]:
    """Render a template from the given source with the *context* as a stream.

    This returns an iterator of strings, which can
    be used as a streaming response from a view.

    Arguments:
        source: The source code of the template to render.
        context: The variables to make available in the template.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.from_string(source)
    return await _stream(current_app._get_current_object(), template, context)


async def _stream(
    app: Quart, template: Template, context: dict[str, Any]
) -> AsyncIterator[str]:
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )

    async def generate() -> AsyncIterator[str]:
        async for chunk in template.generate_async(context):
            yield chunk
        await template_rendered.send_async(
            app,
            _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
            template=template,
            context=context,
        )

    # If a request context is active, keep it while generating.
    if has_request_context():
        return stream_with_context(generate)()
    else:
        return generate()


async def _stream_block(
    app: Quart,
    template: Template,
    block_name: str,
    context: dict[str, Any],
    block_context: Context,
) -> AsyncIterator[str]:
    block = _get_block(block_context, template, block_name)
    iterators: list[Any] = []
    token = _active_async_iterators.set(iterators)

    async def generate() -> AsyncIterator[str]:
        generator = block(block_context)
        try:
            async for chunk in generator:
                yield chunk
        finally:
            await generator.aclose()
            await _close_block_async_iterators(iterators)
            try:
                await template_rendered.send_async(
                    app,
                    _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
                    template=template,
                    context=context,
                )
            finally:
                _active_async_iterators.reset(token)

    if has_request_context():
        return stream_with_context(generate)()
    return generate()
