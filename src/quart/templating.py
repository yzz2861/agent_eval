from __future__ import annotations

from collections.abc import AsyncIterator
from collections.abc import Callable
from contextlib import aclosing
from typing import Any
from typing import TYPE_CHECKING

from flask.templating import (
    DispatchingJinjaLoader as DispatchingJinjaLoader,  # noqa: F401
)
from jinja2 import Environment as BaseEnvironment
from jinja2 import nodes
from jinja2 import Template
from jinja2 import TemplateNotFound
from jinja2.compiler import generate as jinja_generate
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


class TemplateBlockNotFoundError(Exception):
    """Raised when a template does not define the requested block."""

    def __init__(self, block_name: str, template_name: str | None) -> None:
        super().__init__(
            f"Block {block_name!r} not found in template {template_name!r}."
        )
        self.block_name = block_name
        self.template_name = template_name


async def render_template_block(
    template_name_or_list: str | list[str], block_name: str, **context: Any
) -> str:
    """Render a single block of a template with the context given.

    Only the named block is rendered, the rest of the template (and of
    any templates it extends) is not executed. This means output
    expressions outside the block, for example ``{{ counter() }}`` in
    the page body, have no effect. Template inheritance, ``super()``,
    nested blocks and async filters all work as they do in a full
    render.

    Note that ``{% set %}`` assignments outside the block are not
    executed either, pass any required values via the context instead.

    Arguments:
        template_name_or_list: Template name to render of a list of
            possible template names.
        block_name: The name of the block to render.
        context: The variables to pass to the template.

    Raises:
        TemplateBlockNotFoundError: If the template (including the
            templates it extends) does not define the block.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.get_or_select_template(template_name_or_list)  # type: ignore
    return await _render_block(
        template, block_name, context, current_app._get_current_object()
    )


async def stream_template_block(
    template_name_or_list: str | list[str], block_name: str, **context: Any
) -> AsyncIterator[str]:
    """Render a single block of a template with the context as a stream.

    This returns an iterator of strings, which can be used as a
    streaming response from a view. Only the named block is rendered,
    see :func:`render_template_block` for the semantics.

    The request and application contexts are kept active whilst the
    iterator is consumed, and are cleaned up if the iterator is closed
    before it is exhausted.

    Arguments:
        template_name_or_list: Template name to render of a list of
            possible template names.
        block_name: The name of the block to render.
        context: The variables to pass to the template.

    Raises:
        TemplateBlockNotFoundError: If the template (including the
            templates it extends) does not define the block.
    """
    ctx = app_ctx._get_current_object()
    await current_app.update_template_context(ctx, context)
    template = current_app.jinja_env.get_or_select_template(template_name_or_list)  # type: ignore
    return await _stream_block(
        current_app._get_current_object(), template, block_name, context
    )


async def _render_block(
    template: Template, block_name: str, context: dict[str, Any], app: Quart
) -> str:
    jinja_context, block = await _find_block(template, block_name, context)
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    environment = template.environment
    try:
        rendered = environment.concat([chunk async for chunk in block(jinja_context)])
    except Exception:
        return environment.handle_exception()
    await template_rendered.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    return rendered


async def _stream_block(
    app: Quart, template: Template, block_name: str, context: dict[str, Any]
) -> AsyncIterator[str]:
    jinja_context, block = await _find_block(template, block_name, context)
    await before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )

    async def generate() -> AsyncIterator[str]:
        async with aclosing(block(jinja_context)) as generator:
            try:
                async for chunk in generator:
                    yield chunk
            except Exception:
                template.environment.handle_exception()
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


async def _find_block(
    template: Template, block_name: str, context: dict[str, Any]
) -> tuple[Context, Callable[[Context], AsyncIterator[str]]]:
    jinja_context = template.new_context(context)
    await _register_inherited_blocks(template, jinja_context)
    try:
        block_stack = jinja_context.blocks[block_name]
    except KeyError:
        raise TemplateBlockNotFoundError(block_name, template.name) from None
    return jinja_context, block_stack[0]


async def _register_inherited_blocks(template: Template, context: Context) -> None:
    """Register the blocks of every ancestor template on the context.

    Jinja only builds up ``context.blocks`` whilst rendering the root
    of a template that extends another. As the root is not rendered
    here the inheritance chain is walked explicitly so that
    ``super()`` and inherited blocks resolve as they do in a full
    render.
    """
    environment = template.environment
    seen = {id(template)}
    current = template
    while (parent := await _parent_template(environment, current, context)) is not None:
        if id(parent) in seen:
            break
        seen.add(id(parent))
        for name, block in parent.blocks.items():
            context.blocks.setdefault(name, []).append(block)
        current = parent


async def _parent_template(
    environment: BaseEnvironment, template: Template, context: Context
) -> Template | None:
    """Return the template the *template* directly extends, if any.

    The extends clause is resolved from the template source rather
    than by rendering, so that nothing outside the target block is
    executed. Only top-level extends clauses are considered.
    """
    if environment.loader is None or template.name is None:
        return None
    try:
        source = environment.loader.get_source(environment, template.name)[0]
    except TemplateNotFound:
        return None
    extends_node = next(
        (
            node
            for node in environment.parse(source).body
            if isinstance(node, nodes.Extends)
        ),
        None,
    )
    if extends_node is None:
        return None
    expression = extends_node.template
    if isinstance(expression, nodes.Const):
        parent_name = expression.value
    else:
        parent_name = await _evaluate_expression(
            environment, expression, template, context
        )
    if isinstance(parent_name, (list, tuple)):
        return environment.select_template(parent_name, template.name)
    return environment.get_template(parent_name, template.name)


async def _evaluate_expression(
    environment: BaseEnvironment,
    expression: nodes.Expr,
    template: Template,
    context: Context,
) -> Any:
    """Evaluate a single template expression, e.g. a dynamic extends."""
    mini_template = nodes.Template([nodes.Output([expression])])
    source = jinja_generate(
        mini_template, environment, template.name, template.filename
    )
    code = compile(source, template.filename or "<template>", "exec")
    namespace: dict[str, Any] = {"environment": environment}
    exec(code, namespace)
    value = None
    async for chunk in namespace["root"](context):
        value = chunk
    return value
