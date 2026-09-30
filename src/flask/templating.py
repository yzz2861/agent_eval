from __future__ import annotations

import posixpath
import typing as t

from jinja2 import BaseLoader
from jinja2 import Environment as BaseEnvironment
from jinja2 import Template
from jinja2 import TemplateNotFound

from .ctx import AppContext
from .globals import app_ctx
from .helpers import stream_with_context
from .signals import before_render_template
from .signals import template_rendered

if t.TYPE_CHECKING:  # pragma: no cover
    from .sansio.app import App
    from .sansio.blueprints import Blueprint
    from .sansio.scaffold import Scaffold


def _split_template_name(template: str) -> tuple[str | None, str]:
    """Split a template name into an optional blueprint name and the
    template path within that blueprint. A qualified template name has the
    form ``"blueprint_name:template_name"``. The application template folder
    does not participate in lookups using a qualified name.
    """
    blueprint_name, separator, template_path = template.partition(":")

    if separator:
        return blueprint_name, template_path

    return None, template


def _join_template_path(template: str, parent: str) -> str:
    """Join a relative reference with a parent template's directory.

    The reference begins with ``"./`` or ``"../"``. The loader rejects any
    result that still contains a ``".."`` segment.
    """
    parent_dir = posixpath.dirname(parent)
    return posixpath.normpath(posixpath.join(parent_dir, template))


def _default_template_ctx_processor() -> dict[str, t.Any]:
    """Default template context processor.  Replaces the ``request`` and ``g``
    proxies with their concrete objects for faster access.
    """
    ctx = app_ctx._get_current_object()
    rv: dict[str, t.Any] = {"g": ctx.g}

    if ctx.has_request:
        rv["request"] = ctx.request
        # The session proxy cannot be replaced, accessing it gets
        # RequestContext.session, which sets session.accessed.

    return rv


class Environment(BaseEnvironment):
    """Works like a regular Jinja environment but has some additional
    knowledge of how Flask's blueprint works so that it can prepend the
    name of the blueprint to referenced templates if necessary.
    """

    def __init__(self, app: App, **options: t.Any) -> None:
        if "loader" not in options:
            options["loader"] = app.create_global_jinja_loader()
        BaseEnvironment.__init__(self, **options)
        self.app = app

    def join_path(self, template: str, parent: str) -> str:
        """Join a template referenced by a qualified template.

        A relative reference (``"./foo.html"`` or ``"../bar.html"``) stays
        within the parent template's blueprint namespace. Any other
        reference is resolved as an unqualified template name, even when the
        parent is qualified, so existing templates keep using the normal
        application-wide lookup order.
        """
        blueprint_name, parent_path = _split_template_name(parent)

        if blueprint_name is not None and (
            template.startswith("./") or template.startswith("../")
        ):
            return f"{blueprint_name}:{_join_template_path(template, parent_path)}"

        return template


class DispatchingJinjaLoader(BaseLoader):
    """A loader that looks for templates in the application and all
    the blueprint folders.
    """

    def __init__(self, app: App) -> None:
        self.app = app

    def get_source(
        self, environment: BaseEnvironment, template: str
    ) -> tuple[str, str | None, t.Callable[[], bool] | None]:
        if self.app.config["EXPLAIN_TEMPLATE_LOADING"]:
            return self._get_source_explained(environment, template)
        return self._get_source_fast(environment, template)

    def _get_source_explained(
        self, environment: BaseEnvironment, template: str
    ) -> tuple[str, str | None, t.Callable[[], bool] | None]:
        attempts = []
        rv: tuple[str, str | None, t.Callable[[], bool] | None] | None
        trv: None | (tuple[str, str | None, t.Callable[[], bool] | None]) = None

        blueprint_name, template_path = _split_template_name(template)

        for srcobj, loader in self._iter_loaders(blueprint_name):
            try:
                rv = loader.get_source(environment, template_path)
                if trv is None:
                    trv = rv
            except TemplateNotFound:
                rv = None
            attempts.append((loader, srcobj, rv))

        from .debughelpers import explain_template_loading_attempts

        explain_template_loading_attempts(self.app, template, attempts)

        if trv is not None:
            return trv
        raise TemplateNotFound(template)

    def _get_source_fast(
        self, environment: BaseEnvironment, template: str
    ) -> tuple[str, str | None, t.Callable[[], bool] | None]:
        blueprint_name, template_path = _split_template_name(template)

        for _srcobj, loader in self._iter_loaders(blueprint_name):
            try:
                return loader.get_source(environment, template_path)
            except TemplateNotFound:
                continue
        raise TemplateNotFound(template)

    def _iter_loaders(
        self, blueprint_name: str | None
    ) -> t.Iterator[tuple[Scaffold, BaseLoader]]:
        blueprints: t.Iterable[Blueprint]

        if blueprint_name is None:
            loader = self.app.jinja_loader
            if loader is not None:
                yield self.app, loader

            blueprints = self.app.iter_blueprints()
        else:
            blueprint = self.app.blueprints.get(blueprint_name)

            if blueprint is None:
                return

            blueprints = (blueprint,)

        for blueprint in blueprints:
            loader = blueprint.jinja_loader
            if loader is not None:
                yield blueprint, loader

    def list_templates(self) -> list[str]:
        result = set()
        loader = self.app.jinja_loader
        if loader is not None:
            result.update(loader.list_templates())

        for blueprint_name, blueprint in self.app.blueprints.items():
            loader = blueprint.jinja_loader
            if loader is not None:
                for template in loader.list_templates():
                    result.add(f"{blueprint_name}:{template}")

        return list(result)


def _render(ctx: AppContext, template: Template, context: dict[str, t.Any]) -> str:
    app = ctx.app
    app.update_template_context(ctx, context)
    before_render_template.send(
        app, _async_wrapper=app.ensure_sync, template=template, context=context
    )
    rv = template.render(context)
    template_rendered.send(
        app, _async_wrapper=app.ensure_sync, template=template, context=context
    )
    return rv


def render_template(
    template_name_or_list: str | Template | list[str | Template],
    **context: t.Any,
) -> str:
    """Render a template by name with the given context.

    :param template_name_or_list: The name of the template to render. If
        a list is given, the first name to exist will be rendered.
    :param context: The variables to make available in the template.
    """
    ctx = app_ctx._get_current_object()
    template = ctx.app.jinja_env.get_or_select_template(template_name_or_list)
    return _render(ctx, template, context)


def render_template_string(source: str, **context: t.Any) -> str:
    """Render a template from the given source string with the given
    context.

    :param source: The source code of the template to render.
    :param context: The variables to make available in the template.
    """
    ctx = app_ctx._get_current_object()
    template = ctx.app.jinja_env.from_string(source)
    return _render(ctx, template, context)


def _stream(
    ctx: AppContext, template: Template, context: dict[str, t.Any]
) -> t.Iterator[str]:
    app = ctx.app
    app.update_template_context(ctx, context)
    before_render_template.send(
        app, _async_wrapper=app.ensure_sync, template=template, context=context
    )

    def generate() -> t.Iterator[str]:
        yield from template.generate(context)
        template_rendered.send(
            app, _async_wrapper=app.ensure_sync, template=template, context=context
        )

    return stream_with_context(generate())


def stream_template(
    template_name_or_list: str | Template | list[str | Template],
    **context: t.Any,
) -> t.Iterator[str]:
    """Render a template by name with the given context as a stream.
    This returns an iterator of strings, which can be used as a
    streaming response from a view.

    :param template_name_or_list: The name of the template to render. If
        a list is given, the first name to exist will be rendered.
    :param context: The variables to make available in the template.

    .. versionadded:: 2.2
    """
    ctx = app_ctx._get_current_object()
    template = ctx.app.jinja_env.get_or_select_template(template_name_or_list)
    return _stream(ctx, template, context)


def stream_template_string(source: str, **context: t.Any) -> t.Iterator[str]:
    """Render a template from the given source string with the given
    context as a stream. This returns an iterator of strings, which can
    be used as a streaming response from a view.

    :param source: The source code of the template to render.
    :param context: The variables to make available in the template.

    .. versionadded:: 2.2
    """
    ctx = app_ctx._get_current_object()
    template = ctx.app.jinja_env.from_string(source)
    return _stream(ctx, template, context)
