"""Acceptance tests for the optional sandbox egress protection mode."""

import pytest
from jinja2 import Environment
from jinja2 import nodes
from jinja2.egress import DisclosureLevel
from jinja2.egress import EgressError
from jinja2.egress import EgressSandboxedEnvironment
from jinja2.egress import level_of
from jinja2.egress import wrap

PUBLIC = DisclosureLevel.PUBLIC
INTERNAL = DisclosureLevel.INTERNAL
RESTRICTED = DisclosureLevel.RESTRICTED

REPORT_TEMPLATE = """{% macro ticket(t) %}[{{ t.id }}|{{ t.owner }}]{% endmacro %}
agent={{ agent.name }}
note={{ agent.name ~ " / " ~ ticket_id }}
{% if ticket_id %}has-ticket{% else %}no-ticket{% endif %}
{% for item in items %}{{ item }};{% endfor %}
rendered={{ ticket(agent) }}
upper={{ agent.name|upper }}"""


def make_data():
    return {
        "agent": {"name": "Ada"},
        "ticket_id": wrap("T-1024", INTERNAL),
        "items": ["one", wrap("two", INTERNAL)],
    }


@pytest.fixture
def internal_env():
    return EgressSandboxedEnvironment(egress_license=INTERNAL)


@pytest.fixture
def public_env():
    return EgressSandboxedEnvironment(egress_license=PUBLIC)


class TestAcceptance:
    def test_internal_export_shows_everything(self, internal_env):
        rendered = internal_env.from_string(REPORT_TEMPLATE).render(make_data())
        assert "T-1024" in rendered
        assert "two" in rendered
        assert "Ada" in rendered

    def test_public_export_rejects(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string(REPORT_TEMPLATE).render(make_data())

    def test_public_export_without_levels_matches_plain_environment(self):
        plain = Environment()
        guarded = EgressSandboxedEnvironment(egress_license=PUBLIC)
        clean = {
            "agent": {"name": "Ada"},
            "ticket_id": "T-1024",
            "items": ["one", "two"],
        }
        expected = plain.from_string(REPORT_TEMPLATE).render(clean)
        actual = guarded.from_string(REPORT_TEMPLATE).render(clean)
        assert actual == expected
        assert type(actual) is str


class TestLeakVectors:
    def test_plain_field_read(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string("{{ secret }}").render(
                {"secret": wrap("x", INTERNAL)}
            )

    def test_concat_labels_whole_string(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string("{{ a ~ b }}").render(
                {"a": "public-", "b": wrap("secret", INTERNAL)}
            )

    def test_conditional_branch_is_tainted(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string(
                "{% if secret %}ANNOUNCE{% else %}fine{% endif %}"
            ).render({"secret": wrap(True, INTERNAL)})

    def test_macro_output_is_tainted(self, public_env):
        tmpl = "{% macro m(x) %}[{{ x }}]{% endmacro %}{{ m(secret) }}"
        with pytest.raises(EgressError):
            public_env.from_string(tmpl).render({"secret": wrap("x", INTERNAL)})

    def test_filter_propagates_taint(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string("{{ secret|upper }}").render(
                {"secret": wrap("x", INTERNAL)}
            )


class TestStreaming:
    def test_stream_withholds_prefix_on_violation(self, public_env):
        tmpl = public_env.from_string("PREFIX-{{ secret }}-TAIL")
        chunks = []
        with pytest.raises(EgressError):
            for chunk in tmpl.stream({"secret": wrap("x", INTERNAL)}):
                chunks.append(chunk)
        assert chunks == []

    def test_stream_and_render_raise_same_error(self, public_env):
        tmpl = public_env.from_string("{{ secret }}")
        data = {"secret": wrap("x", INTERNAL)}
        with pytest.raises(EgressError):
            tmpl.render(data)
        with pytest.raises(EgressError):
            list(tmpl.stream(data))

    def test_allowed_stream_equals_full_render(self, internal_env):
        tmpl = internal_env.from_string("a={{ a }}|b={{ b }}")
        data = {"a": wrap("x", INTERNAL), "b": "y"}
        assert "".join(tmpl.stream(data)) == tmpl.render(data)


class TestUnsupportedConstructs:
    def test_declared_construct_fails_safely(self):
        env = EgressSandboxedEnvironment(
            egress_license=PUBLIC, unsupported_constructs=(nodes.Include,)
        )
        with pytest.raises(EgressError):
            env.from_string('{% include "other.html" %}')

    def test_unsupported_expression_node(self):
        env = EgressSandboxedEnvironment(
            egress_license=PUBLIC, unsupported_constructs=(nodes.Filter,)
        )
        with pytest.raises(EgressError):
            env.from_string("{{ name|upper }}")

    def test_other_constructs_still_work(self):
        env = EgressSandboxedEnvironment(
            egress_license=PUBLIC, unsupported_constructs=(nodes.Include,)
        )
        assert env.from_string("{{ name }}").render(name="x") == "x"


class TestLabels:
    def test_label_lattice_join(self):
        assert level_of(wrap("x", INTERNAL)) == INTERNAL
        assert level_of("plain") == -1

    def test_restricted_above_internal_license_rejected(self, internal_env):
        with pytest.raises(EgressError):
            internal_env.from_string("{{ secret }}").render(
                {"secret": wrap("x", RESTRICTED)}
            )

    def test_arithmetic_keeps_label(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string("{{ n + 1 }}").render({"n": wrap(2, INTERNAL)})
        assert public_env.from_string("{{ n + 1 }}").render(n=2) == "3"


class TestPropagation:
    def test_attribute_access_tainted(self, public_env):
        class Record:
            def __init__(self, name):
                self.name = name

        with pytest.raises(EgressError):
            public_env.from_string("{{ r.name }}").render(
                {"r": wrap(Record("ghost"), INTERNAL)}
            )

    def test_item_access_tainted(self, public_env):
        with pytest.raises(EgressError):
            public_env.from_string("{{ d.k }}").render(
                {"d": wrap({"k": "v"}, INTERNAL)}
            )

    def test_protect_fields_helper(self, internal_env, public_env):
        raw = {"name": "Ada", "ticket": "T-1"}
        protected = internal_env.protect_fields(raw, {"ticket": INTERNAL})
        assert internal_env.from_string("{{ ticket }}").render(protected) == "T-1"
        with pytest.raises(EgressError):
            public_env.from_string("{{ ticket }}").render(protected)
        assert public_env.from_string("{{ name }}").render(protected) == "Ada"
