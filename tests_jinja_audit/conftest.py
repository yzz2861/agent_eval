import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jinja_audit import (  # noqa: E402
    TemplateRepository,
    build_approval,
)


@pytest.fixture
def two_level_repository():
    """entry -> shell -> footer, plus a multi-value include and a macro lib."""
    return TemplateRepository({
        'entry.html': (
            '{% include "shell.html" %}'
            '{% include ["card_a.html", "card_b.html"] %}'
        ),
        'shell.html': '<div>{% include "footer.html" %}</div>',
        'footer.html': 'footer{% from "icons.html" import icon %}',
        'icons.html': '{% macro icon(name) %}[{{ name }}]{% endmacro %}',
        'card_a.html': 'card a',
        'card_b.html': 'card b',
    })


@pytest.fixture
def all_allowed():
    return {
        'entry.html', 'shell.html', 'footer.html',
        'icons.html', 'card_a.html', 'card_b.html',
    }


@pytest.fixture
def closure_names():
    return (
        'card_a.html', 'card_b.html', 'entry.html',
        'footer.html', 'icons.html', 'shell.html',
    )


@pytest.fixture
def valid_approval(two_level_repository, closure_names):
    return build_approval(
        'entry.html', two_level_repository, closure_names, note='offline review'
    )
