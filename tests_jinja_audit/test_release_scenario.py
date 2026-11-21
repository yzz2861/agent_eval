import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jinja_audit import (  # noqa: E402
    Decision,
    TemplateRepository,
    audit_entry,
    build_approval,
)


def test_approved_entry_still_cannot_be_published_when_a_candidate_is_unbounded():
    """Entry is allow-listed and approved, but release is impossible."""
    repository = TemplateRepository({
        'entry.html': '{% include "shell.html" %} {% include theme ~ ".html" %} ',
        'shell.html': '{% include "footer.html" %} ',
        'footer.html': 'footer',
        'dark.html': 'dark',
        'light.html': 'light',
    })
    allowed = {
        'entry.html', 'shell.html', 'footer.html', 'dark.html', 'light.html',
    }
    approval = build_approval(
        'entry.html', repository, ('entry.html', 'shell.html', 'footer.html')
    )

    report = audit_entry(
        "entry.html", repository, allowed, approval=approval
    )

    assert report.decision is Decision.HOLD
    held = report.holds[0].reference
    assert held.expression.startswith('theme') and '~' in held.expression
    assert 'shell.html' in report.closure
    assert 'footer.html' in report.closure


def test_host_declaring_the_finite_domain_allows_release_after_re_approval():
    repository = TemplateRepository({
        'entry.html': '{% include "shell.html" %} {% include theme %} ',
        'shell.html': '{% include "footer.html" %} ',
        'footer.html': 'footer',
        'dark.html': 'dark',
        'light.html': 'light',
    })
    allowed = {
        'entry.html', 'shell.html', 'footer.html', 'dark.html', 'light.html',
    }
    candidates = {'entry.html': {'theme': ['dark.html', 'light.html']}}
    closure = (
        'dark.html', 'entry.html', 'footer.html', 'light.html', 'shell.html',
    )
    approval = build_approval("entry.html", repository, closure)

    bounded = audit_entry(
        "entry.html", repository, allowed,
        candidates=candidates, approval=approval,
    )
    assert bounded.decision is Decision.RELEASE
    themed = next(
        ref for ref in bounded.references if ref.expression == 'theme'
    )
    assert themed.targets == ('dark.html', 'light.html')


def test_version_bump_on_deep_include_voids_the_original_approval():
    repository = TemplateRepository({
        'entry.html': '{% include "shell.html" %} ',
        'shell.html': '{% include "footer.html" %} ',
        'footer.html': 'footer',
    })
    approval = build_approval(
        'entry.html', repository, ('entry.html', 'shell.html', 'footer.html')
    )
    edited = TemplateRepository({**repository.sources, 'footer.html': 'new footer'})

    report = audit_entry(
        "entry.html", edited, {"entry.html", "shell.html", "footer.html"},
        approval=approval,
    )
    assert report.decision is Decision.REJECT
    assert [
        f.template for f in report.findings if f.code == "approval.stale"
    ] == ["footer.html"]
