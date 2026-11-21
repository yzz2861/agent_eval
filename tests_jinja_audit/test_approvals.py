import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jinja_audit import (  # noqa: E402
    Decision,
    Severity,
    TemplateRepository,
    audit_entry,
    build_approval,
)


def test_missing_approval_blocks_release(two_level_repository, all_allowed):
    report = audit_entry("entry.html", two_level_repository, all_allowed)
    assert report.decision is Decision.REJECT
    assert any(f.code == "approval.missing" for f in report.findings)


def test_editing_a_transitive_template_invalidates_approval(
    two_level_repository, all_allowed, valid_approval
):
    edited = TemplateRepository({
        **two_level_repository.sources,
        'footer.html': 'changed footer content',
    })
    report = audit_entry(
        'entry.html', edited, all_allowed, approval=valid_approval
    )
    assert report.decision is Decision.REJECT
    stale = [f for f in report.findings if f.code == "approval.stale"]
    assert len(stale) == 1
    assert stale[0].template == 'footer.html'


def test_two_level_deep_edit_also_invalidates_approval(
    two_level_repository, all_allowed, valid_approval
):
    edited = TemplateRepository({
        **two_level_repository.sources,
        'icons.html': '{% macro icon(n) %}x{% endmacro %} ',
    })
    report = audit_entry(
        'entry.html', edited, all_allowed, approval=valid_approval
    )
    assert any(
        f.code == "approval.stale" and f.template == "icons.html"
        for f in report.findings
    )


def test_approval_for_other_entry_is_rejected(
    two_level_repository, all_allowed
):
    foreign = build_approval('shell.html', two_level_repository, ('shell.html',))
    report = audit_entry(
        'entry.html', two_level_repository, all_allowed, approval=foreign
    )
    assert report.decision is Decision.REJECT
    assert any(
        f.code == "approval.entry_mismatch" for f in report.findings
    )


def test_missing_target_is_error_unless_ignore_missing(
    two_level_repository, all_allowed, valid_approval
):
    repo = TemplateRepository({
        name: source
        for name, source in two_level_repository.sources.items()
        if name != 'card_b.html'
    })
    report = audit_entry(
        'entry.html', repo, all_allowed, approval=valid_approval
    )
    assert report.decision is Decision.REJECT
    assert any(
        f.code == "template.missing" and "card_b.html" in f.message
        for f in report.findings
    )


def test_ignore_missing_downgrades_to_warning(all_allowed):
    repo = TemplateRepository({
        'entry.html': '{% include "ghost.html" ignore missing %} ',
    })
    approval = build_approval('entry.html', repo, ('entry.html',))
    report = audit_entry(
        'entry.html', repo, all_allowed, approval=approval
    )
    assert report.decision is Decision.RELEASE
    finding = next(f for f in report.findings if f.code == "template.missing")
    assert finding.severity is Severity.WARNING


def test_unparseable_template_is_rejected(all_allowed):
    repo = TemplateRepository({'entry.html': '{% if %} '})
    report = audit_entry("entry.html", repo, all_allowed)
    assert report.decision is Decision.REJECT
    assert any(f.code == "template.parse_error" for f in report.findings)


def test_cycles_do_not_break_the_walk():
    repo = TemplateRepository({
        'a.html': '{% include "b.html" %} ',
        'b.html': '{% include "a.html" %} ',
    })
    approval = build_approval('a.html', repo, ('a.html', 'b.html'))
    report = audit_entry(
        "a.html", repo, {"a.html", "b.html"}, approval=approval
    )
    assert report.decision is Decision.RELEASE
    assert set(report.closure) == {'a.html', 'b.html'}
