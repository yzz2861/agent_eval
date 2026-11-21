import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jinja_audit import (  # noqa: E402
    Decision,
    audit_entry,
    build_approval,
)


def test_two_level_include_closure_is_walked(
    two_level_repository, all_allowed, closure_names, valid_approval
):
    report = audit_entry(
        'entry.html', two_level_repository, all_allowed,
        approval=valid_approval,
    )
    assert report.decision is Decision.RELEASE
    assert report.closure == closure_names
    assert {'entry.html', 'shell.html', 'footer.html'}.issubset(
        report.versions
    )
    kinds = {(ref.source, ref.kind.value) for ref in report.references}
    assert ('shell.html', 'include') in kinds
    assert ('footer.html', 'from_import') in kinds


def test_multi_value_template_name_checks_every_candidate(
    two_level_repository, all_allowed, valid_approval
):
    report = audit_entry(
        'entry.html', two_level_repository, all_allowed,
        approval=valid_approval,
    )
    include = next(
        ref
        for ref in report.references
        if ref.source == "entry.html" and len(ref.targets) == 2
    )
    assert include.targets == ('card_a.html', 'card_b.html')
    assert set(include.targets).issubset(report.closure)


def test_one_disallowed_candidate_rejects_even_if_entry_is_allowed(
    two_level_repository, all_allowed, valid_approval
):
    allowed = all_allowed - {'card_b.html'}
    report = audit_entry(
        'entry.html', two_level_repository, allowed,
        approval=valid_approval,
    )
    assert report.decision is Decision.REJECT
    assert any(
        f.code == "target.not_allowed" and "card_b.html" in f.message
        for f in report.findings
    )


def test_unbounded_name_suspends_publication(
    two_level_repository, all_allowed
):
    sources = dict(two_level_repository.sources)
    sources['entry.html'] = '{% include picker %} '
    repo = type(two_level_repository)(sources)
    approval = build_approval('entry.html', repo, ('entry.html',))
    report = audit_entry(
        'entry.html', repo, all_allowed, approval=approval
    )
    assert report.decision is Decision.HOLD
    hold = report.holds[0]
    assert hold.code == "reference.unbounded"
    assert hold.template == 'entry.html'
    assert 'picker' in hold.message


def test_declared_domain_clears_the_hold(
    two_level_repository, all_allowed
):
    sources = dict(two_level_repository.sources)
    sources['entry.html'] = '{% include picker %} '
    repo = type(two_level_repository)(sources)
    closure = (
        'card_a.html', 'card_b.html', 'entry.html',
        'footer.html', 'icons.html', 'shell.html',
    )
    report = audit_entry(
        'entry.html', repo, all_allowed,
        candidates={'entry.html': {'picker': ['card_a.html', 'card_b.html']}},
        approval=build_approval('entry.html', repo, closure),
    )
    assert report.decision is Decision.RELEASE
    assert report.holds == []
