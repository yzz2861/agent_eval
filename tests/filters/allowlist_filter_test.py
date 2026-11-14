import pytest

from detect_secrets.filters.allowlist import is_line_allowlisted
from detect_secrets.settings import get_settings
from detect_secrets.util.code_snippet import CodeSnippet


EXAMPLE_COMMENT_PARTS = (
    ('#', ''),
    ('# ', ' more text'),

    ('//', ''),
    ('// ', ' more text'),

    ('/*', '*/'),
    ('/* ', ' */'),

    ('--', ''),
    ('-- ', ' more text'),

    ('<!--', '-->'),
)


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_basic(prefix, suffix):
    line = f'AKIAEXAMPLE  {prefix}pragma: allowlist secret{suffix}'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_nextline(prefix, suffix):
    comment = f'{prefix}pragma: allowlist nextline secret{suffix}'
    line = 'AKIAEXAMPLE'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([comment, line], 0, 1),
    )


def test_nextline_exclusivity():
    line = 'AKIAEXAMPLE  # pragma: allowlist nextline secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    ) is False


def test_backwards_compatibility():
    line = 'AKIAEXAMPLE  # pragma: whitelist secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'line, expected_result',
    (
        ('key: value # pragma: allowlist secret', True),
        ('key: value // pragma: allowlist secret', False),
    ),
)
def test_file_based_regexes(line, expected_result):
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([line], 0, 0),
    ) is expected_result


@pytest.mark.parametrize(
    'comment, expected_result',
    (
        ('# pragma: allowlist nextline secret', True),
        ('// pragma: allowlist nextline secret', False),
    ),
)
def test_file_based_nextline_regexes(comment, expected_result):
    line = 'key: value'
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([comment, line], 0, 1),
    ) is expected_result


class TestCandidateScoping:
    @staticmethod
    @pytest.fixture(autouse=True)
    def configure_plugins():
        get_settings().configure_plugins([
            {
                'name': 'Base64HighEntropyString',
                'limit': 4.5,
            },
            {
                'name': 'HexHighEntropyString',
                'limit': 3,
            },
        ])

    FIRST_SECRET = '60b725f10c9c85c70d97880dfe8191b3'
    SECOND_SECRET = '3b5d5c3712955042212316173ccf37be'

    def test_single_candidate_is_allowlisted(self):
        line = f"token = '{self.FIRST_SECRET}'  # pragma: allowlist secret"
        assert is_line_allowlisted(
            'filename',
            line,
            CodeSnippet([line], 0, 0),
        ) is True

    def test_single_candidate_is_allowlisted_with_secret(self):
        line = f"token = '{self.FIRST_SECRET}'  # pragma: allowlist secret"
        assert is_line_allowlisted(
            'filename',
            line,
            CodeSnippet([line], 0, 0),
            secret=self.FIRST_SECRET,
        ) is True

    def test_multiple_candidates_on_same_line_are_not_allowlisted(self):
        line = (
            f"first = '{self.FIRST_SECRET}'; second = '{self.SECOND_SECRET}'"
            '  # pragma: allowlist secret'
        )
        context = CodeSnippet([line], 0, 0)

        # The pragma cannot be attributed to a single candidate, so the
        # strictest outcome applies: nothing on the line is allowlisted.
        assert is_line_allowlisted('filename', line, context) is False
        assert is_line_allowlisted(
            'filename',
            line,
            context,
            secret=self.FIRST_SECRET,
        ) is False
        assert is_line_allowlisted(
            'filename',
            line,
            context,
            secret=self.SECOND_SECRET,
        ) is False

    def test_multiple_candidates_with_nextline_pragma_are_not_allowlisted(self):
        comment = '# pragma: allowlist nextline secret'
        line = f"first = '{self.FIRST_SECRET}'; second = '{self.SECOND_SECRET}'"
        assert is_line_allowlisted(
            'filename',
            line,
            CodeSnippet([comment, line], 0, 1),
        ) is False

    def test_pragma_does_not_cover_other_candidate(self):
        line = f"token = '{self.FIRST_SECRET}'  # pragma: allowlist secret"
        assert is_line_allowlisted(
            'filename',
            line,
            CodeSnippet([line], 0, 0),
            secret=self.SECOND_SECRET,
        ) is False

    def test_scan_line_reports_all_candidates_on_pragma_line(self):
        from detect_secrets.core.scan import scan_line

        line = (
            f"first = '{self.FIRST_SECRET}'; second = '{self.SECOND_SECRET}'"
            '  # pragma: allowlist secret'
        )
        assert len(list(scan_line(line))) == 2

    def test_scan_line_still_respects_single_candidate_pragma(self):
        from detect_secrets.core.scan import scan_line

        line = f"token = '{self.FIRST_SECRET}'  # pragma: allowlist secret"
        assert not list(scan_line(line))
