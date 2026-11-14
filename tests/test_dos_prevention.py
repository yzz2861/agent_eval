"""Tests for DoS prevention mechanisms in sqlparse."""

import time

import pytest

import sqlparse
from sqlparse.engine.filter_stack import FilterStack
from sqlparse.exceptions import SQLParseError, SQLParseLimitError
from sqlparse.limits import (
    GROUPING_CALLS,
    GROUPING_DEPTH,
    NESTING_DEPTH,
    TIMEOUT,
    TOKEN_LENGTH,
    TOKENS,
    ParseLimits,
    build_budget,
    use_budget,
)


class TestDoSPrevention:
    """Test cases to ensure sqlparse is protected against DoS attacks."""

    def test_large_tuple_list_performance(self):
        """Test that parsing a large list of tuples raises SQLParseError."""
        # Generate SQL with many tuples (like Django composite primary key queries)
        sql = '''
        SELECT "composite_pk_comment"."tenant_id", "composite_pk_comment"."comment_id"
        FROM "composite_pk_comment"
        WHERE ("composite_pk_comment"."tenant_id", "composite_pk_comment"."comment_id") IN ('''

        # Generate 5000 tuples - this should trigger MAX_GROUPING_TOKENS
        tuples = []
        for i in range(1, 5001):
            tuples.append(f"(1, {i})")

        sql += ", ".join(tuples) + ")"

        # Should raise SQLParseError due to token limit
        with pytest.raises(SQLParseError, match="Maximum number of tokens exceeded"):
            sqlparse.format(sql, reindent=True, keyword_case="upper")

    def test_deeply_nested_groups_limited(self):
        """Test that deeply nested groups raise SQLParseError."""
        # Create deeply nested parentheses
        sql = "SELECT " + "(" * 200 + "1" + ")" * 200

        # Should raise SQLParseError due to depth limit
        with pytest.raises(SQLParseError, match="Maximum grouping depth exceeded"):
            sqlparse.format(sql, reindent=True)

    def test_very_large_token_list_limited(self):
        """Test that very large token lists raise SQLParseError."""
        # Create a SQL with many identifiers
        identifiers = []
        for i in range(15000):  # More than MAX_GROUPING_TOKENS
            identifiers.append(f"col{i}")

        sql = f"SELECT {', '.join(identifiers)} FROM table1"

        # Should raise SQLParseError due to token limit
        with pytest.raises(SQLParseError, match="Maximum number of tokens exceeded"):
            sqlparse.format(sql, reindent=True)

    def test_nested_paren_within_cap_under_1s(self):
        """Reaching MAX_GROUPING_DEPTH must not require multi-second CPU.

        Before the TokenList.__init__ fix, a 1 KB payload of 500 nested
        parens took ~1.3 s and a 2 KB payload of 1000 nested parens took
        ~11 s before the depth cap raised SQLParseError, because each
        TokenList materialised its ``value`` via ``str(self)`` which
        recursed over the full subtree (O(n * depth)).
        """
        sql = 'SELECT ' + '(' * 1000 + '1' + ')' * 1000
        t0 = time.perf_counter()
        with pytest.raises(SQLParseError, match='Maximum grouping depth'):
            sqlparse.parse(sql)
        dt = time.perf_counter() - t0
        assert dt < 1.0, f'parse took {dt:.2f}s, expected sub-second'

    def test_nested_case_within_cap_under_1s(self):
        """Same invariant as nested parentheses, exercised via CASE WHEN."""
        case = '1'
        for i in range(400):
            case = f'CASE WHEN x={i} THEN {case} ELSE NULL END'
        sql = f'SELECT {case} FROM t'
        t0 = time.perf_counter()
        with pytest.raises(SQLParseError, match='Maximum grouping depth'):
            sqlparse.parse(sql)
        dt = time.perf_counter() - t0
        assert dt < 1.0, f'parse took {dt:.2f}s, expected sub-second'

    def test_normal_sql_still_works(self):
        """Test that normal SQL still works correctly after DoS protections."""
        sql = """
        SELECT u.id, u.name, p.title
        FROM users u
        JOIN posts p ON u.id = p.user_id
        WHERE u.active = 1
        AND p.published_at > '2023-01-01'
        ORDER BY p.published_at DESC
        """

        result = sqlparse.format(sql, reindent=True, keyword_case="upper")

        assert "SELECT" in result
        assert "FROM" in result
        assert "JOIN" in result
        assert "WHERE" in result
        assert "ORDER BY" in result

    def test_reasonable_tuple_list_works(self):
        """Test that reasonable-sized tuple lists still work correctly."""
        sql = '''
        SELECT id FROM table1
        WHERE (col1, col2) IN ('''

        # 100 tuples should work fine
        tuples = []
        for i in range(1, 101):
            tuples.append(f"({i}, {i * 2})")

        sql += ", ".join(tuples) + ")"

        result = sqlparse.format(sql, reindent=True, keyword_case="upper")

        assert "SELECT" in result
        assert "WHERE" in result
        assert "IN" in result
        assert "1," in result  # First tuple should be there
        assert "200" in result  # Last tuple should be there


def test_unterminated_quotes_format_under_1s():
    """format() must not be quadratic on many unterminated quotes.

    split_unquoted_newlines() used a regex that scanned to the end of the
    text for every unterminated quote, so this 40 KB payload took several
    seconds (GHSA-3r5h-5jcg-gmgg).
    """
    for sql in ('"\\' * 20000, "'\\" * 20000):
        t0 = time.perf_counter()
        sqlparse.format(sql)
        dt = time.perf_counter() - t0
        assert dt < 1.0, f'format took {dt:.2f}s, expected sub-second'


class TestResourceLimits:
    """Per-invocation resource budgets for parse()/format()/split()."""

    def test_token_budget_reports_consumed_position(self):
        sql = 'select ' + ', '.join(f'col{i}' for i in range(40))
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(sql, max_tokens=10)
        err = exc_info.value
        assert err.limit == TOKENS
        assert 0 < err.consumed <= len(sql)
        assert sql[err.consumed:err.consumed + 1] in (',', 'c', ' ')

    def test_token_budget_works_in_format_and_split(self):
        sql = 'select ' + ', '.join(f'col{i}' for i in range(40))
        with pytest.raises(SQLParseLimitError, match='Maximum number of tokens'):
            sqlparse.format(sql, reindent=True, max_tokens=10)
        with pytest.raises(SQLParseLimitError):
            sqlparse.split(sql, max_tokens=10)

    def test_nesting_limit_catches_unclosed_parenthesis(self):
        # Unbalanced input never reaches grouping; the splitter must reject
        # it while the offending opening parenthesis is being consumed.
        sql = 'select ' + '(' * 30
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(sql, limits=ParseLimits(max_nesting_depth=10))
        err = exc_info.value
        assert err.limit == NESTING_DEPTH
        # Position points at the 11th opening parenthesis.
        assert sql[err.consumed] == '('
        assert err.consumed == len('select ') + 10

    def test_nesting_limit_catches_deep_case(self):
        case = '1'
        for i in range(20):
            case = f'CASE WHEN x={i} THEN {case} ELSE NULL END'
        sql = f'select {case} from t'
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(sql, limits=ParseLimits(max_nesting_depth=5))
        err = exc_info.value
        assert err.limit == NESTING_DEPTH
        assert sql[err.consumed:err.consumed + 4].upper() == 'CASE'

    def test_nesting_limit_balanced_parenthesis_recoverable(self):
        sql = 'select ' + '(' * 8 + '1' + ')' * 8
        parsed = sqlparse.parse(sql, max_nesting_depth=10)
        assert str(parsed[0]) == sql

    def test_max_token_length_identifier_and_comment(self):
        long_name = 'a' * 500
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(f'select {long_name}', max_token_length=100)
        assert exc_info.value.limit == TOKEN_LENGTH
        assert exc_info.value.consumed == len('select ')

        comment = '/*' + 'x' * 500 + '*/'
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(comment, max_token_length=100)
        assert exc_info.value.limit == TOKEN_LENGTH
        assert exc_info.value.consumed == 0

    def test_empty_and_whitespace_statements_are_cheap(self):
        strict = ParseLimits(max_tokens=10, max_nesting_depth=1)
        assert sqlparse.parse('', limits=strict) == ()
        assert sqlparse.parse('   ;  ', limits=strict)
        assert sqlparse.format('   ', strip_whitespace=True,
                               limits=strict) == ''

    def test_repeated_parses_do_not_accumulate_budget(self):
        limits = ParseLimits(max_tokens=20, max_nesting_depth=20)
        sql = 'select 1'
        for _ in range(10):
            statements = sqlparse.parse(sql, limits=limits)
            assert str(statements[0]) == sql

    def test_budget_does_not_mutate_lexer_singleton(self):
        from sqlparse.lexer import Lexer
        lexer = Lexer.get_default_instance()
        regexes = list(lexer._SQL_REGEX)
        keywords = list(lexer._keywords)
        with pytest.raises(SQLParseLimitError):
            sqlparse.parse('select ' + 'a' * 500, max_token_length=10)
        assert lexer._SQL_REGEX == regexes
        assert lexer._keywords == keywords
        assert not hasattr(lexer, '_budget')

    def test_grouping_call_budget(self):
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(
                'select a, b, c from t',
                limits=ParseLimits(max_grouping_calls=5),
            )
        assert exc_info.value.limit == GROUPING_CALLS

    def test_grouping_depth_budget_before_tree_completes(self):
        sql = 'select ' + '(' * 150 + '1' + ')' * 150
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(
                sql,
                limits=ParseLimits(
                    max_grouping_depth=50, max_nesting_depth=None
                ),
            )
        err = exc_info.value
        assert err.limit == GROUPING_DEPTH
        assert err.budget.peak_grouping_depth == 51

    def test_observed_grouping_metrics_stay_bounded(self):
        sql = 'select a, b, (select c from t2) from t'
        stack = FilterStack(limits=ParseLimits(max_nesting_depth=None))
        stack.enable_grouping()
        budget = build_budget(ParseLimits(max_nesting_depth=None))
        with use_budget(budget):
            list(stack.run(sql))
        # The single parenthesised subselect adds one grouping level.
        calls_before = budget.grouping_calls
        assert budget.peak_grouping_depth == 2
        assert calls_before > 0
        # A second independent run starts from zero again.
        second = build_budget(ParseLimits(max_nesting_depth=None))
        with use_budget(second):
            list(stack.run(sql))
        assert second.grouping_calls == calls_before
        assert second.peak_nesting_depth == budget.peak_nesting_depth

    def test_deeply_nested_input_does_not_overflow_python_stack(self):
        sql = 'select ' + '(' * 300 + '1' + ')' * 300
        with pytest.raises(SQLParseError) as exc_info:
            sqlparse.parse(sql)
        assert not isinstance(exc_info.value, RecursionError)

    def test_deep_paren_reports_bounded_depth_and_subsecond(self):
        sql = 'select ' + '(' * 1000 + '1' + ')' * 1000
        start = time.perf_counter()
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(sql)
        elapsed = time.perf_counter() - start
        error = exc_info.value
        assert error.limit == GROUPING_DEPTH
        # The budget stops one level past the configured 100-level cap and
        # records the peak so callers can monitor real-world headroom.
        assert error.budget.peak_grouping_depth == 101
        assert error.budget.peak_nesting_depth == 1000
        assert error.budget.grouping_calls <= 250
        assert elapsed < 1.0
        assert error.consumed > 0

    def test_mixed_40kb_attack_sample_rejected_fast_with_position(self):
        # Mirrors the reported payload: tens of thousands of brackets plus
        # nested CASE in a ~40 KB input.  The nesting guard must fire while
        # the input is still being split, before any grouping tree exists.
        case = '1'
        for i in range(60):
            case = f'CASE WHEN x={i} THEN {case} ELSE NULL END'
        sql = (
            'select ' + '(' * 8000 + case + ')' * 8000 + ' from t'
        )
        assert len(sql) < 50_000
        start = time.perf_counter()
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(sql, max_nesting_depth=128)
        elapsed = time.perf_counter() - start
        error = exc_info.value
        assert error.limit == NESTING_DEPTH
        assert error.consumed == len('select ') + 128
        assert elapsed < 1.0

    def test_timeout_during_lexing(self, monkeypatch):
        from sqlparse import limits as limits_module
        fake_clock = iter([0.0, 100.0, 100.0])
        monkeypatch.setattr(
            limits_module.time, 'monotonic', lambda: next(fake_clock)
        )
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(
                'select ' + ', '.join(f'c{i}' for i in range(1000)),
                limits=ParseLimits(timeout=1.0, max_tokens=None),
            )
        assert exc_info.value.limit == TIMEOUT
        assert exc_info.value.consumed > 0

    def test_timeout_during_grouping(self, monkeypatch):
        from sqlparse import limits as limits_module
        fake_clock = iter([0.0] + [100.0] * 1000)
        monkeypatch.setattr(
            limits_module.time, 'monotonic', lambda: next(fake_clock)
        )
        with pytest.raises(SQLParseLimitError) as exc_info:
            sqlparse.parse(
                'select a, b from t',
                limits=ParseLimits(timeout=1.0),
            )
        assert exc_info.value.limit == TIMEOUT

    def test_invalid_limits_rejected(self):
        with pytest.raises(ValueError):
            ParseLimits(max_tokens=0)
        with pytest.raises(ValueError):
            ParseLimits(timeout=0)
        with pytest.raises(ValueError):
            ParseLimits(max_nesting_depth=-2)
        with pytest.raises(TypeError):
            sqlparse.parse('select 1', limits={'max_tokens': 1})

    def test_limits_instance_and_keywords_combined(self):
        # Keyword overrides win over the instance for this invocation only.
        base = ParseLimits(max_tokens=100)
        with pytest.raises(SQLParseLimitError):
            sqlparse.parse(
                'select ' + ', '.join(f'c{i}' for i in range(50)),
                limits=base,
                max_tokens=10,
            )
        # The shared instance is unchanged and still allows the same input.
        statements = sqlparse.parse('select 1', limits=base)
        assert str(statements[0]) == 'select 1'
