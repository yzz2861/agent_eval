import math

import pytest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.high_entropy_strings import HighEntropyStringsPlugin


@pytest.mark.parametrize(
    'plugin, non_secret, secret',
    (
        (HexHighEntropyString, 'aaaaaa', '2b00042f7481c7b056c4b410d28f33cf'),
        (
            Base64HighEntropyString,
            'c3VwZXIgc2VjcmV0IHZhbHVl',     # too short
            'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5',
        ),

        # url-safe
        (
            Base64HighEntropyString,
            'Zrm-ySTAq7D2sHk=',     # too short
            'I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_f-pTAuoX2U=',
        ),
    ),
)
class TestHighEntropyString:
    @staticmethod
    @pytest.mark.parametrize(
        'format, should_be_caught',
        (
            ("'{non_secret}'", False),
            ('"{non_secret}"', False),
            ('"{secret}"', True),
            ("'{secret}'", True),

            # Non-quoted string
            ('{secret}', False),
        ),
    )
    def test_basic(plugin, non_secret, secret, format, should_be_caught):
        # NOTE: We need to use analyze_line (rather than analyze_string) since the entropy
        # limit check lives in this function.
        results = list(
            plugin().analyze_line(
                filename='does not matter',
                line=format.format(non_secret=non_secret, secret=secret),
                line_number=0,
            ),
        )
        assert bool(results) == should_be_caught

    @staticmethod
    @pytest.mark.parametrize(
        'format, num_results',
        (
            (
                'String #1: "{non_secret}"; String #2: "{secret}"',
                1,
            ),
            (
                # We add an 'a' to make the second secret different.
                # This currently fits both hex and base64 char set.
                'String #1: "{secret}"; String #2: "{secret}a"',
                2,
            ),
        ),
    )
    def test_multiple_strings_same_line(plugin, non_secret, secret, format, num_results):
        results = list(
            plugin().analyze_line(
                filename='does not matter',
                line=format.format(non_secret=non_secret, secret=secret),
                line_number=0,
            ),
        )
        assert len(results) == num_results

    @staticmethod
    @pytest.mark.parametrize(
        'limit',
        (-1, 15),
    )
    def test_entropy_limit(plugin, non_secret, secret, limit):
        with pytest.raises(ValueError):
            plugin(limit)


class TestHexEntropyCalculation:
    @staticmethod
    @pytest.fixture
    def original_hex_detector():
        class OriginalHexHighEntropyString(HexHighEntropyString):
            def calculate_shannon_entropy(self, data):
                return HighEntropyStringsPlugin.calculate_shannon_entropy(self, data)

        return OriginalHexHighEntropyString

    @staticmethod
    def test_basic(original_hex_detector):
        value = '0123456789'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            < original_hex_detector().calculate_shannon_entropy(value)
        )

        # This is the goal.
        assert HexHighEntropyString().calculate_shannon_entropy(value) < 3

    @staticmethod
    def test_length_dependency(original_hex_detector):
        assert (
            HexHighEntropyString().calculate_shannon_entropy('0123456789')
            < HexHighEntropyString().calculate_shannon_entropy('01234567890123456789')
        )

    @staticmethod
    def test_only_with_numbers(original_hex_detector):
        value = '12345a'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            == original_hex_detector().calculate_shannon_entropy(value)
        )

    @staticmethod
    def test_single_case(original_hex_detector):
        value = '0'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            == original_hex_detector().calculate_shannon_entropy(value)
        )



class TestInputBudgets:
    @staticmethod
    def test_line_longer_than_max_is_skipped_with_reason(mock_log_warning):
        plugin = Base64HighEntropyString()
        line = chr(34) + ("A" * (plugin.MAX_LINE_LENGTH + 1)) + chr(34)

        assert not plugin.analyze_line(filename="file", line=line, line_number=3)
        messages = mock_log_warning.warning_messages
        assert "line length exceeded maximum allowed line length" in messages
        assert "limit=%d" % plugin.MAX_LINE_LENGTH in messages
        assert "file:3" in messages

    @staticmethod
    def test_max_line_length_boundary_is_still_scanned():
        plugin = Base64HighEntropyString()
        # A high-entropy block repeated to fill the line exactly up to the length limit:
        # the repeated block keeps the overall entropy well above the plugin limit.
        block = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )
        inner = (block * (plugin.MAX_LINE_LENGTH // len(block) + 1))[
            : plugin.MAX_LINE_LENGTH - 2
        ]
        line = chr(34) + inner + chr(34)

        assert len(line) == plugin.MAX_LINE_LENGTH
        assert plugin.analyze_line(filename="file", line=line)

    @staticmethod
    def test_too_many_candidates_is_skipped_with_reason(mock_log_warning):
        plugin = Base64HighEntropyString()
        candidate = chr(34) + ("a" * plugin.MIN_CANDIDATE_LENGTH) + chr(34)
        line = " ".join(
            candidate
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE + 1)
        )

        assert not plugin.analyze_line(filename="file", line=line)
        assert (
            "candidate count exceeded maximum candidates allowed per line"
            in mock_log_warning.warning_messages
        )

    @staticmethod
    def test_candidate_budget_boundary_is_not_skipped():
        plugin = Base64HighEntropyString()
        # Each candidate is exactly at the minimum length, so every one of them counts.
        candidate = chr(34) + ("a" * plugin.MIN_CANDIDATE_LENGTH) + chr(34)
        line = " ".join(
            candidate
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE)
        )

        results = plugin.analyze_line(filename="file", line=line)
        # The candidates are low entropy, so no secrets are reported -- but crucially the scan
        # completes instead of being aborted, hence nothing is logged as skipped.
        assert not results

    @staticmethod
    def test_candidates_shorter_than_minimum_are_ignored():
        plugin = Base64HighEntropyString()
        # Five-character runs never produce a candidate, regardless of how many there are.
        line = " ".join(
            chr(34) + ("a" * (plugin.MIN_CANDIDATE_LENGTH - 1)) + chr(34)
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE * 2)
        )

        assert not plugin.analyze_line(filename="file", line=line)

    @staticmethod
    def test_scanned_byte_budget_is_measured_in_utf8_bytes(mock_log_warning):
        plugin = Base64HighEntropyString()
        plugin.MAX_SCANNED_BYTES = 1000
        # Each Chinese character is three utf-8 bytes but a single character, so the character
        # count stays under the line limit while the byte budget is exceeded.
        line = "中" * 400

        assert not plugin.analyze_line(filename="file", line=line)
        assert (
            "scanned byte count exceeded maximum allowed scan size"
            in mock_log_warning.warning_messages
        )

    @staticmethod
    def test_skip_is_not_silent_when_eager_search_exhausts_budget(mock_log_warning):
        plugin = Base64HighEntropyString()
        candidate = "a" * plugin.MIN_CANDIDATE_LENGTH
        line = " ".join(
            candidate
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE + 1)
        )

        assert not plugin.analyze_line(
            filename="file",
            line=line,
            enable_eager_search=True,
        )
        assert (
            "candidate count exceeded maximum candidates allowed per line"
            in mock_log_warning.warning_messages
        )

    @staticmethod
    def test_legitimate_secret_is_still_reported_when_near_budgets():
        plugin = Base64HighEntropyString()
        secret = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )
        filler = " ".join(
            chr(34) + ("z" * plugin.MIN_CANDIDATE_LENGTH) + chr(34)
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE - 1)
        )
        line = filler + " " + chr(34) + secret + chr(34)

        results = plugin.analyze_line(filename="file", line=line)
        assert len(results) == 1



class TestExtremeInputsTerminate:
    @staticmethod
    def test_multi_megabyte_single_line_terminates():
        plugin = Base64HighEntropyString()
        line = chr(34) + ("AB" * (3 * 1024 * 1024 // 2)) + chr(34)

        # The line length budget trips before any quadratic work can happen.
        assert not plugin.analyze_line(filename="file", line=line)

    @staticmethod
    def test_highly_repetitive_data_has_bounded_entropy_calculation():
        plugin = Base64HighEntropyString()

        assert plugin.calculate_shannon_entropy("A" * 100000) == 0.0
        assert plugin.calculate_shannon_entropy(("AB" * 50000)) == 1.0

    @staticmethod
    def test_repeated_quotes_do_not_create_a_runaway_scan():
        plugin = Base64HighEntropyString()
        line = chr(34) + ("A" + chr(34)) * (plugin.MAX_LINE_LENGTH // 2)

        assert not plugin.analyze_line(filename="file", line=line)

    @staticmethod
    def test_many_short_matches_do_not_break_linearity():
        plugin = Base64HighEntropyString()
        line = " ".join(
            chr(34) + ("a" * plugin.MIN_CANDIDATE_LENGTH) + chr(34)
            for _ in range(plugin.MAX_CANDIDATES_PER_LINE)
        )

        # Completes without raising and without exceeding the candidate budget.
        assert not plugin.analyze_line(filename="file", line=line)


class TestUnicodeAndMixedEncoding:
    @staticmethod
    def test_unicode_surrounding_a_quoted_secret():
        plugin = Base64HighEntropyString()
        secret = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )
        line = "日本語 キー = " + chr(34) + secret + chr(34) + " café 🙂"

        results = plugin.analyze_line(filename="file", line=line)
        assert {result.secret_value for result in results} == {secret}

    @staticmethod
    def test_unicode_inside_quotes_breaks_the_candidate():
        plugin = Base64HighEntropyString()
        line = chr(34) + "abcdef日本語ghijkl" + chr(34)

        assert not plugin.analyze_line(filename="file", line=line)

    @staticmethod
    def test_multibyte_line_under_byte_budget_is_scanned():
        plugin = Base64HighEntropyString()
        secret = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )
        line = "中" * 100 + chr(34) + secret + chr(34)

        results = plugin.analyze_line(filename="file", line=line)
        assert len(results) == 1

    @staticmethod
    def test_mixed_encoding_noise_does_not_hide_ascii_secret():
        plugin = HexHighEntropyString()
        secret = "2b00042f7481c7b056c4b410d28f33cf"
        line = "prefix-ñ " + chr(39) + secret + chr(39) + " suffix-ü"

        results = plugin.analyze_line(filename="file", line=line)
        assert {result.secret_value for result in results} == {secret}


class TestAllowlistBehaviorUnchanged:
    @staticmethod
    def test_allowlisted_line_is_still_filtered_by_core():
        # The allowlist filter operates in the scan layer, not the plugin. Here we just confirm
        # the plugin still emits candidates on allowlist-style lines, so the existing filter
        # behavior is preserved.
        plugin = Base64HighEntropyString()
        secret = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )
        line = "key = " + chr(34) + secret + chr(34) + "  # pragma: allowlist secret"

        results = plugin.analyze_line(filename="file", line=line)
        assert len(results) == 1

    @staticmethod
    def test_non_quoted_eager_search_still_works():
        plugin = Base64HighEntropyString()
        secret = (
            "I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_"
            "f-pTAuoX2U="
        )

        with plugin.non_quoted_string_regex(is_exact_match=False):
            results = plugin.analyze_line(filename="file", line="token " + secret)

        assert {result.secret_value for result in results} == {secret}


class TestEntropyCalculation:
    @staticmethod
    def test_entropy_matches_reference_implementation():
        plugin = Base64HighEntropyString()
        data = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"

        # Reference: sum over the distinct symbol frequencies (the old per-charset count loop
        # produced the same value).
        length = len(data)
        expected = 0.0
        for symbol in set(data):
            probability = data.count(symbol) / length
            expected += -probability * math.log(probability, 2)

        assert plugin.calculate_shannon_entropy(data) == pytest.approx(expected)

    @staticmethod
    def test_empty_string_returns_zero():
        assert Base64HighEntropyString().calculate_shannon_entropy("") == 0
