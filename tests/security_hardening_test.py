from decimal import Decimal

import pytest

from zxcvbn import scoring, time_estimates, zxcvbn


PUBLIC_RESULT_KEYS = {
    'password',
    'guesses',
    'guesses_log10',
    'sequence',
    'calc_time',
    'crack_times_seconds',
    'crack_times_display',
    'score',
    'feedback',
}

CRACK_TIME_KEYS = {
    'online_throttling_100_per_hour',
    'online_no_throttling_10_per_second',
    'offline_slow_hashing_1e4_per_second',
    'offline_fast_hashing_1e10_per_second',
}


def test_l33t_combination_space_is_bounded():
    # aaaa...4444 has a very large number of partial substitutions.  The
    # estimator must cap that product instead of treating every combination
    # as an independent attacker guess.
    match = {
        'token': 'a' * 20 + '4' * 20,
        'l33t': True,
        'sub': {'4': 'a'},
    }

    variations = scoring.l33t_variations(match)

    assert variations == scoring.MAX_L33T_VARIATIONS
    assert variations <= scoring.MAX_L33T_VARIATIONS


@pytest.mark.parametrize('password,expected_rank_token', [
    ('w0@1n1', 'w0@1n1'),
    ('2h0n66u0', '2h0n66u0'),
    ('w0aini', 'w0aini'),
])
def test_common_pinyin_l33t_passwords_are_not_overestimated(
        password, expected_rank_token):
    result = zxcvbn(password)

    l33t_matches = [match for match in result['sequence']
                    if match.get('l33t')]
    assert l33t_matches
    assert l33t_matches[0]['token'] == expected_rank_token
    assert l33t_matches[0]['l33t_variations'] <= \
        scoring.MAX_L33T_VARIATIONS
    assert result['score'] <= 2


def _unpenalized_spatial_guesses(match):
    if match['graph'] in ['qwerty', 'dvorak']:
        starting_positions = scoring.KEYBOARD_STARTING_POSITIONS
        average_degree = scoring.KEYBOARD_AVERAGE_DEGREE
    else:
        starting_positions = scoring.KEYPAD_STARTING_POSITIONS
        average_degree = scoring.KEYPAD_AVERAGE_DEGREE

    guesses = 0
    length = len(match['token'])
    for i in range(2, length + 1):
        possible_turns = min(match['turns'], i - 1) + 1
        for j in range(1, possible_turns):
            guesses += (scoring.nCk(i - 1, j - 1) * starting_positions *
                        pow(average_degree, j))
    return guesses


def test_qwerty_snake_is_penalized():
    match = {
        'token': 'plokijuhygtfrdeswaq',
        'graph': 'qwerty',
        'turns': 18,
        'shifted_count': 0,
    }

    guesses = scoring.spatial_guesses(match)

    # The canonical turn formula sees 18 independent turns and estimates
    # ~10^16 guesses for this obvious alternating keyboard snake.
    assert guesses < _unpenalized_spatial_guesses(match)
    assert guesses < 10 ** 8


@pytest.mark.parametrize('password', [
    'plokijuhygtfrdeswaq',
    'plokijuhy',
])
def test_qwerty_snake_password_score_is_not_overestimated(password):
    result = zxcvbn(password)

    assert result['score'] <= 2
    assert any(match['pattern'] == 'spatial'
               for match in result['sequence'])


def test_public_result_structure_and_time_estimates_are_unchanged():
    result = zxcvbn('w0@1n1!2024')

    assert set(result) == PUBLIC_RESULT_KEYS
    assert set(result['crack_times_seconds']) == CRACK_TIME_KEYS
    assert set(result['crack_times_display']) == CRACK_TIME_KEYS
    assert result['score'] == time_estimates.guesses_to_score(
        result['guesses'])
    assert result['crack_times_seconds'][
        'offline_fast_hashing_1e10_per_second'
    ] == Decimal(result['guesses']) / Decimal('1e10')
