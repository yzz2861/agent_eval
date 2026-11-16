# -*- coding: utf-8 -*-
import pytest

from zxcvbn import matching
from zxcvbn import zxcvbn


@pytest.fixture(autouse=True)
def restore_dictionary_state():
    """Snapshot and restore global dictionary state around each test."""
    ranked = matching.get_ranked_dictionaries()
    original_keys = set(ranked.keys())
    original_priorities = dict(matching.DICTIONARY_PRIORITIES)
    original_cache = dict(matching.RANKED_DICT_CACHE)
    yield
    for key in list(ranked.keys()):
        if key not in original_keys:
            del ranked[key]
    matching.DICTIONARY_PRIORITIES.clear()
    matching.DICTIONARY_PRIORITIES.update(original_priorities)
    matching.RANKED_DICT_CACHE.clear()
    matching.RANKED_DICT_CACHE.update(original_cache)


def dictionary_names_for(password, word, **kwargs):
    """Names of dictionaries whose match covers the exact given word."""
    return {
        m['dictionary_name']
        for m in matching.omnimatch(password, **kwargs)
        if m['pattern'] == 'dictionary' and m['matched_word'] == word
    }


def test_add_frequency_lists_custom_hit():
    matching.add_frequency_lists({'pinyin': ['zhongguo', 'beijing']})
    matches = [m for m in matching.dictionary_match('zhongguo')
               if m['matched_word'] == 'zhongguo']
    assert len(matches) == 1
    assert matches[0]['dictionary_name'] == 'pinyin'
    assert matches[0]['rank'] == 1
    assert matches[0]['i'] == 0
    assert matches[0]['j'] == len('zhongguo') - 1


def test_add_frequency_lists_empty_dictionary():
    matching.add_frequency_lists({'empty_dict': []})
    assert matching.get_ranked_dictionaries()['empty_dict'] == {}
    # an empty dictionary never matches and doesn't break matching
    matches = matching.omnimatch('password')
    assert all(m['dictionary_name'] != 'empty_dict'
               for m in matches if m['pattern'] == 'dictionary')
    result = zxcvbn('password')
    assert 'empty_dict' not in result['matched_dictionaries']


def test_add_frequency_lists_override_same_name():
    matching.add_frequency_lists({'corp_terms': ['acmewidget']})
    assert dictionary_names_for('acmewidget', 'acmewidget') == {'corp_terms'}
    # re-registering the same name replaces the previous word list
    matching.add_frequency_lists({'corp_terms': ['globexinc']})
    assert dictionary_names_for('globexinc', 'globexinc') == {'corp_terms'}
    assert 'corp_terms' not in dictionary_names_for('acmewidget', 'acmewidget')


def test_add_frequency_lists_cache_reuses_ranked_dict():
    words = ['acme', 'globex']
    matching.add_frequency_lists({'corp_terms': words})
    first = matching.get_ranked_dictionaries()['corp_terms']
    matching.add_frequency_lists({'corp_terms': list(words)})
    second = matching.get_ranked_dictionaries()['corp_terms']
    assert first is second, "unchanged word list should reuse cached ranked dict"
    matching.add_frequency_lists({'corp_terms': ['initech']})
    third = matching.get_ranked_dictionaries()['corp_terms']
    assert third is not first
    assert third == {'initech': 1}


def test_custom_dictionary_priority_beats_builtin():
    # 'password' also matches the built-in 'passwords' dictionary; the
    # higher-priority custom dictionary wins on the identical span.
    matching.add_frequency_lists({'corp_terms': ['password']})
    assert dictionary_names_for('password', 'password') == {'corp_terms'}


def test_zxcvbn_per_call_custom_dictionaries():
    result = zxcvbn('beijing2024', custom_dictionaries={
        'pinyin': ['beijing', 'shanghai'],
    })
    assert 'pinyin' in result['matched_dictionaries']
    # per-call dictionaries must not leak into the global registry
    assert 'pinyin' not in matching.get_ranked_dictionaries()
    assert 'pinyin' not in dictionary_names_for('beijing', 'beijing')


def test_zxcvbn_per_call_empty_custom_dictionary():
    result = zxcvbn('correcthorse', custom_dictionaries={'empty_dict': []})
    assert 'empty_dict' not in result['matched_dictionaries']


def test_zxcvbn_matched_dictionaries_builtin():
    result = zxcvbn('password')
    assert result['matched_dictionaries'] == ['passwords']


def test_zxcvbn_matched_dictionaries_empty_for_strong_password():
    result = zxcvbn('r9$Kx2!vB7#qL4')
    assert result['matched_dictionaries'] == []
