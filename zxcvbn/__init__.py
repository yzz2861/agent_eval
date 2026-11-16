import os
from datetime import datetime

from . import matching, scoring, time_estimates, feedback


def zxcvbn(password, user_inputs=None, max_length=72, custom_dictionaries=None):
    # Throw error if password exceeds max length
    if len(password) > max_length:
        raise ValueError(f"Password exceeds max length of {max_length} characters.")

    try:
        # Python 2 string types
        basestring = (str, unicode)
    except NameError:
        # Python 3 string types
        basestring = (str, bytes)

    if user_inputs is None:
        user_inputs = []

    if custom_dictionaries is None:
        custom_dictionaries = {}

    start = datetime.now()

    sanitized_inputs = []
    for arg in user_inputs:
        if not isinstance(arg, basestring):
            arg = str(arg)
        sanitized_inputs.append(arg.lower())

    matches = matching.omnimatch(password, user_inputs=sanitized_inputs,
                                 custom_dictionaries=custom_dictionaries)
    result = scoring.most_guessable_match_sequence(password, matches)
    result['calc_time'] = datetime.now() - start

    # names of the dictionaries hit by the matches in the final sequence
    result['matched_dictionaries'] = sorted({
        match['dictionary_name']
        for match in result['sequence']
        if match['pattern'] == 'dictionary'
    })

    attack_times = time_estimates.estimate_attack_times(result['guesses'])
    for prop, val in attack_times.items():
        result[prop] = val

    result['feedback'] = feedback.get_feedback(result['score'],
                                               result['sequence'])

    return result
