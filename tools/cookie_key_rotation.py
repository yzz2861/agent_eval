#!/usr/bin/env python3
"""Annual cookie signing-key rotation helper for Bottle ``CookieKeyring``.

The keyring state is a small JSON document so it can live in a config
repository or a secrets manager. This tool performs the three operations of
a safe rotation:

1. ``init``     create the state file with a single current generation.
2. ``rotate``   add a new current generation while keeping the previous one
                in the allowed rotation window (old sessions keep working,
                new sessions are signed with the new key).
3. ``finish``   close the rotation window: every non-current generation is
                revoked in one shot, so any cookie that was never re-signed
                fails verification on its next request with an attributable
                :class:`bottle.RevokedKeyGenerationError`.

Application code loads the state through :func:`load_keyring`.
"""

import argparse
import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bottle  # noqa: E402

STATE_VERSION = 1


def generate_secret(num_bytes=32):
    """ Return a url-safe random secret string. """
    return base64.urlsafe_b64encode(os.urandom(num_bytes)).rstrip(b'=').decode()


def _write_state(path, state):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix='.keyring-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write('\n')
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def init_state(path, generation='1', secret=None, purpose='', max_age=None):
    """ Create a new keyring state file. """
    if os.path.exists(path):
        raise FileExistsError('Keyring state already exists: %s' % path)
    secret = secret or generate_secret()
    state = {
        'version': STATE_VERSION,
        'purpose': purpose,
        'max_age': max_age,
        'current_generation': str(generation),
        'allowed_generations': [str(generation)],
        'revoked_generations': [],
        'keys': {str(generation): secret},
    }
    _write_state(path, state)
    return state


def read_state(path):
    """ Load and minimally validate the keyring state file. """
    with open(path, 'r', encoding='utf-8') as handle:
        state = json.load(handle)
    if state.get('version') != STATE_VERSION:
        raise ValueError('Unsupported keyring state version.')
    if not state.get('keys'):
        raise ValueError('Keyring state contains no keys.')
    return state


def rotate_state(path, new_generation=None, secret=None,
                 accept_previous=True):
    """ Add a new current generation and persist the rotation window. """
    state = read_state(path)
    previous = state['current_generation']
    if new_generation is None:
        numeric = [gen for gen in state['keys'] if str(gen).isdigit()]
        new_generation = str(max((int(gen) for gen in numeric), default=0) + 1)
    new_generation = str(new_generation)
    if new_generation in state['keys']:
        raise ValueError('Generation %s already exists.' % new_generation)
    state['keys'][new_generation] = secret or generate_secret()
    state['current_generation'] = new_generation
    if new_generation not in state['allowed_generations']:
        state['allowed_generations'].append(new_generation)
    if not accept_previous:
        if previous not in state['revoked_generations']:
            state['revoked_generations'].append(previous)
        state['allowed_generations'] = [
            gen for gen in state['allowed_generations'] if gen != previous]
    _write_state(path, state)
    return state, previous


def finish_state(path):
    """ Revoke every generation except the current one. """
    state = read_state(path)
    current = state['current_generation']
    retired = [gen for gen in state['keys'] if gen != current]
    for gen in retired:
        if gen not in state['revoked_generations']:
            state['revoked_generations'].append(gen)
    state['allowed_generations'] = [current]
    _write_state(path, state)
    return state, retired


def load_keyring(path, **kwargs):
    """ Build a :class:`bottle.CookieKeyring` from a state file. """
    state = read_state(path)
    params = dict(
        keys=state['keys'],
        current_generation=state['current_generation'],
        allowed_generations=state['allowed_generations'],
        revoked_generations=state['revoked_generations'],
        purpose=state.get('purpose', ''),
        max_age=state.get('max_age'),
    )
    params.update(kwargs)
    return bottle.CookieKeyring(**params)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('state', help='Path to the keyring state JSON file.')
    sub = parser.add_subparsers(dest='command', required=True)

    init = sub.add_parser('init', help='Create a new keyring state file.')
    init.add_argument('--generation', default='1')
    init.add_argument('--secret', help='Use this secret instead of a random one.')
    init.add_argument('--purpose', default='')
    init.add_argument('--max-age', type=int, default=None)

    rotate = sub.add_parser('rotate', help='Add a new current generation.')
    rotate.add_argument('--generation', dest='new_generation', default=None)
    rotate.add_argument('--secret', help='Use this secret instead of a random one.')
    rotate.add_argument('--reject-previous', action='store_true',
                        help='Revoke the previous generation immediately.')

    sub.add_parser('finish', help='Revoke all non-current generations.')
    sub.add_parser('status', help='Print the state file as JSON.')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == 'init':
        state = init_state(args.state, generation=args.generation,
                           secret=args.secret, purpose=args.purpose,
                           max_age=args.max_age)
        print('initialized generation %s' % state['current_generation'])
    elif args.command == 'rotate':
        state, previous = rotate_state(
            args.state, new_generation=args.new_generation, secret=args.secret,
            accept_previous=not args.reject_previous)
        print('rotated %s -> %s (previous generation %s)'
              % (previous, state['current_generation'],
                 'accepted' if not args.reject_previous else 'revoked'))
    elif args.command == 'finish':
        state, retired = finish_state(args.state)
        print('revoked generations: %s' % (', '.join(sorted(retired)) or 'none'))
    else:
        print(json.dumps(read_state(args.state), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
