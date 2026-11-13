from textwrap import fill

from django.core.management.base import BaseCommand, CommandError
from django.utils.encoding import force_str

from django_otp.plugins.otp_static.lib import (
    DEFAULT_BATCH_ALPHABET,
    DEFAULT_BATCH_LENGTH,
    add_static_token,
    create_static_token_batch,
    get_user_model,
)


class Command(BaseCommand):
    help = fill(
        'Adds a single static OTP token to the given user. '
        'The token will be added to an arbitrary static device '
        'attached to the user, creating one if necessary.',
        width=78,
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '-t',
            '--token',
            dest='token',
            help='The token to add. If omitted, one will be randomly generated.',
        )
        parser.add_argument(
            '-n',
            '--count',
            dest='count',
            type=int,
            default=None,
            help='Number of tokens to issue as one revocable batch.',
        )
        parser.add_argument(
            '--length',
            dest='length',
            type=int,
            default=None,
            help='Length of each generated token in a batch.',
        )
        parser.add_argument(
            '--alphabet',
            dest='alphabet',
            default=None,
            help='Character set used for every token in a batch.',
        )
        parser.add_argument(
            '--batch-id',
            dest='batch_id',
            default=None,
            help='Optional UUID used for idempotent batch issuance.',
        )
        parser.add_argument(
            '--reference',
            dest='reference',
            default='',
            help='Human-readable batch reference.',
        )
        parser.add_argument(
            'username', help='The user to which the token will be assigned.'
        )

    def handle(self, *args, **options):
        username = options['username']
        count = options['count'] or 1
        batch_options = any(
            options.get(key) not in (None, '', 1)
            for key in ('count', 'length', 'alphabet', 'batch_id', 'reference')
        )
        if options.get('count') is not None:
            batch_options = True

        if batch_options and options.get('token'):
            raise CommandError(
                '--token cannot be combined with batch issuance options.'
            )

        try:
            if batch_options:
                batch = create_static_token_batch(
                    username,
                    count,
                    length=options['length'] or DEFAULT_BATCH_LENGTH,
                    alphabet=options['alphabet'] or DEFAULT_BATCH_ALPHABET,
                    batch_id=options['batch_id'],
                    reference=options['reference'],
                )
                tokens = getattr(batch, 'issued_tokens', None)
                if tokens is None:
                    tokens = list(
                        batch.tokens.values_list('token', flat=True)
                    )
                statictoken = None
            else:
                statictoken = add_static_token(username, options.get('token'))
        except get_user_model().DoesNotExist:
            raise CommandError('User "{0}" does not exist.'.format(username))
        except Exception as error:
            if getattr(error, 'reason', None) is not None:
                raise CommandError(force_str(error.reason))
            raise

        if statictoken is not None:
            self.stdout.write(force_str(statictoken.token))
        else:
            for token in tokens:
                self.stdout.write(force_str(token))
