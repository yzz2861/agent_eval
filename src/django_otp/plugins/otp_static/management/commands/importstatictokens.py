from pathlib import Path
import sys

from django.core.management.base import BaseCommand, CommandError
from django.utils.encoding import force_str

from django_otp.plugins.otp_static.lib import (
    get_user_model,
    import_static_tokens,
)


class Command(BaseCommand):
    help = (
        'Imports recovery codes from a CSV file. '
        'The import is idempotent for the same normalized code set.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            'username', help='The user to which the tokens will be assigned.'
        )
        parser.add_argument(
            'path',
            nargs='?',
            default='-',
            help='CSV file path, or - to read from stdin.',
        )
        parser.add_argument(
            '-f',
            '--file',
            dest='file',
            default=None,
            help='CSV file path (alias for the positional argument).',
        )
        parser.add_argument(
            '--batch-id',
            dest='batch_id',
            default=None,
            help='Optional UUID identifying this import batch.',
        )
        parser.add_argument(
            '--reference',
            dest='reference',
            default='',
            help='Human-readable batch reference.',
        )

    def handle(self, *args, **options):
        username = options['username']
        path = options.get('file') or options['path']

        try:
            if path == '-':
                source = sys.stdin.read()
            else:
                with Path(path).open('rb') as file:
                    source = file.read()

            batch = import_static_tokens(
                username,
                source,
                batch_id=options['batch_id'],
                reference=options['reference'],
            )
        except get_user_model().DoesNotExist:
            raise CommandError('User "{0}" does not exist.'.format(username))
        except OSError as error:
            raise CommandError('Unable to read import file.')
        except Exception as error:
            if getattr(error, 'reason', None) is not None:
                raise CommandError(force_str(error.reason))
            raise

        self.stdout.write(str(batch.batch_id))
        self.stdout.write(
            'imported={0} duplicates={1}'.format(
                getattr(batch, 'imported_count', 0),
                getattr(batch, 'duplicate_count', 0),
            )
        )
