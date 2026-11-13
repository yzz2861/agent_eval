from django.core.management.base import BaseCommand, CommandError
from django.utils.encoding import force_str

from django_otp.plugins.otp_static.lib import revoke_static_token_batch


class Command(BaseCommand):
    help = 'Revokes an entire static token batch and all of its unused codes.'

    def add_arguments(self, parser):
        parser.add_argument('batch_id', help='The UUID of the batch to revoke.')
        parser.add_argument(
            '--reason',
            dest='reason',
            default='',
            help='Optional operator audit reason.',
        )

    def handle(self, *args, **options):
        try:
            batch = revoke_static_token_batch(
                options['batch_id'], reason=options['reason']
            )
        except Exception as error:
            if getattr(error, 'reason', None) is not None:
                raise CommandError(force_str(error.reason))
            raise

        self.stdout.write('{0} {1}'.format(batch.batch_id, batch.status))
