from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('otp_email', '0006_add_timestamps'),
    ]

    operations = [
        migrations.AddField(
            model_name='emaildevice',
            name='generation_failure_count',
            field=models.PositiveIntegerField(
                default=0,
                help_text=(
                    'The number of consecutive failed challenge generations'
                    ' within the current failure window.'
                ),
            ),
        ),
        migrations.AddField(
            model_name='emaildevice',
            name='generation_failure_timestamp',
            field=models.DateTimeField(
                blank=True,
                default=None,
                help_text=(
                    'The datetime of the most recent failed challenge'
                    ' generation. Null if the last attempt succeeded.'
                ),
                null=True,
            ),
        ),
    ]
