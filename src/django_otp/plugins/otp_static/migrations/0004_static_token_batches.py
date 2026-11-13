import re
import uuid

from django.db import migrations, models
import django.db.models.deletion


_SEPARATOR_RE = re.compile(r"[\s\u200b\ufeff\-_.,;:|/\\]+")


def normalize_token(value):
    if value is None:
        return ""
    return _SEPARATOR_RE.sub("", str(value)).upper()


def populate_normalized_tokens(apps, schema_editor):
    StaticToken = apps.get_model('otp_static', 'StaticToken')
    for token in StaticToken.objects.all().iterator():
        normalized = normalize_token(token.token)
        if token.normalized_token != normalized:
            # Update only the new canonical column.  Legacy rows, including
            # intentional duplicates, are never split or recreated.
            StaticToken.objects.filter(pk=token.pk).update(
                normalized_token=normalized
            )


class Migration(migrations.Migration):

    dependencies = [
        ('otp_static', '0003_add_timestamps'),
    ]

    operations = [
        migrations.CreateModel(
            name='StaticTokenBatch',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'batch_id',
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                (
                    'reference',
                    models.CharField(blank=True, default='', max_length=128),
                ),
                (
                    'source',
                    models.CharField(default='generated', max_length=16),
                ),
                (
                    'import_key',
                    models.CharField(
                        blank=True, default=None, max_length=64, null=True
                    ),
                ),
                ('alphabet', models.TextField(blank=True, default='')),
                (
                    'token_length',
                    models.PositiveSmallIntegerField(default=0),
                ),
                (
                    'random_source',
                    models.CharField(blank=True, default='', max_length=128),
                ),
                ('total_count', models.PositiveIntegerField(default=0)),
                ('consumed_count', models.PositiveIntegerField(default=0)),
                (
                    'status',
                    models.CharField(
                        choices=[
                            ('active', 'Active'),
                            ('revoked', 'Revoked'),
                            ('exhausted', 'Exhausted'),
                        ],
                        default='active',
                        max_length=16,
                    ),
                ),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'revoked_at',
                    models.DateTimeField(blank=True, default=None, null=True),
                ),
                (
                    'revocation_reason',
                    models.CharField(blank=True, default='', max_length=64),
                ),
                (
                    'device',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='token_batches',
                        to='otp_static.staticdevice',
                    ),
                ),
            ],
        ),
        migrations.AlterField(
            model_name='statictoken',
            name='token',
            field=models.CharField(db_index=True, max_length=64),
        ),
        migrations.AddField(
            model_name='statictoken',
            name='normalized_token',
            field=models.CharField(
                blank=True, db_index=True, default='', max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='statictoken',
            name='batch',
            field=models.ForeignKey(
                blank=True,
                default=None,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='tokens',
                to='otp_static.statictokenbatch',
            ),
        ),
        migrations.AddField(
            model_name='statictoken',
            name='consumed_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='statictoken',
            name='invalidated_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(
            populate_normalized_tokens,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddConstraint(
            model_name='statictokenbatch',
            constraint=models.UniqueConstraint(
                condition=models.Q(import_key__isnull=False),
                fields=('device', 'import_key'),
                name='otp_static_batch_import_key_uniq',
            ),
        ),
        migrations.AddConstraint(
            model_name='statictoken',
            constraint=models.UniqueConstraint(
                condition=models.Q(batch__isnull=False),
                fields=('device', 'normalized_token'),
                name='otp_static_token_device_uniq',
            ),
        ),
        migrations.AddIndex(
            model_name='statictokenbatch',
            index=models.Index(
                fields=['device', 'status'],
                name='otp_static_batch_status_idx',
            ),
        ),
        migrations.AddIndex(
            model_name='statictoken',
            index=models.Index(
                fields=['device', 'normalized_token'],
                name='otp_static_token_norm_idx',
            ),
        ),
    ]
