from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("axes", "0010_accessattemptexpiration"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessattempt",
            name="http_referer",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="HTTP Referer",
            ),
        ),
        migrations.AddField(
            model_name="accessfailurelog",
            name="http_referer",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="HTTP Referer",
            ),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="http_referer",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="HTTP Referer",
            ),
        ),
        migrations.AddField(
            model_name="accessfailurelog",
            name="session_hash",
            field=models.CharField(
                blank=True,
                default="",
                max_length=64,
                verbose_name="Session key hash (sha256)",
            ),
        ),
    ]
