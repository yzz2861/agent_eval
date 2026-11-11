from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0010_textpkmodel"),
    ]

    operations = [
        migrations.CreateModel(
            name="PostProxy",
            fields=[],
            options={
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("testapp.post",),
        ),
    ]
