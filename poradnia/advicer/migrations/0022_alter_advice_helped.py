# Generated by Django 3.2.18 on 2023-02-16 15:52

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("advicer", "0021_auto_20191015_0510"),
    ]

    operations = [
        migrations.AlterField(
            model_name="advice",
            name="helped",
            field=models.BooleanField(blank=True, null=True, verbose_name="We helped?"),
        ),
    ]
