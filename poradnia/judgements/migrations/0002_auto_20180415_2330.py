# Generated by Django 1.11.8 on 2018-04-15 21:30
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("judgements", "0001_initial")]

    operations = [
        migrations.AlterField(
            model_name="court",
            name="parser_key",
            field=models.CharField(
                blank=True,
                help_text="Identifier of parser",
                max_length=25,
                verbose_name="Parser key",
            ),
        )
    ]
