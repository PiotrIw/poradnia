# Generated by Django 4.2.11 on 2024-04-02 08:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0041_alter_case_status"),
    ]

    operations = [
        migrations.AlterField(
            model_name="case",
            name="name",
            field=models.CharField(max_length=250, verbose_name="Subject"),
        ),
    ]