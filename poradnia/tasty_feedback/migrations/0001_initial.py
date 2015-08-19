# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.timezone
from django.conf import settings
import model_utils.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('text', models.TextField(help_text='Text reported by user', verbose_name='Comment')),
                ('status', models.BooleanField(default=False, help_text='Feedback has been served', verbose_name='Status')),
                ('status_changed', model_utils.fields.MonitorField(default=django.utils.timezone.now, verbose_name='Status change date', monitor=b'status')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='Creation date')),
                ('user', models.ForeignKey(help_text='Author', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Feedback',
                'verbose_name_plural': 'Feedbacks',
            },
            bases=(models.Model,),
        ),
    ]