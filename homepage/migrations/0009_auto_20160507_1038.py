# -*- coding: utf-8 -*-
# Generated by Django 1.9.4 on 2016-05-07 10:38
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('homepage', '0008_columnmenu'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='columnmenu',
            name='column',
        ),
        migrations.DeleteModel(
            name='ColumnMenu',
        ),
    ]