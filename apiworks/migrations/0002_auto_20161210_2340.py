# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-12-10 23:40
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('apiworks', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='CloudAPI',
            new_name='APIWorks',
        ),
        migrations.AlterModelTable(
            name='apiworks',
            table='api_works',
        ),
    ]
