# Generated by Django 2.0.7 on 2018-08-01 02:53

import django.contrib.postgres.fields.hstore
from django.db import migrations, models
from django.contrib.postgres.operations import HStoreExtension
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        #Set up the hstore extension in PostgreSQL for the Scan Results data
        HStoreExtension(),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('device_name', models.CharField(max_length=200)),
                ('dns_name', models.CharField(max_length=200)),
                ('device_ip', models.GenericIPAddressField()),
                ('device_version', models.CharField(max_length=200)),
                ('device_net_bios', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_date', models.DateTimeField(verbose_name='scan date')),
                ('scan_results', django.contrib.postgres.fields.hstore.HStoreField()),
            ],
        ),
        migrations.CreateModel(
            name='Site',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('site_name', models.CharField(max_length=200)),
            ],
        ),
        migrations.AddField(
            model_name='device',
            name='site',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cve_db_app.Site'),
        ),
    ]
