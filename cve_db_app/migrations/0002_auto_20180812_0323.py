# Generated by Django 2.0.6 on 2018-08-12 03:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cve_db_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerability',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cve_db_app.Device'),
        ),
    ]
