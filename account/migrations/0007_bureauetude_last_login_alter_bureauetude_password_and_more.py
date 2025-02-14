# Generated by Django 5.1.5 on 2025-02-12 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_alter_personne_options_alter_startup_options_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='bureauetude',
            name='last_login',
            field=models.DateTimeField(blank=True, null=True, verbose_name='last login'),
        ),
        migrations.AlterField(
            model_name='bureauetude',
            name='password',
            field=models.CharField(max_length=128, verbose_name='password'),
        ),
        migrations.AlterField(
            model_name='startup',
            name='password',
            field=models.CharField(max_length=128, verbose_name='password'),
        ),
    ]
