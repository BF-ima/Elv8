# Generated by Django 5.1.5 on 2025-02-11 11:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0003_alter_personne_genre'),
    ]

    operations = [
        migrations.AddField(
            model_name='startup',
            name='last_login',
            field=models.DateTimeField(blank=True, null=True, verbose_name='last login'),
        ),
    ]
