# Generated by Django 5.2 on 2025-05-22 13:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0018_startupsignuprequest'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='adresse',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='date_creation',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='date_naissance_leader',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='description',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='genre_leader',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='nom_leader',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='numero_telephone',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='secteur',
        ),
        migrations.RemoveField(
            model_name='startupsignuprequest',
            name='wilaya',
        ),
    ]
