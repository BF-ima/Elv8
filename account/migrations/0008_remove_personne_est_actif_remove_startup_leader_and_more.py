# Generated by Django 5.1.5 on 2025-03-06 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0007_bureauetude_last_login_alter_bureauetude_password_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='personne',
            name='est_actif',
        ),
        migrations.RemoveField(
            model_name='startup',
            name='leader',
        ),
        migrations.AddField(
            model_name='startup',
            name='date_naissance_leader',
            field=models.DateField(default='1990-01-01'),
        ),
        migrations.AddField(
            model_name='startup',
            name='genre_leader',
            field=models.CharField(choices=[('Homme', 'Homme'), ('Femme', 'Femme')], default='Homme', max_length=50),
        ),
        migrations.AddField(
            model_name='startup',
            name='nom_leader',
            field=models.CharField(default='Nom par défaut', max_length=255),
        ),
        migrations.AlterField(
            model_name='personne',
            name='titre_role',
            field=models.CharField(max_length=100),
        ),
    ]
