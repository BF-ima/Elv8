# Generated by Django 5.1.5 on 2025-01-31 09:17

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BureauEtude',
            fields=[
                ('id_bureau', models.AutoField(primary_key=True, serialize=False)),
                ('date_creation', models.DateField(verbose_name='Date de création')),
                ('nom', models.CharField(max_length=255, verbose_name='Nom')),
                ('numero_telephone', models.CharField(max_length=10, verbose_name='Numéro de téléphone')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email')),
                ('adresse', models.TextField(verbose_name='Adresse')),
                ('wilaya', models.CharField(max_length=100, verbose_name='Wilaya')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Description')),
            ],
        ),
        migrations.CreateModel(
            name='Personne',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('nom', models.CharField(max_length=255)),
                ('genre', models.CharField(max_length=50)),
                ('id_personne', models.AutoField(primary_key=True, serialize=False)),
                ('adresse', models.TextField()),
                ('numero_telephone', models.CharField(max_length=10, unique=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('wilaya', models.CharField(max_length=100)),
                ('date_naissance', models.DateField()),
                ('id_startup', models.IntegerField(blank=True, null=True)),
                ('titre_role', models.CharField(choices=[('Leader', 'Leader'), ('Member', 'Member')], max_length=10)),
                ('description_role', models.TextField()),
                ('est_actif', models.BooleanField(default=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Startup',
            fields=[
                ('id_startup', models.AutoField(primary_key=True, serialize=False)),
                ('date_creation', models.DateField(verbose_name='Date de création')),
                ('description', models.TextField(verbose_name='Description')),
                ('nom', models.CharField(max_length=255, verbose_name='Nom')),
                ('adresse', models.TextField(verbose_name='Adresse')),
                ('wilaya', models.CharField(max_length=100, verbose_name='Wilaya')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email')),
                ('numero_telephone', models.CharField(max_length=10, verbose_name='Numéro de téléphone')),
                ('secteur', models.CharField(choices=[('Tech', 'Technologie'), ('Health', 'Santé'), ('Finance', 'Finance')], max_length=50, verbose_name="Secteur d'activité")),
                ('leader', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='startups', to='account.personne')),
            ],
        ),
    ]
