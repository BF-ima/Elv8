# Generated by Django 5.2 on 2025-05-21 11:59

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0013_auto_20250419_2035'),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='BlacklistedToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=500, unique=True)),
                ('blacklisted_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'blacklisted_tokens',
            },
        ),
        migrations.CreateModel(
            name='ConsultationType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='PasswordResetCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('code', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.RenameField(
            model_name='bureauetudeprofile',
            old_name='site_web',
            new_name='website',
        ),
        migrations.RenameField(
            model_name='startupprofile',
            old_name='site_web',
            new_name='website',
        ),
        migrations.RemoveField(
            model_name='bureauetudeprofile',
            name='domaines_expertise',
        ),
        migrations.RemoveField(
            model_name='bureauetudeprofile',
            name='logo',
        ),
        migrations.RemoveField(
            model_name='personneprofile',
            name='photo',
        ),
        migrations.RemoveField(
            model_name='startupprofile',
            name='social_media',
        ),
        migrations.RemoveField(
            model_name='startupprofile',
            name='stade_developpement',
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to='bureau_avatars/'),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='bio',
            field=models.TextField(blank=True, help_text='Short description or role (e.g., CEO of ConsultingName)', null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='date_creation',
            field=models.DateField(null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='facebook',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='linkedin',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='location',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='phone',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='bureauetudeprofile',
            name='whatsapp',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to='personne_avatars/'),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='bio',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='date_of_birth',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='facebook',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='first_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='gender',
            field=models.CharField(blank=True, choices=[('Male', 'Male'), ('Female', 'Female')], max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='last_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='location',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='phone',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='personneprofile',
            name='whatsapp',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='date_creation',
            field=models.DateField(null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='facebook',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='industry',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_avatar',
            field=models.ImageField(blank=True, null=True, upload_to='personne_avatars/'),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_bio',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_date_of_birth',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_facebook',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_first_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_gender',
            field=models.CharField(blank=True, choices=[('Male', 'Male'), ('Female', 'Female')], max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_last_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_linkedin',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_location',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_phone',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='leader_whatsapp',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='linkedin',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='location',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='members',
            field=models.ManyToManyField(related_name='startups', to='account.personne'),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='owner_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='phone',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='startupprofile',
            name='whatsapp',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='personneprofile',
            name='personne',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='profile', to='account.personne'),
        ),
        migrations.AlterField(
            model_name='startupprofile',
            name='startup',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='profile', to='account.startup'),
        ),
        migrations.CreateModel(
            name='ConsultationRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('problem_description', models.TextField()),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected'), ('completed', 'Completed')], default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('bureau', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='consultation_requests', to='account.bureauetude')),
                ('startup', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='consultation_requests', to='account.startup')),
                ('consultation_type', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='account.consultationtype')),
            ],
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('event_date', models.CharField(max_length=100)),
                ('owner_id', models.PositiveIntegerField(blank=True, null=True)),
                ('with_who', models.CharField(blank=True, max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('event_type', models.CharField(choices=[('Startup Consultation', 'Startup Consultation'), ('Progress Review', 'Progress Review')], default='Video Meeting', max_length=40)),
                ('owner_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
            ],
        ),
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField()),
                ('rating', models.IntegerField(choices=[(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5')])),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('bureau', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.bureauetude')),
                ('personne', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='account.personne')),
                ('startup', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='account.startup')),
            ],
        ),
        migrations.CreateModel(
            name='PaymentRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('payment_method', models.CharField(default='Baird Mob', max_length=100)),
                ('is_paid', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('consultation', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='payment_request', to='account.consultationrequest')),
            ],
        ),
    ]
