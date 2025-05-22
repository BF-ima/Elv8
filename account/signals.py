from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import StartupSignupRequest, Startup
from django.core.mail import send_mail

@receiver(post_save, sender=StartupSignupRequest)
def handle_startup_signup_approval(sender, instance, created, **kwargs):
    if instance.is_processed and instance.is_approved and not created:
        # Check if the Startup already exists to avoid duplicates
        if not Startup.objects.filter(email=instance.email).exists():
            Startup.objects.create(
                nom=instance.nom,
                email=instance.email,
                password=instance.password,  # already hashed!
                nom_leader=instance.nom_leader,
                genre_leader=instance.genre_leader,
                date_naissance_leader=instance.date_naissance_leader,
                adresse=instance.adresse,
                numero_telephone=instance.numero_telephone,
                wilaya=instance.wilaya,
                description=instance.description,
                date_creation=instance.date_creation,
                secteur=instance.secteur,
                document=instance.document,
            )
            send_mail(
                'Your account is approved!',
                'You can now log in at http://localhost:8000/login',
                'emenoellin@gmail.com',
                [instance.email]
            )