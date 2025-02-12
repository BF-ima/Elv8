from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Create your models here.

class PersonneManager(BaseUserManager):
    def create_user(self, email, nom, numero_telephone, genre, adresse, wilaya, date_naissance, titre_role, description_role,  password):
        if not email:
            raise ValueError('The Email field must be set')
        user = self.model(
            email=self.normalize_email(email),
            nom=nom,
            numero_telephone=numero_telephone,
            genre=genre,
            adresse=adresse,
            wilaya=wilaya,
            date_naissance=date_naissance,
            titre_role=titre_role,
            description_role=description_role,
        )
        extra_fields.setdefault('is_active', True)
        user.set_password(password)
        user.save(using=self._db)
        return user


class StartupManager(BaseUserManager):
    def create_user(self, nom, adresse, numero_telephone, email, wilaya, description, date_creation, password):
        if not email:
            raise ValueError('The Email field must be set')
        user = self.model(
            email=self.normalize_email(email),
            nom=nom,
            numero_telephone=numero_telephone,
            adresse=adresse,
            wilaya=wilaya,
            date_creation=date_creation,
            description=description,
            secteur=secteur,
        )
        extra_fields.setdefault('is_active', True)
        user.set_password(password)
        user.save(using=self._db)
        return user


class Personne(AbstractBaseUser):

    LEADER = 'Leader'
    MEMBER = 'Member'
    
    ROLE_CHOICES = [
        (LEADER, 'Leader'),
        (MEMBER, 'Member'),
    ]

    HOMME = 'Homme'
    FEMME = 'Femme'

    GENDER_CHOICES = [
        (HOMME, 'Homme'),
        (FEMME, 'Femme'),
    ]

    nom = models.CharField(max_length=255)
    genre = models.CharField(max_length=50, choices=GENDER_CHOICES)
    is_active = models.BooleanField(default=True)
    id_personne = models.AutoField(primary_key=True)
    adresse = models.TextField()
    numero_telephone = models.CharField(max_length=10, unique=True)
    email = models.EmailField(unique=True)
    wilaya = models.CharField(max_length=100)
    date_naissance = models.DateField()
    id_startup = models.IntegerField(null=True, blank=True)
    titre_role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    description_role = models.TextField()
    est_actif = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    objects = PersonneManager()


    class Meta:
        db_table = 'personne'
        managed = True   

     #def check_password(self, raw_password):
       # from django.contrib.auth.hashers import check_password
        #return check_password(raw_password, self.password)

    def __str__(self):
        return self.email


class BureauEtude(models.Model):
    id_bureau = models.AutoField(primary_key=True)  # ID auto-incrémenté
    date_creation = models.DateField(verbose_name="Date de création")
    nom = models.CharField(max_length=255, verbose_name="Nom")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone")
    email = models.EmailField(unique=True, verbose_name="Email")
    adresse = models.TextField(verbose_name="Adresse")
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya")
    description = models.TextField(blank=True, null=True, verbose_name="Description")
    password = models.CharField(max_length=128, default="default_password")
    
    def __str__(self):
        return self.nom

class Startup(AbstractBaseUser):
    id_startup = models.AutoField(primary_key=True)
    date_creation = models.DateField(verbose_name="Date de création")
    description = models.TextField(verbose_name="Description")
    nom = models.CharField(max_length=255, verbose_name="Nom")
    is_active = models.BooleanField(default=True)
    adresse = models.TextField(verbose_name="Adresse")
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya")
    email = models.EmailField(unique=True, verbose_name="Email")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone")
    password = models.CharField(max_length=128, default="default_password")
    TYPE_S = [
        ('Tech', 'Technologie'),
        ('Health', 'Santé'),
        ('Finance', 'Finance'),
    ]
    secteur = models.CharField(max_length=50, choices=TYPE_S, verbose_name="Secteur d'activité")

    # ForeignKey to Personne, ensuring only one leader per startup
    leader = models.ForeignKey('Personne', on_delete=models.CASCADE, related_name='startups', null=True, blank=True)      

    USERNAME_FIELD = "email"
    objects = StartupManager()

    class Meta:
        db_table = "startup"  # Define custom table name
        managed = True  # Ensure Django manages this model

     #def check_password(self, raw_password):
     #   from django.contrib.auth.hashers import check_password
        #return check_password(raw_password, self.password)

    def __str__(self):
        return self.email    