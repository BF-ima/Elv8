from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
import uuid
import os
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
User = get_user_model()
# Create your models here.


class StartupSignupRequest(models.Model):
    # Basic info
    nom = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # Store hashed password!
    
    # Leader info
    nom_leader = models.CharField(max_length=255,null=True,blank=True)
    genre_leader = models.CharField(max_length=50,null=True,blank=True)
    date_naissance_leader = models.DateField(null=True,blank=True)
    
    # Startup details
    adresse = models.TextField(null=True,blank=True)
    numero_telephone = models.CharField(max_length=10,null=True,blank=True)
    wilaya = models.CharField(max_length=100,null=True,blank=True)
    description = models.TextField(blank=True, null=True)
    date_creation = models.DateField(null=True,blank=True)
    secteur = models.CharField(max_length=50,null=True,blank=True)
    
    # Document upload
    
    document = models.FileField(upload_to='startup_documents/')
    
    # Admin review fields
    is_processed = models.BooleanField(default=False)
    is_approved = models.BooleanField(null=True)  # None = pending, True = approved, False = rejected
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.nom} ({self.email})"

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
        user.set_password(password)
        user.save(using=self._db)
        return user


class StartupManager(BaseUserManager):
    def create_user(self, genre_leader, nom_leader, date_naissance_leader, nom, adresse, numero_telephone, email, wilaya, description, date_creation, secteur, password):
        if not email:
            raise ValueError('The Email field must be set')
        user = self.model(
            email=self.normalize_email(email),
            nom_leader=nom_leader,
            genre_leader=genre_leader,
            date_naissance_leader=date_naissance_leader,
            nom=nom,
            numero_telephone=numero_telephone,
            adresse=adresse,
            wilaya=wilaya,
            date_creation=date_creation,
            description=description,
            secteur=secteur,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


class Personne(AbstractBaseUser):

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
    titre_role = models.CharField(max_length=100)
    description_role = models.TextField()
    startups = models.ManyToManyField(
        'Startup',
        related_name='personne_memberships',
        blank=True
    )


    USERNAME_FIELD = "email"
    objects = PersonneManager()


    class Meta:
        db_table = 'personne'
        managed = True   


    def __str__(self):
        return self.email


class BureauEtude(AbstractBaseUser):
    id_bureau = models.AutoField(primary_key=True)
    date_creation = models.DateField(verbose_name="Date de création")
    nom = models.CharField(max_length=255, verbose_name="Nom")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone")
    email = models.EmailField(unique=True, verbose_name="Email")
    adresse = models.TextField(verbose_name="Adresse")
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya")
    description = models.TextField(blank=True, null=True, verbose_name="Description")

    USERNAME_FIELD = "email"
    
    def __str__(self):
        return self.nom

class Startup(AbstractBaseUser):
    HOMME = 'Homme'
    FEMME = 'Femme'

    GENDER_CHOICES = [
        (HOMME, 'Homme'),
        (FEMME, 'Femme'),
    ]
    nom_leader = models.CharField(max_length=255,null=True,blank=True)  
    genre_leader = models.CharField(max_length=50, choices=GENDER_CHOICES,null=True,blank=True)  
    date_naissance_leader = models.DateField(null=True,blank=True)
    id_startup = models.AutoField(primary_key=True)
    date_creation = models.DateField(verbose_name="Date de création",null=True,blank=True)
    description = models.TextField(verbose_name="Description",null=True,blank=True)
    nom = models.CharField(max_length=255, verbose_name="Nom")
    is_active = models.BooleanField(default=True)
    adresse = models.TextField(verbose_name="Adresse",null=True,blank=True)
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya",null=True,blank=True)
    email = models.EmailField(unique=True, verbose_name="Email")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone",null=True,blank=True)
    TYPE_S = [
        ('Tech', 'Technologie'),
        ('Health', 'Santé'),
        ('Finance', 'Finance'),
    ]
    secteur = models.CharField(max_length=50, choices=TYPE_S, verbose_name="Secteur d'activité",null=True,blank=True)
     #Added many-to-many relationship with Personne as members
    members = models.ManyToManyField(Personne, through='StartupMember', related_name='member_of_startups')      
    document = models.FileField(upload_to='startup_documents/',null=True,blank=True)

    USERNAME_FIELD = "email"
    objects = StartupManager()

    class Meta:
        db_table = "startup"  # Define custom table name
        managed = True  # Ensure Django manages this model
   

    def __str__(self):
        return self.email    

class StartupMember(models.Model):
    # Through model for the many-to-many relationship between Startup and Personne
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE)
    personne = models.ForeignKey(Personne, on_delete=models.CASCADE)
    date_joined = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=100, blank=True, null=True)  # Role within the startup

    class Meta:
        unique_together = ('startup', 'personne')  # A person can only be a member of a startup once

    def __str__(self):
        return f"{self.personne.nom} - {self.startup.nom}"


class Feedback(models.Model):
    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE)
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, null=True, blank=True)
    personne = models.ForeignKey(Personne, on_delete=models.CASCADE, null=True, blank=True)
    
    comment = models.TextField()
    rating = models.IntegerField(choices=[(i, str(i)) for i in range(1, 6)])  # 1 to 5 stars
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback ({self.rating}★) from {self.startup or self.personne} to {self.bureau}"
       

class PersonneProfile(models.Model):
    personne = models.OneToOneField(Personne, on_delete=models.CASCADE, related_name='profile',null=True,blank=True)#nulled

    avatar = models.ImageField(upload_to='personne_avatars/', blank=True, null=True)
    
    first_name = models.CharField(max_length=100,null=True,blank=True)#nulled
    last_name = models.CharField(max_length=100,null=True,blank=True)#nulled
    
    date_of_birth = models.DateField(null=True,blank=True)#nulled
    gender = models.CharField(max_length=10, choices=[("Male", "Male"), ("Female", "Female")],null=True,blank=True)#nulled
    
    bio = models.TextField(blank=True, null=True)  # e.g., "Co-CEO of Startup"

    phone = models.CharField(max_length=20,null=True,blank=True)#nulled

    email = models.EmailField(null=True,blank=True)#nulled
    location = models.CharField(max_length=255,null=True,blank=True)#nulled

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    startups = models.ManyToManyField(
        'Startup',
        related_name='memberss'
    )


    def __str__(self):
        return f"{self.first_name} {self.last_name} Profile"               

class BureauEtudeProfile(models.Model):
    bureau = models.OneToOneField(BureauEtude, on_delete=models.CASCADE, related_name='profile')

    avatar = models.ImageField(upload_to='bureau_avatars/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True, help_text="Short description or role (e.g., CEO of ConsultingName)")

    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    location = models.CharField(max_length=255, null=True, blank=True)#nulled 

    date_creation = models.DateField(null=True)

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    website = models.URLField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.bureau.nom}"

class StartupProfile(models.Model):
    startup = models.OneToOneField(Startup, on_delete=models.CASCADE, related_name='profile',null=True,blank=True)#nulled

    ## leader info 

    leader_avatar = models.ImageField(upload_to='personne_avatars/', blank=True, null=True)
    
    leader_first_name = models.CharField(max_length=100,null=True,blank=True)#nulled
    leader_last_name = models.CharField(max_length=100,null=True,blank=True)#nulled
    
    leader_date_of_birth = models.DateField(null=True,blank=True)#nulled
    leader_gender = models.CharField(max_length=10, choices=[("Male", "Male"), ("Female", "Female")],null=True,blank=True)#nulled
    
    leader_bio = models.TextField(blank=True, null=True)  # e.g., "Co-CEO of Startup"

    leader_phone = models.CharField(max_length=20,null=True,blank=True)#nulled

    leader_email = models.EmailField(null=True,blank=True)#nulled
    leader_location = models.CharField(max_length=255,null=True,blank=True)#nulled

    leader_facebook = models.URLField(blank=True, null=True)
    leader_linkedin = models.URLField(blank=True, null=True)
    leader_whatsapp = models.CharField(max_length=20, blank=True, null=True)

    
    ## startup info 

    logo = models.ImageField(upload_to='startup_logos', blank=True, null=True)
    owner_name = models.CharField(max_length=100,null=True,blank=True)  # "Owned by Fatima Ben Ali" #nulled
    
    phone = models.CharField(max_length=10,null=True,blank=True)#nulled

    email = models.EmailField(null=True,blank=True)#nulled
    location = models.CharField(max_length=255,null=True,blank=True)  # e.g., "Algeria, Sidi Bel Abbes"   #nulled

    industry = models.CharField(max_length=100,null=True,blank=True)#nulled
    description = models.TextField(null=True,blank=True)#nulled

    website = models.URLField(blank=True, null=True)
    
    date_creation = models.DateField(null=True)

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #  memebers of the startup

    members = models.ManyToManyField(
        'Personne',
        related_name='profile_memberships',
        blank=True
    )

    def __str__(self):
        return f"Profile of {self.startup.nom}"  


class Chat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE, related_name='chats')
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, related_name='chats')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_message_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('bureau', 'startup')

    def __str__(self):
        return f"Chat between {self.bureau.nom} and {self.startup.nom}"


def message_file_path(instance, filename):
    """Generate a structured file path for each message attachment."""
    ext = filename.split('.')[-1]
    filename = f"{uuid4()}.{ext}"  # Generates a unique file name
    return os.path.join('messages', str(instance.chat.id), filename)

class Message(models.Model):
    # Updated Message model to support different content types
    TEXT = 'text'
    IMAGE = 'image'
    VIDEO = 'video'
    FILE = 'file'
    AUDIO = 'audio'
    
    CONTENT_TYPE_CHOICES = [
        (TEXT, 'Text'),
        (IMAGE, 'Image'),
        (VIDEO, 'Video'),
        (FILE, 'File'),
        (AUDIO, 'Audio'),
    ]
    
    # Type choices for the sender and receiver
    BUREAU = 'bureau'
    STARTUP = 'startup'
    
    ENTITY_TYPE_CHOICES = [
        (BUREAU, 'Bureau d\'Étude'),
        (STARTUP, 'Startup'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    
    # Sender information
    sender_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    sender_id = models.IntegerField()  # ID of the sender (bureau_id or startup_id)
    
    # Receiver information
    receiver_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    receiver_id = models.IntegerField()  # ID of the receiver
    
    # Content type and actual content
    content_type = models.CharField(max_length=5, choices=CONTENT_TYPE_CHOICES, default=TEXT)
    text_content = models.TextField(blank=True, null=True)
    media_file = models.FileField(upload_to=message_file_path, blank=True, null=True)
    
    # Metadata
    timestamp = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['timestamp']
    
    def __str__(self):
        return f"Message in {self.chat} at {self.timestamp}"

    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])


# Message Content models to associate with a message
class MessageAttachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to=message_file_path)
    file_name = models.CharField(max_length=255)
    file_size = models.IntegerField()  # Size in bytes
    file_type = models.CharField(max_length=100)  # MIME type
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Attachment for {self.message}" 


"""class ConsultationType(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name
"""
class ConsultationRequest(models.Model):
    PENDING = 'pending'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    COMPLETED = 'completed'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (ACCEPTED, 'Accepted'),
        (REJECTED, 'Rejected'),
        (COMPLETED, 'Completed'),
    ]
    
    FINANCIAL = 'Financial'
    STRATEGIC = 'Strategic'
    IT= 'It'
    
    
    ConsultationTypes_CHOICES = [
        (FINANCIAL, 'Financial'),
        (STRATEGIC, 'Strategic'),
        (IT, 'It'),
    ]
    
    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE, related_name='consultation_requests')
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, related_name='consultation_requests')
    #consultation_type = models.ForeignKey(ConsultationType, on_delete=models.SET_NULL, null=True)
    consultation_type = models.CharField(max_length=30, choices=ConsultationTypes_CHOICES, default=STRATEGIC)
    problem_description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Consultation request from {self.startup.nom} to {self.bureau.nom}"

class PaymentRequest(models.Model):
    consultation = models.OneToOneField(ConsultationRequest, on_delete=models.CASCADE, related_name='payment_request')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=100, default='Baird Mob')
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Payment request for {self.consultation} - {self.amount} DA"
    
#addedddddddddddddddddddddd

class PasswordResetCode(models.Model): 
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + datetime.timedelta(minutes=10)  # code expires in 10 min        


class Event(models.Model):
    title = models.CharField(max_length=255)
    event_date = models.CharField(max_length=100)
    
    # Generic Foreign Key for multiple user types
    owner_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True) 
    owner = GenericForeignKey('owner_type', 'owner_id')
    
    with_who = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    Startup_Consultation = 'Startup Consultation'
    Progress_Review = 'Progress Review'
    
    EVENT_TYPE_CHOICES = [
        (Startup_Consultation, 'Startup Consultation'),
        (Progress_Review, 'Progress Review'),
    ]
    
    event_type = models.CharField(
        max_length=40,
        choices=EVENT_TYPE_CHOICES,
        default='Video Meeting',  # Optional: set a default
    )
    
    
    

class BlacklistedToken(models.Model):# addeddddddddddddddd
    token = models.CharField(max_length=500, unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"Token blacklisted at {self.blacklisted_at}"

    class Meta:
        db_table = 'blacklisted_tokens'    
    
    
    