from rest_framework import serializers
from .models import Personne, Startup, BureauEtude
from django.contrib.auth.password_validation import validate_password 
from rest_framework.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.contrib.auth.backends import ModelBackend
   
    
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Personne
        fields = [
            'nom', 'genre', 'adresse', 'numero_telephone', 'email',
            'wilaya', 'date_naissance', 'titre_role', 'description_role', 'password2', 'password'
        ]  # Removed 'id_startup'
    
    def validate(self, attrs):
        # Validate that password and password2 match
        if attrs['password'] != attrs['password2']:
            raise ValidationError({"password": "Password fields didn't match."})
        if len(attrs['numero_telephone']) != 10:
            raise ValidationError({"numero_telephone": "Phone number must be 10 digits."})    
        return attrs
       
    def create(self, validated_data):
        validated_data.pop('password2')  # Remove 'password2' since it's not part of the model
        return Personne.objects.create_user(**validated_data)


class RegisterStartupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)  # 🔹 Ensure password is not exposed

    class Meta:
        model = Startup
        fields = ['nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation', 'secteur', 'password2', 'password'] # Excludes 'id_startup'
    
    def validate(self, attrs):
        # Validate that password and password2 match
        if attrs['password'] != attrs['password2']:
            raise ValidationError({"password": "Password fields didn't match."})
        if len(attrs['numero_telephone']) != 10:
            raise ValidationError({"numero_telephone": "Phone number must be 10 digits."})    
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        validated_data['password'] = make_password(validated_data['password'])  # 🔹 Hash password
        return Startup.objects.create(**validated_data)



class PersonneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Personne
        fields = ['nom', 'genre', 'adresse', 'numero_telephone', 'email', 'wilaya', 'date_naissance', 'titre_role', 'description_role']

class StartupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Startup
        fields = ['nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation', 'secteur']


class BureauEtudeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Startup
        fields = ['nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation']       