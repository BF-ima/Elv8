import jwt, datetime
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from .models import Personne, Startup, BureauEtude, BlacklistedToken
from datetime import datetime, timedelta #addedddddddddddddd
from django.conf import settings #added
from django.core.mail import send_mail#added

def create_access_token(id, nom):
    return jwt.encode({ 
        'name': nom,
        'user_id': id,
        #'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),  these 2 lines are removed; the 2 lines below were added
        #'iat': datetime.datetime.utcnow()
        'exp': datetime.utcnow() + timedelta(minutes=50),
        'iat': datetime.utcnow()
    }, 'access_secret', algorithm='HS256')

def create_refresh_token(id, nom):
    return jwt.encode({
        'name': nom,
        'user_id': id,
        #'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),  these 2 lines are removed; the 2 lines below were added
        #'iat': datetime.datetime.utcnow()
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')    
    


class CustomJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split(' ')
            if prefix.lower() != 'bearer':
                raise exceptions.AuthenticationFailed('Invalid token prefix')
        except ValueError:
            raise exceptions.AuthenticationFailed('Invalid authorization header')

        # Check if token is blacklisted
        if BlacklistedToken.objects.filter(token=token).exists():
            raise exceptions.AuthenticationFailed('Token has been invalidated')

        try:
            # Try to decode the token
            payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])
            
            # Check if token has expired
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp) < datetime.now():
                raise exceptions.AuthenticationFailed('Token has expired')
                
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('Invalid token')

        user_id = payload.get('user_id')
        name = payload.get('name')

        # Search in all user models
        user = None
        for model in [Personne, Startup, BureauEtude]:
            user = model.objects.filter(nom=name).first()
            if user:
                break

        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        return (user, None)
    




def generate_reset_token(id, nom):          #addedddddddddddddddddddddddddddddddddddddddd
    payload = {
        'user_id': id,
        'nom': nom,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow()
        
    }
    return jwt.encode(payload, 'reset_secret', algorithm='HS256')

def send_reset_email(email, token):
    reset_link = f"http://localhost:8000/reset-password?token={token}"
    subject = "Password Reset Request"
    message = f"Click the following link to reset your password: {reset_link}"
    send_mail(subject, message, 'noreply@example.com', [email])