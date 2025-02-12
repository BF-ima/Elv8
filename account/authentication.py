import jwt, datetime
from rest_framework import exceptions


def create_access_token(id, nom):
    return jwt.encode({ 
        'name': nom,
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')

def create_refresh_token(id, nom):
    return jwt.encode({
        'name': nom,
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')    