from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from .models import Personne, Startup, BureauEtude
from .serializers import PersonneSerializer, StartupSerializer, BureauEtudeSerializer, RegisterStartupSerializer, RegisterSerializer
from rest_framework.permissions import AllowAny
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.exceptions import APIException
from .authentication import create_access_token, create_refresh_token


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            raise APIException('Email and password are required!')

        user = None
        t = None

        for model in [Startup, Personne, BureauEtude]:
            user = model.objects.filter(email=email).first()
            if user:
                if model==Personne:
                    t=user.id_personne
                elif model==Startup:
                    t=user.id_startup
                else:
                    t=user.id_bureau        
                break

        if not user:
            raise APIException('Invalid credentials!')
     
        elif not user.check_password(request.data['password']): #not check_password(password, user.password):
            raise APIException('Invalid password!')

        access_token = create_access_token(t, user.nom)
        refresh_token = create_refresh_token(t, user.nom)

        response = Response()
        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token,
        }

        return response

     

# For creating and listing Personne objects
class PersonneListCreateView(generics.ListCreateAPIView):
    queryset = Personne.objects.all()
    serializer_class = RegisterSerializer

# For creating and listing Startup objects
class StartupListCreateView(generics.ListCreateAPIView):
    queryset = Startup.objects.all()
    serializer_class = RegisterStartupSerializer

# For listing BureauEtude objects (assuming no POST method here)
class BureauEtudeListView(generics.ListAPIView):
    queryset = BureauEtude.objects.all()
    serializer_class = BureauEtudeSerializer

@api_view(['GET', 'POST'])
def personne_view(request):
    if request.method == 'GET':
        personnes = Personne.objects.all()
        serializer = PersonneSerializer(personnes, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def startup_view(request):
    if request.method == 'GET':
        startups = Startup.objects.all()
        serializer = StartupSerializer(startups, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = RegisterStartupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def bureau_etude_view(request):
    if request.method == 'GET':
        bureau_etudes = BureauEtude.objects.all()
        serializer = BureauEtudeSerializer(bureau_etudes, many=True)
        return Response(serializer.data)
