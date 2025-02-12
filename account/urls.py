from django.urls import path
from .views import PersonneListCreateView, StartupListCreateView, BureauEtudeListView, LoginAPIView





urlpatterns = [
    path('login', LoginAPIView.as_view()),
    path('personne/', PersonneListCreateView.as_view(), name='personne_list_create'),
    path('startup/', StartupListCreateView.as_view(), name='startup_list_create'),
    path('bureau/', BureauEtudeListView.as_view(), name='bureau_etude_list'),
    
    ]
