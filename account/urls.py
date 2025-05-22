from django.urls import path, include
from .views import PersonneListCreateView, StartupListCreateView, BureauEtudeListView, LoginAPIView, ChatViewSet, MessageViewSet, PersonneProfileViewSet, StartupProfileViewSet, BureauEtudeProfileViewSet, FeedbackViewSet
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import MemberSearchView, MemberManagementViewSet, BureauEtudeSearchView, BureauEtudeDetailView
from .views import ChangePasswordView, ForgotPasswordAPIView, ResetPasswordAPIView,LogoutAPIView, DeleteAccountView, EventListCreateAPIView, EventRetrieveUpdateDestroyAPIView
from .views import (
  
    ConsultationRequestViewSet,
    ConsultationRequestActionView,
    PaymentRequestViewSet,
    dashboard_stats,
    member_dashboard_stats,
    AdminStartupSignupRequestViewSet,
    StartupSignupRequestView
)



# Create a router for the main viewsets
router = DefaultRouter()
router.register(r'chats', ChatViewSet, basename='chat')
# Other router registrations...
router.register(r'personne-profiles', PersonneProfileViewSet, basename='personne-profile')
router.register(r'startup-profiles', StartupProfileViewSet, basename='startup-profile')
router.register(r'bureau-profiles', BureauEtudeProfileViewSet, basename='bureau-profile')

router.register(r'feedbacks', FeedbackViewSet, basename='feedback')

# Create a nested router for the messages within chats
chat_router = routers.NestedSimpleRouter(router, r'chats', lookup='chat')
chat_router.register(r'messages', MessageViewSet, basename='chat-messages')

chat_router.register(r'messages/(?P<message_id>[^/.]+)/mark_as_read', MessageViewSet, basename='mark_as_read')
router.register(r'members', MemberManagementViewSet, basename='member-management')   
router.register(r'consultation-requests', ConsultationRequestViewSet, basename='consultation-request')
router.register(r'startup-signup-requests', AdminStartupSignupRequestViewSet, basename='startup-signup-request')
urlpatterns = [
    path('login', LoginAPIView.as_view()),
    path('personne/', PersonneListCreateView.as_view(), name='personne_list_create'),
    path('startup/', StartupListCreateView.as_view(), name='startup_list_create'),
    path('bureau/', BureauEtudeListView.as_view(), name='bureau_etude_list'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password'),#addedddddddd
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),#addeddddddd
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),
    path('events/', EventListCreateAPIView.as_view(), name='event-list-create'),
    path('events/<int:id>/', EventRetrieveUpdateDestroyAPIView.as_view(), name='event-retrieve-update-destroy'),
    path('', include(router.urls)),
    path('', include(chat_router.urls)),
    path('members/search/', MemberSearchView.as_view(), name='member-search'),
    path('startup-signup/', StartupSignupRequestView.as_view(), name='startup-signup'),
    path('bureau/search/', BureauEtudeSearchView.as_view(), name='bureau-search'),
    path('bureau/<int:pk>/', BureauEtudeDetailView.as_view(), name='bureau-detail'),
    #path('consultation-types/', ConsultationTypeListView.as_view(), name='consultation-types'),
    path('consultation-requests/<int:pk>/<str:action>/', ConsultationRequestActionView.as_view(), name='consultation-action'),
    path('dashboard-stats/', dashboard_stats, name='dashboard-stats'),
    path('member-dashboard-stats/', member_dashboard_stats, name='member-dashboard-stats'),
]

# Register the member management viewset

router.register(r'payment-requests', PaymentRequestViewSet, basename='payment-request')
    

