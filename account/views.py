from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from .serializers import PersonneSerializer, StartupSerializer, BureauEtudeSerializer, RegisterStartupSerializer, RegisterSerializer, ChatSerializer, MessageSerializer, PersonneProfileSerializer, StartupProfileSerializer, BureauEtudeProfileSerializer, FeedbackSerializer 
from rest_framework.permissions import AllowAny , IsAuthenticated
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.exceptions import APIException
from .authentication import create_access_token, create_refresh_token, generate_reset_token, send_reset_email
from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from django.db.models import Q, Max, Count, OuterRef, Subquery
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from .models import (
    Chat, Message, Personne, Startup, BureauEtude,
    PersonneProfile, StartupProfile, BureauEtudeProfile,
    MessageAttachment, StartupMember, ConsultationRequest, PaymentRequest, Feedback
)
from rest_framework.permissions import IsAdminUser
#from .models import ConsultationType
from .permissions import IsOwnerOrReadOnly, IsStartupOrPersonne
#from .serializers import ConsultationTypeSerializer
from .serializers import ConsultationRequestCreateSerializer, ConsultationRequestSimpleSerializer
from .serializers import ConsultationRequestSerializer
from .serializers import PaymentRequestSerializer
from .serializers import StartupProfileUpdateSerializer
from django.contrib.contenttypes.models import ContentType
import re
from django.contrib.auth.hashers import check_password
import random
from django.core.mail import send_mail
from .models import PasswordResetCode, StartupSignupRequest
from .serializers import ForgotPasswordSerializer, ResetPasswordWithCodeSerializer
from django.contrib.auth import get_user_model
from .models import Event
from .serializers import EventSerializer, StartupSignupRequestSerializer
from django.shortcuts import get_object_or_404
import jwt
from datetime import datetime
from .models import BlacklistedToken
from django.db.models.signals import post_save
from django.dispatch import receiver


User = get_user_model()

def is_password_valid(password):
    # Check length (>= 8 characters)
    if len(password) < 8:
        return False
    
    # Check for at least 1 digit
    if not re.search(r"\d", password):
        return False
    
    # Check for at least 1 symbol (customize symbols as needed)
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    
    # Check for at least 1 capital letter
    if not re.search(r"[A-Z]", password):
        return False
    
    return True  


class StartupSignupRequestView(generics.CreateAPIView):
    serializer_class = StartupSignupRequestSerializer
    permission_classes = [AllowAny]
    
    
class AdminStartupSignupRequestViewSet(viewsets.ModelViewSet):
    queryset = StartupSignupRequest.objects.filter(is_processed=False)
    serializer_class = StartupSignupRequestSerializer
    permission_classes = [IsAdminUser]  # or your custom admin permission

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        signup_request = self.get_object()
        # Create the actual Startup account
        from account.models import Startup
        startup = Startup.objects.create(
            nom=signup_request.nom,
            email=signup_request.email,
            password=signup_request.password,  # already hashed!
            # ... other fields ...
        )
        signup_request.is_processed = True
        signup_request.is_approved = True
        signup_request.save()
        # Send email to startup
        send_mail(
            'Your account is approved!',
            'You can now log in at http://localhost:8000/login',
            'emenoellin@gmail.com',
            [signup_request.email]
        )
        return Response({'status': 'approved'})

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        signup_request = self.get_object()
        signup_request.is_processed = True
        signup_request.is_approved = False
        signup_request.save()
        # Optionally send rejection email
        return Response({'status': 'rejected'})    

class ConsultationRequestViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'id_startup'):
            return ConsultationRequest.objects.filter(startup=user.id_startup.startup)
        elif hasattr(user, 'id_bureau'):
            return ConsultationRequest.objects.filter(bureau=user)
        return ConsultationRequest.objects.none()
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ConsultationRequestSimpleSerializer
        if self.action == 'retrieve':
            return ConsultationRequestSimpleSerializer
        if self.action == 'create':
            return ConsultationRequestCreateSerializer
        return ConsultationRequestSerializer
    
    def perform_create(self, serializer):
        if hasattr(self.request.user, 'id_startup'):
            bureau_id = self.request.data.get('bureau_id')
            bureau = get_object_or_404(BureauEtude, id_bureau=bureau_id)
            serializer.save(
                startup=self.request.user,
                bureau=bureau,
                status='pending'
            )
        else:
            raise PermissionDenied("Only startups can create consultation requests")

class ConsultationRequestActionView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, pk, action):
        consultation = get_object_or_404(ConsultationRequest, pk=pk)
        
        # Check if user is the bureau owner
        if not hasattr(request.user, 'id_bureau') :    #or consultation.bureau.id_bureau != request.user:
            raise PermissionDenied("You don't have permission to perform this action")
        
        if action == 'accept':
            consultation.status = 'accepted'
            consultation.save()
            
            # Create payment request
            payment_request = PaymentRequest.objects.create(
                consultation=consultation,
                amount=10000,  # Default amount or get from consultation type
                payment_method='Baird Mob'
            )
            
            # Create notification for startup
            # You'll need to implement your notification system here
            
            return Response({
                'status': 'consultation accepted',
                'payment_request': PaymentRequestSerializer(payment_request).data
            })
            
        elif action == 'reject':
            consultation.status = 'rejected'
            consultation.delete()
            consultation.save()
            
            # Create notification for startup
            return Response({'status': 'consultation rejected'})
        
        return Response(
            {'error': 'Invalid action'},
            status=status.HTTP_400_BAD_REQUEST
        )

class PaymentRequestViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = PaymentRequestSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'id_startup'):
            return PaymentRequest.objects.filter(consultation__startup=user.id_startup.startup)
        elif hasattr(user, 'id_bureauetude'):
            return PaymentRequest.objects.filter(consultation__bureau=user.id_bureauetude.bureau)
        return PaymentRequest.objects.none()
    


class BureauEtudeSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        specialization = request.query_params.get('specialization', '')
        
        bureaus = BureauEtude.objects.all()
        
        if query:
            bureaus = bureaus.filter(
                Q(nom__icontains=query) |
                Q(description__icontains=query)
            )
        
        if specialization:
            bureaus = bureaus.filter(description__icontains=specialization)
        
        serializer = BureauEtudeSerializer(bureaus, many=True)
        return Response(serializer.data)

class BureauEtudeDetailView(generics.RetrieveAPIView):
    queryset = BureauEtude.objects.all()
    serializer_class = BureauEtudeSerializer
    permission_classes = [permissions.IsAuthenticated]


class MemberSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        
        # Ensure the user is a startup
        if not hasattr(request.user, 'startupprofile'):
            return Response(
                {'error': 'Only startups can search members'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Search in current members
        current_members = request.user.startupprofile.members.filter(
            Q(nom__icontains=query) | 
            Q(email__icontains=query)
        ).distinct()
        
        # Search in potential members (users not in the startup)
        potential_members = Personne.objects.filter(
            Q(nom__icontains=query) | 
            Q(email__icontains=query)
        ).exclude(id_personne__in=current_members.values_list('id_personne', flat=True)).distinct()
        
        current_members_data = PersonneSerializer(current_members, many=True).data
        potential_members_data = PersonneSerializer(potential_members, many=True).data
        
        return Response({
            'current_members': current_members_data,
            'potential_members': potential_members_data
        })


class MemberManagementViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    def list(self, request):
        # Recognize the startup user by their id, not by profile
        from .models import StartupProfile, Startup
        user = request.user
        # Check if user is a Startup (has id_startup)
        
        if hasattr(user, 'id_startup'):
            try:
                startup = Startup.objects.get(id_startup=user.id_startup)
                members = startup.members.all()
                data = PersonneSerializer(members, many=True).data
                return Response(data)
            except StartupProfile.DoesNotExist:
                return Response({'error': 'Startup profile not found'}, status=404)
        return Response({'error': 'Only startups can list members'}, status=403)
    @action(detail=False, methods=['post'])
    def add_member(self, request):
        from .models import Startup, Personne
        user = request.user
        if hasattr(user, 'id_startup'):
            member_name = request.data.get('member_name')
            if not member_name:
                return Response({'error': 'member_name is required'}, status=400)
            try:
                startup = Startup.objects.get(id_startup=user.id_startup)
                member = Personne.objects.get(nom=member_name)
                # Add the member to the startup's members (if you want)
                startup.members.add(member)
                # Add the startup to the member's startups field
                member.startups.add(startup)
                return Response({'status': 'member added'})
            except Startup.DoesNotExist:
                return Response({'error': 'Startup not found'}, status=404)
            except Personne.DoesNotExist:
                return Response({'error': 'Member not found'}, status=404)
        return Response({'error': 'Only startups can add members'}, status=403)
        class MemberManagementViewSet(viewsets.ViewSet):
            permission_classes = [permissions.IsAuthenticated]
    """
    @action(detail=False, methods=['post'])
    def add_member(self, request):
        # Check if user is a startup
        if not hasattr(request.user, 'startup_id'):
            return Response(
                {'error': 'Only startups can add members'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        member_name = request.data.get('member_name')
        if not member_name:
            return Response(
                {'error': 'member_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        #try:
            member = Personne.objects.get(nom=member_name)
            request.user.startup.profile.members.add(member)
            return Response({'status': 'member added'})
        except Personne.DoesNotExist:
            return Response(
                {'error': 'Member not found'},
                status=status.HTTP_404_NOT_FOUND
            )"""
    @action(detail=False, methods=['delete'])
    def remove_member(self, request):
        from .models import Startup, Personne
        user = request.user
        if hasattr(user, 'id_startup'):
            member_name = request.data.get('member_name')
            if not member_name:
                return Response({'error': 'member_name is required'}, status=400)
            try:
                startup = Startup.objects.get(id_startup=user.id_startup)
                member = Personne.objects.get(nom=member_name)
                startup.members.remove(member)
                member.startups.remove(startup)
                return Response({'status': 'member removed'})
            except Startup.DoesNotExist:
                return Response({'error': 'Startup not found'}, status=404)
            except Personne.DoesNotExist:
                return Response({'error': 'Member not found'}, status=404)
        return Response({'error': 'Only startups can remove members'}, status=403)


class FeedbackViewSet(viewsets.ModelViewSet):
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated, IsStartupOrPersonne]


    def get_queryset(self):
        # Allow all logged-in users to see all feedbacks
        return Feedback.objects.all()

    def perform_create(self, serializer):
        user = self.request.user

        bureau = None
        startup = None
        personne = None

        # Determine which user type is sending the feedback
        if hasattr(user, 'startupprofile'):
            startup = user.startupprofile.startup
        elif hasattr(user, 'personneprofile'):
            personne = user.personneprofile.personne

        # Assume feedback is for a specific bureau, passed via request data
        bureau_id = self.request.data.get('bureau_id')
        bureau = BureauEtude.objects.get(id=bureau_id)

        serializer.save(bureau=bureau, startup=startup, personne=personne)


class PersonneProfileViewSet(viewsets.ModelViewSet):
    serializer_class = PersonneProfileSerializer
    queryset = PersonneProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(personne=self.request.user)


class StartupProfileViewSet(viewsets.ModelViewSet):
    serializer_class = StartupProfileSerializer
    queryset = StartupProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(startup=self.request.user)

    def get_serializer_class(self):
        if self.action in ['update', 'partial_update']:
            return StartupProfileUpdateSerializer
        return self.serializer_class


class BureauEtudeProfileViewSet(viewsets.ModelViewSet):
    serializer_class = BureauEtudeProfileSerializer
    queryset = BureauEtudeProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(bureau=self.request.user)


class ChatViewSet(viewsets.ModelViewSet):
    queryset = Chat.objects.all()
    serializer_class = ChatSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        # Determine which chats to fetch based on user type
        if hasattr(user, 'id_bureau'):
            return Chat.objects.filter(bureau=user)
        elif hasattr(user, 'id_startup'):
            return Chat.objects.filter(startup=user)
        return Chat.objects.none()
    

    @action(detail=False, methods=['post'])
    def create_or_get(self, request):
        bureau_id = request.data.get('bureau_id')
        startup_id = request.data.get('startup_id')
        
        if not bureau_id or not startup_id:
            return Response(
                {'error': 'Both bureau_id and startup_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if chat already exists
        try:
            chat = Chat.objects.get(bureau_id=bureau_id, startup_id=startup_id)
            serializer = self.get_serializer(chat)
            return Response(serializer.data)
        except Chat.DoesNotExist:
            # Create a new chat
            serializer = self.get_serializer(data={
                'bureau': bureau_id,
                'startup': startup_id,
                'is_active': True
            })
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        chat_id = self.kwargs.get('chat_pk') or self.request.query_params.get('chat_id')
        user = self.request.user
        if not chat_id:
            return Message.objects.none()

        queryset = Message.objects.filter(chat_id=chat_id).order_by('timestamp')

        # Automatically mark unread messages as read
        if hasattr(user, 'id_bureau'):
            receiver_type = 'bureau'
            receiver_id = user.id_bureau
        elif hasattr(user, 'id_startup'):
            receiver_type = 'startup'
            receiver_id = user.id_startup
        else:
            return queryset  # unknown user, don't touch

        unread_messages = queryset.filter(
            receiver_type=receiver_type,
            receiver_id=receiver_id,
            is_read=False
        )

        now = timezone.now()
        unread_messages.update(is_read=True, read_at=now)

        return queryset

             
    
    def create(self, request, *args, **kwargs):
    # Use the provided sender info instead of overriding it
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
    
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None, chat_pk=None):
        message = self.get_object()
        message.mark_as_read()
        return Response({'status': 'message marked as read'})
    
    @action(detail=False, methods=['post'])
    def mark_all_as_read(self, request):
        chat_id = request.data.get('chat_id')
        if not chat_id:
            return Response(
                {'error': 'chat_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get current user type and ID
        user = request.user
        if hasattr(user, 'id_bureau'):
            receiver_type = 'bureau'
            receiver_id = user.id_bureau
        elif hasattr(user, 'id_startup'):
            receiver_type = 'startup'
            receiver_id = user.id_startup
        else:
            return Response(
                {'error': 'Unknown user type'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark all unread messages as read
        now = timezone.now()
        updated = Message.objects.filter(
            chat_id=chat_id,
            receiver_type=receiver_type,
            receiver_id=receiver_id,
            is_read=False
        ).update(is_read=True, read_at=now)
        
        return Response({'status': f'{updated} messages marked as read'})

    


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

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            # Get the access token from the Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    prefix, token = auth_header.split(' ')
                    if prefix.lower() == 'bearer':
                        # Decode token to get expiration
                        payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])
                        expires_at = datetime.fromtimestamp(payload['exp'])
                        
                        # Add token to blacklist
                        BlacklistedToken.objects.create(
                            token=token,
                            expires_at=expires_at
                        )
                except (ValueError, jwt.InvalidTokenError) as e:
                    print(f"Error processing access token: {str(e)}")

            # Get and blacklist the refresh token from cookies
            refresh_token = request.COOKIES.get('refreshToken')
            if refresh_token:
                try:
                    # Decode refresh token to get expiration
                    payload = jwt.decode(refresh_token, 'refresh_secret', algorithms=['HS256'])
                    expires_at = datetime.fromtimestamp(payload['exp'])
                    
                    # Add refresh token to blacklist
                    BlacklistedToken.objects.create(
                        token=refresh_token,
                        expires_at=expires_at
                    )
                except (ValueError, jwt.InvalidTokenError) as e:
                    print(f"Error processing refresh token: {str(e)}")

            response = Response()
            response.delete_cookie('refreshToken')  # Clear the cookie
            response.data = {
                'message': 'Logged out successfully'
            }
            response.status_code = status.HTTP_200_OK
            return response
        except Exception as e:
            return Response(
                {'error': f'Error during logout: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ChangePasswordView(APIView): #addeeeeedddddddddddddddddddddddddddddddddddddddddddddd
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        email = user.email
        print(f"User: {request.user}, Type: {type(request.user)}")
       
        print(f"User email: {request.user.email}")
        

        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        actual_user = None
        if Personne.objects.filter(email=email).exists():
            actual_user = Personne.objects.get(email=email)
        elif Startup.objects.filter(email=email).exists():
            actual_user = Startup.objects.get(email=email)
        elif BureauEtude.objects.filter(email=email).exists():
            actual_user = BureauEtude.objects.get(email=email)
    
    # Use this user for password operations if found
        if actual_user:
            user = actual_user
        if not old_password or not new_password or not confirm_new_password:
            return Response({'error': 'All three fields are required'}, status=status.HTTP_400_BAD_REQUEST)
        #new passwords match
        if new_password != confirm_new_password:
            return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        if not is_password_valid(new_password):
                return Response({'password': 'Please choose a strong password'}) 
        if new_password == old_password:
            return Response({'error': 'New password cannot be the same as the current one'}, status=status.HTTP_400_BAD_REQUEST)
        # Check if the old password is correct
        if not user.check_password(old_password):
            return Response({'error': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
    
class ForgotPasswordAPIView(APIView):        #addeddddddddddddddddd
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = str(random.randint(100000, 999999))
            user_exists = (
            Startup.objects.filter(email=email).exists() or
            Personne.objects.filter(email=email).exists() or
            BureauEtude.objects.filter(email=email).exists()
            )
            if not user_exists:
                return Response({'error': 'No user with this email'}, status=status.HTTP_404_NOT_FOUND)
            PasswordResetCode.objects.create(email=email, code=code)
                

            send_mail(
                'Password Reset Verification Code',
                f'Your verification code is: {code}',
                'emenoellin@gmail.com',  # replace with your configured email
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Verification code sent to email'})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ResetPasswordAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ResetPasswordWithCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']
            confirm_new_password = serializer.validated_data['confirm_new_password']
            
            
            try:
                reset_code = PasswordResetCode.objects.filter(email=email, code=code).latest('created_at')
                print(f"Found reset code created at: {reset_code.created_at}")
            except PasswordResetCode.DoesNotExist:
                print("No matching reset code found")
                return Response({'error': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)

            if reset_code.is_expired():
                return Response({'error': 'Code expired'}, status=status.HTTP_400_BAD_REQUEST)
            if new_password != confirm_new_password :
                return Response({'password': 'Passwords do not match'})   
            if not is_password_valid(new_password):
                return Response({'password': 'Not a strong password.'})   
             
            user = None
            if Personne.objects.filter(email=email).exists():
                user = Personne.objects.get(email=email)
               
            elif Startup.objects.filter(email=email).exists():
                user = Startup.objects.get(email=email)
               
            elif BureauEtude.objects.filter(email=email).exists():
                user = BureauEtude.objects.get(email=email)
                
            else:
               
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            
            user.set_password(new_password)
            user.save()
            

            reset_code.delete()
            

            return Response({'message': 'Password reset successful'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EventListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Get events where the owner is the current user (any type)
        return Event.objects.filter(
            owner_type=ContentType.objects.get_for_model(self.request.user),
            owner_id=self.request.user.pk
        )

    def perform_create(self, serializer):
        # No need to manually set owner, handled in serializer
        serializer.save()


class EventRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]  # Replace IsAuthenticated
    lookup_field = 'id'  # Use 'id' as the URL lookup field

    def get_queryset(self):
        # Only allow access to events owned by the current user
        return Event.objects.filter(
            owner_type=ContentType.objects.get_for_model(self.request.user),
            owner_id=self.request.user.pk
        )
    

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

class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            user = request.user  # the currently logged-in user
            password = request.data.get('password')
            
            if not password:
                return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if password is correct
            if not check_password(request.data.get('password'), user.password):
                return Response({'error': 'Incorrect password.'}, status=status.HTTP_400_BAD_REQUEST)

            # Get the access token from the Authorization header and blacklist it
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    prefix, token = auth_header.split(' ')
                    if prefix.lower() == 'bearer':
                        # Decode token to get expiration
                        payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])
                        expires_at = datetime.fromtimestamp(payload['exp'])
                        
                        # Add token to blacklist
                        BlacklistedToken.objects.create(
                            token=token,
                            expires_at=expires_at
                        )
                except (ValueError, jwt.InvalidTokenError) as e:
                    print(f"Error processing access token: {str(e)}")

            # Get and blacklist the refresh token from cookies
            refresh_token = request.COOKIES.get('refreshToken')
            if refresh_token:
                try:
                    # Decode refresh token to get expiration
                    payload = jwt.decode(refresh_token, 'refresh_secret', algorithms=['HS256'])
                    expires_at = datetime.fromtimestamp(payload['exp'])
                    
                    # Add refresh token to blacklist
                    BlacklistedToken.objects.create(
                        token=refresh_token,
                        expires_at=expires_at
                    )
                except (ValueError, jwt.InvalidTokenError) as e:
                    print(f"Error processing refresh token: {str(e)}")

            # Delete the user
            user.delete()
            
            response = Response()
            response.delete_cookie('refreshToken')  # Clear the cookie
            response.data = {
                'message': 'Account deleted successfully.'
            }
            response.status_code = status.HTTP_200_OK
            return response
            
        except Exception as e:
            return Response(
                {'error': f'Error during account deletion: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# NEW: Dashboard stats for the startup and bureau
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    user = request.user
    # Only allow startup users
    if hasattr(user, 'id_startup') or hasattr(user, 'StartupProfile'):
        # Use id_startup for direct Startup, or get from profile
        startup = getattr(user, 'StartupProfile', None)
        if startup:
            startup = startup.startup
        else:
            startup = user
        new_requests = ConsultationRequest.objects.filter(startup=startup, status='pending').count()
        ongoing_consultations = ConsultationRequest.objects.filter(startup=startup, status='accepted').count()
        completed_consultations = ConsultationRequest.objects.filter(startup=startup, status='completed').count()
        monthly = (
            ConsultationRequest.objects.filter(startup=startup)
            .extra({'month': "strftime('%%m', created_at)"})
            .values('month')
            .annotate(count=Count('id'))
            .order_by('month')
        )
        events = list(Event.objects.filter(owner_id=startup.id_startup, owner_type__model='startup').order_by('event_date')[:2].values())
        return Response({
            'user_type': 'startup',
            'new_requests': new_requests,
            'ongoing': ongoing_consultations,
            'completed': completed_consultations,
            'monthly': list(monthly),
            'events': events,
        })
        #for bureau user 
    if hasattr(user, 'id_bureau') or hasattr(user, 'bureauetudeprofile'):
        bureau = getattr(user, 'bureauetudeprofile', None)
        if bureau:
            bureau = bureau.bureau
        else:
            bureau = user
        new_requests = ConsultationRequest.objects.filter(bureau=bureau, status='pending').count()
        ongoing_consultations = ConsultationRequest.objects.filter(bureau=bureau, status='accepted').count()
        completed_consultations = ConsultationRequest.objects.filter(bureau=bureau, status='completed').count()
        monthly = (
            ConsultationRequest.objects.filter(bureau=bureau)
            .extra({'month': "strftime('%%m', created_at)"})
            .values('month')
            .annotate(count=Count('id'))
            .order_by('month')
        )
        events = list(Event.objects.filter(owner_id=bureau.id_bureau, owner_type__model='bureauetude').order_by('event_date')[:2].values())
        return Response({
            'user_type': 'bureau',
            'new_requests': new_requests,
            'ongoing_consultations': ongoing_consultations,
            'completed_consultations': completed_consultations,
            'monthly_consultations': list(monthly),
            'events': events,
        })    
    return Response({'error': 'not a valid user'}, status=400)

# NEW: Member dashboard stats endpoint for Personne users (showing only their own events)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def member_dashboard_stats(request):
    user = request.user

    # Only for Personne users
    if hasattr(user, 'id_personne'):
        from .models import ConsultationRequest, Event
        # Use the direct startups field on Personne
        startups = user.startups.all()

        # Aggregate stats across all these startups
        new_requests = ConsultationRequest.objects.filter(startup__in=startups, status='pending').count()
        ongoing = ConsultationRequest.objects.filter(startup__in=startups, status='accepted').count()
        completed = ConsultationRequest.objects.filter(startup__in=startups, status='completed').count()
        monthly = (
            ConsultationRequest.objects.filter(startup__in=startups)
            .extra({'month': "strftime('%%m', created_at)"})
            .values('month')
            .annotate(count=Count('id'))
            .order_by('month')
        )
        # Only events created by this member (Personne)
        events = list(Event.objects.filter(owner_id=user.id_personne, owner_type__model='personne').order_by('event_date')[:2].values())
        # List the startups (as dicts)
        startup_list = list(startups.values('id_startup', 'nom'))

        return Response({
            'user_type': 'member',
            'new_requests': new_requests,
            'ongoing_consultations': ongoing,
            'completed_consultations': completed,
            'monthly_consultations': list(monthly),
            'events': events,
            'startups': startup_list,
        })
    return Response({'error': 'Not a member user'}, status=400)
