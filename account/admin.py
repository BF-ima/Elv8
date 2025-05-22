
from django.contrib import admin
from .models import Personne, Startup, BureauEtude, Chat, Message, MessageAttachment, StartupSignupRequest

@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('id', 'bureau', 'startup', 'created_at', 'updated_at', 'last_message_at', 'is_active')
    search_fields = ('bureau__name', 'startup__name')
    list_filter = ('is_active',)
    ordering = ('-last_message_at',)

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'chat', 'sender_type', 'sender_id', 'content_type', 'text_content', 'timestamp', 'is_read')
    search_fields = ('text_content', 'sender_type')
    list_filter = ('is_read', 'timestamp', 'content_type')
    ordering = ('-timestamp',)

@admin.register(MessageAttachment)
class MessageAttachmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'message', 'file', 'file_name', 'file_size', 'file_type', 'created_at')
    search_fields = ('file_name', 'file_type')
    list_filter = ('created_at',)
    ordering = ('-created_at',)

admin.site.register(Personne)
admin.site.register(StartupSignupRequest)


#admin.site.register(Startup)

#admin.site.register(BureauEtude)
# Register your models here.
@admin.register(Startup)
class StartupAdmin(admin.ModelAdmin):
    list_display = ('id_startup', 'nom', 'email', 'wilaya')  # Show ID in the admin panel
    search_fields = ('id_startup', 'nom', 'email')  # Allow search by ID

@admin.register(BureauEtude)
class BureauAdmin(admin.ModelAdmin):
    list_display = ('id_bureau', 'nom', 'email', 'wilaya')  # Show ID in the admin panel
    search_fields = ('id_bureau', 'nom', 'email')  # Allow search by ID