from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group, Permission
from django_otp.plugins.otp_totp.models import TOTPDevice

# Custom User Model
class User(AbstractUser):
    groups = models.ManyToManyField(
        Group,
        related_name='core_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='core_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def __str__(self):
        return self.username
    
# File Model
class File(models.Model):
    user = models.ForeignKey(User, related_name='files', on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    encryption_key = models.CharField(max_length=256)
    iv = models.CharField(max_length=255, default='default_value') 

    def __str__(self):
        return self.file.name

# File Permissions Model
class FilePermission(models.Model):
    VIEW = 'view'
    DOWNLOAD = 'download'

    PERMISSION_CHOICES = [
        (VIEW, 'View'),
        (DOWNLOAD, 'Download')
    ]

    file = models.ForeignKey(File, related_name='permissions', on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='file_permissions', on_delete=models.CASCADE)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.user.username} - {self.permission}"
