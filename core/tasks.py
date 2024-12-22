from celery import shared_task
from django.utils import timezone
from .models import File, FilePermission

@shared_task
def delete_expired_files():
    expired_files = FilePermission.objects.filter(expires_at__lt=timezone.now())
    for permission in expired_files:
        permission.delete()
        file = permission.file
        if not file.file_permissions.exists():
            file.delete()

