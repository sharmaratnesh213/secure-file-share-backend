from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'file_sharing.settings')

app = Celery('file_sharing')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()


from celery.schedules import crontab

app.conf.beat_schedule = {
    'delete_expired_files_daily': {
        'task': 'core.tasks.delete_expired_files',
        'schedule': crontab(minute=0, hour=0),
    },
}

