from django.urls import path
from .views import UserRegistrationView, LoginView, FileUploadView, FileDownloadView, FileShareView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('upload/', FileUploadView.as_view(), name='upload'),
    path('files/download/<int:file_id>/', FileDownloadView.as_view(), name='file_download'),
    path('files/share/', FileShareView.as_view(), name='file_share'),
]
