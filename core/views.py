from rest_framework import status, serializers, views
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny
import logging

logger = logging.getLogger(__name__)

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = get_user_model()
        fields = ('username', 'password', 'email')

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        user = get_user_model().objects.create(**validated_data)
        return user

class UserRegistrationView(views.APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers, views
from rest_framework.response import Response
from django.contrib.auth import authenticate

from django_otp import user_has_device
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.tokens import RefreshToken

class MFARequiredLoginView(views.APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                if user_has_device(user):
                    device = TOTPDevice.objects.get(user=user)
                    otp = request.data['otp']
                    if not device.verify_token(otp):
                        return Response({"detail": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

                refresh = RefreshToken.for_user(user)
                return Response({
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                })
            return Response({"detail": "Invalid credentials"}, status=400)
        return Response(serializer.errors, status=400)


class LoginView(views.APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                })
            return Response({"detail": "Invalid credentials"}, status=400)
        return Response(serializer.errors, status=400)
    

from rest_framework import status, views
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from .models import File
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_file(file_data, encryption_key, iv):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return encrypted_data

class FileUploadView(views.APIView):
    def post(self, request):
        file = request.FILES['file']
        encryption_key = os.urandom(32)
        iv = os.urandom(16)

        encrypted_content = encrypt_file(file.read(), encryption_key, iv)

        output_directory = 'media/encrypted'
        os.makedirs(output_directory, exist_ok=True)

        file_path = os.path.join(output_directory, file.name)
        with open(file_path, 'wb') as f:
            f.write(encrypted_content)

        print(f"User {request.user} uploaded file {file.name}")

        custom_user = User.objects.get(username=request.user.username)

        File.objects.create(
            file=file_path,
            encryption_key=encryption_key.hex(),
            iv=iv.hex(),
            user=custom_user
        )
        return Response({"message": "File uploaded and encrypted successfully."}, status=status.HTTP_201_CREATED)


from rest_framework import status, views
from rest_framework.response import Response
from .models import File, FilePermission, User
from django.contrib.auth import get_user_model

class FileShareView(views.APIView):
    def post(self, request):
        file_id = request.data['file_id']
        user_id = request.data['user_id']
        permission = request.data['permission']
        expires_at = request.data['expires_at']

        file = File.objects.get(id=file_id)
        user = User.objects.get(id=user_id)

        permission_instance = FilePermission.objects.create(
            file=file,
            user=user,
            permission=permission,
            expires_at=expires_at
        )

        return Response({"message": "File shared successfully"}, status=status.HTTP_200_OK)
    

from rest_framework import status, views
from rest_framework.response import Response
from django.http import HttpResponse
from .models import File
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(encrypted_data, encryption_key, iv):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

from django.utils.timezone import now

class FileDownloadView(views.APIView):
    def get(self, request, file_id):
        try:
            file = File.objects.get(id=file_id)

            if file.user == request.user:
                has_access = True
            else:
                has_access = FilePermission.objects.filter(
                    file=file,
                    user=request.user,
                    permission='download',
                    expires_at__gte=now()
                ).exists()

            if not has_access:
                return Response({"detail": "You don't have permission to access this file."}, status=status.HTTP_403_FORBIDDEN)

            encrypted_file = file.file.path
            encryption_key_bytes = bytes.fromhex(file.encryption_key)
            iv_bytes = bytes.fromhex(file.iv)

            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_file(encrypted_data, encryption_key_bytes, iv_bytes)

            response = HttpResponse(decrypted_data, content_type="application/pdf")
            response['Content-Disposition'] = f'attachment; filename={file.file.name}'
            return response

        except File.DoesNotExist:
            logger.error(f"File not found for id: {file_id}")
            return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)


