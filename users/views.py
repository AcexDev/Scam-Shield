from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .serializers import RegisterSerializer
import hashlib
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import PasswordReset
from .serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer
from django.shortcuts import redirect
from rest_framework_simplejwt.tokens import RefreshToken
from .google_oauth import build_auth_url, exchange_code_for_token, get_google_user_info
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                'email': user.email,
                'message': 'Account created successfully.',
            },
            status=status.HTTP_201_CREATED,
        )



class PasswordResetRequestView(APIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email__iexact=email).first()
        reset, otp, token = PasswordReset.create_for_user(user)
        reset_link = f"{settings.FRONTEND_URL}/reset-password?email={email}&token={token}"
        send_mail(
            subject='ShieldAI Password Reset',
            message=(
                f"Your OTP code is: {otp}\n\n"
                f"Or click this link to reset your password:\n{reset_link}\n\n"
                f"This expires in 15 minutes. If you didn't request this, ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

        # always return the same response, whether user exists or not — prevents email enumeration
        return Response(
            {'message': 'If that email exists, a reset code has been sent.'},
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = User.objects.filter(email__iexact=data['email']).first()
        if not user:
            return Response({'detail': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

        reset = user.password_resets.filter(is_used=False).order_by('-created_at').first()
        if not reset or not reset.is_valid():
            return Response({'detail': 'Reset code expired or invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        matched = False
        if data.get('otp'):
            matched = hashlib.sha256(data['otp'].encode()).hexdigest() == reset.otp_hash
        elif data.get('token'):
            matched = hashlib.sha256(data['token'].encode()).hexdigest() == reset.token_hash

        if not matched:
            return Response({'detail': 'Invalid code or token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(data['new_password'])
        user.save()
        reset.is_used = True
        reset.save()

        return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(status=status.HTTP_205_RESET_CONTENT)

class GoogleLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return redirect(build_auth_url())


class GoogleCallbackView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        code = request.GET.get('code')
        if not code:
            return Response({'detail': 'Missing authorization code.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token_data = exchange_code_for_token(code)
            user_info = get_google_user_info(token_data['access_token'])
        except requests.RequestException:
            return Response({'detail': 'Google authentication failed.'}, status=status.HTTP_400_BAD_REQUEST)

        email = user_info.get('email')
        if not email:
            return Response({'detail': 'No email returned from Google.'}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'auth_provider': 'GOOGLE',
                'is_verified': True,   # Google already verified this email
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', ''),
            },
        )
        if created:
            user.set_unusable_password()
            user.save()

        refresh = RefreshToken.for_user(user)
        # Redirect back to frontend with tokens (query params, or swap for a redirect+postMessage pattern later)
        redirect_url = f"{settings.FRONTEND_URL}/oauth-success?access={refresh.access_token}&refresh={refresh}"
        return redirect(redirect_url)
