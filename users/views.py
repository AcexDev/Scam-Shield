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

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        try:
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
        except Exception as exc:
            return Response(
                {"error": exc},
                status=status.HTTP_400_BAD_REQUEST
            )


class PasswordResetRequestView(APIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if user:
            if user != request.user:
                return Response({'detail': 'Enter your account email'}, status=status.HTTP_400_BAD_REQUEST)
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


def test_merge_conflict():
    merged = False
    conflict =  True
    if (not merged) and conflict:
        print("Pending Conflict")
        
