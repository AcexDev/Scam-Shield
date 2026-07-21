from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.password_validation import validate_password
import secrets
from django.conf import settings
from django.db import models
from django.utils import timezone
from datetime import timedelta

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        if not password:
            raise ValueError('Password is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        validate_password(password, user)
        user.set_password(password)      
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    
    def create_passwordless_user(self, email, **extra_fields):
        """For OAuth, magic links, etc. — explicit, no password."""
        if not email:
            raise ValueError('Email is required')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_unusable_password()
        user.save(using=self._db)
        return user
    
class User(AbstractUser):
    username = None  # drop the default username field entirely
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # email + password are already required by default

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    
class PasswordReset(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_resets')
    otp_hash = models.CharField(max_length=128)
    token_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

    @classmethod
    def create_for_user(cls, user):
        otp = f"{secrets.randbelow(1000000):06d}"
        token = secrets.token_urlsafe(32)
        reset = cls.objects.create(
            user=user,
            otp_hash=cls._hash(otp),
            token_hash=cls._hash(token),
            expires_at=timezone.now() + timedelta(minutes=15),
        )
        return reset, otp, token

    @staticmethod
    def _hash(value):
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()