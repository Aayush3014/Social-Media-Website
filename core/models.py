from django.db import models
import unicodedata

from django.db import models

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import (
    PermissionsMixin,
    BaseUserManager,
)
import jwt
from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.hashers import (
    check_password, is_password_usable, make_password,
)
from django.utils.crypto import get_random_string, salted_hmac
from django.utils.translation import gettext_lazy as _
from datetime import datetime
import random
import uuid



class SoftDeleteManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)



class TimestampedModel(models.Model):
    # A timestamp representing when this object was created.
    created_at = models.DateTimeField(auto_now_add=True)

    # A timestamp reprensenting when this object was last updated.
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    objects = SoftDeleteManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True
        ordering = ["-pk"]


class UserGroups(models.TextChoices):
    SuperAdmin = 'SuperAdmin'
    Admin = 'Admin'
    Customer = 'Customer'


def check_username(username):
    try:
        User.objects.get(username=username)
        return True
    except User.DoesNotExist:
        return False

def create_username(fullname):
    fullname = fullname.replace(" ", "")
    username = fullname
    check_count = 1
    while check_username(username):
        if check_count >= 2:
            username = fullname + str(check_count)
        if len(username) < 6:
            username = username + "".join(map(str, random.sample(range(1, 10), 6 - len(username))))
        check_count += 1
    return username


class UserManager(BaseUserManager):
    def create_user(self, username=None, fullname=None, phonenumber=None, password=None, email=None, usergroup=None, is_active=None):
        if fullname is None:
            raise TypeError("User must have a fullname.")
        if username is None:
            username = create_username(fullname)
        user = self.model(username=username, fullname=fullname, phonenumber=phonenumber)
        if email:
            user.email = self.normalize_email(email)
        if is_active is not None:
            user.is_active = is_active
        user.usergroup = usergroup
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, fullname, phonenumber, password, email=None, usergroup=UserGroups.Admin):
        if password is None:
            raise TypeError("Superusers must have a password.")
        user = self.create_user(username, fullname, phonenumber, password, email, usergroup)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin, TimestampedModel):

    GENDER_CHOICES = [('male', 'Male'), 
                      ('female', 'Female'), 
                      ('other', 'Other')]
    
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(db_index=True, max_length=128, unique=True)
    email = models.EmailField(null=True, max_length=128, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    phonenumber = models.CharField(max_length=15, unique=True)
    usergroup = models.CharField(max_length=50, choices=UserGroups.choices, null=True, blank=True)
    fullname = models.CharField(max_length=50)
    
    age = models.PositiveIntegerField(default=0, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.TextField(null=True, blank=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["phonenumber", "fullname"]
    objects = UserManager()

    def __str__(self):
        return self.username

    @property
    def token_pair(self):
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }