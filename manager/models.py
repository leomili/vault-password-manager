from django.db import models
from django.contrib.auth.models import User


# Extends Django's built-in User model with a salt field
# used to derive the vault key with Argon2
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    salt = models.BinaryField()


# Stores an encrypted password entry belonging to a user
class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.BinaryField()  # always encrypted, never plaintext