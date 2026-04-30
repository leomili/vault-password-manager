from django.contrib import admin
from .models import PasswordEntry, UserProfile

admin.site.register(PasswordEntry)
admin.site.register(UserProfile)