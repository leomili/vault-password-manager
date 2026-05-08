import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from manager.models import PasswordEntry, UserProfile
from encryption_helper import (
    derive_key, encrypt, decrypt,
    encrypt_for_session, decrypt_from_session
)


def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        master_password = request.POST.get("master_password")

        # Validate empty fields
        if not username or not master_password:
            return render(request, "add.html", {"error": "All fields are required"})
        # Validate lengths
        if len(username) > 30:
            return render(request, "add.html", {"error": "Username is too long (max 50 characters)"})
        if len(master_password) > 64:
            return render(request, "add.html", {"error": "Password is too long (max 64 characters)"})

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "Username already exists"})
        
        try:
            user = User.objects.create_user(username=username, password=master_password)
            salt = os.urandom(16)
            UserProfile.objects.create(user=user, salt=salt)
            login(request, user)
            request.session["master_password"] = encrypt_for_session(master_password)
            return redirect("dashboard")

        except Exception as e:
            print(e)
            return render(request, "register.html", {"error": "Something went wrong, please try again"})

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        master_password = request.POST.get("master_password")

        # Validate empty fields
        if not username or not master_password:
            return render(request, "add.html", {"error": "All fields are required"})
        # Validate lengths
        if len(username) > 30:
            return render(request, "add.html", {"error": "Username is too long (max 50 characters)"})
        if len(master_password) > 64:
            return render(request, "add.html", {"error": "Password is too long (max 64 characters)"})       

        user = authenticate(request, username=username, password=master_password)

        if user:
            try:
                login(request, user)
                request.session["master_password"] = encrypt_for_session(master_password)
                return redirect("dashboard")

            except Exception as e:
                print(e)
                return render(request, "login.html", {"error": "Something went wrong, please try again"})
        else:
            return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")


@login_required
def lock_vault(request):
    request.session.pop("master_password", None)
    return redirect("locked")


@login_required
def locked_view(request):
    if request.session.get("master_password"):
        return redirect("dashboard")

    if request.method == "POST":
        master_password = request.POST.get("master_password")
        
        # Validate empty fields
        if not master_password:
            return render(request, "add.html", {"error": "All fields are required"})
        # Validate lengths
        if len(master_password) > 64:
            return render(request, "add.html", {"error": "Password is too long (max 64 characters)"})
        
        user = authenticate(request, username=request.user.username, password=master_password)

        if user:
            try:
                request.session["master_password"] = encrypt_for_session(master_password)
                return redirect("dashboard")

            except Exception as e:
                print(e)
                return render(request, "locked.html", {"error": "Something went wrong, please try again"})
        else:
            return render(request, "locked.html", {"error": "Invalid master password"})

    return render(request, "locked.html")


@login_required
def dashboard(request):
    try:
        entries = PasswordEntry.objects.filter(user=request.user)
        return render(request, "dashboard.html", {"entries": entries})

    except Exception as e:
        print(e)
        return render(request, "dashboard.html", {"entries": [], "error": "Could not load your passwords, please try again"})


@login_required
def add_password(request):
    encrypted_master = request.session.get("master_password")
    if not encrypted_master:
        return redirect("locked")

    if request.method == "POST":
        try:
            website = request.POST.get("website")
            username = request.POST.get("username")
            password = request.POST.get("password")


            # Validate empty fields
            if not website or not username or not password:
                return render(request, "add.html", {"error": "All fields are required"})
            # Validate lengths
            if len(website) > 20:
                return render(request, "add.html", {"error": "Website name is too long (max 20 characters)"})
            if len(username) > 50:
                return render(request, "add.html", {"error": "Username is too long (max 50 characters)"})
            if len(password) > 64:
                return render(request, "add.html", {"error": "Password is too long (max 64 characters)"})


            # Derive vault key and encrypt
            master_password = decrypt_from_session(encrypted_master)
            salt = bytes(request.user.userprofile.salt)
            key = derive_key(master_password, salt)
            encrypted = encrypt(password, key)

            PasswordEntry.objects.create(
                user=request.user,
                website=website,
                username=username,
                password=encrypted
            )
            return redirect("dashboard")

        except Exception as e:
            print(e)
            return render(request, "add.html", {"error": "Something went wrong, please try again"})

    return render(request, "add.html")


@login_required
def view_password(request, entry_id):
    encrypted_master = request.session.get("master_password")
    if not encrypted_master:
        return redirect("locked")

    try:
        master_password = decrypt_from_session(encrypted_master)
        salt = bytes(request.user.userprofile.salt)
        key = derive_key(master_password, salt)

        entry = get_object_or_404(PasswordEntry, id=entry_id, user=request.user)
        decrypted = decrypt(entry.password, key)

        return render(request, "view.html", {"entry": entry, "password": decrypted})

    except Exception as e:
        print(e)
        return render(request, "view.html", {"error": "Could not decrypt this password, please try again"})


@login_required
def delete_password(request, entry_id):
    entry = get_object_or_404(PasswordEntry, id=entry_id, user=request.user)

    if request.method == "POST":
        try:
            entry.delete()
            return redirect("dashboard")
        except Exception as e:
            print(e)
            return redirect("dashboard")

    return redirect("dashboard")


def logout_view(request):
    request.session.flush()
    logout(request)
    return redirect("login")