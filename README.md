# Vault - Password Manager

A secure password manager web application built with Django, inspired by Bitwarden.

## Features

- User registration and login with a master password
- Vault encryption using Argon2id key derivation and Fernet (AES) encryption
- Per-user random salt for key derivation
- Master password encrypted in session using Django's SECRET_KEY
- Vault key derived fresh on every request and never stored
- Lock vault without logging out
- Add, view and delete password entries
- Password generator with customizable length and character options

## Security

- Passwords are encrypted using Fernet (AES-128-CBC + HMAC-SHA256)
- Master password is never stored anywhere in plaintext
- Vault key only exists briefly in server memory during a request
- Per-user unique salt stored in database
- Argon2id used for key derivation (memory-hard, GPU resistant)
- Django's built-in PBKDF2 hashing for authentication

## Tech Stack

- Python 3.13
- Django 6.0.3
- cryptography (Fernet encryption)
- argon2-cffi (Argon2id key derivation)
- python-decouple (environment variables)
- SQLite (development database)

## Installation

1. Clone the repository:
   git clone https://github.com/leomili/vault-password-manager.git
   cd vault-password-manager

2. Install dependencies:
   pip install -r requirements.txt

3. Set up environment variables:
   cp .env.example .env
   Then edit `.env` and add your own `DJANGO_SECRET_KEY`.

4. Generate a new secret key:
   python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

5. Run migrations:
   python manage.py migrate

6. Start the development server:
   python manage.py runserver

7. Visit `http://127.0.0.1:8000/` in your browser.

## Project Structure

vault_project/
vault/ # Django project settings
settings.py
urls.py
manager/ # Main app
models.py # PasswordEntry and UserProfile models
views.py # All view functions
templates/ # HTML templates
static/ # CSS files
encryption_helper.py # Encryption and key derivation functions
manage.py
requirements.txt
.env # Secret key (never commit this)

## Usage

1. Register a new account with a username and master password
2. You will be automatically logged in after registration
3. Add password entries using the Add new password button
4. Click any entry on the dashboard to view its details
5. Use the password generator to create strong passwords
6. Lock your vault without logging out using the Lock Vault button
