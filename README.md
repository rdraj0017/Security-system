# Secure Web Login System with 2FA

A secure authentication web application built using Python, Flask, and SQLite. Features standard-compliant password hashing, parameterized SQL execution, secure session invalidation, and Time-Based Two-Factor Authentication (TOTP).

## Features

- **Secure Password Hashing**: Uses `scrypt` key derivation function with random salts.
- **SQL Injection Prevention**: Prepared statements for all SQLite CRUD operations.
- **2FA Integration**: Optional TOTP generation compatible with Google Authenticator and Authy.
- **Session Management**: Cryptographically signed cookie sessions with complete server-side logouts.

---

## Installation & Setup

1. **Install Requirements**:
   ```bash
   pip install flask pyotp qrcode pillow werkzeug
