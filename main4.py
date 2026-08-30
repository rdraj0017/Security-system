import os
import sqlite3
import pyotp
import qrcode
import io
import base64
from flask import (
    Flask, render_template_string, request, redirect, 
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for signing session cookies securely
app.secret_key = os.urandom(32)
DB_PATH = "secure_users.db"

# ---------------------------------------------------------------------------
# Database Initialization & Prepared Statements
# ---------------------------------------------------------------------------
def init_db():
    """Creates tables with parameterized structure to prevent SQL injection."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                is_2fa_enabled INTEGER DEFAULT 0
            )
        """)
        conn.commit()

init_db()

# ---------------------------------------------------------------------------
# HTML Templates (In-Memory for Single-File Portability)
# ---------------------------------------------------------------------------
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Auth System</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { margin-top: 0; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem; margin: 0.5rem 0 1rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 0.75rem; background: #0066cc; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
        button:hover { background: #0052a3; }
        .flash { padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; }
        .flash.error { background: #ffe6e6; color: #cc0000; }
        .flash.success { background: #e6ffe6; color: #008000; }
        a { color: #0066cc; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, msg in messages %}
                    <div class="flash {{ category }}">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

REGISTER_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Create Account</h2>
<form method="POST">
    <label>Username</label>
    <input type="text" name="username" required>
    <label>Password</label>
    <input type="password" name="password" required minlength="8">
    <button type="submit">Register</button>
</form>
<p>Already have an account? <a href="/login">Login here</a></p>
""")

LOGIN_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Secure Login</h2>
<form method="POST">
    <label>Username</label>
    <input type="text" name="username" required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Log In</button>
</form>
<p>Need an account? <a href="/register">Register here</a></p>
""")

VERIFY_2FA_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Two-Factor Authentication</h2>
<p>Enter the 6-digit verification code from your authenticator app.</p>
<form method="POST">
    <label>2FA Code</label>
    <input type="text" name="totp_code" required placeholder="123456" maxlength="6">
    <button type="submit">Verify Code</button>
</form>
""")

SETUP_2FA_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Setup 2FA</h2>
<p>Scan this QR code with Google Authenticator or Authy:</p>
<div style="text-align: center; margin: 1rem 0;">
    <img src="data:image/png;base64,{{ qr_code }}" alt="2FA QR Code" style="max-width:200px;">
</div>
<form method="POST" action="/enable-2fa">
    <label>Enter 6-Digit Code to Confirm</label>
    <input type="text" name="totp_code" required maxlength="6">
    <button type="submit">Activate 2FA</button>
</form>
""")

DASHBOARD_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>User Dashboard</h2>
<p>Welcome, <strong>{{ username }}</strong>!</p>
<p>Status: <span style="color: green; font-weight: bold;">Authenticated</span></p>
<hr>
{% if not is_2fa_enabled %}
    <p>⚡ <strong>Enhance Security:</strong> 2FA is currently disabled.</p>
    <a href="/setup-2fa"><button style="background: #28a745;">Setup 2FA</button></a>
{% else %}
    <p>✅ <strong>Two-Factor Authentication is Enabled</strong></p>
{% endif %}
<br><br>
<a href="/logout"><button style="background: #dc3545;">Logout</button></a>
""")

# ---------------------------------------------------------------------------
# Routes & Controllers
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input Validation
        if not username or len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template_string(REGISTER_HTML)

        # Hash password securely (PBKDF2/SHA256 via Werkzeug abstraction)
        password_hash = generate_password_hash(password, method="scrypt")
        totp_secret = pyotp.random_base32()

        try:
            # Parameterized Query prevents SQL Injection
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
                    (username, password_hash, totp_secret)
                )
                conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists. Choose another.", "error")

    return render_template_string(REGISTER_HTML)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Safe SQL querying using parameters
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, totp_secret, is_2fa_enabled FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[1], password):
            # Password matches, now handle 2FA check
            user_id, _, totp_secret, is_2fa_enabled = user

            if is_2fa_enabled:
                # Store partial login state in session
                session["pending_user_id"] = user_id
                session["pending_username"] = username
                return redirect(url_for("verify_2fa"))
            else:
                # Log user in directly if 2FA disabled
                session.clear()
                session["user_id"] = user_id
                session["username"] = username
                flash("Logged in successfully!", "success")
                return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template_string(LOGIN_HTML)


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        totp_code = request.form.get("totp_code", "").strip()
        user_id = session["pending_user_id"]

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

        if user:
            totp = pyotp.TOTP(user[0])
            if totp.verify(totp_code):
                # Promote session to full authentication
                session["user_id"] = user_id
                session["username"] = session.pop("pending_username")
                session.pop("pending_user_id")
                flash("2FA Verification Successful!", "success")
                return redirect(url_for("dashboard"))

        flash("Invalid 2FA code. Please try again.", "error")

    return render_template_string(VERIFY_2FA_HTML)


@app.route("/setup-2fa", methods=["GET"])
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, totp_secret FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()

    # Generate TOTP URI and QR Code Image
    totp = pyotp.TOTP(user[1])
    provisioning_uri = totp.provisioning_uri(name=user[0], issuer_name="SecureApp")

    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template_string(SETUP_2FA_HTML, qr_code=qr_b64)


@app.route("/enable-2fa", methods=["POST"])
def enable_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))

    totp_code = request.form.get("totp_code", "").strip()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT totp_secret FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()

    if user and pyotp.TOTP(user[0]).verify(totp_code):
        with sqlite3.connect(DB_PATH) as conn:
            conn.cursor().execute("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (session["user_id"],))
            conn.commit()
        flash("Two-Factor Authentication activated!", "success")
        return redirect(url_for("dashboard"))

    flash("Invalid verification code.", "error")
    return redirect(url_for("setup_2fa"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to access dashboard.", "error")
        return redirect(url_for("login"))

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (session["user_id"],))
        is_2fa = cursor.fetchone()[0]

    return render_template_string(
        DASHBOARD_HTML, 
        username=session["username"], 
        is_2fa_enabled=is_2fa
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    print("[*] Starting Secure Login Server at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)