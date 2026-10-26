"""Hostel Management System: Flask application (step 4: session revalidation)."""
import re
import secrets
import sqlite3
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect,
    render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hostel.db"
INSTANCE_DIR = BASE_DIR / "instance"
SECRET_PATH = INSTANCE_DIR / "secret_key"

USERNAME_RE = re.compile(r"^[A-Za-z0-9/_-]{3,40}$")

# Used to burn the same time on unknown usernames as on real ones,
# so response timing does not reveal which usernames exist.
DUMMY_HASH = generate_password_hash("not-a-real-password")


def load_secret_key() -> str:
    """Read the session signing key, creating it once if missing."""
    INSTANCE_DIR.mkdir(exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_text(secrets.token_hex(32))
        SECRET_PATH.chmod(0o600)
    return SECRET_PATH.read_text().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024,  # reject oversized request bodies
)


# ---------- database ----------

def get_db() -> sqlite3.Connection:
    """Return one database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # SQLite disables foreign keys by default, per connection.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- session revalidation ----------

@app.before_request
def load_current_user() -> None:
    """Never trust the cookie alone: confirm the user still exists.

    Name and role are refreshed from the database on every request, so a
    deleted account is logged out and a role change takes effect at once.
    """
    user_id = session.get("user_id")
    if user_id is None:
        return
    user = get_db().execute(
        "SELECT full_name, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        session.clear()
        return
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]


# ---------- CSRF protection ----------

def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf() -> None:
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# ---------- routes ----------

@app.route("/")
def home():
    """Home page: capacity and occupancy for every hostel."""
    hostels = get_db().execute(
        """
        SELECT h.name,
               h.gender,
               COUNT(DISTINCT r.id)        AS rooms,
               COALESCE(SUM(r.capacity), 0) AS beds,
               (SELECT COUNT(*)
                  FROM bookings b
                 WHERE b.hostel_id = h.id
                   AND b.status = 'approved') AS occupied
          FROM hostels h
          LEFT JOIN rooms r ON r.hostel_id = h.id
         GROUP BY h.id
         ORDER BY h.name
        """
    ).fetchall()
    return render_template("home.html", hostels=hostels)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    gender = request.form.get("gender", "")
    password = request.form.get("password", "")

    error = None
    if not USERNAME_RE.fullmatch(username):
        error = "Registration number must be 3-40 characters: letters, digits, / _ -"
    elif not 2 <= len(full_name) <= 100:
        error = "Full name must be 2-100 characters."
    elif gender not in ("M", "F"):
        error = "Select a gender."
    elif not 8 <= len(password) <= 128:
        error = "Password must be 8-128 characters."

    if error:
        flash(error, "error")
        return render_template("register.html"), 400

    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, full_name, gender, password_hash, role) "
            "VALUES (?, ?, ?, ?, 'student')",
            (username, full_name, gender, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("That registration number is already registered.", "error")
        return render_template("register.html"), 400

    flash("Account created. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = get_db().execute(
        "SELECT id, full_name, role, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored_hash = user["password_hash"] if user else DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password)

    if not user or not password_ok:
        # Same message for unknown user and wrong password.
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    session.clear()  # drop the old session to prevent session fixation
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]
    flash("Logged in successfully.", "success")
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
