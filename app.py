"""Hostel Management System: Flask application (step 14: rejection email)."""
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect,
    render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from mailer import send_email

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hostel.db"
INSTANCE_DIR = BASE_DIR / "instance"
SECRET_PATH = INSTANCE_DIR / "secret_key"

# Bump this whenever templates/_rules_text.html is edited.
RULES_VERSION = 1

# East Africa Time (Nairobi): UTC+3, no daylight saving in Kenya.
EAT = timezone(timedelta(hours=3), "EAT")

USERNAME_RE = re.compile(r"^[A-Za-z0-9/_-]{3,40}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAX_EMAIL_LENGTH = 120

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Login rate limiting. Counts failures inside a sliding window.
MAX_FAILED_ATTEMPTS = 5          # per username
MAX_FAILED_ATTEMPTS_PER_IP = 20  # per IP (campus networks share addresses)
LOCKOUT_SECONDS = 15 * 60

# Passwords attackers try first. Compared in lowercase.
COMMON_PASSWORDS = {
    "password", "password1", "password1!", "password123", "p@ssw0rd",
    "passw0rd", "passw0rd!", "12345678", "123456789", "1234567890",
    "11111111", "qwerty123", "qwertyuiop", "iloveyou", "admin123",
    "admin@123", "welcome1", "welcome123", "letmein1", "abc12345",
    "changeme", "student123", "hostel123",
}

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


# ---------- time display (EAT) ----------

def to_eat(value) -> str:
    """Convert a stored UTC timestamp to Nairobi time for display.

    Times are stored in UTC and converted only when shown.
    """
    if not value:
        return ""
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(EAT).strftime("%d %b %Y, %H:%M EAT")


app.jinja_env.filters["eat"] = to_eat


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


# ---------- password policy ----------

def password_problems(password: str, username: str) -> list:
    """Return a list of reasons the password is too weak (empty = OK)."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"at most {MAX_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[0-9]", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        problems.append("a symbol such as ! @ # $ %")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("to not be a commonly used password")
    if len(username) >= 3 and username.lower() in password.lower():
        problems.append("to not contain your registration number")
    return problems


# ---------- login rate limiting ----------

def client_ip() -> str:
    """The connecting address. We deliberately ignore X-Forwarded-For,
    because without a trusted proxy a client could forge it and dodge
    the limit."""
    return request.remote_addr or "unknown"


def is_locked_out(username_key: str, ip: str) -> bool:
    """True if this username or this IP has too many recent failures."""
    since = int(time.time()) - LOCKOUT_SECONDS
    db = get_db()
    user_count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND attempted_at > ?",
        (username_key, since),
    ).fetchone()[0]
    ip_count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND attempted_at > ?",
        (ip, since),
    ).fetchone()[0]
    if user_count >= MAX_FAILED_ATTEMPTS:
        return True
    if ip_count >= MAX_FAILED_ATTEMPTS_PER_IP:
        return True
    return False


def record_failed_login(username_key: str, ip: str) -> None:
    """Store a failure and delete rows older than the lockout window."""
    now = int(time.time())
    db = get_db()
    db.execute(
        "DELETE FROM login_attempts WHERE attempted_at <= ?",
        (now - LOCKOUT_SECONDS,),
    )
    db.execute(
        "INSERT INTO login_attempts (username, ip, attempted_at) VALUES (?, ?, ?)",
        (username_key, ip, now),
    )
    db.commit()


def clear_failed_logins(username_key: str) -> None:
    """A successful login resets that username's failure count."""
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE username = ?", (username_key,))
    db.commit()


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


def login_required(role=None):
    """Require a logged-in user, optionally with a specific role."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if role is not None and session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


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


# ---------- helpers ----------

def hostels_for_gender(gender: str):
    """Hostels a student of this gender may book, with free beds."""
    return get_db().execute(
        """
        SELECT h.id,
               h.name,
               (SELECT COALESCE(SUM(r.capacity), 0)
                  FROM rooms r WHERE r.hostel_id = h.id)
               - (SELECT COUNT(*)
                    FROM bookings b
                   WHERE b.hostel_id = h.id AND b.status = 'approved') AS available
          FROM hostels h
         WHERE h.gender = ?
         ORDER BY h.name
        """,
        (gender,),
    ).fetchall()


def current_booking(student_id: int):
    return get_db().execute(
        """
        SELECT b.status, b.rules_accepted_at, b.rules_version, b.bed_number,
               h.name AS hostel_name, r.room_number, r.floor
          FROM bookings b
          JOIN hostels h ON h.id = b.hostel_id
          LEFT JOIN rooms r ON r.id = b.room_id
         WHERE b.student_id = ?
        """,
        (student_id,),
    ).fetchone()


def student_gender(student_id: int):
    row = get_db().execute(
        "SELECT gender FROM users WHERE id = ?", (student_id,)
    ).fetchone()
    return row["gender"] if row else None


def build_receipt(details) -> tuple:
    """Return (subject, body) for the accommodation receipt email."""
    receipt_number = f"HS-{details['booking_id']:06d}"
    issued = to_eat(datetime.now(timezone.utc).isoformat(timespec="seconds"))
    subject = f"Hostel accommodation receipt {receipt_number}"
    body = (
        "HOSTEL MANAGEMENT SYSTEM\n"
        "Accommodation receipt\n"
        "\n"
        f"Receipt no:           {receipt_number}\n"
        f"Date issued:          {issued}\n"
        "\n"
        f"Student:              {details['full_name']}\n"
        f"Registration number:  {details['username']}\n"
        "\n"
        f"Hostel:               {details['hostel_name']}\n"
        f"Floor:                {details['floor']}\n"
        f"Room:                 {details['room_number']}\n"
        f"Bed:                  {details['bed_number']}\n"
        "\n"
        f"Rules accepted:       version {details['rules_version']}\n"
        "\n"
        "Your booking has been approved. Please present this receipt to the\n"
        "warden when you arrive. Clearing at the end of your stay is done by\n"
        "the warden and releases your bed immediately.\n"
        "\n"
        "This is an automated message. Do not reply to it.\n"
    )
    return subject, body


def build_rejection_email(details) -> tuple:
    """Return (subject, body) telling a student their request was declined."""
    subject = "Update on your hostel booking request"
    body = (
        "HOSTEL MANAGEMENT SYSTEM\n"
        "\n"
        f"Dear {details['full_name']},\n"
        "\n"
        f"Your request for a room in {details['hostel_name']} hostel "
        "has been declined by the warden.\n"
        "\n"
        "You may log in and submit a new request, or contact the warden's\n"
        "office to find out more.\n"
        "\n"
        "This is an automated message. Do not reply to it.\n"
    )
    return subject, body


# ---------- routes: public and student ----------

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


@app.route("/rules")
def rules():
    return render_template("rules.html")


@app.route("/book", methods=["GET", "POST"])
@login_required(role="student")
def book():
    student_id = session["user_id"]
    existing = current_booking(student_id)

    # A rejected request does not block the student: they may try again.
    rejected = existing is not None and existing["status"] == "rejected"
    active = existing if existing is not None and not rejected else None

    def render_form(status: int = 200):
        return render_template(
            "book.html",
            booking=None,
            rejected=rejected,
            hostels=hostels_for_gender(student_gender(student_id)),
            rules_version=RULES_VERSION,
        ), status

    if request.method == "GET":
        if active:
            return render_template("book.html", booking=active)
        return render_form()

    # ----- POST: submit a booking request -----
    def form_with_error(message: str, status: int = 400):
        flash(message, "error")
        return render_form(status)

    if active:
        flash("You already have a booking.", "error")
        return redirect(url_for("book"))

    if request.form.get("accept_rules") != "yes":
        return form_with_error("You must accept the rules and regulations to book.")

    try:
        hostel_id = int(request.form.get("hostel_id", ""))
    except ValueError:
        return form_with_error("Select a valid hostel.")

    # Re-check everything on the server; never trust the form's dropdown.
    allowed = {h["id"]: h for h in hostels_for_gender(student_gender(student_id))}
    hostel = allowed.get(hostel_id)
    if hostel is None:
        return form_with_error("That hostel is not available for you.", 403)
    if hostel["available"] <= 0:
        return form_with_error(f"{hostel['name']} has no free beds.")

    accepted_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db = get_db()
    try:
        # Delete the old rejected row (if any) and insert the new request in
        # one transaction, so a failure never leaves the student with neither.
        db.execute(
            "DELETE FROM bookings WHERE student_id = ? AND status = 'rejected'",
            (student_id,),
        )
        db.execute(
            "INSERT INTO bookings (student_id, hostel_id, status, "
            "rules_accepted_at, rules_version) VALUES (?, ?, 'pending', ?, ?)",
            (student_id, hostel_id, accepted_at, RULES_VERSION),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # student_id is UNIQUE: a double-submit lands here.
        db.rollback()
        flash("You already have a booking.", "error")
        return redirect(url_for("book"))

    flash("Booking request submitted. Wait for the warden's decision.", "success")
    return redirect(url_for("book"))


# ---------- routes: warden ----------

@app.route("/warden")
@login_required(role="warden")
def warden_panel():
    db = get_db()
    totals = db.execute(
        """
        SELECT h.name,
               COALESCE((SELECT SUM(r.capacity)
                           FROM rooms r WHERE r.hostel_id = h.id), 0) AS beds,
               (SELECT COUNT(*)
                  FROM bookings b
                 WHERE b.hostel_id = h.id AND b.status = 'approved') AS housed
          FROM hostels h
         ORDER BY h.name
        """
    ).fetchall()
    pending = db.execute(
        """
        SELECT b.id, u.username, u.full_name, h.name AS hostel_name
          FROM bookings b
          JOIN users u ON u.id = b.student_id
          JOIN hostels h ON h.id = b.hostel_id
         WHERE b.status = 'pending'
         ORDER BY b.created_at, b.id
        """
    ).fetchall()
    housed = db.execute(
        """
        SELECT b.id, u.username, u.full_name, b.bed_number,
               h.name AS hostel_name, r.room_number, r.floor
          FROM bookings b
          JOIN users u ON u.id = b.student_id
          JOIN hostels h ON h.id = b.hostel_id
          JOIN rooms r ON r.id = b.room_id
         WHERE b.status = 'approved'
         ORDER BY h.name, r.room_number, b.bed_number
        """
    ).fetchall()
    return render_template(
        "warden.html", totals=totals, pending=pending, housed=housed
    )


@app.route("/warden/approve/<int:booking_id>", methods=["POST"])
@login_required(role="warden")
def warden_approve(booking_id: int):
    db = get_db()
    try:
        # Lock the database so two approvals cannot claim the same last bed.
        db.execute("BEGIN IMMEDIATE")
        booking = db.execute(
            "SELECT id, hostel_id FROM bookings WHERE id = ? AND status = 'pending'",
            (booking_id,),
        ).fetchone()
        if booking is None:
            db.rollback()
            flash("That request is no longer pending.", "error")
            return redirect(url_for("warden_panel"))

        # First room in the hostel that still has a free bed.
        room = db.execute(
            """
            SELECT r.id, r.room_number, r.floor, r.capacity
              FROM rooms r
             WHERE r.hostel_id = ?
               AND (SELECT COUNT(*) FROM bookings b WHERE b.room_id = r.id) < r.capacity
             ORDER BY r.room_number
             LIMIT 1
            """,
            (booking["hostel_id"],),
        ).fetchone()
        if room is None:
            db.rollback()
            flash("No free bed left in that hostel.", "error")
            return redirect(url_for("warden_panel"))

        # Lowest bed number in that room that nobody holds.
        taken = {
            row["bed_number"]
            for row in db.execute(
                "SELECT bed_number FROM bookings WHERE room_id = ?", (room["id"],)
            )
        }
        bed_number = next(n for n in range(1, room["capacity"] + 1) if n not in taken)

        db.execute(
            "UPDATE bookings SET status = 'approved', room_id = ?, bed_number = ? "
            "WHERE id = ?",
            (room["id"], bed_number, booking_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        flash("Could not approve the request. Try again.", "error")
        return redirect(url_for("warden_panel"))

    flash(
        f"Request approved. Student placed in floor {room['floor']}, "
        f"room {room['room_number']}, bed {bed_number}.",
        "success",
    )

    # The approval is already saved. A mail problem must never undo it,
    # so sending happens after the commit and only produces a warning.
    details = db.execute(
        """
        SELECT b.id AS booking_id, b.bed_number, b.rules_version,
               u.full_name, u.username, u.email,
               h.name AS hostel_name, r.room_number, r.floor
          FROM bookings b
          JOIN users u ON u.id = b.student_id
          JOIN hostels h ON h.id = b.hostel_id
          JOIN rooms r ON r.id = b.room_id
         WHERE b.id = ?
        """,
        (booking_id,),
    ).fetchone()
    if details is None or not details["email"]:
        flash("No email address on file, so no receipt was sent.", "error")
    else:
        subject, body = build_receipt(details)
        if send_email(details["email"], subject, body):
            flash("Receipt emailed to the student.", "success")
        else:
            flash("Approved, but the receipt email could not be sent.", "error")
    return redirect(url_for("warden_panel"))


@app.route("/warden/reject/<int:booking_id>", methods=["POST"])
@login_required(role="warden")
def warden_reject(booking_id: int):
    db = get_db()

    # Read the student's details first, while the request is still pending.
    details = db.execute(
        """
        SELECT b.id AS booking_id, u.full_name, u.username, u.email,
               h.name AS hostel_name
          FROM bookings b
          JOIN users u ON u.id = b.student_id
          JOIN hostels h ON h.id = b.hostel_id
         WHERE b.id = ? AND b.status = 'pending'
        """,
        (booking_id,),
    ).fetchone()

    cur = db.execute(
        "UPDATE bookings SET status = 'rejected' WHERE id = ? AND status = 'pending'",
        (booking_id,),
    )
    db.commit()
    if cur.rowcount == 0 or details is None:
        flash("That request is no longer pending.", "error")
        return redirect(url_for("warden_panel"))

    flash("Request rejected.", "success")

    # The rejection is already saved. A mail problem must never undo it.
    if not details["email"]:
        flash("No email address on file, so no notice was sent.", "error")
    else:
        subject, body = build_rejection_email(details)
        if send_email(details["email"], subject, body):
            flash("Rejection notice emailed to the student.", "success")
        else:
            flash("Rejected, but the notice email could not be sent.", "error")
    return redirect(url_for("warden_panel"))


@app.route("/warden/clear/<int:booking_id>", methods=["POST"])
@login_required(role="warden")
def warden_clear(booking_id: int):
    """Clear a student: delete the booking so the bed is free at once.

    No record of the past occupant is kept (data privacy).
    """
    db = get_db()
    cur = db.execute(
        "DELETE FROM bookings WHERE id = ? AND status = 'approved'",
        (booking_id,),
    )
    db.commit()
    if cur.rowcount == 0:
        flash("That student is not currently housed.", "error")
    else:
        flash("Student cleared. The bed is now free.", "success")
    return redirect(url_for("warden_panel"))


# ---------- routes: accounts ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    gender = request.form.get("gender", "")
    password = request.form.get("password", "")

    error = None
    if not USERNAME_RE.fullmatch(username):
        error = "Registration number must be 3-40 characters: letters, digits, / _ -"
    elif not 2 <= len(full_name) <= 100:
        error = "Full name must be 2-100 characters."
    elif len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.fullmatch(email):
        error = "Enter a valid email address."
    elif gender not in ("M", "F"):
        error = "Select a gender."
    else:
        problems = password_problems(password, username)
        if problems:
            error = "Password is too weak. It needs: " + ", ".join(problems) + "."

    if error:
        flash(error, "error")
        return render_template("register.html"), 400

    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, full_name, gender, email, password_hash, role) "
            "VALUES (?, ?, ?, ?, ?, 'student')",
            (username, full_name, gender, email, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # One message for both cases, so it does not say which one matched.
        flash("That registration number or email address is already registered.", "error")
        return render_template("register.html"), 400

    flash("Account created. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Same key and message whether or not the username exists, so the lockout
    # cannot be used to discover real accounts.
    username_key = username.lower()[:40]
    ip = client_ip()

    if is_locked_out(username_key, ip):
        flash("Too many failed attempts. Try again in 15 minutes.", "error")
        return render_template("login.html"), 429

    user = get_db().execute(
        "SELECT id, full_name, role, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored_hash = user["password_hash"] if user else DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password)

    if not user or not password_ok:
        record_failed_login(username_key, ip)
        # Same message for unknown user and wrong password.
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    clear_failed_logins(username_key)
    session.clear()  # drop the old session to prevent session fixation
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]
    flash("Logged in successfully.", "success")
    if user["role"] == "warden":
        return redirect(url_for("warden_panel"))
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
