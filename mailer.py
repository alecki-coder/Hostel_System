"""Send email through Gmail SMTP.

Credentials come from the .env file (never from code, never from Git).
If they are missing, the email is printed in the terminal instead
(development mode), so nothing breaks while testing.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
TIMEOUT_SECONDS = 15


def load_env() -> None:
    """Load KEY=VALUE lines from .env into the environment."""
    if not ENV_PATH.exists():
        return
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Real environment variables win over the file.
        os.environ.setdefault(key.strip(), value.strip())


load_env()


def send_email(to_address: str, subject: str, body: str) -> bool:
    """Send a plain-text email. Returns True if it was sent (or printed)."""
    username = os.environ.get("MAIL_USERNAME", "")
    password = os.environ.get("MAIL_PASSWORD", "")

    if not username or not password:
        print("\n[DEV MODE: no mail credentials, email not sent]")
        print(f"To: {to_address}\nSubject: {subject}\n\n{body}\n")
        return True

    message = EmailMessage()
    message["From"] = f"Hostel System <{username}>"
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=ssl.create_default_context(),
            timeout=TIMEOUT_SECONDS,
        ) as server:
            server.login(username, password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError, ValueError) as exc:
        # Log only the error type: never the password or message contents.
        print(f"Email could not be sent: {type(exc).__name__}")
        return False
    return True
