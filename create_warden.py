"""Create a warden account, or add an email to an existing one.

Wardens cannot register through the website: only someone with access to
the server can create one, by running this script. A warden needs an email
address so that the Forgot password page can reach them.
"""
import sqlite3
from getpass import getpass

from werkzeug.security import generate_password_hash

from app import DB_PATH, EMAIL_RE, MAX_EMAIL_LENGTH, USERNAME_RE, password_problems


def ask_email(prompt: str):
    email = input(prompt).strip().lower()
    if not email:
        return None
    if len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.fullmatch(email):
        print("That is not a valid email address.")
        return None
    return email


def main() -> None:
    username = input("Warden username: ").strip()
    if not USERNAME_RE.fullmatch(username):
        print("Username must be 3-40 characters: letters, digits, / _ -")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT id, role, email FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row is not None:
            if row[1] != "warden":
                print("That username belongs to a student, not a warden.")
                return
            print("This warden already exists. Their password will not be changed.")
            email = ask_email("Email address to save (blank to cancel): ")
            if email is None:
                print("Nothing changed.")
                return
            try:
                conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, row[0]))
                conn.commit()
            except sqlite3.IntegrityError:
                print("That email address is already used by another account.")
                return
            print(f"Email saved for warden '{username}'.")
            return

        full_name = input("Full name: ").strip()
        if not 2 <= len(full_name) <= 100:
            print("Full name must be 2-100 characters.")
            return
        email = ask_email("Email address (needed for password reset): ")
        if email is None:
            print("A valid email address is required.")
            return
        password = getpass("Password (hidden): ")
        problems = password_problems(password, username)
        if problems:
            print("Password is too weak. It needs: " + ", ".join(problems) + ".")
            return
        if getpass("Repeat password: ") != password:
            print("Passwords do not match.")
            return

        try:
            conn.execute(
                "INSERT INTO users (username, full_name, gender, email, password_hash, role) "
                "VALUES (?, ?, NULL, ?, ?, 'warden')",
                (username, full_name, email, generate_password_hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            print("That username or email address already exists.")
            return
        print(f"Warden '{username}' created.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
