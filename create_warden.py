"""Create a warden account from the terminal.

Wardens cannot register through the website: only someone with access to
the server can create one, by running this script.
"""
import sqlite3
from getpass import getpass

from werkzeug.security import generate_password_hash

from app import DB_PATH, USERNAME_RE, password_problems


def main() -> None:
    username = input("Warden username: ").strip()
    if not USERNAME_RE.fullmatch(username):
        print("Username must be 3-40 characters: letters, digits, / _ -")
        return

    full_name = input("Full name: ").strip()
    if not 2 <= len(full_name) <= 100:
        print("Full name must be 2-100 characters.")
        return

    password = getpass("Password (hidden): ")
    problems = password_problems(password, username)
    if problems:
        print("Password is too weak. It needs: " + ", ".join(problems) + ".")
        return
    if getpass("Repeat password: ") != password:
        print("Passwords do not match.")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO users (username, full_name, gender, password_hash, role) "
            "VALUES (?, ?, NULL, ?, 'warden')",
            (username, full_name, generate_password_hash(password)),
        )
        conn.commit()
        print(f"Warden '{username}' created.")
    except sqlite3.IntegrityError:
        print("That username already exists.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
