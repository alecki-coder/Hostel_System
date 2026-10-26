"""Create the SQLite database from schema.sql and seed hostels and rooms.

WARNING: running this resets the database. All existing data is lost.
"""
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hostel.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"

HOSTELS = [
    ("Berlin", "M"),
    ("Moscow", "M"),
    ("Denver", "M"),
    ("Tokyo", "F"),
    ("Nairobi", "F"),
]
ROOMS_PER_HOSTEL = 50
BEDS_PER_ROOM = 4


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA_PATH.read_text())

        for name, gender in HOSTELS:
            cur = conn.execute(
                "INSERT INTO hostels (name, gender) VALUES (?, ?)",
                (name, gender),
            )
            hostel_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO rooms (hostel_id, room_number, capacity) VALUES (?, ?, ?)",
                [
                    (hostel_id, number, BEDS_PER_ROOM)
                    for number in range(1, ROOMS_PER_HOSTEL + 1)
                ],
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print(f"Database created at {DB_PATH}")
    print(f"{len(HOSTELS)} hostels, {len(HOSTELS) * ROOMS_PER_HOSTEL} rooms, "
          f"{len(HOSTELS) * ROOMS_PER_HOSTEL * BEDS_PER_ROOM} beds")


if __name__ == "__main__":
    init_db()
