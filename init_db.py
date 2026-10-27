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
FLOORS_PER_HOSTEL = 5
ROOMS_PER_FLOOR = 10
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
            # Room numbers carry the floor as the first digit: 101-110, 201-210, ...
            rooms = [
                (hostel_id, floor, floor * 100 + position, BEDS_PER_ROOM)
                for floor in range(1, FLOORS_PER_HOSTEL + 1)
                for position in range(1, ROOMS_PER_FLOOR + 1)
            ]
            conn.executemany(
                "INSERT INTO rooms (hostel_id, floor, room_number, capacity) "
                "VALUES (?, ?, ?, ?)",
                rooms,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    total_rooms = len(HOSTELS) * FLOORS_PER_HOSTEL * ROOMS_PER_FLOOR
    print(f"Database created at {DB_PATH}")
    print(f"{len(HOSTELS)} hostels, {total_rooms} rooms, "
          f"{total_rooms * BEDS_PER_ROOM} beds")


if __name__ == "__main__":
    init_db()
