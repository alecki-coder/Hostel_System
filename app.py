"""Hostel Management System: Flask application (step 1: database + status page)."""
import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hostel.db"

app = Flask(__name__)


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


@app.route("/")
def status():
    """Show capacity and occupancy for every hostel."""
    rows = get_db().execute(
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
    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
