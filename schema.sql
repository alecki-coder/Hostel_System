-- Hostel Management System: database schema
-- Running this file resets the database structure.

PRAGMA foreign_keys = ON;

DROP TRIGGER IF EXISTS room_capacity_insert;
DROP TRIGGER IF EXISTS room_capacity_update;
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS hostels;
DROP TABLE IF EXISTS users;

-- Students and wardens share one table, separated by role.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,           -- reg number for students
    full_name     TEXT NOT NULL,
    gender        TEXT CHECK (gender IN ('M', 'F')),
    password_hash TEXT NOT NULL,                  -- never store plain passwords
    role          TEXT NOT NULL CHECK (role IN ('student', 'warden')),
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- students must have a gender, because it decides which hostel they can book
    CHECK (role = 'warden' OR gender IS NOT NULL)
);

CREATE TABLE hostels (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name   TEXT NOT NULL UNIQUE,                  -- Hostel A, B, C
    gender TEXT NOT NULL CHECK (gender IN ('M', 'F'))
);

CREATE TABLE rooms (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostel_id   INTEGER NOT NULL REFERENCES hostels(id),
    room_number INTEGER NOT NULL,
    capacity    INTEGER NOT NULL DEFAULT 4 CHECK (capacity BETWEEN 1 AND 4),
    UNIQUE (hostel_id, room_number)
);

-- One row per student currently booked or housed.
-- Clearing a student DELETES their row, so no history is kept.
CREATE TABLE bookings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id        INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    hostel_id         INTEGER NOT NULL REFERENCES hostels(id),
    room_id           INTEGER REFERENCES rooms(id),
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'rejected')),
    rules_accepted_at TEXT NOT NULL,              -- booking is impossible without acceptance
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- an approved booking must have a room; any other status must not
    CHECK (
        (status = 'approved' AND room_id IS NOT NULL) OR
        (status <> 'approved' AND room_id IS NULL)
    )
);

-- Database-level capacity enforcement: even if the app code has a bug,
-- a room can never exceed its capacity.
CREATE TRIGGER room_capacity_insert
BEFORE INSERT ON bookings
WHEN NEW.room_id IS NOT NULL
 AND (SELECT COUNT(*) FROM bookings WHERE room_id = NEW.room_id)
     >= (SELECT capacity FROM rooms WHERE id = NEW.room_id)
BEGIN
    SELECT RAISE(ABORT, 'Room is full');
END;

CREATE TRIGGER room_capacity_update
BEFORE UPDATE OF room_id ON bookings
WHEN NEW.room_id IS NOT NULL
 AND (SELECT COUNT(*) FROM bookings WHERE room_id = NEW.room_id AND id <> NEW.id)
     >= (SELECT capacity FROM rooms WHERE id = NEW.room_id)
BEGIN
    SELECT RAISE(ABORT, 'Room is full');
END;
