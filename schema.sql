-- Hostel Management System: database schema
-- Running this file resets the database structure.

PRAGMA foreign_keys = ON;

DROP TRIGGER IF EXISTS room_capacity_insert;
DROP TRIGGER IF EXISTS room_capacity_update;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS hostels;
DROP TABLE IF EXISTS users;

-- Students and wardens share one table, separated by role.
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,         -- reg number for students
    full_name       TEXT NOT NULL,
    gender          TEXT CHECK (gender IN ('M', 'F')),
    email           TEXT UNIQUE,                  -- stored lowercase; used for receipts and password reset
    password_hash   TEXT NOT NULL,                -- never store plain passwords
    role            TEXT NOT NULL CHECK (role IN ('student', 'warden')),
    session_version INTEGER NOT NULL DEFAULT 0,   -- raised on password change; ends old sessions
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- students must have a gender, because it decides which hostel they can book
    CHECK (role = 'warden' OR gender IS NOT NULL),
    -- students must have an email, because receipts and resets are sent there
    CHECK (role = 'warden' OR email IS NOT NULL)
);

CREATE TABLE hostels (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name   TEXT NOT NULL UNIQUE,
    gender TEXT NOT NULL CHECK (gender IN ('M', 'F'))
);

CREATE TABLE rooms (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostel_id   INTEGER NOT NULL REFERENCES hostels(id),
    floor       INTEGER NOT NULL CHECK (floor >= 1),
    room_number INTEGER NOT NULL,                 -- first digit is the floor, e.g. 204
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
    bed_number        INTEGER CHECK (bed_number BETWEEN 1 AND 4),
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'rejected')),
    rules_accepted_at TEXT NOT NULL,              -- booking is impossible without acceptance
    rules_version     INTEGER NOT NULL,           -- which version of the rules was accepted
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- an approved booking must have a room and a bed; any other status must have neither
    CHECK (
        (status = 'approved' AND room_id IS NOT NULL AND bed_number IS NOT NULL) OR
        (status <> 'approved' AND room_id IS NULL AND bed_number IS NULL)
    ),
    -- the same bed in the same room can never be given to two students
    UNIQUE (room_id, bed_number)
);

-- Fee payments for a booking. DEMO MODE: no real money moves.
-- One row per instalment; deleted with the booking, so no history is kept.
CREATE TABLE payments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id  INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('booking_fee', 'semester_1', 'semester_2')),
    amount      INTEGER NOT NULL CHECK (amount > 0),      -- whole Kenya shillings
    status      TEXT NOT NULL DEFAULT 'due'
                CHECK (status IN ('due', 'pending', 'paid', 'refunded')),
    checkout_id TEXT UNIQUE,                              -- random id of an open payment prompt
    reference   TEXT UNIQUE,                              -- receipt number once paid
    paid_at     TEXT,                                     -- UTC, set when paid
    UNIQUE (booking_id, kind)
);
CREATE INDEX idx_payments_booking ON payments (booking_id);

-- Failed login attempts, used for rate limiting.
-- The username column holds a keyed hash (HMAC) of the username, never the text
-- that was typed, so a password pasted into the username box is not stored.
-- Rows older than the lockout window are deleted by the app.
CREATE TABLE login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,                   -- HMAC-SHA256 of the lowercase username
    ip           TEXT NOT NULL,
    attempted_at INTEGER NOT NULL                 -- Unix time in seconds
);
CREATE INDEX idx_attempts_username ON login_attempts (username, attempted_at);
CREATE INDEX idx_attempts_ip       ON login_attempts (ip, attempted_at);

-- Password reset requests. Only a hash of the emailed token is stored,
-- so reading the database never reveals a usable reset link.
-- A row is deleted as soon as it is used, so no history is kept.
CREATE TABLE password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,              -- SHA-256 of the token in the email link
    expires_at INTEGER NOT NULL,                  -- Unix time in seconds
    created_at INTEGER NOT NULL                   -- Unix time in seconds
);
CREATE INDEX idx_resets_user ON password_resets (user_id, created_at);

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
