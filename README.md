# Hostel Management System

A web-based system that manages university hostel accommodation: students register, accept the rules and request a room, and a warden approves, rejects and clears them. Students are told every outcome by email, including the exact hostel, floor, room and bed.

Built as a system analysis and design course project with Python and Flask.

## What it does

**Students**

- Register with registration number, name, email, gender and a strong password
- See live availability for every hostel
- Read and accept the hostel rules before booking (the time and rules version are recorded)
- Request one room, only in a hostel that matches their gender
- Receive emails: request received, receipt (hostel, floor, room, bed), or rejection notice
- Request again after a rejection, reset a forgotten password, change their password

**Warden**

- Approve or reject pending requests (the system assigns floor, room and bed automatically)
- Clear students when they leave, which frees the bed immediately
- See every room with its occupants and free beds, and totals per hostel
- Reset or change their own password

## Hostels and capacity

| Hostel | For | Rooms | Beds |
|---|---|---|---|
| Berlin | Boys | 10 (2 floors of 5) | 20 |
| Moscow | Boys | 10 | 20 |
| Denver | Boys | 10 | 20 |
| Tokyo | Girls | 10 | 20 |
| Nairobi | Girls | 10 | 20 |

Each room holds 2 students. The layout is set in `init_db.py`.

## Tech stack

Python 3.12, Flask 3.1, SQLite, Jinja2 templates, Gmail SMTP for email, Git and GitHub.

## Quick start (Linux)

    git clone https://github.com/alecki-coder/Hostel_System.git
    cd Hostel_System
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python init_db.py
    python create_warden.py
    python app.py

Then open http://127.0.0.1:5000

`init_db.py` builds the database and **resets it**, so run it only on a fresh install. `create_warden.py` asks for a username, name, email and a strong password (typed hidden). Wardens cannot register through the website.

## Email setup (optional)

Without any setup the system still works: emails are printed in the terminal instead of being sent.

To send real email, copy `.env.example` to `.env` and fill it in. Use a Gmail account with 2-step verification and a 16-character app password (never your normal password). `.env` is listed in `.gitignore` and must never be committed.

## Project structure

    app.py               routes, rules and security checks
    mailer.py            sends email over SSL (or prints it in development)
    schema.sql           database tables, constraints and triggers
    init_db.py           builds the database and seeds hostels and rooms
    create_warden.py     creates a warden or adds an email to one
    templates/           HTML pages (Jinja2)
    requirements.txt     Python dependencies
    .env.example         names of the settings kept in .env

## Security design

- Passwords are stored only as salted hashes; a strength policy requires upper and lower case, a digit and a symbol, and blocks common passwords
- Login lockout: 5 failures per username or 20 per IP address in 15 minutes; the attempts table stores a keyed hash of the username, never the text typed
- Same message for a wrong username and a wrong password, so accounts cannot be guessed
- Password reset by an emailed one-time link: 256-bit random token, only its SHA-256 hash is stored, 30-minute expiry, deleted when used, the same reply whether or not the address exists
- Changing or resetting a password ends all other sessions
- CSRF token on every form, session rechecked against the database on each request, HttpOnly and SameSite cookies, security headers
- Booking rules are enforced on the server and again by the database: a room can never exceed its capacity and the same bed can never be given twice, even if two approvals happen at once
- Clearing a student deletes the booking, so no history of past occupants is kept

## Database

Six tables: `users`, `hostels`, `rooms`, `bookings`, `login_attempts`, `password_resets`. Times are stored in UTC and shown in East Africa Time (Nairobi).

## Known limitations

- Email addresses are not verified at registration
- No fee payments yet
- No audit log of warden actions
- Uses Flask's development server; a production server and HTTPS are needed before public deployment

## Author

alecki-coder, Murang'a University of Technology.
