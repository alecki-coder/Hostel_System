# Hostel Management System

A web-based system that manages university hostel accommodation. Students register, accept the rules, request a room and pay their fees (demo money). A warden approves, rejects and clears them from a dashboard. Students are told every outcome by email, including the exact hostel, floor, room and bed.

Built as a system analysis and design course project with Python and Flask.

## What it does

**Students and visitors** (a hostel website: hero page, services, hostel cards, how it works)

- Register with registration number, name, email, gender and a strong password
- See live availability for every hostel
- Read and accept the rules before booking (the time and rules version are recorded)
- Request one room, only in a hostel that matches their gender
- Pay a KES 10 booking fee right after booking to secure the request
- Pay the semester fees once approved: KES 245 for Semester 1 (needed before collecting keys) and KES 245 for Semester 2
- Receive emails: request received, payment received, receipt (hostel, floor, room, bed), or rejection notice
- Apply again after a rejection, reset a forgotten password, change their password

**Warden** (a dashboard: dark sidebar, stat cards, occupancy donut, bar per hostel)

- See pending requests with **Paid / Not paid**; only requests whose booking fee is paid can be approved
- Approve or reject (the system assigns floor, room and bed automatically; a rejection refunds the fee)
- See each housed student's paid amount, balance and whether their keys are ready
- Clear a student when they leave; a student with an unpaid balance cannot be cleared
- Browse every room as cards with bed chips, and see empty rooms and free beds
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

## Fees (demo mode)

| Item | Amount (KES) | When |
|---|---|---|
| Booking fee | 10 | Right after booking |
| Semester 1 fees | 245 | After approval, before collecting keys |
| Semester 2 fees | 245 | After approval |
| **Academic year total** | **500** | |

**No real money moves.** Payment is simulated: the student sees a demo phone prompt and presses Approve. There is no PIN field and none must ever be added. The fee schedule and the demo provider live in `payments.py`, so a real M-Pesa integration (for example the Safaricom Daraja sandbox) can replace the demo step without changing the pages. Real payments would also need credentials from the owner of the Paybill, a public callback address, and verification of every callback.

## Tech stack

Python 3.12, Flask 3.1, SQLite, Jinja2 templates, plain CSS, Gmail SMTP for email, gunicorn for sharing, Git and GitHub.

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

## Run the tests

    python tests/smoke_test.py

The test builds a throwaway database, never touches `hostel.db` and never sends email. It checks registration, booking, the fee rules, approval, keys, clearing, refunds, the boys-only rule, access control, the emails and the login lockout.

## Email setup (optional)

Without any setup the system still works: emails are printed in the terminal instead of being sent.

To send real email, copy `.env.example` to `.env` and fill it in. Use a Gmail account with 2-step verification and a 16-character app password (never your normal password). `.env` is listed in `.gitignore` and must never be committed.

## Sharing a temporary public link

Install `cloudflared` once, then run:

    ./share.sh

It starts the app with gunicorn through `wsgi.py` (secure cookies, real visitor addresses, stricter headers, limits on registrations and reset requests) and prints a public `https://...trycloudflare.com` address. The link works only while your computer and that terminal stay on, and it changes every time. It suits demos and defenses, not permanent hosting.

## Project structure

    app.py               routes, rules and security checks
    payments.py          fee schedule and the demo payment provider
    mailer.py            sends email over SSL (or prints it in development)
    wsgi.py              hardened entry point used when sharing publicly
    share.sh             starts the app and a temporary public link
    schema.sql           database tables, constraints and triggers
    init_db.py           builds the database and seeds hostels and rooms
    create_warden.py     creates a warden or adds an email to one
    templates/           HTML pages (website layout and dashboard layout)
    static/              stylesheet and hero illustration
    tests/               end-to-end smoke test
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
- Fee rules are enforced on the server: unpaid requests cannot be approved and unpaid students cannot be cleared; a payment prompt can only be completed by the student it belongs to
- Clearing a student deletes the booking and its payments, so no history of past occupants is kept

## Database

Seven tables: `users`, `hostels`, `rooms`, `bookings`, `payments`, `login_attempts`, `password_resets`. Times are stored in UTC and shown in East Africa Time (Nairobi).

## Known limitations

- Payments are simulated; no real money moves
- The public link is temporary; permanent hosting is not set up yet
- Email addresses are not verified at registration
- No audit log of warden actions
- Financial records are deleted with the booking, which a real institution may not allow

## Author

alecki-coder, Murang'a University of Technology.
