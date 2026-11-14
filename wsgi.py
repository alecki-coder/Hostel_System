"""Production entry point: the same app, hardened for public access.

Run it with gunicorn behind a tunnel that connects from this machine only
(the app listens on 127.0.0.1, so nobody can reach it directly or forge the
headers the tunnel adds). Local development still uses: python app.py
"""
import ipaddress
import threading
import time
from collections import defaultdict, deque

from flask import request

from app import app

# Cookies only travel over HTTPS (the tunnel provides it).
app.config.update(SESSION_COOKIE_SECURE=True)


class RealIP:
    """Use the visitor's real address from Cloudflare instead of the tunnel's.

    Without this every visitor would look like 127.0.0.1 and the per-IP login
    lockout would count the whole class together.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        raw = environ.get("HTTP_CF_CONNECTING_IP", "").strip()
        if raw:
            try:
                environ["REMOTE_ADDR"] = str(ipaddress.ip_address(raw))
            except ValueError:
                pass  # ignore a malformed header
        return self.wsgi_app(environ, start_response)


app.wsgi_app = RealIP(app.wsgi_app)

# Requests allowed per address per hour on the routes an abuser would hammer.
# Generous, because a campus network can share one public address.
LIMITS = {"/register": 60, "/forgot": 20}
WINDOW_SECONDS = 3600
_hits = defaultdict(deque)
_lock = threading.Lock()


@app.before_request
def rate_limit_sensitive_routes():
    if request.method != "POST" or request.path not in LIMITS:
        return None
    key = (request.path, request.remote_addr or "unknown")
    now = time.time()
    with _lock:
        hits = _hits[key]
        while hits and hits[0] <= now - WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= LIMITS[request.path]:
            return "Too many requests from this address. Try again later.", 429
        hits.append(now)
    return None


@app.after_request
def extra_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Cache-Control"] = "no-store"
    return response
