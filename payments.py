"""Fee schedule and helpers for the demo payment provider.

DEMO MODE: no real money moves. The student presses Pay, a simulated phone
prompt appears, and pressing Approve marks the payment as paid. There is no
PIN field, and none must ever be added. To use real M-Pesa later, replace the
two helpers at the bottom and keep everything else.
"""
import secrets

MODE = "demo"

# (kind, label, amount in whole Kenya shillings). The booking fee is part of the total.
FEES = (
    ("booking_fee", "Booking fee", 10),
    ("semester_1", "Semester 1 fees", 245),
    ("semester_2", "Semester 2 fees", 245),
)
LABELS = {kind: label for kind, label, _ in FEES}
AMOUNTS = {kind: amount for kind, _, amount in FEES}
TOTAL = sum(amount for _, _, amount in FEES)  # 500


def new_checkout_id() -> str:
    """Random id of one open payment prompt (hard to guess)."""
    return secrets.token_urlsafe(16)


def new_reference() -> str:
    """Receipt number shown once a payment succeeds, like an M-Pesa code."""
    return "DEMO" + secrets.token_hex(4).upper()
