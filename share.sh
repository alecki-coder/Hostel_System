#!/usr/bin/env bash
# Start the hostel system and a temporary public HTTPS link to it.
# Stop with Ctrl+C: that also closes the public link.
set -euo pipefail
cd "$(dirname "$0")"
source venv/bin/activate

PORT=8000
LOG=$(mktemp)
cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:${PORT}" > "$LOG" 2>&1 &
TUNNEL_PID=$!
trap 'kill "$TUNNEL_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

URL=""
for _ in $(seq 1 60); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" | grep -v '^https://api\.' | head -1 || true)
  [ -n "$URL" ] && break
  sleep 1
done
if [ -z "$URL" ]; then
  echo "Could not get a public link. Is cloudflared installed and are you online?"
  exit 1
fi

echo
echo "Share this link:  $URL"
echo "Press Ctrl+C to stop sharing."
echo

# Reset emails must point at the public address, not 127.0.0.1.
export APP_BASE_URL="$URL"
gunicorn --workers 1 --threads 4 --bind "127.0.0.1:${PORT}" wsgi:app
