#!/bin/sh
# Starts the honeypot in both modes against a throwaway log file and port,
# runs a real paramiko SSH client against each, and checks the outcome -
# no mocks: this is a real SSH protocol handshake over a real socket.
set -e

cd "$(dirname "$0")/.."
PORT=2299
LOG_LOW="/tmp/honeypot_test_low.jsonl"
LOG_INTERACTIVE="/tmp/honeypot_test_interactive.jsonl"
rm -f "$LOG_LOW" "$LOG_INTERACTIVE" host_key

echo "== Low-interaction mode: expect auth rejected, credentials logged =="
python3 honeypot.py --port $PORT --log "$LOG_LOW" &
SERVER_PID=$!
sleep 1
python3 test_fixtures/test_client.py --port $PORT --mode low
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

if grep -q '"event": "auth_attempt".*"outcome": "rejected"' "$LOG_LOW"; then
    echo "PASS: low-interaction auth attempt logged and rejected"
else
    echo "FAIL: expected rejected auth_attempt in $LOG_LOW"
    exit 1
fi

echo
echo "== Interactive mode: expect login accepted, fake shell commands logged =="
rm -f host_key
python3 honeypot.py --port $PORT --interactive --log "$LOG_INTERACTIVE" &
SERVER_PID=$!
sleep 1
python3 test_fixtures/test_client.py --port $PORT --mode interactive
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

if grep -q '"event": "auth_attempt".*"outcome": "accepted"' "$LOG_INTERACTIVE" \
   && grep -q '"command": "whoami"' "$LOG_INTERACTIVE" \
   && grep -q '"event": "disconnect"' "$LOG_INTERACTIVE"; then
    echo "PASS: interactive login accepted, commands logged, clean disconnect"
else
    echo "FAIL: expected accepted login + logged commands in $LOG_INTERACTIVE"
    exit 1
fi

rm -f host_key "$LOG_LOW" "$LOG_INTERACTIVE"
echo
echo "All tests passed."
