# SSH Honeypot

A fake SSH server that completes a real SSH protocol handshake (via `paramiko`), accepts connections on the real SSH negotiation path, and logs attacker behavior — every credential attempt, and, in interactive mode, every command typed into a fake shell — without ever executing anything an attacker sends or touching the real filesystem beyond its own log file.

This is a different mechanism from the rest of this portfolio: the earlier projects parse logs or static input and report on them. This one *is* a live network service — a real listening socket that speaks the actual SSH wire protocol to anything that connects to it.

## What This Project Does

- **A real SSH server**, not a fake banner: it performs a genuine key exchange and auth negotiation using `paramiko.Transport`, so it looks and behaves like OpenSSH to scanners, bots, and curious attackers — right down to an `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` version string
- **Two modes**:
  - **Low-interaction** (default) — logs every username/password attempt, then rejects the login. Low effort, low risk, good for pure recon of what credentials automated bots are trying.
  - **Interactive** (`--interactive`) — accepts *any* credentials and drops the attacker into a fake Linux shell that logs every command they type and returns a plausible, hardcoded response, while never running anything for real
- **Structured JSONL logging**: one JSON object per event (`connect`, `auth_attempt`, `command`, `exec_command`, `disconnect`) — easy to `tail -f`, `grep`, or load into `jq`/pandas later
- **A hard safety boundary**: `fake_shell.py` contains zero calls to `subprocess`, `os.system`, or `eval`. Every response is either a hardcoded string or built from the session's own in-memory fake filesystem state. There is no path from attacker input to real code execution.

## Example Output

Low-interaction mode, watching a login attempt in real time:

```
SSH honeypot listening on 0.0.0.0:2222 [low-interaction (log + reject)], logging to honeypot.jsonl
{"timestamp": "2026-10-15T20:14:49Z", "event": "connect", "session_id": "203.0.113.4:51223:1", "src_ip": "203.0.113.4", "src_port": 51223}
{"timestamp": "2026-10-15T20:14:49Z", "event": "auth_attempt", "session_id": "203.0.113.4:51223:1", "src_ip": "203.0.113.4", "src_port": 51223, "username": "root", "password": "admin123", "outcome": "rejected"}
```

Interactive mode, an attacker poking around the fake shell:

```
admin@web-prod-03:/home/admin$ whoami
admin
admin@web-prod-03:/home/admin$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
admin@web-prod-03:/home/admin$ 
```

— with every one of those commands landing in the JSONL log as a `command` event, none of them actually running.

## Tech Stack

- Python 3.11
- `paramiko` for the real SSH protocol implementation (transport, key exchange, auth, channels)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
python3 honeypot.py --port 2222                                  # low-interaction (default)
python3 honeypot.py --port 2222 --interactive --log attacks.jsonl # interactive, custom log path
```

A 2048-bit RSA host key is generated on first run and reused afterward (`host_key`, gitignored — regenerate by deleting it).

**Only run this on a port and host you're allowed to expose.** It's a real, if fake, network service.

## Testing

`test_fixtures/run_test.sh` starts the real server in both modes, drives a real `paramiko` SSH client against it (`test_fixtures/test_client.py`), and checks the actual JSONL output — no mocked sockets or stubbed protocol:

```bash
sh test_fixtures/run_test.sh
```

It verifies: low-interaction mode logs the credential attempt and rejects the login; interactive mode accepts the login, logs each command run through the fake shell, and records a clean disconnect.

## Architecture

```
TCP accept (raw socket)
        |
        v
paramiko.Transport  <-- real SSH key exchange + protocol negotiation
        |
        v
HoneypotServer(paramiko.ServerInterface)
  check_auth_password / check_auth_publickey  -> log every attempt
  check_channel_request / pty / shell          -> only ever open a "session" channel
        |
        v
  low-interaction: reject auth, wait for client to give up, close
  interactive: accept auth, open channel -> FakeShell.run(line) per command
                                              (hardcoded responses only -
                                               no subprocess, no eval)
        |
        v
JsonlLogger -> one JSON object per line, per event
```

## Project Structure

```
ssh-honeypot/
├── honeypot.py              # SSH server: paramiko Transport/ServerInterface, logging, CLI
├── fake_shell.py             # The entire attacker-facing safety boundary - hardcoded command responses
├── requirements.txt
└── test_fixtures/
    ├── test_client.py        # Real paramiko client used to drive the server in tests
    └── run_test.sh            # Starts the server in both modes, runs the client, checks the logs
```

## What I Learned

- `paramiko.Transport.start_server()` is non-blocking — it hands off to the transport's own background thread and returns almost immediately. Closing the transport right after calling it (as I first wrote it) tears down the connection before the client ever gets to send its auth request, which from the client's side looks exactly like a mid-handshake connection reset. The fix is to actually wait for that background thread to finish (`transport.join(timeout=...)`) before closing.
- Debugging a "no exception, but it still fails" bug is a process of elimination: once `traceback.print_exc()` around every `try`/`except` in the suspect code path shows nothing, the bug isn't an exception at all — it's a timing/lifecycle issue, which pointed at the one place code decided *when* to close a resource rather than *whether* an operation succeeded.
- Low-interaction honeypots are a genuinely different design point from interactive ones: they're near-zero risk (nothing an attacker sends ever reaches anything resembling a real shell) and still collect the thing most attackers' automated tooling cares about — valid-looking credential pairs to try elsewhere — without needing to fake command behavior at all.
- Why the safety boundary has to live in one deliberately small, audit-friendly file (`fake_shell.py`) with no execution primitives available to it at all, rather than scattered pattern-matching throughout the server — a reviewer should be able to convince themselves of safety by reading one file.

## Next Steps

- Rate-limit or auto-ban IPs with an excessive connection rate, to reduce log noise from the most aggressive scanners
- A small companion script to summarize a day's JSONL log: top attempted usernames/passwords, most common commands, connection counts
- Fake `scp`/`sftp` subsystem handling, since some automated tools immediately try to exfiltrate or drop files after a successful login
- Optionally advertise a different, randomized OS/version banner per run, so a single deployment doesn't fingerprint identically to every other instance of this honeypot
