"""
A real paramiko SSH client used to exercise the honeypot end to end -
not a mock. Connects, authenticates (expected to fail in low-interaction
mode, succeed in interactive mode), and in interactive mode runs a short
sequence of commands through the fake shell to confirm real responses
come back over the wire.
"""
import argparse
import time
import sys

import paramiko


def test_low_interaction(port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=port, username="root", password="admin123",
            timeout=5, banner_timeout=5,
        )
        print("UNEXPECTED: login succeeded in low-interaction mode")
        sys.exit(1)
    except paramiko.AuthenticationException:
        print("OK: authentication correctly rejected")
    finally:
        client.close()


def test_interactive(port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1", port=port, username="root", password="admin123",
        timeout=5, banner_timeout=5,
    )
    print("OK: login accepted in interactive mode")

    chan = client.invoke_shell()
    time.sleep(1)
    chan.recv(4096)  # banner + first prompt

    for cmd in ["whoami", "id", "exit"]:
        chan.send(cmd + "\n")
        time.sleep(0.5)
        out = chan.recv(4096).decode(errors="replace")
        print(f"OK: ran '{cmd}', got {len(out)} bytes back")

    time.sleep(0.5)
    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=["low", "interactive"], required=True)
    args = parser.parse_args()

    if args.mode == "low":
        test_low_interaction(args.port)
    else:
        test_interactive(args.port)
