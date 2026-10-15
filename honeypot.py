"""
SSH Honeypot

A fake SSH server that looks real enough to attract and log automated
attacks: it completes a genuine SSH protocol handshake (via paramiko),
accepts any username/password combination, logs every credential
attempt, and - in interactive mode - drops the attacker into a fake
shell that logs every command they type while never actually executing
anything.

SAFETY: This tool never runs a real shell, never executes attacker
input, and never touches the real filesystem beyond writing its own log
file. fake_shell.py's hardcoded responses are the entire interaction
surface - see that file for the complete list of simulated commands.

Usage:
    python3 honeypot.py --port 2222
    python3 honeypot.py --port 2222 --interactive --log attacks.jsonl
"""

import os
import json
import socket
import threading
import argparse
import traceback
from datetime import datetime, timezone

import paramiko

from fake_shell import FakeShell

HOST_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_key")


def get_or_create_host_key(path=HOST_KEY_PATH):
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class JsonlLogger:
    """Appends one JSON object per line - easy to tail, grep, or load
    into pandas/jq for analysis later."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def log(self, event, session_id, src_ip, src_port, **detail):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            **detail,
        }
        line = json.dumps(entry)
        with self._lock:
            print(line)
            with open(self.path, "a") as f:
                f.write(line + "\n")


class HoneypotServer(paramiko.ServerInterface):
    """Implements the paramiko server-side auth/channel callbacks. Every
    auth attempt is logged regardless of outcome; whether it's allowed
    to succeed is controlled by `interactive_mode` (passed in by main())."""

    def __init__(self, logger, session_id, src_ip, src_port, interactive_mode):
        self.logger = logger
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.interactive_mode = interactive_mode
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        self.logger.log(
            "auth_attempt", self.session_id, self.src_ip, self.src_port,
            username=username, password=password,
            outcome="accepted" if self.interactive_mode else "rejected",
        )
        if self.interactive_mode:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.logger.log(
            "auth_attempt", self.session_id, self.src_ip, self.src_port,
            username=username, auth_method="publickey",
            key_fingerprint=key.get_fingerprint().hex(), outcome="rejected",
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.logger.log(
            "exec_command", self.session_id, self.src_ip, self.src_port,
            command=command.decode(errors="replace"),
        )
        # Never actually executes - just acknowledges and closes, since a
        # non-interactive exec is usually an automated scanner/exploit tool
        # probing for command execution, not a human attacker worth
        # engaging in a fake shell session.
        channel.send(b"")
        channel.send_exit_status(0)
        return True


def handle_shell_session(channel, logger, session_id, src_ip, src_port):
    shell = FakeShell()
    channel.send(f"Welcome to {os.uname().sysname if hasattr(os, 'uname') else 'Ubuntu'} 22.04.3 LTS\r\n\r\n".encode())
    channel.send(shell.prompt().encode())

    buffer = ""
    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break
            text = data.decode(errors="replace")

            for ch in text:
                if ch in ("\r", "\n"):
                    channel.send(b"\r\n")
                    line = buffer
                    buffer = ""
                    output, should_exit = shell.run(line)
                    logger.log(
                        "command", session_id, src_ip, src_port,
                        command=line, cwd=shell.cwd,
                    )
                    if output:
                        channel.send(output.replace("\n", "\r\n").encode())
                    if should_exit:
                        channel.close()
                        return
                    channel.send(shell.prompt().encode())
                elif ch == "\x7f" or ch == "\x08":  # backspace
                    if buffer:
                        buffer = buffer[:-1]
                        channel.send(b"\x08 \x08")
                elif ch == "\x03":  # Ctrl-C
                    channel.send(b"^C\r\n")
                    buffer = ""
                    channel.send(shell.prompt().encode())
                else:
                    buffer += ch
                    channel.send(ch.encode())
    except Exception:
        pass
    finally:
        logger.log("disconnect", session_id, src_ip, src_port, commands_run=len(shell.history))


class ThreadSafeCounter:
    def __init__(self):
        self._n = 0
        self._lock = threading.Lock()

    def next(self):
        with self._lock:
            self._n += 1
            return self._n


def handle_connection(client_sock, addr, logger, host_key, interactive_mode, session_counter):
    src_ip, src_port = addr
    session_id = f"{src_ip}:{src_port}:{session_counter.next()}"
    logger.log("connect", session_id, src_ip, src_port)

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(host_key)
    except Exception:
        traceback.print_exc()
        return

    server = HoneypotServer(logger, session_id, src_ip, src_port, interactive_mode)
    try:
        transport.start_server(server=server)
    except Exception as e:
        traceback.print_exc()
        logger.log("transport_error", session_id, src_ip, src_port, error=str(e))
        return

    if not interactive_mode:
        # Low-interaction mode: every auth attempt is logged and rejected
        # by check_auth_password above. start_server() is non-blocking -
        # it hands negotiation off to the Transport's own background
        # thread and returns immediately - so we have to actually wait
        # for that thread to finish (the client gives up, or times out)
        # rather than closing right away, or we'd tear down the
        # connection before the client ever got to send its credentials.
        transport.join(timeout=30)
        transport.close()
        return

    channel = transport.accept(20)
    if channel is None:
        transport.close()
        return

    server.event.wait(10)
    handle_shell_session(channel, logger, session_id, src_ip, src_port)
    transport.close()


def main():
    parser = argparse.ArgumentParser(description="A fake SSH server that logs attacker behavior.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--log", default="honeypot.jsonl", help="Path to the JSONL log file")
    parser.add_argument(
        "--interactive", action="store_true",
        help="Allow any login to succeed and drop the attacker into a fake shell "
             "(logs commands, never executes them). Default is low-interaction: "
             "log every credential attempt and reject all logins.",
    )
    args = parser.parse_args()

    host_key = get_or_create_host_key()
    logger = JsonlLogger(args.log)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(100)

    mode = "interactive (fake shell)" if args.interactive else "low-interaction (log + reject)"
    print(f"SSH honeypot listening on {args.host}:{args.port} [{mode}], logging to {args.log}")

    session_counter = ThreadSafeCounter()

    try:
        while True:
            client_sock, addr = sock.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, logger, host_key, args.interactive, session_counter),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down.")
        sock.close()


if __name__ == "__main__":
    main()
