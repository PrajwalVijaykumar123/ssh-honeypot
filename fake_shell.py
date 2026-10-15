"""
A fake Linux shell: takes a command line and the session's fake current
directory, returns plausible output, and never actually executes
anything on the real system. This is the entire safety boundary of the
honeypot - no subprocess, no os.system, no eval. Every response here is
a hardcoded string or built from the session's own fake, in-memory
filesystem state.
"""

FAKE_HOSTNAME = "web-prod-03"
FAKE_USER = "admin"

FAKE_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    ),
    "/etc/hostname": f"{FAKE_HOSTNAME}\n",
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
    ),
}

FAKE_DIR_LISTINGS = {
    "/home/admin": ["backup.sh", "notes.txt", ".bash_history", "deploy_keys"],
    "/": ["bin", "boot", "etc", "home", "lib", "root", "tmp", "usr", "var"],
    "/var/www": ["html", "logs"],
}


class FakeShell:
    """Per-session fake shell state. Every method returns a string to
    send back to the client - nothing here touches the real filesystem
    or spawns a real process."""

    def __init__(self):
        self.cwd = f"/home/{FAKE_USER}"
        self.history = []

    def prompt(self):
        return f"{FAKE_USER}@{FAKE_HOSTNAME}:{self.cwd}$ "

    def run(self, line):
        """Returns (output_text, should_exit)."""
        self.history.append(line)
        line = line.strip()
        if not line:
            return "", False

        parts = line.split()
        cmd, args = parts[0], parts[1:]

        if cmd in ("exit", "logout", "quit"):
            return "logout\n", True

        if cmd == "whoami":
            return f"{FAKE_USER}\n", False

        if cmd == "id":
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n", False

        if cmd == "pwd":
            return f"{self.cwd}\n", False

        if cmd == "uname":
            if "-a" in args:
                return f"Linux {FAKE_HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n", False
            return "Linux\n", False

        if cmd == "hostname":
            return f"{FAKE_HOSTNAME}\n", False

        if cmd in ("ls", "ll", "dir"):
            target_dir = args[0] if args and not args[0].startswith("-") else self.cwd
            listing = FAKE_DIR_LISTINGS.get(target_dir, ["file1.txt", "file2.txt"])
            return "  ".join(listing) + "\n", False

        if cmd == "cd":
            if args:
                self.cwd = args[0] if args[0].startswith("/") else f"{self.cwd}/{args[0]}"
            return "", False

        if cmd == "cat":
            if not args:
                return "", False
            content = FAKE_FILES.get(args[0])
            if content:
                return content, False
            return f"cat: {args[0]}: No such file or directory\n", False

        if cmd == "echo":
            return " ".join(args) + "\n", False

        if cmd in ("wget", "curl"):
            return f"{cmd}: unable to resolve host address\n", False

        if cmd in ("ps", "ps aux"):
            return (
                "USER       PID %CPU %MEM COMMAND\n"
                "root         1  0.0  0.1 /sbin/init\n"
                "admin     812  0.1  0.3 -bash\n"
            ), False

        if cmd == "history":
            return "\n".join(f"{i+1}  {h}" for i, h in enumerate(self.history)) + "\n", False

        return f"-bash: {cmd}: command not found\n", False
