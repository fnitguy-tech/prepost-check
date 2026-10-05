"""SSH host-key checking: trust on first use, refuse on change.

Why it matters: you type your password into whatever answers at the
device's address. If something else answers (a mis-patched cable, a
reused IP, an attacker), a host-key check is the only thing that
notices before the password is sent.

What netmiko 4.7 does when left alone: it gives paramiko an
AutoAddPolicy and loads no known-hosts file. Every key is accepted, and
nothing is remembered, so a changed key can never be noticed.

What this module does instead, in the way ssh itself does:

1. First connection to a host: its key is written to a known-hosts
   file that belongs to this tool. One line per host, the same format
   OpenSSH uses:

       192.0.2.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWUuvvn72gGpK5huKh1JezglZ6Wv72ywrrJtSlEu1m2

2. Every later connection: the key must match that line. If it doesn't,
   the connection is refused before any password is sent, with an error
   that names the host, both fingerprints, the file, and the fix.

The file lives at ~/.config/prepost-check/known_hosts (on Windows,
%APPDATA%\\prepost-check\\known_hosts). Set PREPOST_CHECK_KNOWN_HOSTS or
pass --known-hosts to use another one.

It's wired in with options netmiko supports. `alt_host_keys` and
`alt_key_file` make paramiko load our file and do the comparison for
hosts it already knows. For hosts it doesn't, paramiko calls the
connection's `key_policy`; we set ours on a connection built with
`auto_connect=False`, then open it. That's the same sequence netmiko's
own ConnLogOnly and ConnUnify helpers use.
"""

import base64
import hashlib
import os
import threading

import paramiko

# Re-exported so callers of this module keep working. They live in
# hostkey_paths so the CLI can read them without loading paramiko.
from modules.hostkey_paths import ENV_VAR, default_path  # noqa: E402,F401


def fingerprint(key):
    """A key's SHA256 fingerprint, written the way `ssh-keygen -l` writes it."""
    digest = hashlib.sha256(key.asbytes()).digest()

    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class HostKeyChanged(paramiko.SSHException):
    """A host offered a different key than the one on file.

    It's an SSHException so netmiko treats it like any other failed
    handshake: it closes the socket, then raises its own error with this
    one attached as the cause. find_changed_key() digs it back out.
    """

    def __init__(self, hostname, stored_key, offered_key, path):
        self.hostname = hostname
        self.path = path
        super().__init__(
            f"The SSH host key for {hostname} has changed, so the connection was refused "
            "before any password was sent.\n"
            f"  Key on file:  {stored_key.get_name()} {fingerprint(stored_key)}\n"
            f"  Key offered:  {offered_key.get_name()} {fingerprint(offered_key)}\n"
            f"  File:         {path}\n"
            "If this device was replaced or re-imaged, that's expected. To accept the new key, delete "
            f'the line that starts with "{hostname} " from that file, or run:\n'
            f'  ssh-keygen -R "{hostname}" -f "{path}"\n'
            "Then run again, and the new key is recorded. If nothing was replaced, stop and find out "
            "what's answering at that address."
        )


class _TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
    """paramiko asks this policy about any host that isn't in the file."""

    def __init__(self, store):
        self.store = store

    def missing_host_key(self, client, hostname, key):
        self.store.remember(hostname, key)


class HostKeyStore:
    """One known-hosts file, safe to use from several connections at once.

    The collector connects to five devices at a time. paramiko's own
    save rewrites the whole file from one connection's copy of it, so
    two first-time hosts finishing together could each write a file
    without the other's line. Here a new host is one appended line,
    written under a lock, and the rest of the file is never rewritten.
    """

    def __init__(self, path=None):
        self.path = os.path.abspath(path or default_path())
        self._lock = threading.Lock()

    def connect_options(self):
        """The netmiko options that make paramiko load and check this file."""
        return {"alt_host_keys": True, "alt_key_file": self.path}

    def policy(self):
        return _TrustOnFirstUse(self)

    def remember(self, hostname, key):
        """Record a new host's key, or raise HostKeyChanged if it's on
        file with a different one."""
        with self._lock:
            known = paramiko.HostKeys()

            # Read again inside the lock: another connection may have
            # recorded this same host since this one loaded the file.
            if os.path.isfile(self.path):
                known.load(self.path)

            stored = known.lookup(hostname)

            if stored is not None:
                same_type = stored.get(key.get_name())

                if same_type is not None and same_type.asbytes() == key.asbytes():
                    return

                raise HostKeyChanged(hostname, same_type or list(stored.values())[0], key, self.path)

            self._append(f"{hostname} {key.get_name()} {key.get_base64()}\n")

    def _append(self, line):
        folder = os.path.dirname(self.path)
        # Private to you, like ~/.ssh: the file lists every device you manage.
        os.makedirs(folder, mode=0o700, exist_ok=True)

        # A hand-edited file may not end in a newline; don't glue our
        # line onto its last one.
        if os.path.isfile(self.path) and os.path.getsize(self.path):
            with open(self.path, "rb") as file:
                file.seek(-1, os.SEEK_END)

                if file.read(1) != b"\n":
                    line = "\n" + line

        # O_APPEND and a single write: the line lands whole at the end of
        # the file, even if a second copy of the tool is writing too.
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)

    def find_changed_key(self, error):
        """The HostKeyChanged behind a connection error, or None.

        A changed key reaches us two ways. For a host paramiko found in
        the file, paramiko raises its own BadHostKeyException. For one
        recorded moments ago by another connection, remember() raises
        HostKeyChanged. netmiko wraps both in a generic error, so walk
        the chain of causes to find either.
        """
        seen = set()

        while error is not None and id(error) not in seen:
            seen.add(id(error))

            if isinstance(error, HostKeyChanged):
                return error

            if isinstance(error, paramiko.BadHostKeyException):
                return HostKeyChanged(error.hostname, error.expected_key, error.key, self.path)

            error = error.__cause__ or error.__context__

        return None
