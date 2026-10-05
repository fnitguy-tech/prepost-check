"""Where the known-hosts file lives.

This is its own module, with no SSH imports, on purpose. The command-line
parser needs the default path for its help text. Importing it from
`hostkeys` would load paramiko on every run, including `compare`, which
never opens a connection. That cost about 80 ms per start.
"""

import os

ENV_VAR = "PREPOST_CHECK_KNOWN_HOSTS"


def default_path():
    """Where the known-hosts file lives unless you say otherwise."""
    override = os.environ.get(ENV_VAR)

    if override:
        return os.path.expanduser(override)

    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, "prepost-check", "known_hosts")

    return os.path.join(os.path.expanduser("~"), ".config", "prepost-check", "known_hosts")
