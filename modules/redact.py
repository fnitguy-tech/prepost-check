"""Strip passwords, hashes and other secrets from captured output.

Off by default. precheck.py / postcheck.py enable it with
--redact-secrets, and the collector then runs every command's output
through scrub() before it is written to disk, so the capture files,
the zips and every report built from them never contain a credential.

Each rule keeps the keyword and any type marker (``secret sha512``,
``password 7``, ``phash``) and replaces only the value with
``<REDACTED>``. The line stays recognisable in a diff: a password that
was added, moved or removed is still visible as a change; only its
value is gone. A password that was merely rotated to a different value
is invisible after redaction - that is the trade-off the flag makes.

The rules are written for the platforms the inventory ships with
(Arista EOS and PAN-OS set-format config) plus the common IOS-style
forms, and two catch-alls run last regardless of keyword: anything that
looks like a crypt(3) hash (``$6$...``, ``$1$...``) and anything that
looks like a PAN-OS encrypted blob (``-AQ==...``).
"""

import re

REDACTED = "<REDACTED>"

# Type markers that may sit between the keyword and the value and are
# kept so the line still says what kind of secret it carried:
# 0/5/7/8/9 (IOS/EOS encryption types), 6 (IOS AES), sha512/sha256/md5
# (EOS hashed), md7 (EOS encrypted MD5 key).
_TYPE_WORDS = r"(?:0|5|6|7|8|9|sha512|sha256|sha|md5|md7)"
_TYPE = r"(?:" + _TYPE_WORDS + r"\s+)?"

# One value: a quoted string (PAN-OS set-format quotes values that
# contain spaces) or a run of non-space characters. Never a type marker
# that is followed by more text, and never a value an earlier pass
# already redacted, so overlapping rules and repeated runs are
# idempotent ("secret sha512 <REDACTED>" must not become
# "secret <REDACTED> <REDACTED>").
_VALUE = r"(?!<REDACTED>)(?!" + _TYPE_WORDS + r"\s)" + r'("[^"]*"|\'[^\']*\'|\S+)'

# Free-text lines are left to the catch-alls only, so "description
# password reset server" is not mangled by the keyword rules.
_FREE_TEXT_LINE = re.compile(r"^\s*(?:description|comment|banner)\b", re.IGNORECASE)

# (pattern, replacement). The replacement keeps group 1 (everything up
# to and including the type marker) and drops the value.
KEYWORD_RULES = [
    # Arista EOS / IOS-style:
    #   username admin secret sha512 $6$...   enable password sha512 ...
    #   neighbor 10.0.0.1 password 7 ...      enable secret 5 $1$...
    (re.compile(r"(\b(?:bind-)?(?:secret|password)\s+" + _TYPE + ")" + _VALUE), r"\1" + REDACTED),
    #   tacacs-server host 10.0.0.1 key 7 ...   radius-server key 7 ...
    #   key-string 7 ... (key chains)            shared-key 7 ... (IPsec)
    #   ip ospf authentication-key 7 ...         isakmp key 0 ... (IOS)
    (
        re.compile(
            r"(\b(?:key-string|shared-key|pre-shared-key\s+key|authentication-key|authentication\s+text|isakmp\s+key|key)"
            r"\s+(?:[0678]\s+))" + _VALUE
        ),
        r"\1" + REDACTED,
    ),
    #   ntp authentication-key 1 md5 7 ...   ip ospf message-digest-key 1 md7 ...
    (
        re.compile(r"(\b(?:message-digest-key|authentication-key)\s+\d+\s+(?:md5|md7|sha\S*)\s+(?:[07]\s+)?)" + _VALUE),
        r"\1" + REDACTED,
    ),
    #   tacacs-server key <plain>   radius-server host 10.0.0.1 key <plain>
    (re.compile(r"(\b(?:tacacs-server|radius-server)\b.*?\bkey\s+(?:[07]\s+)?)" + _VALUE), r"\1" + REDACTED),
    #   snmp-server community <string> ro
    (re.compile(r"(\bsnmp-server\s+community\s+)" + _VALUE), r"\1" + REDACTED),
    #   snmp-server user bob grp v3 auth sha <key> priv aes <key>
    (
        re.compile(r"(\b(?:auth|priv)\s+(?:md5|sha|sha224|sha256|sha384|sha512|des|3des|aes|aes128|aes192|aes256)\s+)" + _VALUE),
        r"\1" + REDACTED,
    ),
    # PAN-OS set-format config:
    #   set mgt-config users admin phash $1$...
    #   set network ike gateway GW authentication pre-shared-key key -AQ==...
    #   set shared server-profile radius R server S secret -AQ==...   (secret: rule above)
    #   set shared certificate C private-key -AQ==...
    #   set deviceconfig system snmp-setting ... snmp-community-string public
    #   set deviceconfig system snmp-setting ... v3 users U authpwd -AQ==... privpwd -AQ==...
    (
        re.compile(
            r"(\b(?:phash|pre-shared-key\s+key|private-key|authpwd|privpwd|passphrase|api-key"
            r"|snmp-community-string|community-string|client-secret|collector-secret|shared-secret"
            r"|master-key|auth-key|license-key)\s+)" + _VALUE
        ),
        r"\1" + REDACTED,
    ),
]

# Run on every line, keyword or not.
CATCHALL_RULES = [
    #   crypt(3)-style hashes: $1$ (MD5), $5$/$6$ (SHA-256/512), $2a$/$2b$/$2y$ (bcrypt)
    (re.compile(r"\$(?:1|2[abxy]?|5|6)\$[^\s$]+(?:\$\S+)?"), REDACTED),
    #   PAN-OS encrypted values (base64 blobs that always start with -AQ==)
    (re.compile(r"-AQ==\S*"), REDACTED),
]


def scrub_line(line):
    """Return one line with every secret value replaced by <REDACTED>."""
    if not _FREE_TEXT_LINE.match(line):
        for pattern, replacement in KEYWORD_RULES:
            line = pattern.sub(replacement, line)

    for pattern, replacement in CATCHALL_RULES:
        line = pattern.sub(replacement, line)

    return line


def scrub(text):
    """Return text with every secret value replaced by <REDACTED>.

    Works line by line; a line that is already clean comes back
    unchanged, so scrubbing is idempotent and never disturbs the
    "### <command> ###" section headers the compare modules parse.
    """
    if not text:
        return text

    return "\n".join(scrub_line(line) for line in text.split("\n"))
