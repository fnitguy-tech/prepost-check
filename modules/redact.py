"""Strip passwords, hashes, and other secrets from captured output.

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
(Arista EOS and PAN-OS set-format config) plus the common IOS / IOS-XE,
NX-OS, Junos, and PAN-OS XML forms. Catch-alls run last regardless of
keyword: anything that looks like a crypt(3) hash (``$6$...``,
``$1$...``), a Junos or IOS ``$9$`` / ``$8$`` value, or a PAN-OS
encrypted blob (``-AQ==...``).

Most rules look at one line. Two things need more than one, and scrub()
handles them before the line rules run:

- A PEM private key runs over many lines. The BEGIN and END lines stay
  and everything between them becomes one ``<REDACTED>`` line.
- IOS-XE puts a server's key on its own line under a header, where a
  bare ``key 7 ...`` looks just like a key-chain key number:

      radius server RAD-1
       address ipv4 192.0.2.50 auth-port 1812 acct-port 1813
       key 7 <REDACTED>

  So that line is only redacted inside a ``tacacs server NAME`` or
  ``radius server NAME`` block.

Running scrub() on its own output changes nothing. Every rule refuses a
value that is already ``<REDACTED>``.
"""

import re

REDACTED = "<REDACTED>"

# Type markers that may sit between the keyword and the value and are
# kept so the line still says what kind of secret it carried:
# 0/5/7/8/9 (IOS/EOS encryption types), 3/4 (NX-OS and old IOS), 6 (IOS
# AES), 8a (EOS AES-256-GCM: "password 8a <blob>"), sha512/sha256/md5
# (EOS hashed), md7 (EOS encrypted MD5 key), encrypted/clear (IOS-XR).
# "8a" has to come before "8": tried the other way round, "8" would
# never match in front of the "a" and the blob would be left behind
# with only the "8a" marker redacted.
_TYPE_WORDS = r"(?:0|3|4|5|6|7|8a|8|9|sha512|sha256|sha|md5|md7|encrypted|clear)"
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
    # Arista EOS / IOS-style, and Junos (the value may be quoted):
    #   username admin secret sha512 $6$...   enable password sha512 ...
    #   neighbor 10.0.0.1 password 7 ...      enable secret 5 $1$...
    #   neighbor 10.0.0.1 password 8a ...     isis password ...   area-password ...
    #   secret "$9$..."; (Junos)              encrypted-password "$6$..."; (Junos)
    (re.compile(r"(\b(?:bind-)?(?:secret|password)\s+" + _TYPE + ")" + _VALUE), r"\1" + REDACTED),
    #   ntp authentication-key 1 md5 7 ...   ip ospf message-digest-key 1 md7 ...
    #   ntp authentication-key 1 md5 <plain>
    # Runs before the plain authentication-key rule below, which would
    # otherwise take the key number "1" for the secret.
    (
        re.compile(r"(\b(?:message-digest-key|authentication-key)\s+\d+\s+(?:md5|md7|sha\S*)\s+" + _TYPE + ")" + _VALUE),
        r"\1" + REDACTED,
    ),
    # Keywords that always introduce a secret, with or without a type
    # marker:
    #   key-string 7 ...            key-string <plain>            (key chains)
    #   ip ospf authentication-key 7 ...   ip ospf authentication-key <plain>
    #   authentication-key "$9$...";       (Junos)
    #   crypto isakmp key 0 ... address 192.0.2.1    crypto isakmp key <plain> address ...
    #   pre-shared-key <plain>      pre-shared-key local 0 ...    (IOS IKEv2 keyring)
    #   pre-shared-key ascii-text "$9$...";          (Junos)
    #   pre-shared-key key -AQ==...                  (PAN-OS set format)
    #   isis authentication key <plain>    authentication text <plain>   (HSRP/VRRP, NX-OS)
    (
        re.compile(
            r"(\b(?:key-string|shared-key|authentication-key|isakmp\s+key|authentication\s+key|authentication\s+text"
            r"|pre-shared-key)\s+(?:(?:key|local|remote|ascii-text|hexadecimal|hex)\s+)?"
            # Never take the key number or one of the words above for
            # the secret. Without this, a second run would back up and
            # redact "key" in "pre-shared-key key <REDACTED>".
            r"(?!\d+\s+(?:md5|md7|sha\S*)\s)(?!(?:key|local|remote|ascii-text|hexadecimal|hex)\s)" + _TYPE + ")" + _VALUE
        ),
        r"\1" + REDACTED,
    ),
    # A bare "key" is a secret only when a type marker follows it:
    #   tacacs-server host 10.0.0.1 key 7 ...   key 8a ...
    # Without one it is a key-chain key number ("key 1") or a GRE tunnel
    # key ("tunnel key 1234"), and those stay.
    (re.compile(r"(\bkey\s+(?:0|6|7|8a|8)\s+)" + _VALUE), r"\1" + REDACTED),
    #   tacacs-server key <plain>   radius-server host 10.0.0.1 key <plain>
    #   server-private 10.0.0.1 key <plain>   (IOS "aaa group server" block)
    (re.compile(r"(\b(?:tacacs-server|radius-server|server-private)\b.*?\bkey\s+" + _TYPE + ")" + _VALUE), r"\1" + REDACTED),
    #   snmp-server community <string> ro
    (re.compile(r"(\bsnmp-server\s+community\s+)" + _VALUE), r"\1" + REDACTED),
    #   snmp-server host 10.0.0.9 version 2c <community>
    #   snmp-server host 10.0.0.9 vrf MGMT traps version 2c <community> udp-port 162
    # v1 and v2c only: after "version 3" comes a user name, not a secret.
    (re.compile(r"(\bsnmp-server\s+host\s+.*?\bversion\s+(?:1|2c)\s+)" + _VALUE), r"\1" + REDACTED),
    #   snmp-server host 10.0.0.9 <community>      snmp-server host 10.0.0.9 traps <community>
    # The older form with no "version". Skipped when the next word is an
    # option, so the line above keeps its job.
    (
        re.compile(
            r"(\bsnmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?)"
            r"(?!(?:vrf|use-vrf|traps|informs|version|udp-port|source-interface|filter-vrf)\b)" + _VALUE
        ),
        r"\1" + REDACTED,
    ),
    #   snmp-server user bob grp v3 auth sha <key> priv aes <key>
    (
        re.compile(r"(\b(?:auth|priv)\s+(?:md5|sha|sha224|sha256|sha384|sha512|des|3des|aes|aes128|aes192|aes256)\s+)" + _VALUE),
        r"\1" + REDACTED,
    ),
    # HSRP / VRRP plain-text authentication:
    #   standby 10 authentication <plain>      standby 10 authentication text <plain>
    #   vrrp 10 authentication text <plain>    vrrp 10 peer authentication <plain>  (EOS)
    # "md5 key-string ..." is left for the key-string rule, and
    # "md5 key-chain NAME" names a chain, which is not a secret.
    (
        re.compile(
            r"(\b(?:standby|vrrp)\s+\d+\s+(?:peer\s+)?authentication\s+(?:text\s+)?)"
            r"(?!(?:md5|ietf-md5|key-chain|key-string|text)\b)" + _TYPE + _VALUE
        ),
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
            r"(\b(?:phash|private-key|authpwd|privpwd|passphrase|api-key"
            r"|snmp-community-string|community-string|client-secret|collector-secret|shared-secret"
            r"|master-key|auth-key|license-key)\s+)" + _VALUE
        ),
        r"\1" + REDACTED,
    ),
    # PAN-OS XML config (the default output format, and what an export holds):
    #   <phash>$1$...</phash>      <snmp-community-string>public</snmp-community-string>
    #   <pre-shared-key><key>-AQ==...</key></pre-shared-key>      <secret>-AQ==...</secret>
    # The value may not contain "<", so a second run sees <REDACTED>
    # between the tags and leaves it alone.
    (
        re.compile(
            r"(<(snmp-community-string|community-string|phash|password|bind-password|key|secret|pre-shared-key"
            r"|private-key|authpwd|privpwd|passphrase|api-key|auth-key)>)[^<]+(?=</\2>)"
        ),
        r"\1" + REDACTED,
    ),
]

# Run on every line, keyword or not.
CATCHALL_RULES = [
    #   crypt(3)-style hashes: $1$ (MD5), $5$/$6$ (SHA-256/512), $2a$/$2b$/$2y$ (bcrypt)
    (re.compile(r"\$(?:1|2[abxy]?|5|6)\$[^\s$]+(?:\$\S+)?"), REDACTED),
    #   Junos "$9$..." (reversible) and "$8$..." (AES), IOS type 8/9 and
    #   "$14$" hashes. Junos quotes the value and ends the line with ";",
    #   so the match stops at a quote or semicolon and leaves them.
    (re.compile(r"\$(?:8|9|14)\$[^\s\";<]+"), REDACTED),
    #   PAN-OS encrypted values (base64 blobs that always start with -AQ==)
    (re.compile(r"-AQ==[^\s<]*"), REDACTED),
    #   A whole PEM private key that sits on one line
    (
        re.compile(r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)"),
        r"\1" + REDACTED + r"\2",
    ),
]

# A PEM private key block: OpenSSH, RSA, EC, PKCS#8, encrypted or not.
# Only labels that say PRIVATE KEY. A certificate is public and stays;
# a private key pasted inside a certificate bundle is still caught,
# because the rule goes by the key's own BEGIN line wherever it sits.
_PEM_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")

# IOS-XE server blocks whose indented "key" line is a secret.
_KEY_BLOCK_START = re.compile(r"^(\s*)(?:tacacs|radius)\s+server\s+\S+", re.IGNORECASE)
_KEY_BLOCK_LINE = re.compile(r"^(\s+key\s+" + _TYPE + ")" + _VALUE)


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

    A line that is already clean comes back unchanged, so scrubbing is
    idempotent and never disturbs the "### <command> ###" section
    headers the compare modules parse.

    Mostly line by line. Two kinds of secret need the lines around them
    (see the module docstring): PEM private key blocks, and the "key"
    line inside an IOS-XE "tacacs server" / "radius server" block.
    """
    if not text:
        return text

    cleaned = []
    in_pem_key = False
    # Indent of the "tacacs server" / "radius server" header we are
    # under, or None. The block ends at the first line indented no
    # deeper than its header.
    key_block_indent = None

    for line in text.split("\n"):
        if in_pem_key:
            end = _PEM_KEY_END.search(line)

            if end:
                in_pem_key = False
                # Keep the END marker and whatever follows it (a closing
                # quote), drop any key material in front of it.
                cleaned.append(scrub_line(line[end.start():]))

            continue

        begin = _PEM_KEY_BEGIN.search(line)

        if begin and not _PEM_KEY_END.search(line, begin.end()):
            in_pem_key = True
            # The BEGIN line is kept as it is, minus anything after the
            # marker. The keyword rules are skipped for it: they would
            # read the marker itself as a value and mangle it.
            cleaned.append(line[: begin.end()])
            cleaned.append(REDACTED)
            continue

        if key_block_indent is not None:
            indent = len(line) - len(line.lstrip())

            if line.strip() and indent > key_block_indent:
                line = _KEY_BLOCK_LINE.sub(r"\1" + REDACTED, line)
            else:
                key_block_indent = None

        block = _KEY_BLOCK_START.match(line)

        if block:
            key_block_indent = len(block.group(1))

        cleaned.append(scrub_line(line))

    return "\n".join(cleaned)
