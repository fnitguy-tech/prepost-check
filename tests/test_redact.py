import io
import os

import pytest
from rich.console import Console

from modules import collect
from modules.redact import REDACTED, scrub

EOS_CONFIG = """\
hostname SITE-A-SW-1
!
username admin privilege 15 role network-admin secret sha512 $6$abc123/def$hashhashhash
username ops secret 0 plaintextpass
username svc ssh-key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 svc@host
enable password sha512 $6$zzz$yyyy
!
tacacs-server host 10.1.1.1 key 7 1234ABCD
tacacs-server key supersecret
radius-server host 10.1.1.2 key 7 DEADBEEF
!
snmp-server community mycommunity ro
snmp-server user bob grp v3 localized 0x80001f auth sha 0xabc priv aes 0xdef
!
ntp authentication-key 1 md5 7 0A1B2C
!
key chain KC
   key 1
      key-string 7 CAFEBABE
!
interface Ethernet1
   description password reset server
   ip ospf authentication-key 7 ABCDEF
   ip ospf message-digest-key 1 md7 FEDCBA
!
interface Tunnel1
   tunnel key 1234
!
router bgp 65000
   neighbor 10.0.0.1 password 7 0822455D0A16
   neighbor 10.0.0.2 remote-as 65000
"""

PANOS_CONFIG = """\
set mgt-config users admin phash $1$abcde$fghijklmnopq
set mgt-config password-complexity enabled yes
set network ike gateway GW authentication pre-shared-key key -AQ==abcdef0123456789==
set shared server-profile radius RAD server S1 secret -AQ==zzzz
set shared server-profile ldap L bind-password -AQ==yyyy
set shared certificate C private-key -AQ==xxxx
set shared certificate C public-key -AB==keepme
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string "my community"
set deviceconfig system snmp-setting access-setting version v3 users U authpwd -AQ==a privpwd -AQ==b
set network virtual-router default protocol bgp auth-profile AP secret -AQ==c
"""

SECRET_VALUES = [
    "$6$abc123/def$hashhashhash",
    "plaintextpass",
    "$6$zzz$yyyy",
    "1234ABCD",
    "supersecret",
    "DEADBEEF",
    "mycommunity",
    "0xabc",
    "0xdef",
    "0A1B2C",
    "CAFEBABE",
    "ABCDEF",
    "FEDCBA",
    "0822455D0A16",
    "$1$abcde$fghijklmnopq",
    "-AQ==abcdef0123456789==",
    "-AQ==zzzz",
    "-AQ==yyyy",
    "-AQ==xxxx",
    "my community",
    "-AQ==a",
    "-AQ==b",
    "-AQ==c",
]


def test_every_secret_value_is_gone():
    cleaned = scrub(EOS_CONFIG + PANOS_CONFIG)

    for value in SECRET_VALUES:
        assert value not in cleaned, value


def test_keyword_and_type_marker_survive():
    cleaned = scrub(EOS_CONFIG + PANOS_CONFIG).splitlines()

    assert f"username admin privilege 15 role network-admin secret sha512 {REDACTED}" in cleaned
    assert f"username ops secret 0 {REDACTED}" in cleaned
    assert f"enable password sha512 {REDACTED}" in cleaned
    assert f"tacacs-server host 10.1.1.1 key 7 {REDACTED}" in cleaned
    assert f"tacacs-server key {REDACTED}" in cleaned
    assert f"snmp-server community {REDACTED} ro" in cleaned
    assert f"snmp-server user bob grp v3 localized 0x80001f auth sha {REDACTED} priv aes {REDACTED}" in cleaned
    assert f"ntp authentication-key 1 md5 7 {REDACTED}" in cleaned
    assert f"      key-string 7 {REDACTED}" in cleaned
    assert f"   ip ospf authentication-key 7 {REDACTED}" in cleaned
    assert f"   ip ospf message-digest-key 1 md7 {REDACTED}" in cleaned
    assert f"   neighbor 10.0.0.1 password 7 {REDACTED}" in cleaned
    assert f"set mgt-config users admin phash {REDACTED}" in cleaned
    assert f"set network ike gateway GW authentication pre-shared-key key {REDACTED}" in cleaned
    assert f"set shared server-profile ldap L bind-password {REDACTED}" in cleaned
    assert f"set shared certificate C private-key {REDACTED}" in cleaned
    assert (
        "set deviceconfig system snmp-setting access-setting version v2c "
        f"snmp-community-string {REDACTED}"
    ) in cleaned
    assert (
        "set deviceconfig system snmp-setting access-setting version v3 users U "
        f"authpwd {REDACTED} privpwd {REDACTED}"
    ) in cleaned


def test_non_secret_lines_untouched():
    cleaned = scrub(EOS_CONFIG + PANOS_CONFIG).splitlines()

    # Public keys, GRE tunnel keys, peers without passwords and config
    # keywords that merely contain the word "password" are not secrets.
    assert "username svc ssh-key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 svc@host" in cleaned
    assert "   tunnel key 1234" in cleaned
    assert "   neighbor 10.0.0.2 remote-as 65000" in cleaned
    assert "set mgt-config password-complexity enabled yes" in cleaned
    assert "set shared certificate C public-key -AB==keepme" in cleaned
    # Free text is left alone by the keyword rules.
    assert "   description password reset server" in cleaned
    assert "hostname SITE-A-SW-1" in cleaned


def test_show_output_without_secrets_is_unchanged():
    bgp_summary = (
        "  Neighbor        V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State  PfxRcd PfxAcc\n"
        "  10.118.9.3      4  65000          1234      1230    0    0 01:02:03 Estab  3      3\n"
    )

    assert scrub(bgp_summary) == bgp_summary
    assert scrub("") == ""


def test_scrub_is_idempotent():
    once = scrub(EOS_CONFIG + PANOS_CONFIG)

    assert scrub(once) == once


def test_section_headers_survive():
    capture = "### show running-config ###\n" + "-" * 80 + "\n" + EOS_CONFIG

    assert scrub(capture).startswith("### show running-config ###\n" + "-" * 80 + "\n")


class FakeConnection:
    def __init__(self, **_device):
        pass

    def send_command(self, command, **_kwargs):
        if command == "show hostname":
            return "Hostname: SITE-A-SW-1"
        return EOS_CONFIG

    def disconnect(self):
        pass


def _run(tmp_path, monkeypatch, redact_secrets):
    monkeypatch.setattr(collect, "ConnectHandler", FakeConnection)
    jobs = [{
        "device": {"device_type": "arista_eos", "host": "192.0.2.1", "username": "u", "password": "p"},
        "commands": ["show running-config"],
    }]
    console = Console(file=io.StringIO())

    # host_keys=None: the fake connection has no SSH host key to check.
    folder, _zip_name = collect.run_collection(
        jobs, "precheck", str(tmp_path), "2026-01-01_00-00", console,
        redact_secrets=redact_secrets, host_keys=None,
    )

    with open(os.path.join(folder, "SITE-A-SW-1.txt"), encoding="utf-8") as file:
        return file.read()


def test_collection_redacts_when_enabled(tmp_path, monkeypatch):
    capture = _run(tmp_path, monkeypatch, redact_secrets=True)

    assert "Secrets: redacted" in capture
    assert "### show running-config ###" in capture
    for value in SECRET_VALUES[:14]:
        assert value not in capture, value
    assert f"neighbor 10.0.0.1 password 7 {REDACTED}" in capture


def test_collection_is_verbatim_by_default(tmp_path, monkeypatch):
    capture = _run(tmp_path, monkeypatch, redact_secrets=False)

    assert "Secrets: redacted" not in capture
    assert "$6$abc123/def$hashhashhash" in capture


# One example per rule added for the review: (input, the secret that
# must be gone, what the line must read afterwards). Every value is made
# up. Each secret is unique so "not in the output" can't pass by luck.
CORPUS = [
    # Arista type 8a (AES-256-GCM) on password, secret, and key
    ("   neighbor 10.0.0.3 password 8a Zm9vYmFyQkdQOGE=", "Zm9vYmFyQkdQOGE=", f"   neighbor 10.0.0.3 password 8a {REDACTED}"),
    ("username eng secret 8a c2VjcmV0OGFibG9i", "c2VjcmV0OGFibG9i", f"username eng secret 8a {REDACTED}"),
    ("tacacs-server host 10.1.1.9 key 8a a2V5OGFibG9iMDE=", "a2V5OGFibG9iMDE=", f"tacacs-server host 10.1.1.9 key 8a {REDACTED}"),
    # Plain, untyped secrets
    ("      key-string PlainChainKey1", "PlainChainKey1", f"      key-string {REDACTED}"),
    ("   ip ospf authentication-key PlainOspf2", "PlainOspf2", f"   ip ospf authentication-key {REDACTED}"),
    (
        "crypto isakmp key PlainIsakmp3 address 192.0.2.1",
        "PlainIsakmp3",
        f"crypto isakmp key {REDACTED} address 192.0.2.1",
    ),
    (
        "crypto isakmp key 6 TypedIsakmp4 address 192.0.2.2",
        "TypedIsakmp4",
        f"crypto isakmp key 6 {REDACTED} address 192.0.2.2",
    ),
    (" pre-shared-key PlainPsk5", "PlainPsk5", f" pre-shared-key {REDACTED}"),
    (" pre-shared-key 0 TypedPsk6", "TypedPsk6", f" pre-shared-key 0 {REDACTED}"),
    ("  pre-shared-key local 6 LocalPsk7", "LocalPsk7", f"  pre-shared-key local 6 {REDACTED}"),
    # SNMP
    (
        "snmp-server host 10.0.0.9 version 2c TrapComm8",
        "TrapComm8",
        f"snmp-server host 10.0.0.9 version 2c {REDACTED}",
    ),
    (
        "snmp-server host 10.0.0.9 vrf MGMT traps version 2c TrapComm9 udp-port 162",
        "TrapComm9",
        f"snmp-server host 10.0.0.9 vrf MGMT traps version 2c {REDACTED} udp-port 162",
    ),
    ("snmp-server host 10.0.0.9 OldComm10", "OldComm10", f"snmp-server host 10.0.0.9 {REDACTED}"),
    ("snmp-server community ReadComm11 RO", "ReadComm11", f"snmp-server community {REDACTED} RO"),
    # NTP
    ("ntp authentication-key 5 md5 PlainNtp12", "PlainNtp12", f"ntp authentication-key 5 md5 {REDACTED}"),
    ("ntp authentication-key 6 md5 7 TypedNtp13", "TypedNtp13", f"ntp authentication-key 6 md5 7 {REDACTED}"),
    # OSPF / IS-IS / BGP / HSRP / VRRP
    (
        " ip ospf message-digest-key 1 md5 PlainMd14",
        "PlainMd14",
        f" ip ospf message-digest-key 1 md5 {REDACTED}",
    ),
    (
        " ip ospf message-digest-key 2 md5 7 TypedMd15",
        "TypedMd15",
        f" ip ospf message-digest-key 2 md5 7 {REDACTED}",
    ),
    (" neighbor 192.0.2.7 password PlainBgp16", "PlainBgp16", f" neighbor 192.0.2.7 password {REDACTED}"),
    (" isis password PlainIsis17 level-2", "PlainIsis17", f" isis password {REDACTED} level-2"),
    ("   isis authentication key 7 TypedIsis18", "TypedIsis18", f"   isis authentication key 7 {REDACTED}"),
    (" standby 10 authentication PlainHsrp19", "PlainHsrp19", f" standby 10 authentication {REDACTED}"),
    (" standby 11 authentication text TextHsrp20", "TextHsrp20", f" standby 11 authentication text {REDACTED}"),
    (
        " standby 12 authentication md5 key-string 7 Md5Hsrp21",
        "Md5Hsrp21",
        f" standby 12 authentication md5 key-string 7 {REDACTED}",
    ),
    (" vrrp 20 authentication text TextVrrp22", "TextVrrp22", f" vrrp 20 authentication text {REDACTED}"),
    (" vrrp 21 authentication PlainVrrp23", "PlainVrrp23", f" vrrp 21 authentication {REDACTED}"),
    # Junos
    ('            secret "$9$JunosRad24abc"; ## SECRET-DATA', "JunosRad24abc", f"            secret {REDACTED}; ## SECRET-DATA"),
    ('    authentication-key "$9$JunosBgp25abc";', "JunosBgp25abc", f"    authentication-key {REDACTED};"),
    (
        '        pre-shared-key ascii-text "$9$JunosPsk26abc";',
        "JunosPsk26abc",
        f"        pre-shared-key ascii-text {REDACTED};",
    ),
    (
        '            encrypted-password "$6$JunosUser27$abcdefghijk";',
        "JunosUser27",
        f"            encrypted-password {REDACTED};",
    ),
    # PAN-OS XML
    (
        "<snmp-community-string>XmlComm28</snmp-community-string>",
        "XmlComm28",
        f"<snmp-community-string>{REDACTED}</snmp-community-string>",
    ),
    ("      <phash>$1$XmlHash29$abcdefgh</phash>", "XmlHash29", f"      <phash>{REDACTED}</phash>"),
    ("<password>XmlPass30</password>", "XmlPass30", f"<password>{REDACTED}</password>"),
    (
        "<pre-shared-key><key>-AQ==XmlKey31abc=</key></pre-shared-key>",
        "XmlKey31abc",
        f"<pre-shared-key><key>{REDACTED}</key></pre-shared-key>",
    ),
    ("<secret>XmlSecret32</secret>", "XmlSecret32", f"<secret>{REDACTED}</secret>"),
    ("<pre-shared-key>XmlPsk33</pre-shared-key>", "XmlPsk33", f"<pre-shared-key>{REDACTED}</pre-shared-key>"),
    # PAN-OS set format
    (
        "set deviceconfig system snmp-setting access-setting version v2c snmp-community-string SetComm34",
        "SetComm34",
        f"set deviceconfig system snmp-setting access-setting version v2c snmp-community-string {REDACTED}",
    ),
    ("set mgt-config users ops phash $1$SetHash35$abcdefgh", "SetHash35", f"set mgt-config users ops phash {REDACTED}"),
    ("set shared local-user-database user u1 password SetPass36", "SetPass36", f"set shared local-user-database user u1 password {REDACTED}"),
]

# IOS / IOS-XE block form: the key sits on its own line under the header.
IOS_XE_BLOCKS = """\
tacacs server TAC-1
 address ipv4 192.0.2.40
 key 7 BlockTac37
!
tacacs server TAC-2
 address ipv4 192.0.2.41
 key BlockTac38
radius server RAD-1
 address ipv4 192.0.2.50 auth-port 1812 acct-port 1813
 key 6 BlockRad39
 key 0 BlockRad40
!
key chain KC
 key 1
  key-string 7 ChainKey41
interface Tunnel1
 tunnel key 4242
"""

PEM_KEY_BODY = [
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7fakekeyline1",
    "q8wFakeKeyLine2Zm9vYmFyYmF6cXV4Y29ycmVjdGhvcnNlYmF0dGVyeXN0YXBs",
]
PEM_TEXT = "\n".join([
    "crypto key export:",
    "-----BEGIN RSA PRIVATE KEY-----",
    *PEM_KEY_BODY,
    "-----END RSA PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----",
    "MIIDdzCCAl+gAwIBAgIEPublicCertLineStays",
    "-----END CERTIFICATE-----",
    "after the key",
])


@pytest.mark.parametrize("line, secret, expected", CORPUS)
def test_corpus_rule(line, secret, expected):
    cleaned = scrub(line)

    assert secret not in cleaned
    assert cleaned == expected
    # Idempotent: a second run changes nothing.
    assert scrub(cleaned) == cleaned


def test_no_corpus_secret_survives_together():
    text = "\n".join(line for line, _secret, _expected in CORPUS) + "\n" + IOS_XE_BLOCKS + PEM_TEXT
    cleaned = scrub(text)

    for _line, secret, _expected in CORPUS:
        assert secret not in cleaned, secret

    for secret in ("BlockTac37", "BlockTac38", "BlockRad39", "BlockRad40", "ChainKey41", *PEM_KEY_BODY):
        assert secret not in cleaned, secret

    assert scrub(cleaned) == cleaned


def test_ios_xe_server_block_keys_are_redacted_and_key_numbers_are_not():
    cleaned = scrub(IOS_XE_BLOCKS).splitlines()

    assert f" key 7 {REDACTED}" in cleaned
    assert f" key {REDACTED}" in cleaned
    assert f" key 6 {REDACTED}" in cleaned
    assert f" key 0 {REDACTED}" in cleaned
    # Outside a server block, a bare "key N" is a key number or a GRE
    # tunnel key, and both must survive.
    assert " key 1" in cleaned
    assert " tunnel key 4242" in cleaned
    assert " address ipv4 192.0.2.40" in cleaned


def test_pem_private_key_block_is_redacted_and_certificate_is_kept():
    cleaned = scrub(PEM_TEXT).splitlines()

    assert cleaned == [
        "crypto key export:",
        "-----BEGIN RSA PRIVATE KEY-----",
        REDACTED,
        "-----END RSA PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "MIIDdzCCAl+gAwIBAgIEPublicCertLineStays",
        "-----END CERTIFICATE-----",
        "after the key",
    ]


def test_pem_private_key_inside_a_quoted_value_or_on_one_line():
    quoted = 'set shared certificate C private-key "-----BEGIN PRIVATE KEY-----\nQuotedKeyBody42\n-----END PRIVATE KEY-----"\nnext'
    cleaned = scrub(quoted)

    assert "QuotedKeyBody42" not in cleaned
    assert cleaned.endswith("\nnext")
    assert scrub(cleaned) == cleaned

    one_line = "key: -----BEGIN EC PRIVATE KEY-----OneLineBody43-----END EC PRIVATE KEY----- done"
    assert scrub(one_line) == f"key: -----BEGIN EC PRIVATE KEY-----{REDACTED}-----END EC PRIVATE KEY----- done"


def test_a_cut_off_pem_key_is_redacted_to_the_end():
    cleaned = scrub("-----BEGIN OPENSSH PRIVATE KEY-----\nCutOffBody44\nCutOffBody45")

    assert "CutOffBody" not in cleaned


def test_lookalikes_are_left_alone():
    for line in [
        " vrrp 10 authentication md5 key-chain VRRP-CHAIN",
        " standby 10 authentication md5 key-chain HSRP-CHAIN",
        "snmp-server host 10.0.0.9 version 3 priv snmpuser",
        "   authentication-key-chain BGP-CHAIN;",
        "crypto isakmp policy 10",
        " authentication pre-share",
        "<public-key>AAAAB3NzaC1yc2EAAAADAQAB</public-key>",
    ]:
        assert scrub(line) == line, line
