import io
import os

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

    folder, _zip_name = collect.run_collection(
        jobs, "precheck", str(tmp_path), "2026-01-01_00-00", console, redact_secrets=redact_secrets
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
