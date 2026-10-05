"""SSH host-key checking, with no real SSH.

The keys are generated here and thrown away. paramiko's connect() is
replaced by a stand-in that does the one thing under test, the host-key
decision, the way paramiko does it, so the netmiko wiring around it is
the real code.
"""

import os
import threading

import paramiko
import pytest
from netmiko.exceptions import NetmikoAuthenticationException

from modules import collect, hostkeys
from modules.hostkeys import HostKeyChanged, HostKeyStore, fingerprint


def new_key():
    return paramiko.ECDSAKey.generate()


def device(host="192.0.2.11"):
    return {"device_type": "arista_eos", "host": host, "username": "admin", "password": "not-a-real-password"}


@pytest.fixture
def fake_server(monkeypatch):
    """Make paramiko 'connect' to a server that offers keys[host].

    Runs paramiko's own host-key decision (known host: compare; unknown
    host: ask the policy), then stops with an authentication error so
    nothing past the key check runs.
    """
    keys = {}

    def connect(client, hostname, **_kwargs):
        server_key = keys[hostname]
        known = client._host_keys.get(hostname)

        if known is None:
            client._policy.missing_host_key(client, hostname, server_key)
        else:
            ours = known.get(server_key.get_name())

            if ours != server_key:
                raise paramiko.BadHostKeyException(hostname, server_key, ours or list(known.values())[0])

        raise paramiko.AuthenticationException("stopped after the host-key check")

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)

    return keys


def test_first_connect_records_the_key_and_the_next_one_accepts_it(tmp_path, fake_server):
    store = HostKeyStore(str(tmp_path / "known_hosts"))
    key = fake_server["192.0.2.11"] = new_key()

    # Both attempts get as far as authentication: the key was accepted.
    for _attempt in range(2):
        with pytest.raises(NetmikoAuthenticationException):
            collect.open_connection(device(), store)

    with open(store.path, encoding="utf-8") as file:
        assert file.read() == f"192.0.2.11 {key.get_name()} {key.get_base64()}\n"


def test_a_changed_key_is_refused_with_an_error_that_says_how_to_fix_it(tmp_path, fake_server):
    store = HostKeyStore(str(tmp_path / "known_hosts"))
    old_key = fake_server["192.0.2.11"] = new_key()

    with pytest.raises(NetmikoAuthenticationException):
        collect.open_connection(device(), store)

    new = fake_server["192.0.2.11"] = new_key()

    with pytest.raises(Exception) as caught:
        collect.open_connection(device(), store)

    # Refused at the key check: it never reached authentication.
    assert not isinstance(caught.value, NetmikoAuthenticationException)

    changed = store.find_changed_key(caught.value)
    message = str(changed)

    assert isinstance(changed, HostKeyChanged)
    assert "192.0.2.11" in message
    assert fingerprint(old_key) in message
    assert fingerprint(new) in message
    assert store.path in message
    assert f'ssh-keygen -R "192.0.2.11" -f "{store.path}"' in message

    # The stored key is untouched, so the next run is refused too.
    with open(store.path, encoding="utf-8") as file:
        assert file.read().count("\n") == 1


def test_a_key_recorded_by_another_connection_a_moment_ago_still_counts(tmp_path):
    # paramiko loaded the file before another thread wrote this host, so
    # it asks the policy. The policy re-reads the file and must refuse.
    store = HostKeyStore(str(tmp_path / "known_hosts"))
    store.remember("192.0.2.11", new_key())

    with pytest.raises(HostKeyChanged):
        store.policy().missing_host_key(None, "192.0.2.11", new_key())


def test_many_first_connections_at_once_all_land_in_the_file(tmp_path):
    store = HostKeyStore(str(tmp_path / "nested" / "known_hosts"))
    keys = {f"192.0.2.{n}": new_key() for n in range(1, 41)}
    start = threading.Barrier(len(keys))

    def record(host):
        start.wait()
        store.remember(host, keys[host])

    threads = [threading.Thread(target=record, args=(host,)) for host in keys]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    loaded = paramiko.HostKeys(store.path)

    assert len(loaded) == len(keys)

    for host, key in keys.items():
        assert loaded.check(host, key), host

    with open(store.path, encoding="utf-8") as file:
        assert all(len(line.split(" ")) == 3 for line in file.read().splitlines())


def test_a_hand_edited_file_without_a_final_newline_is_not_corrupted(tmp_path):
    path = tmp_path / "known_hosts"
    first, second = new_key(), new_key()
    path.write_text(f"192.0.2.1 {first.get_name()} {first.get_base64()}")  # no trailing newline
    store = HostKeyStore(str(path))

    store.remember("192.0.2.2", second)

    loaded = paramiko.HostKeys(str(path))
    assert loaded.check("192.0.2.1", first)
    assert loaded.check("192.0.2.2", second)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_file_is_private_to_the_user(tmp_path):
    store = HostKeyStore(str(tmp_path / "cfg" / "known_hosts"))
    store.remember("192.0.2.1", new_key())

    assert os.stat(store.path).st_mode & 0o077 == 0


def test_netmiko_is_given_our_file_and_our_policy(tmp_path, monkeypatch):
    from netmiko.base_connection import BaseConnection

    opened = []
    monkeypatch.setattr(BaseConnection, "_open", lambda self: opened.append(self))
    store = HostKeyStore(str(tmp_path / "known_hosts"))
    key = new_key()
    store.remember("192.0.2.11", key)

    conn = collect.open_connection(device(), store)
    client = conn._build_ssh_client()

    assert opened == [conn]
    assert isinstance(client._policy, hostkeys._TrustOnFirstUse)
    assert client._host_keys.check("192.0.2.11", key)


def test_opting_out_leaves_netmiko_alone(monkeypatch):
    seen = {}
    monkeypatch.setattr(collect, "ConnectHandler", lambda **kwargs: seen.update(kwargs) or "connection")

    assert collect.open_connection(device(), None) == "connection"
    assert seen == device()


def test_default_path_and_the_environment_override(monkeypatch, tmp_path):
    monkeypatch.delenv(hostkeys.ENV_VAR, raising=False)
    monkeypatch.setattr(os.path, "expanduser", lambda path: path.replace("~", "/home/example"))

    if os.name != "nt":
        assert hostkeys.default_path() == "/home/example/.config/prepost-check/known_hosts"

    monkeypatch.setenv(hostkeys.ENV_VAR, str(tmp_path / "elsewhere"))
    assert hostkeys.default_path() == str(tmp_path / "elsewhere")
    assert HostKeyStore().path == str(tmp_path / "elsewhere")
