"""Tests for the deterministic rule engine, including outdated-version detection."""
from pathlib import Path

from recon_reporter.enrich import rules
from recon_reporter.enrich.rules import _ver_tuple
from recon_reporter.model import Host, Service, Severity
from recon_reporter.parsers.nmap_xml import parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def test_ver_tuple():
    assert _ver_tuple("6.6.1p1") == (6, 6, 1)
    assert _ver_tuple("2.4.7") == (2, 4, 7)
    assert _ver_tuple("1:2.4.7") == (2, 4, 7)   # Debian epoch stripped
    assert _ver_tuple("1.18.0-ubuntu") == (1, 18, 0)
    assert _ver_tuple("") == ()
    assert _ver_tuple("nope") == ()


def test_outdated_software_flagged():
    hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    flags = rules.evaluate(hosts)
    outdated = [f for f in flags if "outdated" in f.title.lower()]
    # OpenSSH 6.6.1 (< 9.0) and Apache httpd 2.4.7 (< 2.4.60) should both flag
    assert any("OpenSSH" in t for t in [f.title for f in outdated])
    assert any("Apache" in t for t in [f.title for f in outdated])
    assert all(f.severity == Severity.MEDIUM for f in outdated)


def test_remote_access_and_legacy_services():
    host = Host(address="10.0.0.5", services=[
        Service(port=5900, service="vnc"),
        Service(port=6000, service="x11"),
        Service(port=389, service="ldap"),
    ])
    flags = rules.evaluate([host])
    titles = [f.title for f in flags]
    assert any("VNC remote access exposed" in t for t in titles)
    assert any(f.severity == Severity.HIGH and "VNC" in f.title for f in flags)
    assert any("Legacy/risky service: X11" in t for t in titles)
    assert any("LDAP" in t for t in titles)


def test_large_attack_surface_flagged():
    services = [Service(port=p, service="svc", state="open") for p in range(1000, 1020)]  # 20
    flags = rules.evaluate([Host(address="10.0.0.6", services=services)])
    assert any("Large attack surface" in f.title for f in flags)


def test_ssh_weak_algorithms_detected():
    """The sample fixture includes SSH with weak KEX, host key, cipher, and MAC algos."""
    hosts = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    flags = rules.evaluate(hosts)
    ssh_flags = [f for f in flags if "SSH" in f.title]

    assert any("Diffie-Hellman Group 1 (1024" in f.title for f in ssh_flags)
    assert any("DSA host key" in f.title for f in ssh_flags)
    assert any("arcfour256" in f.detail.lower() for f in ssh_flags)
    assert any("hmac-md5" in f.detail.lower() for f in ssh_flags)


def test_ssh_weak_host_key_bits():
    host = Host(address="10.0.0.7", services=[
        Service(port=22, service="ssh", product="OpenSSH", version="8.9",
                scripts={"ssh-hostkey": "1024 aa:bb:cc (RSA)"}),
    ])
    flags = rules.evaluate([host])
    ssh_flags = [f for f in flags if "SSH" in f.title and "RSA" in f.title]
    assert len(ssh_flags) == 1
    assert "1024" in ssh_flags[0].title
    assert ssh_flags[0].severity == Severity.MEDIUM


def test_ssh_clean_server_no_flags():
    host = Host(address="10.0.0.8", services=[
        Service(port=22, service="ssh", product="OpenSSH", version="9.6",
                scripts={"ssh2-enum-algorithms": (
                    "kex_algorithms: curve25519-sha256,diffie-hellman-group16-sha512\n"
                    "host_key_algorithms: ssh-ed25519\n"
                    "encryption_algorithms: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
                    "mac_algorithms: hmac-sha2-256-etm@openssh.com"
                )}),
    ])
    flags = rules.evaluate([host])
    # Filter to only weak SSH flags (exclude "Version disclosed" INFO)
    weak_ssh = [f for f in flags if "SSH" in f.title and f.severity != Severity.INFO]
    assert len(weak_ssh) == 0
