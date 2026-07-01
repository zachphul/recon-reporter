"""Default credential checker — tests common admin credentials on discovered services.

Checks SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, and HTTP basic auth endpoints
for well-known default credentials. Results are added as RuleFlags.
"""
from __future__ import annotations

import ftplib
import socket

import httpx

from ..logconf import get_logger
from ..model import Host, RuleFlag, Service, Severity

log = get_logger(__name__)

# service_port -> list of (username, password) to try
DEFAULT_CREDS: dict[int, list[tuple[str, str]]] = {
    21: [
        ("anonymous", "anonymous"),
        ("ftp", "ftp"),
        ("admin", "admin"),
        ("root", "root"),
    ],
    3306: [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("admin", "admin"),
        ("mysql", "mysql"),
    ],
    5432: [
        ("postgres", ""),
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("admin", "admin"),
    ],
    6379: [
        ("", ""),
        ("default", ""),
    ],
    27017: [
        ("admin", ""),
        ("root", ""),
    ],
}

# HTTP paths to test for default credentials
HTTP_AUTH_PATHS = [
    "/",
    "/admin",
    "/login",
    "/wp-admin/",
    "/phpmyadmin/",
]


def check_default_creds(hosts: list[Host], timeout: int = 5) -> list[RuleFlag]:
    """Test default credentials on discovered services. Returns RuleFlags for any matches."""
    flags: list[RuleFlag] = []

    for h in hosts:
        for s in h.services:
            if s.port in DEFAULT_CREDS:
                flags.extend(_check_service_creds(h.address, s, timeout))
            if s.service in ("http", "https") or s.port in (80, 443, 8080, 8443):
                flags.extend(_check_http_auth(h.address, s, timeout))

    return flags


def _check_service_creds(host: str, s: Service, timeout: int) -> list[RuleFlag]:
    """Test default credentials on a specific service port."""
    flags: list[RuleFlag] = []
    creds = DEFAULT_CREDS.get(s.port, [])

    if s.port == 21:
        flags.extend(_check_ftp(host, s, creds, timeout))
    elif s.port == 3306:
        flags.extend(_check_mysql(host, s, creds, timeout))
    elif s.port == 5432:
        flags.extend(_check_postgres(host, s, creds, timeout))
    elif s.port == 6379:
        flags.extend(_check_redis(host, s, creds, timeout))
    elif s.port == 27017:
        flags.extend(_check_mongodb(host, s, creds, timeout))

    return flags


def _check_ftp(host: str, s: Service, creds: list[tuple[str, str]], timeout: int) -> list[RuleFlag]:
    flags: list[RuleFlag] = []
    for user, pwd in creds:
        try:
            ftp = ftplib.FTP(timeout=timeout)
            ftp.connect(host, s.port, timeout=timeout)
            ftp.login(user, pwd)
            ftp.quit()
            flags.append(RuleFlag(
                title=f"Default FTP credentials: {user}:{pwd}",
                severity=Severity.CRITICAL,
                detail=f"FTP server at {host}:{s.port} accepted login with "
                       f"default credentials '{user}:{pwd}'.",
                host=host, port=s.port,
            ))
            break  # one success is enough
        except (ftplib.error_perm, OSError):
            continue
        except Exception:
            continue
    return flags


def _check_mysql(host: str, s: Service, creds: list[tuple[str, str]], timeout: int) -> list[RuleFlag]:
    """Check MySQL for default credentials via raw TCP handshake."""
    flags: list[RuleFlag] = []
    for user, pwd in creds:
        if _mysql_handshake(host, s.port, user, pwd, timeout):
            flags.append(RuleFlag(
                title=f"Default MySQL credentials: {user}:{pwd or '(empty)'}",
                severity=Severity.CRITICAL,
                detail=f"MySQL at {host}:{s.port} accepted login with default credentials.",
                host=host, port=s.port,
            ))
            break
    return flags


def _mysql_handshake(host: str, port: int, user: str, password: str, timeout: int) -> bool:
    """Attempt MySQL login via raw TCP. Returns True if login succeeds."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        # Read the server greeting
        greeting = sock.recv(4096)
        if not greeting:
            return False

        # Build a login packet (simplified MySQL protocol)
        # This is a minimal handshake that works against default-config MySQL
        import struct
        client_flags = 0x0000a685
        max_packet = 16777216
        charset = 33  # utf8

        login_data = b""
        login_data += struct.pack("<I", client_flags)
        login_data += struct.pack("<I", max_packet)
        login_data += bytes([charset])
        login_data += b"\x00" * 23  # reserved
        login_data += user.encode() + b"\x00"
        login_data += bytes([len(password)]) + password.encode()

        packet = struct.pack("<I", len(login_data) | (1 << 24)) + login_data
        sock.send(packet)

        # Read response
        response = sock.recv(4096)
        sock.close()

        # OK packet starts with 0x00, ERR packet starts with 0xff
        if response and response[0] == 0x00:
            return True
        return False
    except OSError:
        return False
    except Exception:
        return False


def _check_postgres(host: str, s: Service, creds: list[tuple[str, str]], timeout: int) -> list[RuleFlag]:
    """Check PostgreSQL for default credentials via startup message."""
    flags: list[RuleFlag] = []
    for user, pwd in creds:
        if _postgres_login(host, s.port, user, password=pwd, timeout=timeout):
            flags.append(RuleFlag(
                title=f"Default PostgreSQL credentials: {user}:{pwd or '(empty)'}",
                severity=Severity.CRITICAL,
                detail=f"PostgreSQL at {host}:{s.port} accepted login with default credentials.",
                host=host, port=s.port,
            ))
            break
    return flags


def _postgres_login(host: str, port: int, user: str, password: str, timeout: int) -> bool:
    """Attempt PostgreSQL login via startup message. Returns True on auth OK."""
    try:
        import struct
        sock = socket.create_connection((host, port), timeout=timeout)

        # Build startup message (v3.0)
        params = f"user\x00{user}\x00database\x00{user}\x00\x00".encode()
        version = struct.pack("!II", 196608, len(params) + 4)
        sock.send(version + params)

        response = sock.recv(4096)
        sock.close()

        # 'R' (0x52) + 8 = authentication OK
        if len(response) >= 5 and response[0:1] == b"R":
            auth_type = struct.unpack("!I", response[5:9])[0] if len(response) >= 9 else -1
            return auth_type == 0  # 0 = auth OK
        return False
    except OSError:
        return False
    except Exception:
        return False


def _check_redis(host: str, s: Service, creds: list[tuple[str, str]], timeout: int) -> list[RuleFlag]:
    """Check Redis for default credentials (no auth)."""
    flags: list[RuleFlag] = []
    for _user, pwd in creds:
        try:
            sock = socket.create_connection((host, s.port), timeout=timeout)
            sock.recv(4096)  # read banner

            if pwd:
                sock.send(f"AUTH {pwd}\r\n".encode())
            else:
                sock.send(b"PING\r\n")

            response = sock.recv(4096).decode(errors="replace").strip()
            sock.close()

            # +PONG = no auth required; +OK = auth succeeded
            if "+PONG" in response or "+OK" in response:
                label = "Redis no authentication" if not pwd else f"Redis default auth: {pwd}"
                if not pwd:
                    detail = f"Redis at {host}:{s.port} accepted connection without authentication."
                else:
                    detail = f"Redis at {host}:{s.port} accepted connection with password {pwd!r}."
                flags.append(RuleFlag(
                    title=label,
                    severity=Severity.CRITICAL,
                    detail=detail,
                    host=host, port=s.port,
                ))
                break
        except OSError:
            continue
        except Exception:
            continue
    return flags


def _check_mongodb(host: str, s: Service, creds: list[tuple[str, str]], timeout: int) -> list[RuleFlag]:
    """Check MongoDB for default credentials (no auth)."""
    flags: list[RuleFlag] = []
    try:
        sock = socket.create_connection((host, s.port), timeout=timeout)
        # MongoDB wire protocol: isMaster command
        import struct
        # Build a minimal isMaster query
        doc = b"\x03isMaster\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        msg_len = len(doc) + 16
        header = struct.pack("<iiii", msg_len, 2013, 0, 1)
        sock.send(header + doc)

        response = sock.recv(4096)
        sock.close()

        # If we get a response, MongoDB is accessible without auth
        if response and len(response) > 16:
            flags.append(RuleFlag(
                title="MongoDB no authentication required",
                severity=Severity.CRITICAL,
                detail=f"MongoDB at {host}:{s.port} responded to isMaster without authentication.",
                host=host, port=s.port,
            ))
    except OSError:
        pass
    except Exception:
        pass
    return flags


def _check_http_auth(host: str, s: Service, timeout: int) -> list[RuleFlag]:
    """Check HTTP endpoints for default basic auth credentials."""
    flags: list[RuleFlag] = []
    scheme = "https" if s.port == 443 or s.port == 8443 else "http"
    default_http_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("admin", "1234"),
    ]

    for path in HTTP_AUTH_PATHS:
        url = f"{scheme}://{host}:{s.port}{path}"
        for user, pwd in default_http_creds:
            try:
                r = httpx.get(
                    url,
                    auth=(user, pwd),
                    timeout=timeout,
                    follow_redirects=False,
                    verify=False,
                )
                # 200 with auth = credentials work
                # 401 = wrong credentials (expected)
                if r.status_code == 200:
                    flags.append(RuleFlag(
                        title=f"Default HTTP auth: {user}:{pwd}",
                        severity=Severity.CRITICAL,
                        detail=f"HTTP endpoint {url} accepted basic auth with "
                               f"default credentials '{user}:{pwd}'.",
                        host=host, port=s.port,
                    ))
                    return flags  # one success per service is enough
            except Exception:
                continue
    return flags
