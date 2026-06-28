"""Authorization gate. This is the line between a security tool and a liability:
the tool refuses to touch any target not explicitly listed in a scope file, and
requires the operator to assert authorization."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

import yaml


class AuthorizationError(Exception):
    pass


class Scope:
    def __init__(self, entries: list[str]):
        self.raw = entries
        self._nets: list[ipaddress._BaseNetwork] = []
        self._names: set[str] = set()
        for e in entries:
            e = e.strip()
            if not e:
                continue
            try:
                self._nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                self._names.add(e.lower())

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        entries = data.get("authorized_targets", [])
        if not entries:
            raise AuthorizationError(f"scope file {path} has no authorized_targets")
        return cls(entries)

    def _resolved_ips(self, target: str) -> list[ipaddress._BaseAddress]:
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(target, None)
            return [ipaddress.ip_address(i[4][0]) for i in infos]
        except socket.gaierror:
            return []

    def authorizes(self, target: str) -> bool:
        t = target.strip().lower()
        if t in self._names:
            return True
        for ip in self._resolved_ips(target):
            for net in self._nets:
                if ip in net:
                    return True
        return False

    def require(self, target: str, acknowledged: bool) -> None:
        """Raise unless the target is in scope AND the operator asserted authorization."""
        if not acknowledged:
            raise AuthorizationError(
                "Refusing to scan: pass --authorized to assert you own or have written "
                "permission to test this target."
            )
        if not self.authorizes(target):
            raise AuthorizationError(
                f"Refusing to scan '{target}': not covered by the scope file. "
                f"Add it to authorized_targets only if you are permitted to test it."
            )
