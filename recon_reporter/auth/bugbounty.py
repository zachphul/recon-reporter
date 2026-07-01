"""Bug bounty scope parser — loads target lists from common program formats.

Supports:
  - Simple YAML/JSON lists of domains, IPs, and CIDR ranges
  - Wildcard domains (*.example.com)
  - Exclusion lists (out-of-scope targets)
  - Bugcrowd/HackerOne-style program metadata

Usage:
    scope = BugBountyScope.load("program.yml")
    scope.authorize("app.example.com")  # True if in scope
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
from pathlib import Path

import yaml

from .scope import AuthorizationError


class BugBountyScope:
    """Scope definition for a bug bounty program with in-scope and out-of-scope targets."""

    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        program_name: str = "",
        program_url: str = "",
        rules_url: str = "",
        max_severity: str = "",
    ):
        self.program_name = program_name
        self.program_url = program_url
        self.rules_url = rules_url
        self.max_severity = max_severity
        self._in_scope = in_scope
        self._out_of_scope = [e.strip().lower() for e in (out_of_scope or []) if e.strip()]
        self._nets: list[ipaddress._BaseNetwork] = []
        self._wildcards: list[str] = []
        self._names: set[str] = set()

        for entry in in_scope:
            entry = entry.strip()
            if not entry:
                continue
            if entry.startswith("*."):
                self._wildcards.append(entry[1:])  # keep the leading dot
            else:
                try:
                    self._nets.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    self._names.add(entry.lower())

    @classmethod
    def load(cls, path: str | Path) -> BugBountyScope:
        """Load a bug bounty scope from YAML or JSON."""
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)

        return cls(
            in_scope=data.get("in_scope", data.get("authorized_targets", [])),
            out_of_scope=data.get("out_of_scope", data.get("excluded_targets", [])),
            program_name=data.get("program_name", ""),
            program_url=data.get("program_url", ""),
            rules_url=data.get("rules_url", ""),
            max_severity=data.get("max_severity", ""),
        )

    def _is_out_of_scope(self, target: str) -> bool:
        t = target.strip().lower()
        for excluded in self._out_of_scope:
            if t == excluded:
                return True
            if excluded.startswith("*.") and t.endswith(excluded[1:]):
                return True
            if fnmatch.fnmatch(t, excluded):
                return True
        return False

    def _matches_wildcard(self, target: str) -> bool:
        t = target.strip().lower()
        for wc in self._wildcards:
            # *.example.com matches sub.example.com but NOT example.com itself
            if t.endswith(wc) and t != wc.lstrip("."):
                return True
        return False

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
        """Check if a target is within the bug bounty scope."""
        if self._is_out_of_scope(target):
            return False
        t = target.strip().lower()
        if t in self._names:
            return True
        if self._matches_wildcard(t):
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
                "Refusing to scan: pass --authorized to assert you have permission "
                "to test this target under the bug bounty program."
            )
        if self._is_out_of_scope(target):
            raise AuthorizationError(
                f"Refusing to scan '{target}': this target is explicitly OUT OF SCOPE "
                f"for this bug bounty program."
            )
        if not self.authorizes(target):
            raise AuthorizationError(
                f"Refusing to scan '{target}': not covered by this bug bounty program's scope. "
                f"Check the program's rules for eligible targets."
            )

    def summary(self) -> str:
        """Human-readable scope summary for reports."""
        lines = []
        if self.program_name:
            lines.append(f"Program: {self.program_name}")
        if self.program_url:
            lines.append(f"URL: {self.program_url}")
        if self.rules_url:
            lines.append(f"Rules: {self.rules_url}")
        lines.append(f"In-scope targets: {len(self._in_scope)} entries")
        if self._wildcards:
            lines.append(f"Wildcard domains: {', '.join('*' + w for w in self._wildcards)}")
        if self._out_of_scope:
            lines.append(f"Out-of-scope: {', '.join(self._out_of_scope)}")
        return "\n".join(lines)
