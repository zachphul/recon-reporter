"""Subdomain enumeration collector — discovers subdomains via passive sources.

Wraps subfinder (if installed) and falls back to crt.sh certificate transparency
logs when subfinder is unavailable. Results are merged into the host list as new
Host entries with DNS-resolved addresses.
"""
from __future__ import annotations

import json
import socket
from urllib.parse import quote

import httpx

from ..logconf import get_logger
from ..model import Host
from .base import Collector, RawOutput

log = get_logger(__name__)

CRTSH_URL = "https://crt.sh/?q={}&output=json"


class SubdomainCollector(Collector):
    name = "subdomains"
    binary = "subfinder"

    def run(self, target: str, timeout: int = 120) -> RawOutput:
        """Discover subdomains. Tries subfinder first, falls back to crt.sh."""
        if self.available():
            return self._run_subfinder(target, timeout)
        return self._run_crtsh(target, timeout)

    def _run_subfinder(self, target: str, timeout: int) -> RawOutput:
        args = [self.binary, "-d", target, "-silent", "-oJ", "-"]
        try:
            _, out, err = self._exec(args, timeout)
        except FileNotFoundError:
            return self._run_crtsh(target, timeout)
        if not out.strip():
            return RawOutput(self.name, False, "", error=err.strip() or "no subdomains found")
        return RawOutput(self.name, True, out)

    def _run_crtsh(self, target: str, timeout: int) -> RawOutput:
        """Query crt.sh certificate transparency logs for subdomains."""
        url = CRTSH_URL.format(quote(target))
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True)
            r.raise_for_status()
            entries = r.json()
        except Exception as e:
            return RawOutput(self.name, False, "", error=f"crt.sh failed: {e}")

        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.endswith(f".{target}") or line == target:
                    subdomains.add(line)

        if not subdomains:
            return RawOutput(self.name, False, "", error="no subdomains found via crt.sh")

        output = "\n".join(sorted(subdomains))
        return RawOutput(self.name, True, output)


def parse_subdomains(raw: str, source: str = "subfinder") -> list[str]:
    """Parse subdomain output (JSON from subfinder, or newline-delimited from crt.sh)."""
    subdomains = set()

    if source == "subfinder":
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                if host:
                    subdomains.add(host.lower())
            except json.JSONDecodeError:
                continue
    else:
        for line in raw.splitlines():
            line = line.strip().lower()
            if line:
                subdomains.add(line)

    return sorted(subdomains)


def resolve_subdomain(subdomain: str) -> str | None:
    """Resolve a subdomain to its IP address. Returns None if unresolvable."""
    try:
        infos = socket.getaddrinfo(subdomain, None)
        return str(infos[0][4][0])
    except (socket.gaierror, IndexError):
        return None


def merge_subdomains(subdomains: list[str], hosts: list[Host]) -> int:
    """Add discovered subdomains as new Host entries with resolved IPs.
    Returns the number of new hosts added."""
    existing_addrs = {h.address.lower() for h in hosts}
    existing_names = {h.hostname.lower() for h in hosts if h.hostname}
    added = 0

    for sub in subdomains:
        if sub in existing_names:
            continue
        ip = resolve_subdomain(sub)
        if not ip:
            log.debug("could not resolve %s — skipping", sub)
            continue
        if ip.lower() in existing_addrs:
            # Subdomain resolves to an already-known host; add hostname alias
            for h in hosts:
                if h.address.lower() == ip.lower() and not h.hostname:
                    h.hostname = sub
                    break
            continue

        hosts.append(Host(address=ip, hostname=sub, services=[]))
        existing_addrs.add(ip.lower())
        existing_names.add(sub)
        added += 1

    return added
