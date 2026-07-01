"""Parse Nmap XML output into the canonical model."""
from __future__ import annotations

from defusedxml import ElementTree as ET

from ..model import Host, Service


def parse_nmap_xml(xml_text: str) -> list[Host]:
    hosts: list[Host] = []
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state", "up") if status is not None else "up"

        address = ""
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr", "")
                break
        if not address:
            mac = h.find("address")
            address = mac.get("addr", "") if mac is not None else "unknown"

        hostname = None
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        os_guess = None
        osm = h.find("os/osmatch")
        if osm is not None:
            os_guess = osm.get("name")

        services: list[Service] = []
        for p in h.findall("ports/port"):
            pstate = p.find("state")
            if pstate is not None and pstate.get("state") != "open":
                continue
            svc_el = p.find("service")
            scripts = {
                s.get("id", "script"): (s.get("output", "") or "").strip()
                for s in p.findall("script")
            }
            services.append(
                Service(
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),
                    state=pstate.get("state", "open") if pstate is not None else "open",
                    service=svc_el.get("name") if svc_el is not None else None,
                    product=svc_el.get("product") if svc_el is not None else None,
                    version=svc_el.get("version") if svc_el is not None else None,
                    extra_info=svc_el.get("extrainfo") if svc_el is not None else None,
                    scripts=scripts,
                )
            )

        hosts.append(
            Host(address=address, hostname=hostname, os_guess=os_guess,
                 state=state, services=services)
        )
    return hosts
