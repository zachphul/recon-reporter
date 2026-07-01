"""The recon pipeline as a pure, testable function — collect → parse → enrich → rules → AI.

Separated from the CLI so it can be unit-tested (offline) and reused (e.g. the MCP server).
The CLI owns the scope gate, file output, and console rendering; the pipeline owns the work.
Side-effecting concerns are injected: `raw_sink` to persist raw tool output, `progress` for
user-facing status. Errors that the CLI must map to exit codes raise `PipelineError`."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from .ai.analyst import get_analyst
from .ai.base import Analysis
from .collectors import tls as tlsmod
from .collectors import whatweb as whatwebmod
from .collectors.default_creds import check_default_creds
from .collectors.http_headers import HttpHeaderCollector
from .collectors.nmap import NmapCollector
from .collectors.subdomains import SubdomainCollector, merge_subdomains, parse_subdomains
from .config import Settings
from .config import settings as default_settings
from .enrich import rules
from .enrich.cve import CveLookup
from .enrich.exploit import ExploitEnricher
from .enrich.risk import calculate_risk
from .logconf import get_logger
from .model import ScanRun
from .parsers.nmap_xml import parse_nmap_xml

log = get_logger(__name__)


class PipelineError(RuntimeError):
    """Raised for conditions the CLI maps to an exit code (e.g. nmap missing/failed)."""


@dataclass
class PipelineResult:
    scan: ScanRun
    analysis: Analysis | None


def _noop_sink(tool: str, raw: str) -> None:
    return None


def _noop_progress(msg: str) -> None:
    return None


def run_pipeline(
    target: str,
    *,
    offline_xml: str | None = None,
    profile: str = "default",
    web: bool = False,
    http: bool = False,
    cve: bool = False,
    insecure: bool = False,
    no_ai: bool = False,
    settings: Settings = default_settings,
    raw_sink: Callable[[str, str], None] = _noop_sink,
    progress: Callable[[str], None] = _noop_progress,
) -> PipelineResult:
    run = ScanRun(target=target, started_at=datetime.now())
    live = offline_xml is None

    # 1) nmap (or replay offline XML)
    if offline_xml is not None:
        xml = offline_xml
        run.tool_versions["nmap"] = "offline"
    else:
        nm = NmapCollector(profile=profile)
        if not nm.available():
            raise PipelineError("nmap not found on PATH (Kali ships it) — or use offline mode.")
        progress(f"Running nmap ({profile})… this can take a few minutes")
        res = nm.run(target)
        if not res.ok:
            raise PipelineError(f"nmap failed: {res.error}")
        xml = res.raw
        run.tool_versions["nmap"] = res.version or "unknown"
    raw_sink("nmap", xml)

    # 2) parse
    run.hosts = parse_nmap_xml(xml)

    # 2b) subdomain enumeration (live only)
    if live:
        progress("Enumerating subdomains…")
        sub_collector = SubdomainCollector()
        sub_result = sub_collector.run(target)
        if sub_result.ok:
            raw_sink("subdomains", sub_result.raw)
            subdomains = parse_subdomains(sub_result.raw, "crt.sh" if not sub_collector.available() else "subfinder")
            added = merge_subdomains(subdomains, run.hosts)
            if added:
                progress(f"Found {len(subdomains)} subdomains, {added} new hosts added")
                run.tool_versions["subdomains"] = sub_collector.name
        else:
            log.info("subdomain enumeration failed or returned no results: %s", sub_result.error)

    # 3) web/TLS collectors (live only) — merge into the model before rules
    if web and live:
        for coll, merge, label in (
            (whatwebmod.WhatWebCollector(), whatwebmod.merge_into_hosts, "whatweb"),
            (tlsmod.TlsCollector(), tlsmod.merge_into_hosts, "sslscan"),
        ):
            if coll.available():
                progress(f"Running {label}…")
                r = coll.run(target)
                if r.ok:
                    raw_sink(label, r.raw)
                    merge(r.raw, run.hosts)
                    run.tool_versions[label] = "present"
                else:
                    log.warning("%s collector failed: %s", label, r.error)
            else:
                log.info("%s not installed — skipping", label)

    # 4) HTTP security-header grading (live only) — produces flags directly
    header_flags = []
    if http and live:
        progress("Grading HTTP security headers…")
        header_flags = HttpHeaderCollector(verify=not insecure).collect(run.hosts)

    # 5) CVE enrichment
    if cve:
        progress("Querying NVD for CVEs… (rate-limited; cached)")
        added = CveLookup(api_key=settings.nvd_api_key).enrich(run.hosts)
        log.info("attached %d CVE reference(s)", added)
        # 5b) prioritize those CVEs by real-world exploitability (CISA KEV + EPSS)
        progress("Prioritizing CVEs by exploitation (CISA KEV + EPSS)…")
        ExploitEnricher().enrich(run.hosts)

    # 6) deterministic rules (after all collectors have contributed)
    run.flags = rules.evaluate(run.hosts) + header_flags

    # 6b) default credential checking (live only)
    if live:
        progress("Checking for default credentials…")
        cred_flags = check_default_creds(run.hosts)
        run.flags.extend(cred_flags)
        if cred_flags:
            log.warning("found %d service(s) with default credentials!", len(cred_flags))

    # 7) risk scoring (after rules and CVE enrichment)
    run.risk_score, run.risk_breakdown = calculate_risk(run)

    # 8) AI analysis (best-effort: failure degrades to a rule-based report)
    analysis: Analysis | None = None
    if not no_ai:
        progress(f"Analyzing with provider: {settings.resolved_provider()}")
        try:
            analysis = get_analyst(settings).analyze(run)
        except Exception as e:  # noqa: BLE001 - degrade, but log the reason
            log.warning("AI analysis failed (%s): %s", type(e).__name__, e)
            progress(f"AI analysis skipped ({type(e).__name__}); writing rule-based report.")

    run.finished_at = datetime.now()
    return PipelineResult(scan=run, analysis=analysis)
