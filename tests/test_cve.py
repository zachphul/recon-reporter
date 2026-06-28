"""CVE enrichment tests — CVSS/summary parsing and cache hit. No network."""
from recon_reporter.enrich.cve import CveLookup, _cvss, _summary


def test_cvss_prefers_v31():
    cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                       "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}
    assert _cvss(cve) == 9.8


def test_cvss_falls_back_to_v2():
    assert _cvss({"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}) == 7.5


def test_cvss_missing_is_none():
    assert _cvss({"metrics": {}}) is None
    assert _cvss({}) is None


def test_summary_picks_english():
    cve = {"descriptions": [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": "Buffer overflow in foo."},
    ]}
    assert _summary(cve) == "Buffer overflow in foo."


def test_query_hits_cache_without_network(tmp_path):
    look = CveLookup(cache_path=tmp_path / "cache.json")
    look.cache["openssh|6.6.1"] = [
        {"id": "CVE-2024-0001", "cvss": 7.0, "summary": "x"},
        {"id": "CVE-2024-0002", "cvss": 9.1, "summary": "y"},
    ]
    refs = look._query("OpenSSH", "6.6.1")  # key is lowercased
    assert [r.id for r in refs] == ["CVE-2024-0002", "CVE-2024-0001"]  # sorted by CVSS desc
