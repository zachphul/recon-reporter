"""Compare two saved runs (findings.json) and report what changed — new/closed ports,
new services, new rule flags. Useful for monitoring an asset over time."""
from __future__ import annotations

from pathlib import Path

from .model import ScanRun


def load_run(path: str | Path) -> ScanRun:
    return ScanRun.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _endpoints(run: ScanRun) -> dict[str, str]:
    """host:port -> service label."""
    out: dict[str, str] = {}
    for h in run.hosts:
        for s in h.services:
            out[f"{h.address}:{s.port}"] = s.label or (s.service or "?")
    return out


def diff_runs(old: ScanRun, new: ScanRun) -> dict:
    eo, en = _endpoints(old), _endpoints(new)
    opened = sorted(set(en) - set(eo))
    closed = sorted(set(eo) - set(en))
    changed = sorted(k for k in set(eo) & set(en) if eo[k] != en[k])
    fo = {(f.title, f.host, f.port) for f in old.flags}
    fn = {(f.title, f.host, f.port) for f in new.flags}
    new_flags = sorted(t for (t, _, _) in (fn - fo))
    return {
        "target": new.target,
        "opened": [{"endpoint": k, "service": en[k]} for k in opened],
        "closed": [{"endpoint": k, "service": eo[k]} for k in closed],
        "changed": [{"endpoint": k, "from": eo[k], "to": en[k]} for k in changed],
        "new_flags": new_flags,
    }


def render_markdown(d: dict) -> str:
    out = [f"# Scan diff — {d['target']}\n"]
    out.append(f"- **Newly open:** {len(d['opened'])}")
    out.append(f"- **Newly closed:** {len(d['closed'])}")
    out.append(f"- **Changed service:** {len(d['changed'])}")
    out.append(f"- **New rule flags:** {len(d['new_flags'])}\n")
    if d["opened"]:
        out.append("## 🔺 Newly open")
        out += [f"- `{x['endpoint']}` — {x['service']}" for x in d["opened"]]
    if d["closed"]:
        out.append("\n## 🔻 Newly closed")
        out += [f"- `{x['endpoint']}` — {x['service']}" for x in d["closed"]]
    if d["changed"]:
        out.append("\n## 🔁 Changed service")
        out += [f"- `{x['endpoint']}`: {x['from']} → {x['to']}" for x in d["changed"]]
    if d["new_flags"]:
        out.append("\n## 🚩 New rule flags")
        out += [f"- {t}" for t in d["new_flags"]]
    if not any([d["opened"], d["closed"], d["changed"], d["new_flags"]]):
        out.append("\n_No changes detected._")
    return "\n".join(out)
