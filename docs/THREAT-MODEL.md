# Threat Model

A short, honest threat model — what Recon Reporter protects, what it assumes, and where its
limits are. Written so a reviewer (or a future you) can reason about trust quickly.

## Actors & assets

| Actor | Interest |
|-------|----------|
| Operator (you) | Run authorized recon, get an accurate report |
| Target system | Should only be scanned with authorization |
| AI provider | Receives structured findings (not raw dumps, not secrets) |

| Asset | Protection |
|-------|-----------|
| Authorization boundary | `scope.yml` allow-list + `--authorized`, enforced before any packet leaves |
| API keys / secrets | Env vars only; never persisted to `runs/` |
| Scan output | Written under git-ignored `runs/`; may contain sensitive data |

## Trust boundaries

1. **Operator → tool:** the tool trusts the operator's scope file as the authorization source
   of truth. It will not scan outside it.
2. **Tool → external tools (nmap, whatweb, sslscan):** their output is parsed defensively; a
   missing/garbled tool degrades to "skipped," never a crash.
3. **Tool → AI provider:** only the *structured model* is sent — no raw banners beyond short
   script snippets, no credentials. With `--local`, nothing leaves the machine at all.
4. **AI → report:** AI output is **not trusted blindly**. Every finding is grounded against
   real scan endpoints; ungrounded findings are flagged, not hidden.

## What this tool is NOT designed to resist

- A malicious operator pointing it at unauthorized targets (the scope gate is a guardrail, not
  a sandbox — the operator controls the machine).
- Network-level interception of scan traffic (use it from a trusted vantage point).
- Adversarial target responses crafted to mislead fingerprinting (treat findings as leads).

## Failure modes & handling

| Failure | Behavior |
|---------|----------|
| Target out of scope | Hard refuse, exit 2 |
| nmap missing | Clear error, exit 3 (or use `--offline`) |
| No network / NVD rate-limited | CVE enrichment returns nothing; report still generated |
| AI provider unreachable | Falls back to a rule-based report |
| AI hallucinates a finding | Grounding marks it "ungrounded — review" |
