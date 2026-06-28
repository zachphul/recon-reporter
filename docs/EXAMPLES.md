# Examples

Annotated walkthroughs. The committed sample report lives at
[`samples/sample-report.md`](../samples/sample-report.md) (and `.html`, `.sarif.json`).

## 1. First run against the sanctioned practice host

```bash
cp scope.example.yml scope.yml          # scanme.nmap.org is already listed
recon-reporter scan scanme.nmap.org --scope scope.yml --authorized --cve --http
```

What happens, in order:
1. **Scope gate** confirms `scanme.nmap.org` is authorized.
2. **nmap** runs `-sV -sC` against the top 1000 ports.
3. **HTTP headers** are fetched and graded (`--http`).
4. **NVD** is queried for CVEs on disclosed versions (`--cve`).
5. **Rules** flag telnet, weak TLS, outdated software, missing headers, etc.
6. **AI** writes the executive summary, per-finding severity, and remediation — each grounded.
7. Output: `report.md`, `report.html`, `report.sarif.json`, `findings.json`, `raw/`.

## 2. Fast, offline-friendly, no LLM

```bash
recon-reporter scan 127.0.0.1 --scope scope.yml --authorized --no-ai
```
Rule-based findings only. No API key, no provider, no network beyond the scan itself.

## 3. Replay a saved scan (dev / CI / demo)

```bash
recon-reporter scan demo --offline tests/fixtures/sample_nmap.xml --no-scope-check --no-ai
```
Drives the whole pipeline off a saved nmap XML — how the test suite exercises everything.

## 4. Track an asset over time

```bash
recon-reporter scan host --scope scope.yml --authorized --out runs   # week 1
# ... a week later ...
recon-reporter scan host --scope scope.yml --authorized --out runs   # week 2
recon-reporter diff runs/host-<week1>/findings.json runs/host-<week2>/findings.json
```
Reports newly open/closed ports, changed services, and new rule flags.

## 5. Feed a CI security gate (SARIF)

Every run writes `report.sarif.json`. Upload it to GitHub code scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: runs/host-latest/report.sarif.json
```

## Sample finding (from the bundled fixture)

```
### 1. Telnet exposed — 🟠 HIGH
- Affected: 45.33.32.156:23
- Why it matters: Telnet transmits credentials in cleartext.
- Remediation: Disable telnetd; use SSH.
- Evidence: open telnet service on port 23
```
