# Security & Responsible Use

Recon Reporter is an **active reconnaissance** tool. Used wrongly it can be illegal and
harmful. Used responsibly it's a defender's and a learner's tool. Read this before running it.

## Authorized use only

- Only scan systems you **own** or have **explicit written permission** to test.
- The tool enforces a scope file (`scope.yml`) and refuses any target not listed. There is
  no override for a live scan — by design.
- Sanctioned practice targets: [`scanme.nmap.org`](http://scanme.nmap.org), your own lab VMs,
  [DVWA](https://github.com/digininja/DVWA), [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).
- Unauthorized scanning may violate the U.S. Computer Fraud and Abuse Act and equivalent laws
  elsewhere. **You are solely responsible for how you use this tool.**

## What it does / does not do

- **Does:** enumerate services, grade configuration (TLS, HTTP headers), match versions to
  potential CVEs, and summarize — read-only observation.
- **Does NOT:** exploit, brute-force, or alter target systems. Findings are *observations to
  verify*, not confirmed vulnerabilities.

## Handling output

- `runs/` may contain sensitive recon data; it is git-ignored by default. Don't commit it.
- API keys come from environment variables only and are never written to run output.

## Reporting a vulnerability in this tool

If you find a security issue in Recon Reporter itself, open a private report rather than a
public issue, and allow reasonable time to fix before disclosure.
