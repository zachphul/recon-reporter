"""Generate actionable remediation steps for rule-based findings.

Maps known finding titles to specific, copy-pasteable commands and config changes.
Used as a fallback when the AI analyst is disabled (--no-ai) and as a supplement
when the AI is enabled (merged into its findings)."""
from __future__ import annotations

from .base import RemediationStep

# ---------------------------------------------------------------------------
# Template registry:  title-substring -> list[RemediationStep]
# Each entry is (action, command_or_None, description)
# ---------------------------------------------------------------------------
_TEMPLATES: list[tuple[str, list[tuple[str, str | None, str]]]] = [
    # --- SSH ---
    ("Telnet exposed", [
        ("Disable Telnet and use SSH instead",
         "sudo systemctl stop telnet.socket && sudo systemctl disable telnet.socket",
         "Telnet transmits all data including credentials in cleartext. "
         "Verify SSH is accessible on port 22 before disabling."),
        ("Block Telnet at the firewall",
         "sudo ufw deny 23/tcp",
         "Prevents external connections even if the service is accidentally re-enabled."),
    ]),
    ("Anonymous FTP allowed", [
        ("Disable anonymous FTP access",
         "sudo sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf && sudo systemctl restart vsftpd",
         "After restarting, verify with: ftp localhost and confirm anonymous login is rejected."),
    ]),
    ("Weak/deprecated TLS", [
        ("Disable old TLS versions in Apache",
         "sudo sed -i 's/SSLProtocol.*/SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1/' /etc/apache2/sites-available/default-ssl.conf && sudo systemctl restart apache2",
         "Verify with: nmap --script ssl-enum-ciphers -p 443 <host> — only TLSv1.2+ should appear."),
    ]),
    ("Weak SSH key exchange", [
        ("Update KexAlgorithms in sshd_config",
         "sudo sed -i 's/^#*KexAlgorithms.*/KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
         "Verify with: ssh -vv <host> 2>&1 | grep kex — only strong algorithms should appear."),
    ]),
    ("Weak SSH host key algorithm", [
        ("Remove weak host key algorithms from sshd_config",
         "sudo sed -i 's/^#*HostKeyAlgorithms.*/HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
         "Verify with: nmap --script ssh2-enum-algorithms -p 22 <host>."),
    ]),
    ("Weak SSH cipher", [
        ("Update Ciphers in sshd_config",
         "sudo sed -i 's/^#*Ciphers.*/Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
         "After restart, verify with: ssh -vv <host> 2>&1 | grep cipher."),
    ]),
    ("Weak SSH MAC", [
        ("Update MACs in sshd_config",
         "sudo sed -i 's/^#*MACs.*/MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
         "After restart, verify with: ssh -vv <host> 2>&1 | grep MAC."),
    ]),
    ("Weak SSH RSA key", [
        ("Regenerate SSH host key with sufficient bits",
         "sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' && sudo systemctl restart sshd",
         "Keep the old key as backup. Clients will see a host key change warning on first connect."),
    ]),
    # --- Services ---
    ("VNC remote access exposed", [
        ("Restrict VNC to localhost or VPN",
         "sudo sed -i 's/^#*localhostonly.*/localhostonly=1/' /etc/tigervnc/vncserver.users && sudo systemctl restart vncserver",
         "Alternatively, tunnel VNC through SSH: ssh -L 5900:localhost:5900 user@host"),
    ]),
    ("RDP reachable", [
        ("Enable Network Level Authentication and restrict access",
         "sudo ufw allow from 10.0.0.0/8 to any port 3389 && sudo ufw deny 3389/tcp",
         "Allow only from trusted subnets. For full lockdown, use a VPN gateway."),
    ]),
    ("SMB reachable", [
        ("Restrict SMB to trusted networks",
         "sudo ufw deny 445/tcp",
         "SMB should never be internet-facing. Use VPN for remote file access."),
    ]),
    ("PostgreSQL reachable", [
        ("Bind PostgreSQL to localhost and restrict via pg_hba.conf",
         "sudo sed -i \"s/listen_addresses = '\\*'/listen_addresses = 'localhost'/\" /etc/postgresql/*/main/postgresql.conf && sudo systemctl restart postgresql",
         "Edit pg_hba.conf to allow only specific IPs if remote access is required."),
    ]),
    ("MySQL reachable", [
        ("Bind MySQL to localhost",
         "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf && sudo systemctl restart mysql",
         "Use SSH tunnel for remote database administration."),
    ]),
    ("MongoDB reachable", [
        ("Enable MongoDB authentication and bind to localhost",
         "sudo sed -i 's/^  bindIp:.*/  bindIp: 127.0.0.1/' /etc/mongod.conf && sudo systemctl restart mongod",
         "Also enable --auth and create admin users before exposing to any network."),
    ]),
    ("Redis reachable", [
        ("Bind Redis to localhost and require authentication",
         "sudo sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf && echo 'requirepass YOUR_STRONG_PASSWORD' | sudo tee -a /etc/redis/redis.conf && sudo systemctl restart redis",
         "Never expose Redis to the internet without auth — it can execute arbitrary commands."),
    ]),
    ("Legacy/risky service", [
        ("Disable the legacy service if not required",
         "sudo systemctl stop <service-name> && sudo systemctl disable <service-name>",
         "Replace with a modern, encrypted alternative where possible."),
    ]),
    ("Cleartext protocol", [
        ("Migrate to the encrypted equivalent",
         None,
         "Replace the cleartext protocol (FTP/POP3/IMAP) with its TLS-wrapped version "
         "(FTPS/SFTP, POP3S, IMAPS)."),
    ]),
    ("Large attack surface", [
        ("Audit and disable unnecessary services",
         "sudo ss -tlnp | grep LISTEN",
         "Review each listening service. Disable anything not required for production use."),
    ]),
    ("Version disclosed", [
        ("Suppress version disclosure",
         None,
         "In Apache: set ServerTokens Prod and ServerSignature Off. "
         "In nginx: set server_tokens off. This prevents fingerprinting."),
    ]),
]


def generate_remediation(title: str, detail: str = "") -> list[RemediationStep]:
    """Look up actionable steps for a finding by matching its title against known patterns.

    Returns an empty list if no template matches — callers should fall back to the
    generic `remediation` text in that case."""
    title_lower = title.lower()
    for pattern, steps in _TEMPLATES:
        if pattern.lower() in title_lower:
            return [RemediationStep(action=a, command=c, description=d) for a, c, d in steps]
    return []
