"""
MitigationAgent — Actionable Remediation Generation.

Generates precise, actionable mitigation playbooks based on the critical
and high vulnerabilities identified during the pentest.
Outputs a human-readable Markdown guide and an executable Bash script
that an administrator can push to the target machine.

Output: 
  - reports/{mission_id}/mitigation_playbook.md
  - reports/{mission_id}/mitigation_playbook.yml
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory

_log = logging.getLogger(__name__)


class MitigationAgent(BaseAgent):
    """
    Creates actionable mitigation playbooks (Markdown + Bash script) 
    for administrators to fix the vulnerabilities found.
    """

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="MitigationAgent",
            mission_memory=mission_memory,
            llm_role="reasoning",  # DeepSeek-R1 for complex remediation logic
            max_react_iterations=1,
        )
        self.console = Console()
        self.target = ""
        self.report_dir = Path("reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.mission_id = ""

    def run(self, target: str, briefing: dict = {}) -> dict:
        """
        Generate mitigation playbooks.
        
        Args:
            target: Target IP/hostname
            briefing: Briefing from orchestrator
        """
        self.target = target
        self.mission_id = self.memory.mission_id
        
        self.console.print(Panel(
            f"[bold green]🛡️ MitigationAgent — Playbook Generation[/]\n"
            f"[white]Target:[/] [blue]{target}[/]\n"
            f"[white]Mission ID:[/] {self.mission_id}\n"
            f"[white]Output:[/] Markdown + Ansible Playbook (YAML)",
            border_style="green",
        ))

        try:
            self.log_info("Extracting actionable vulnerabilities...")
            target_vulns = self._extract_critical_vulns()
            
            if not target_vulns:
                self.log_info("No critical/high vulnerabilities found to mitigate. Writing empty playbook.")
                self._write_empty_playbooks()
                return {"success": True, "mitigations_generated": 0}

            self.log_info(f"Generating mitigation playbooks for {len(target_vulns)} vulnerabilities...")
            playbooks = self._generate_playbooks(target_vulns)
            
            self._save_playbooks(playbooks)
            
            return {
                "success": True, 
                "mitigations_generated": len(target_vulns),
                "playbook_md": f"reports/{self.mission_id}/mitigation_playbook.md",
                "playbook_yml": f"reports/{self.mission_id}/mitigation_playbook.yml",
            }

        except Exception as e:
            self.log_error(f"MitigationAgent failed: {e}")
            import traceback
            self.log_error(traceback.format_exc())
            return {
                "agent": self.agent_name,
                "success": False,
                "error": str(e),
            }

    def _extract_critical_vulns(self) -> list[dict]:
        """Extract Critical and High vulnerabilities from MissionMemory."""
        state = self.memory.state
        target_vulns = []
        
        hosts = state.get("hosts", {})
        for ip, host_data in hosts.items():
            for vuln in host_data.get("vulnerabilities", []):
                cvss = vuln.get("cvss", 0) or 0
                sev = self._cvss_to_severity(cvss)
                if sev in ("critical", "high"):
                    vuln["ip"] = ip
                    target_vulns.append(vuln)
                    
        return sorted(target_vulns, key=lambda x: x.get("cvss", 0) or 0, reverse=True)

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity."""
        try:
            score = float(score)
            if score >= 9.0: return "critical"
            if score >= 7.0: return "high"
            if score >= 4.0: return "medium"
            if score > 0.0: return "low"
            return "info"
        except (ValueError, TypeError):
            return "info"

    def _generate_playbooks(self, vulns: list[dict]) -> dict[str, str]:
        """Use LLM to generate Markdown and Bash playbooks for the vulnerabilities."""
        
        vuln_context = []
        for v in vulns[:10]: # Cap at top 10 to avoid token limits
            vuln_context.append(
                f"- CVE: {v.get('cve', 'Unknown')}\n"
                f"  Service: {v.get('service', 'Unknown')} (Port {v.get('port', 'Unknown')})\n"
                f"  CVSS: {v.get('cvss', 0)}\n"
                f"  Issue: {v.get('description', '')}\n"
            )
            
        vuln_text = "\n".join(vuln_context)
        
        prompt = f"""You are an expert Linux System Administrator and Security Engineer.
Create a detailed mitigation playbook for the following vulnerabilities found on target {self.target}.

VULNERABILITIES:
{vuln_text}

Provide your response in TWO SECTIONS EXACTLY as formatted below.

==================== MARKDOWN GUIDE ====================
(Provide a professional markdown guide here explaining the risks and step-by-step mitigations)

==================== ANSIBLE PLAYBOOK ====================
(Provide an executable Ansible Playbook in YAML format here that applies the mitigations automatically. Assume Debian/Ubuntu based system for package managers. Use standard ansible modules like apt, service, lineinfile, ufw)
"""
        
        self.log_info("Querying LLM for remediation playbooks...")
        raw_response = self._llm_with_timeout(prompt, timeout=120)
        
        md_content = ""
        sh_content = ""
        
        if raw_response:
            # Parse sections
            import re
            
            md_match = re.search(r'={10,}\s*MARKDOWN GUIDE\s*={10,}(.*?)(?:={10,}\s*ANSIBLE PLAYBOOK\s*={10,}|$)', raw_response, re.DOTALL | re.IGNORECASE)
            yml_match = re.search(r'={10,}\s*ANSIBLE PLAYBOOK\s*={10,}(.*)', raw_response, re.DOTALL | re.IGNORECASE)
            
            if md_match:
                md_content = md_match.group(1).strip()
            if yml_match:
                sh_content = yml_match.group(1).strip()
                # Remove markdown code blocks if LLM added them
                sh_content = re.sub(r'^```yaml|^```yml|^```', '', sh_content, flags=re.MULTILINE)
                
        # Fallback if parsing fails or LLM timeouts
        if not md_content or not sh_content:
            self.log_warning("LLM playbook generation failed or returned invalid format. Using deterministic fallback.")
            return self._generate_fallback_playbook(vulns)
            
        return {
            "markdown": md_content,
            "yaml": sh_content
        }

    def _generate_fallback_playbook(self, vulns: list[dict]) -> dict[str, str]:
        """Deterministic fallback if LLM fails."""
        md = f"# Mitigation Playbook for {self.target}\n\n"
        yml = f"---\n- name: Mitigation Playbook for {self.target}\n  hosts: all\n  become: yes\n  tasks:\n"
        
        for v in vulns:
            service = v.get("service", "").lower()
            port = str(v.get("port", ""))
            cve = v.get("cve", "Unknown")
            
            md += f"## Fix {service} (Port {port}) - {cve}\n"
            md += f"**Issue**: {v.get('description', '')}\n"
            
            if "ftp" in service or "vsftpd" in service:
                md += "**Action**: Update vsftpd and restart service.\n\n"
                yml += f"    - name: Update vsftpd\n      apt:\n        name: vsftpd\n        state: latest\n        update_cache: yes\n"
                yml += f"    - name: Restart vsftpd\n      service:\n        name: vsftpd\n        state: restarted\n"
            elif "smb" in service or "samba" in service:
                md += "**Action**: Update Samba and disable SMBv1.\n\n"
                yml += f"    - name: Update Samba\n      apt:\n        name: samba\n        state: latest\n        update_cache: yes\n"
                yml += f"    - name: Disable SMBv1 in smb.conf\n      lineinfile:\n        path: /etc/samba/smb.conf\n        insertafter: '^\\[global\\]'\n        line: '   min protocol = SMB2'\n"
                yml += f"    - name: Restart smbd\n      service:\n        name: smbd\n        state: restarted\n"
            elif "ssh" in service:
                md += "**Action**: Disable password authentication in SSH.\n\n"
                yml += f"    - name: Hardening SSH PasswordAuthentication\n      lineinfile:\n        path: /etc/ssh/sshd_config\n        regexp: '^#?PasswordAuthentication'\n        line: 'PasswordAuthentication no'\n"
                yml += f"    - name: Restart sshd\n      service:\n        name: sshd\n        state: restarted\n"
            else:
                md += f"**Action**: Restrict access to port {port} using firewall.\n\n"
                if port and port.isdigit():
                    yml += f"    - name: Deny port {port} using ufw\n      ufw:\n        rule: deny\n        port: '{port}'\n"
                    
        return {"markdown": md, "yaml": yml}

    def _save_playbooks(self, playbooks: dict[str, str]):
        """Save the generated playbooks to the reports directory."""
        mission_dir = self.report_dir / self.mission_id
        mission_dir.mkdir(parents=True, exist_ok=True)
        
        md_path = mission_dir / "mitigation_playbook.md"
        yml_path = mission_dir / "mitigation_playbook.yml"
        
        # Add headers
        md_content = f"# Autonomous Mitigation Playbook\n**Target**: {self.target}\n**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        md_content += playbooks.get("markdown", "")
        
        yml_content = playbooks.get("yaml", "")
        if not yml_content.startswith("---"):
            yml_content = "---\n" + yml_content
            
        with open(md_path, "w") as f:
            f.write(md_content)
            
        with open(yml_path, "w") as f:
            f.write(yml_content)
            
        self.log_success(f"Saved Markdown playbook: {md_path}")
        self.log_success(f"Saved Ansible playbook: {yml_path}")

    def _write_empty_playbooks(self):
        """Write empty playbooks if no vulnerabilities were found."""
        mission_dir = self.report_dir / self.mission_id
        mission_dir.mkdir(parents=True, exist_ok=True)
        
        with open(mission_dir / "mitigation_playbook.md", "w") as f:
            f.write("# Autonomous Mitigation Playbook\n\nNo critical or high vulnerabilities were discovered during this assessment. No mitigations are required.")
            
        with open(mission_dir / "mitigation_playbook.yml", "w") as f:
            f.write("---\n# No critical vulnerabilities to mitigate.\n- hosts: all\n  tasks: []\n")

    def _llm_with_timeout(self, prompt: str, timeout: int = 60) -> str:
        """Call LLM with a strict timeout."""
        import concurrent.futures
        
        def _call():
            try:
                response = self.llm.invoke(prompt)
                return response.content if hasattr(response, "content") else str(response)
            except Exception as e:
                self.log_warning(f"LLM call error: {e}")
                return ""
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_call)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                self.log_warning(f"LLM call timed out after {timeout} seconds.")
                return ""
