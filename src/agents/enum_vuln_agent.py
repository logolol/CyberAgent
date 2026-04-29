"""
EnumVulnAgent — combined active enumeration and vulnerability detection.

This agent reads Recon findings from MissionMemory, runs iterative LLM+RAG
reasoning loops, executes adaptive tool batches through DynamicToolManager,
and stores confirmed findings back into MissionMemory.
"""
from __future__ import annotations

import concurrent.futures
import concurrent.futures.thread
import json
import os
import re
import subprocess
import sys
import threading
import weakref
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.table import Table

# ── Path bootstrap ────────────────────────────────────────────────────────────
_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class _DaemonThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    """ThreadPoolExecutor variant whose workers are daemonized."""

    def _adjust_thread_count(self):
        if self._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            worker = threading.Thread(
                name=thread_name,
                target=concurrent.futures.thread._worker,
                args=(
                    weakref.ref(self, weakref_cb),
                    self._work_queue,
                    self._initializer,
                    self._initargs,
                ),
            )
            worker.daemon = True
            worker.start()
            self._threads.add(worker)
            concurrent.futures.thread._threads_queues[worker] = self._work_queue


def _is_executable(path: str | Path | None) -> bool:
    """
    Return True only if the file is reachable and executable by current user.
    """
    try:
        if not path:
            return False
        os.stat(path)
        return os.access(path, os.X_OK)
    except (PermissionError, OSError, TypeError):
        return False


class EnumVulnAgent(BaseAgent):
    """
    Active enumeration + vulnerability detection agent.

    Reads ReconAgent findings from MissionMemory.
    Uses LLM + RAG + MITRE to plan and adapt enumeration.
    Runs tools in parallel waves (ThreadPoolExecutor).
    Classifies vulnerabilities by CVSS severity.
    Writes confirmed findings to MissionMemory.
    """

    MAX_CONCURRENT = 4
    MAX_ITERATIONS = 8

    TOOL_TIMEOUTS = {
        "port_scan_fast": 120,
        "port_scan_full": 300,
        "port_scan_udp": 180,
        "service_detect": 120,
        "web_tech_detect": 60,
        "dir_enum": 180,
        "vhost_enum": 90,
        "web_vuln_scan": 300,
        "smb_enum": 60,
        "ftp_enum": 30,
        "ssh_enum": 30,
        "smtp_enum": 30,
        "dns_zone_xfer": 20,
        "mysql_enum": 30,
        "ldap_enum": 60,
        "nuclei_scan": 300,
        "vuln_script_scan": 180,
        "ssl_scan": 60,
        "default_creds": 120,
        "firewall_detect": 30,
    }
    DEFAULT_TIMEOUT = 120

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="EnumVulnAgent",
            mission_memory=mission_memory,
            llm_role="default",
            max_react_iterations=self.MAX_ITERATIONS,
        )
        self.target = mission_memory.target
        self.recon_findings: dict[str, Any] = {}
        self.attack_surface: dict[str, Any] = {}
        self.all_results: dict[str, str] = {}
        self.vulnerabilities: list[dict[str, Any]] = []
        self.iteration = 0
        self.done = False
        self.briefing: dict[str, Any] = {}
        self._completed_tools: set[str] = set()
        self._firewall_detected: bool = False
        self.intelligence_log: list[dict[str, Any]] = []
        self._security_controls: dict[str, Any] = {}
        self.force_llm_only = os.getenv("CA_FORCE_LLM_ONLY", "0").strip().lower() in {
            "1", "true", "yes", "on"
        }
        if not self.force_llm_only:
            self.allow_deterministic_fallback = True

        # Warm the model NOW — before any agent logic runs
        # This ensures subsequent LLM calls find model already in RAM
        from utils.llm_factory import warm_model
        self.log_info("Pre-warming Qwen2.5:7b for enumeration...")
        warm_model(role="default")
    
    # ── Version-aware CVE filtering helpers ──────────────────────────────────────
    
    def _parse_version(self, version_string: str) -> tuple[int, int, int] | None:
        """
        Parse version string into (major, minor, patch) tuple.
        Returns None if parsing fails.
        
        Examples:
            "Apache 2.4.29" → (2, 4, 29)
            "vsftpd 2.3.4" → (2, 3, 4)
            "Samba 3.0.20" → (3, 0, 20)
        """
        try:
            # Extract version numbers from string
            match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_string)
            if match:
                return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
            
            # Try shorter format (major.minor)
            match = re.search(r'(\d+)\.(\d+)', version_string)
            if match:
                return (int(match.group(1)), int(match.group(2)), 0)
            
            return None
        except Exception:
            return None
    
    def _version_matches(self, detected_version: str, cve_affected: str) -> bool:
        """
        Check if detected service version matches CVE's affected range.
        
        Simple heuristic:
        - Exact version match (e.g., "2.4.29" in "2.4.29")
        - Major.minor match (e.g., "2.4.x" matches "2.4.29")
        - Range check if brackets present (e.g., "(2.4.20-2.4.29)")
        
        Args:
            detected_version: Version from service scan (e.g., "Apache 2.4.29")
            cve_affected: Affected versions from CVE (e.g., "2.4.20-2.4.29" or "2.4.x")
        
        Returns:
            True if versions match, False otherwise
        """
        if not detected_version or not cve_affected:
            return True  # Can't filter without data, keep it
        
        # Parse detected version
        detected_parsed = self._parse_version(detected_version)
        if not detected_parsed:
            return True  # Can't parse, keep it
        
        detected_major, detected_minor, detected_patch = detected_parsed
        
        # Exact version match
        if f"{detected_major}.{detected_minor}.{detected_patch}" in cve_affected:
            return True
        if f"{detected_major}.{detected_minor}" in cve_affected:
            return True
        
        # Major.minor.x wildcard match
        if f"{detected_major}.{detected_minor}.x" in cve_affected.lower():
            return True
        
        # Range match (e.g., "2.4.20-2.4.50")
        range_match = re.search(
            r'(\d+)\.(\d+)\.(\d+)\s*-\s*(\d+)\.(\d+)\.(\d+)',
            cve_affected
        )
        if range_match:
            start_major, start_minor, start_patch = int(range_match.group(1)), int(range_match.group(2)), int(range_match.group(3))
            end_major, end_minor, end_patch = int(range_match.group(4)), int(range_match.group(5)), int(range_match.group(6))
            
            # Check if detected version is within range
            detected_tuple = (detected_major, detected_minor, detected_patch)
            start_tuple = (start_major, start_minor, start_patch)
            end_tuple = (end_major, end_minor, end_patch)
            
            if start_tuple <= detected_tuple <= end_tuple:
                return True
        
        # No match found
        return False
    
    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, target: str, briefing: dict = {}) -> dict:
        self.target = target
        # Keep parity with agents that expose resolved_ip for placeholder rendering
        self.resolved_ip = self._normalize_host_ip(target)
        self.briefing = briefing or {}
        self.recon_findings = {}
        self.attack_surface = {}
        self.all_results = {}
        self.vulnerabilities = []
        self.iteration = 0
        self.done = False
        self._completed_tools = set()
        self._llm_failures = 0  # Track consecutive LLM failures

        self.console.print(Panel(
            f"[bold cyan]🔎 EnumVulnAgent — Active Enum + Vuln Detection[/]\n"
            f"[white]Target:[/] [cyan]{target}[/]\n"
            f"[white]Model:[/] Qwen2.5:7b | [white]RAG:[/] 147K docs\n"
            f"[white]Strategy:[/] LLM-first dynamic enumeration",
            border_style="cyan",
        ))

        try:
            # Stage 1: load reconnaissance context (no LLM loop)
            self.recon_findings = self._load_recon_findings(briefing=self.briefing)
            self.attack_surface = self.recon_findings.get("hosts", {})
            self.log_info(
                f"Loaded reconnaissance context: {len(self.attack_surface)} host(s), "
                f"{len(self.recon_findings.get('osint_context', []))} mission context item(s)"
            )
            
            # ══════════════════════════════════════════════════════════════
            # COG04: Check if ports already known - skip full port scan
            # ══════════════════════════════════════════════════════════════
            known_ports = self._extract_known_ports(briefing)
            port_scan_done = len(known_ports) > 0
            
            if port_scan_done:
                self.log_info(f"[COG04] Using {len(known_ports)} pre-discovered ports (skipping -p- scan)")
                # Pre-populate findings from briefing
                for port_info in known_ports:
                    self.all_results[f"port_{port_info.get('port', 0)}"] = port_info

            # Stage 2: deterministic baseline first (ports/services/vuln scans)
            self._run_gather_phase()

            # Stage 3: LLM refinement loop only when deterministic evidence is weak
            if self.force_llm_only or not self._should_skip_llm_enum_loop():
                initial_plan = self._plan_initial_attack()
                self._enumeration_loop(initial_plan)
            else:
                self.log_info(
                    "Deterministic gather produced strong evidence — "
                    "skipping noisy LLM tool-planning loop"
                )
            self._llm_failures = 0 if self.all_results else 1
            analysis = self._run_analysis_phase()

            # Stage 4: compile + store final findings
            findings = self._compile_vuln_report(analysis)
            self._write_findings_to_memory(findings)
            return findings

        except Exception as e:
            self.log_error(f"EnumVulnAgent failed: {e}")
            return {
                "agent": "EnumVulnAgent",
                "success": False,
                "error": str(e),
                "result": {
                    "target": self.target,
                    "ports_found": self._extract_all_ports(),
                    "services_found": len(self._extract_all_services()),
                    "services": self._extract_all_services(),
                    "vulnerabilities": self.vulnerabilities,
                    "exploitable_vulns": len([v for v in self.vulnerabilities if v.get("exploitable")]),
                    "critical_path": {},
                    "all_attack_vectors": [],
                    "security_controls": self._security_controls,
                    "intelligence_log": self.intelligence_log,
                    "mitre_attack_chain": list(self.memory.state.get("mitre_techniques", [])),
                    "tools_used": list(self.all_results.keys()),
                },
                "raw_outputs": self.all_results,
            }
    
    def _build_enum_task(self, context: dict) -> str:
        """Build a concise task description for ReAct enumeration loop."""
        hosts = context.get("hosts", {})
        host_summary = ", ".join(list(hosts.keys())[:5])
        
        return f"""Enumerate services and find vulnerabilities on {context['target']}.

KNOWN HOSTS: {host_summary or context['target']}

AVAILABLE ACTIONS:
- nmap: Port scan with service detection
- nuclei: Vulnerability scanner
- nikto: Web vulnerability scanner
- enum4linux: SMB/Windows enumeration
- gobuster: Directory brute-forcing

GOAL: Find open ports, identify services, detect vulnerabilities.
For each vulnerability, determine if it's exploitable.
When you have enough findings, return FINAL_ANSWER with vulnerabilities list."""

    # ── Stage 1: mission briefing ─────────────────────────────────────────────
    
    def _extract_known_ports(self, briefing: dict | None) -> list[dict]:
        """
        COG04: Extract already-discovered ports from briefing/memory.
        
        This prevents redundant full port scans when ports are already known
        from a previous recon phase.
        
        Returns:
            List of port dicts: [{"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}, ...]
        """
        known_ports = []
        
        # From MissionMemory hosts
        if hasattr(self.memory, '_state'):
            hosts = self.memory._state.get("hosts", {})
            for ip, host_data in hosts.items():
                if isinstance(host_data, dict):
                    for port_info in host_data.get("ports", []):
                        if isinstance(port_info, dict) and port_info.get("port"):
                            known_ports.append({
                                "port": port_info.get("port"),
                                "service": port_info.get("service", "unknown"),
                                "version": port_info.get("version", ""),
                                "ip": ip,
                            })
        
        # From briefing (orchestrator may pass pre-discovered ports)
        if isinstance(briefing, dict):
            briefing_ports = briefing.get("open_ports", [])
            if isinstance(briefing_ports, list):
                for port_info in briefing_ports:
                    if isinstance(port_info, dict) and port_info.get("port"):
                        known_ports.append(port_info)
            
            # Also check known_info structure
            known_info = briefing.get("known_info", {})
            if isinstance(known_info, dict):
                for port_info in known_info.get("ports", []):
                    if isinstance(port_info, dict) and port_info.get("port"):
                        known_ports.append(port_info)
        
        # Deduplicate by port number
        seen_ports = set()
        unique_ports = []
        for p in known_ports:
            port_num = p.get("port")
            if port_num and port_num not in seen_ports:
                seen_ports.add(port_num)
                unique_ports.append(p)
        
        return unique_ports

    def _load_recon_findings(self, briefing: dict | None = None) -> dict[str, Any]:
        """
        Reads MissionMemory state + mission Chroma context and builds attack surface.
        """
        state = self.memory.state
        hosts = state.get("hosts", {})
        mission_context: list[dict[str, Any]] = []

        try:
            mission_context = self.chroma.get_mission_context(
                mission_id=self.memory.mission_id,
                query=f"technologies services enumeration {self.target}",
                n=10,
            )
        except Exception as e:
            self.log_warning(f"Mission context query failed: {e}")

        attack_surface: dict[str, dict[str, Any]] = {}
        for ip, host_data in hosts.items():
            host_ports = host_data.get("ports", []) or []
            inferred_services = {
                str(p.get("port", "")): {
                    "service": p.get("service", "unknown"),
                    "version": p.get("version", ""),
                    "banner": p.get("banner", ""),
                }
                for p in host_ports
                if isinstance(p, dict)
            }
            attack_surface[ip] = {
                "hostname": host_data.get("hostname", ip),
                "os_guess": host_data.get("os", "unknown"),
                "ports": host_ports,
                "technologies": host_data.get("technologies", []),
                "services": inferred_services,
                "vulnerabilities": host_data.get("vulnerabilities", []),
            }

        chain = state.get("attack_chain", [])
        tech_findings = [
            a for a in chain
            if "technology" in str(a.get("action", "")).lower()
        ]

        if not attack_surface and briefing:
            known_info = briefing.get("known_info", {}) if isinstance(briefing, dict) else {}
            briefing_techs = known_info.get("technologies", [])
            attack_surface[self.target] = {
                "hostname": self.target,
                "os_guess": known_info.get("os", "unknown"),
                "ports": known_info.get("ports", []),
                "technologies": briefing_techs if isinstance(briefing_techs, list) else [],
                "services": {},
                "vulnerabilities": [],
            }

        return {
            "hosts": attack_surface,
            "tech_findings": tech_findings,
            "osint_context": mission_context,
            "target_count": len(attack_surface),
        }

    # ── Stage 2: gather (zero LLM routing) ────────────────────────────────────

    def _run_gather_phase(self):
        """
        Run deterministic tool waves without iterative LLM planning.
        """
        self.log_info("Starting gather phase — running tools without LLM planning")

        # Wave 1: broad port/service discovery first.
        port_scanner = self.tools.find("nmap") or self.tools.find("masscan") or self.tools.find("rustscan")
        if not port_scanner:
            self.log_warning("No port scanner available — skipping wave 1")
        else:
            scanner_name = Path(port_scanner).name
            if scanner_name == "nmap":
                # IMPORTANT: nmap -p overrides --top-ports, so we must use -p alone
                # Comprehensive port list: common services + backdoor ports
                # This covers top 1000 equivalent + critical backdoor ports
                SCAN_PORTS = (
                    "1-1024,"  # Well-known ports (includes most top-1000)
                    "1099,1433,1521,1524,2049,2121,3306,3389,3632,"  # DB/services/backdoors
                    "5432,5900,5985,6000,6667,6697,8009,8080,8180,8443,8787,"  # More services
                    "9000,9090,9200,31337,4444,5555"  # Common backdoors
                )
                wave1_args = [
                    self.target, "-sV", "-sC",
                    "-p", SCAN_PORTS,
                    "-T4", "--open"
                ]
            elif scanner_name == "masscan":
                wave1_args = [self.target, "-p1-1024,1099,1524,2049,3306,3632,5432,5900,6667,8180,31337", "--rate", "1000"]
            elif scanner_name == "rustscan":
                wave1_args = ["-a", self.target, "--ulimit", "5000", "--", "-sV", "-sC", "--open"]
            else:
                wave1_args = [self.target]

            wave1_specs = [{
                "tool_hint": scanner_name,
                "purpose": "discover open ports and service versions",
                "_resolved_args": wave1_args,
                "_timeout": 180,
            }]
            wave1_results = self._run_tool_batch(wave1_specs)
            self.all_results.update(wave1_results)
            self.log_success(f"Wave 1 complete: {len(wave1_results)} result(s)")
            self._update_intelligence_log(1, wave1_results, {})

        # Security control analysis: reason about wave 1 outputs before wave 2
        self._analyze_security_controls()

        # Wave 2: Deterministic service probing based on discovered ports.
        # Uses _build_wave2_from_ports() which maps services → tools without LLM.
        # This avoids 300s LLM timeout that blocks the entire pipeline.
        try:
            port_services = self._extract_port_services()
            if port_services:
                self.log_info(f"Wave 2: deterministic service probing for {len(port_services)} ports")
                wave2_specs = self._build_wave2_from_ports()
            else:
                wave2_specs = []
            if wave2_specs:
                wave2_results = self._run_tool_batch(wave2_specs)
                self.all_results.update(wave2_results)
                self.log_success(f"Wave 2 complete: {len(wave2_results)} result(s)")
                self._update_intelligence_log(2, wave2_results, {})
            else:
                self.log_info("Wave 2 skipped: no specs generated")
        except PermissionError as e:
            self.log_warning(f"Wave 2: permission denied on tool — {e}")
            self.log_warning("Continuing to wave 3 with wave 1 data")
        except Exception as e:
            self.log_warning(f"Wave 2 failed: {e} — continuing")

        # Wave 3: vulnerability-oriented scans.
        try:
            wave3_specs = self._build_wave3_vuln_scan()
            if wave3_specs:
                wave3_results = self._run_tool_batch(wave3_specs)
                self.all_results.update(wave3_results)
                self.log_success(f"Wave 3 complete: {len(wave3_results)} result(s)")
                self._update_intelligence_log(3, wave3_results, {})
            else:
                self.log_info("Wave 3 skipped: no scanners available")
        except Exception as e:
            self.log_warning(f"Wave 3 failed: {e} — proceeding to analysis")

        self.log_success(f"Gather phase complete: {len(self.all_results)} total tool output(s)")

    def _analyze_security_controls(self) -> dict:
        """
        Detect security controls from wave 1 output.
        Pure regex — no LLM, instant, always works.
        """
        all_output = "\n".join(
            str(v) for v in self.all_results.values()
        )
        
        controls = {
            "firewall": None,
            "ids": None,
            "waf": None,
            "evasion_needed": False,
            "scan_adjustments": ""
        }
        
        # Evidence-based detection only
        filtered_count = len(re.findall(
            r'filtered', all_output, re.IGNORECASE
        ))
        reset_count = len(re.findall(r'RST|reset', all_output))
        
        if filtered_count > 5:
            controls["firewall"] = "packet_filtering"
            controls["evasion_needed"] = True
            controls["scan_adjustments"] = "-T2 --scan-delay 1s"
        
        if re.search(r'WAF|Web Application Firewall|403.*unusual',
                      all_output, re.IGNORECASE):
            controls["waf"] = "detected"
            controls["evasion_needed"] = True
        
        # Log what was found
        for k, v in controls.items():
            if v and k not in ["evasion_needed", "scan_adjustments"]:
                self.memory.log_action(
                    "EnumVulnAgent",
                    "security_control_detected",
                    f"{k}={v}"
                )
        
        self._security_controls = controls
        self.log_info(
            f"Security controls: firewall={controls['firewall']} "
            f"waf={controls['waf']} "
            f"evasion={controls['evasion_needed']}"
        )
        return controls

    def _extract_anomaly_patterns(self) -> str:
        """
        Extracts observable anomalies from tool outputs.
        Used to build a meaningful RAG query about security controls.
        Pure regex — no LLM, no assumptions.
        """
        patterns_found = []
        all_output = "\n".join(str(v) for v in self.all_results.values())

        if re.search(r"filtered", all_output, re.IGNORECASE):
            patterns_found.append("port_filtered")
        if re.search(r"reset|RST", all_output):
            patterns_found.append("connection_reset")
        if re.search(r"403|406|429", all_output):
            patterns_found.append("http_blocked")
        if re.search(r"timeout", all_output, re.IGNORECASE):
            patterns_found.append("scan_timeout")

        return " ".join(patterns_found) if patterns_found else "standard_responses"

    def _build_wave2_from_ports(self) -> list[dict[str, Any]]:
        """
        Build service-probing specs by regex parsing open ports from current outputs.
        Uses the RIGHT tool for each service — not just nmap.
        No LLM needed — deterministic service-to-tool mapping.
        """
        import os
        
        open_ports: dict[int, str] = {}
        for output in self.all_results.values():
            for match in re.finditer(
                r"(\d{1,5})/(tcp|udp)\s+open(?:\|filtered)?\s+([^\s]+)",
                str(output),
            ):
                try:
                    port = int(match.group(1))
                except Exception:
                    continue
                service = str(match.group(3)).strip().lower()
                if 1 <= port <= 65535:
                    open_ports[port] = service
        
        if not open_ports:
            return []
        
        self.log_info(
            f"Wave 2 planning from ports: "
            f"{sorted(list(open_ports.keys()))[:15]}"
        )
        
        # Service-to-tool mapping — deterministic, no LLM
        # Each entry: (service_keywords, tool, args_fn, timeout)
        SERVICE_TOOLS = [
            # SMB/NetBIOS — critical for lateral movement
            (
                lambda p, s: p in [139, 445] or "netbios" in s or "smb" in s,
                "enum4linux",
                lambda t, p: ["-a", t],
                90,
            ),
            (
                lambda p, s: p in [139, 445] or "netbios" in s or "smb" in s,
                "smbclient",
                lambda t, p: ["-L", f"//{t}/", "-N"],
                30,
            ),
            # HTTP/HTTPS — web enumeration
            (
                lambda p, s: p in [80, 8080, 8180, 8443, 443] or "http" in s,
                "nikto",
                lambda t, p: ["-h", f"http://{{t}}:{{p}}", "-maxtime", "120"],
                180,
            ),
            (
                lambda p, s: p in [80, 8080, 8180] or "http" in s,
                "gobuster",
                lambda t, p: [
                    "dir", "-u", f"http://{{t}}:{{p}}",
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "20", "-q", "--no-error"
                ],
                120,
            ),
            # FTP — check anonymous login
            (
                lambda p, s: p in [21, 2121] or "ftp" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV", "-sC",
                    "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # MySQL — anonymous access
            (
                lambda p, s: p == 3306 or "mysql" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "mysql-empty-password,mysql-info,mysql-databases",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # SSH — version and known vulns
            (
                lambda p, s: p == 22 or "ssh" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "ssh-auth-methods,ssh2-enum-algos",
                    "-p", str(p), "-T4"
                ],
                30,
            ),
            # RPC/NFS — mount points
            (
                lambda p, s: p in [111, 2049] or "rpc" in s or "nfs" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "rpcinfo,nfs-ls,nfs-showmount",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # IRC — check for backdoors
            (
                lambda p, s: p == 6667 or "irc" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "irc-info,irc-unrealircd-backdoor",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # Bindshell / suspicious ports — connect directly
            (
                lambda p, s: p in [1524, 4444, 5555, 31337] or "backdoor" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV", "--script", "banner",
                    "-p", str(p), "-T4"
                ],
                30,
            ),
            # VNC
            (
                lambda p, s: p == 5900 or "vnc" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "vnc-info,vnc-brute",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # PostgreSQL
            (
                lambda p, s: p == 5432 or "postgresql" in s or "postgres" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "pgsql-brute",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
            # Tomcat / Java
            (
                lambda p, s: p in [8080, 8180, 8443] or "tomcat" in s or "jserv" in s,
                "nmap",
                lambda t, p: [
                    t, "-sV",
                    "--script", "http-tomcat-manager,ajp-request",
                    "-p", str(p), "-T4"
                ],
                60,
            ),
        ]
        
        specs: list[dict[str, Any]] = []
        used_tools: set[str] = set()
        
        for port, service in sorted(open_ports.items()):
            for (matcher, tool, args_fn, timeout) in SERVICE_TOOLS:
                if len(specs) >= self.MAX_CONCURRENT * 3:
                    break
                try:
                    if not matcher(port, service):
                        continue
                except Exception:
                    continue
                
                # Check tool exists
                tool_key = f"{tool}:{port}"
                if tool_key in used_tools:
                    continue
                
                tool_path = self.tools.find(tool)
                if not tool_path:
                    continue
                try:
                    import os
                    os.stat(tool_path)
                    if not os.access(tool_path, os.X_OK):
                        continue
                except (PermissionError, OSError):
                    continue
                
                try:
                    args = args_fn(self.target, port)
                except Exception:
                    args = [self.target]
                
                used_tools.add(tool_key)
                specs.append({
                    "tool_hint": tool,
                    "purpose": f"{service} enumeration port {port}",
                    "_resolved_args": [str(a) for a in args],
                    "_timeout": timeout,
                })
        
        # Sort by priority: SMB and HTTP first, then others
        def priority(spec: dict) -> int:
            purpose = spec.get("purpose", "")
            if any(k in purpose for k in ["smb", "netbios"]):
                return 0
            if any(k in purpose for k in ["http", "ftp"]):
                return 1
            if "backdoor" in purpose or "bindshell" in purpose:
                return 0  # highest priority
            return 2
        
        specs.sort(key=priority)
        return specs[:self.MAX_CONCURRENT * 2]

    def _extract_port_services(self) -> dict[int, str]:
        """Extracts {port: service} from all results. No LLM."""
        port_services: dict[int, str] = {}
        for output in self.all_results.values():
            for m in re.finditer(
                r"(\d+)/tcp\s+open\s+(\S+)", str(output)
            ):
                try:
                    port = int(m.group(1))
                except Exception:
                    continue
                if 1 <= port <= 65535:
                    port_services[port] = m.group(2).lower()
        return port_services

    def _decide_wave2_with_llm(
        self, port_services: dict[int, str]
    ) -> list[dict[str, Any]]:
        """
        LLM analyzes nmap output and decides what to probe next.
        Model is warm — this will complete in ~30-60s not timeout.
        RAG injected for deep knowledge.
        MITRE ATT&CK guides technique selection.
        Falls back to _build_wave2_from_ports() if LLM unavailable.
        """
        # Get nmap output summary
        nmap_summary = ""
        for key, output in self.all_results.items():
            if "nmap" in key.lower() or "discover" in key.lower():
                nmap_summary += str(output)[:1500]
                break

        # RAG: enumeration techniques for discovered services
        services_str = " ".join(set(port_services.values()))
        rag_enum = ""
        try:
            results = self.chroma.get_phase_rag_context(
                phase="enumeration",
                query=f"enumerate {services_str} linux pentest techniques",
                n=3,
            )
            rag_enum = "\n".join(
                r.get("text", "")[:200] for r in results
            )
        except Exception:
            pass

        # RAG: CVEs for discovered services
        rag_cve = ""
        try:
            for svc in list(set(port_services.values()))[:3]:
                results = self.chroma.get_rag_context(
                    f"{svc} vulnerability exploit CVE linux",
                    collections=["cve_database", "exploitdb"],
                    n=2,
                )
                for r in results[:1]:
                    rag_cve += r.get("text", "")[:200] + "\n"
        except Exception:
            pass

        # MITRE ATT&CK TA0007 Discovery techniques
        rag_mitre = ""
        try:
            results = self.chroma.get_rag_context(
                "MITRE ATT&CK TA0007 discovery enumeration T1046 T1135 T1049",
                collections=["mitre_attack"],
                n=2,
            )
            rag_mitre = "\n".join(r.get("text", "")[:150] for r in results)
        except Exception:
            pass

        # Available tools — instant check, no LLM
        available: list[str] = []
        check_tools = [
            "nmap", "nikto", "gobuster", "ffuf", "dirb", "enum4linux",
            "smbclient", "smbmap", "hydra", "nuclei", "sqlmap",
            "svmap", "svwar", "smtp-user-enum", "snmpwalk", "redis-cli",
            "ldapsearch", "wfuzz", "whatweb", "curl", "netcat", "telnet",
            "ftp", "ssh", "mysql", "psql", "rpcinfo", "showmount",
        ]
        for tool in check_tools:
            path = self.tools.find(tool)
            if _is_executable(path):
                available.append(tool)

        firewall = getattr(self, "_firewall_detected", False)

        prompt = f"""You are a senior penetration tester.
You just ran nmap on a Linux target and got these results:

{nmap_summary[:800]}

Open ports and services: {dict(list(port_services.items())[:15])}
Firewall/filtering detected: {firewall}

Investigation history:
{self._format_intelligence_history()}

Knowledge base techniques:
{rag_enum[:300] if rag_enum else 'use standard enum techniques'}

Known CVEs for these services:
{rag_cve[:300] if rag_cve else 'check service versions manually'}

MITRE ATT&CK context:
{rag_mitre[:200] if rag_mitre else 'T1046 T1135 T1049 applicable'}

Available tools on this system: {available[:20]}

{"FIREWALL DETECTED: use evasion — slow timing, fragmentation, decoys, source port 53/80/443" if firewall else "No firewall — use aggressive scanning"}

Select the best tools to enumerate the discovered services.
Prioritize: services most likely to have vulnerabilities.
Consider: default credentials, version exploits, misconfigs.
Tag the MITRE technique for each action.

Return JSON only:
{{
  "reasoning": "what I see and why I chose these tools",
  "mitre_techniques": ["T1046", "T1135"],
  "tool_batch": [
    {{
      "tool": "enum4linux",
      "purpose": "enumerate SMB shares and users",
      "args": ["-a", "{self.target}"],
      "timeout": 60,
      "mitre": "T1135"
    }}
  ]
}}

Max {self.MAX_CONCURRENT} tools. Only use tools from available list."""

        # Explicit model warm before critical LLM call
        from utils.llm_factory import warm_model
        warm_model(role="default", keep_alive="2h")
        
        # FIX 9: Reduced timeout from 300s to 60s (wave planning)
        raw = self._llm_with_timeout(prompt, timeout=60)
        decision = self._extract_json_robust(raw)

        if not decision or not decision.get("tool_batch"):
            self.log_warning("LLM wave decision failed — using port-based fallback")
            return self._build_wave2_from_ports()

        # Log reasoning and MITRE
        if decision.get("reasoning"):
            self.log_info(f"🧠 {decision['reasoning'][:150]}")

        for technique in decision.get("mitre_techniques", []):
            if technique:
                self.memory.log_action(
                    "EnumVulnAgent", "mitre_technique", str(technique)
                )

        # Build specs from LLM decision
        specs: list[dict[str, Any]] = []
        for spec in decision.get("tool_batch", []):
            tool = str(spec.get("tool", "")).strip()
            path = self.tools.find(tool)
            if _is_executable(path):
                specs.append({
                    "tool_hint": tool,
                    "purpose": spec.get("purpose", f"enumerate {tool}"),
                    "_resolved_args": [str(a) for a in spec.get("args", [self.target])],
                    "_timeout": int(spec.get("timeout", 60)),
                })

        if not specs:
            self.log_warning("LLM selected no available tools — using port-based fallback")
            return self._build_wave2_from_ports()

        return specs[: self.MAX_CONCURRENT]

    def _update_intelligence_log(
        self,
        wave_num: int,
        batch_results: dict,
        analysis: dict,
    ) -> None:
        """
        Build wave intelligence summary from tool output — no LLM.
        Pure extraction: ports, services, versions, CVEs found.
        Fast and always works regardless of model availability.
        
        CRITICAL: Also directly persists ports and vulns to MissionMemory!
        """
        all_output = "\n".join(str(v) for v in batch_results.values())
        
        # DEBUG: Log what we're receiving
        self.log_info(f"🔍 Wave {wave_num}: Processing {len(batch_results)} tool outputs, total {len(all_output)} chars")
        for tool_key, output in list(batch_results.items())[:3]:
            self.log_info(f"  Tool: {tool_key}, output: {len(output)} chars, preview: {output[:100].replace(chr(10), ' ')}")
        
        # Extract what was actually found from nmap output
        ports_found = re.findall(
            r'(\d+)/tcp\s+open\s+(\S+)', all_output
        )
        versions_found = self._extract_versions_from_outputs(
            batch_results
        )
        cves_found = re.findall(
            r'CVE-\d{4}-\d{4,7}', all_output, re.IGNORECASE
        )
        nuclei_found = re.findall(
            r'\[([A-Za-z0-9_\-]+)\]\s*\[[a-z]+\]\s*\[(critical|high)\]',
            re.sub(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', all_output)
        )
        
        # DEBUG: Log what was extracted
        self.log_info(f"🔍 Extracted: {len(ports_found)} ports, {len(cves_found)} CVEs, {len(nuclei_found)} nuclei hits")
        
        # ═══════════════════════════════════════════════════════════════════════
        # CRITICAL FIX: Directly persist extracted ports to MissionMemory
        # The LLM analysis may not return data in expected format
        # ═══════════════════════════════════════════════════════════════════════
        resolved_ip = self._normalize_host_ip(self.target)
        for port_tuple in ports_found:
            try:
                port_num = int(port_tuple[0])
                service = str(port_tuple[1])
                version = versions_found.get(service, "")
                self.memory.add_port(
                    ip=resolved_ip,
                    port=port_num,
                    service=service,
                    version=version,
                    banner="",
                )
                self.log_info(f"📍 Port persisted: {port_num}/{service} v{version}")
            except Exception as e:
                self.log_warning(f"Failed to persist port {port_tuple}: {e}")
        
        # Persist nuclei CVE findings as vulnerabilities
        for nuclei_match in nuclei_found:
            cve_id = nuclei_match[0]
            severity = nuclei_match[1]
            try:
                self.memory.add_vulnerability(
                    ip=resolved_ip,
                    cve=cve_id,
                    cvss=9.8 if severity == "critical" else 7.5,
                    description=f"Nuclei detected {cve_id} ({severity})",
                    exploitable=True,
                )
                self.log_info(f"🔴 Vuln persisted: {cve_id} ({severity})")
            except Exception as e:
                self.log_warning(f"Failed to persist nuclei vuln {cve_id}: {e}")
        
        # Persist CVEs found in any tool output
        for cve_id in set(cves_found):
            try:
                # Check if already added
                existing = [v.get("cve") for v in self.vulnerabilities]
                if cve_id.upper() not in [str(c).upper() for c in existing]:
                    self.memory.add_vulnerability(
                        ip=resolved_ip,
                        cve=cve_id,
                        cvss=7.0,  # Default high for detected CVEs
                        description=f"CVE detected in tool output: {cve_id}",
                        exploitable=True,
                    )
                    self.log_info(f"🔴 CVE persisted: {cve_id}")
            except Exception as e:
                self.log_warning(f"Failed to persist CVE {cve_id}: {e}")
        
        summary = {
            "wave": wave_num,
            "tools_run": list(batch_results.keys()),
            "ports_found": [f"{p[0]}/{p[1]}" for p in ports_found[:10]],
            "versions": versions_found,
            "cves_in_output": list(set(cves_found))[:5],
            "nuclei_critical_high": [n[0] for n in nuclei_found],
            "next_wave_priority": (
                f"Probe: {[p[1] for p in ports_found[:3]]}"
                if ports_found else "continue enumeration"
            ),
        }
        
        self.intelligence_log.append(summary)
        self.memory.log_action(
            "EnumVulnAgent",
            f"wave_{wave_num}_intelligence",
            str(summary.get("next_wave_priority",""))[:200]
        )

    def _format_intelligence_history(self) -> str:
        """
        Compact summary of all previous wave intelligence.
        Injected into each new wave's LLM decision prompt.
        """
        if not self.intelligence_log:
            return "No previous waves completed."

        parts = []
        for entry in self.intelligence_log[-3:]:
            wave = entry.get("wave", "?")
            confirmed = entry.get("what_was_confirmed", "")
            priority = entry.get("next_wave_priority", "")
            parts.append(
                f"Wave {wave}: confirmed={confirmed[:80]}, "
                f"next_priority={priority[:80]}"
            )

        return " | ".join(parts)

    def _build_wave3_vuln_scan(self) -> list[dict[str, Any]]:
        """
        Build vulnerability-focused specs from available scanners.
        """
        import os

        specs: list[dict[str, Any]] = []
        http_target = self.target if re.match(r"^https?://", self.target, re.IGNORECASE) else f"http://{self.target}"

        nuclei_path = self.tools.find("nuclei")
        if nuclei_path and os.access(nuclei_path, os.X_OK):
            specs.append({
                "tool_hint": "nuclei",
                "purpose": "scan for known vulnerabilities and misconfigurations",
                "_resolved_args": ["-u", http_target, "-severity", "critical,high,medium", "-silent", "-timeout", "30"],
                "_timeout": 180,
            })

        nmap_path = self.tools.find("nmap")
        if nmap_path and os.access(nmap_path, os.X_OK):
            specs.append({
                "tool_hint": "nmap",
                "purpose": "run vulnerability scripts against reachable services",
                "_resolved_args": [self.target, "--script", "vuln", "--top-ports", "100", "-T4"],
                "_timeout": 180,
            })

        return specs[: self.MAX_CONCURRENT]

    # ── Stage 3: one-pass analysis ─────────────────────────────────────────────

    def _run_analysis_phase(self) -> dict[str, Any]:
        """
        Run one LLM analysis over all gathered outputs using all relevant RAG collections.
        Falls back to regex+RAG-only analysis if LLM is unavailable.
        """
        summary = self._build_full_output_summary()
        versions = self._extract_versions_from_all_outputs()
        version_query = " ".join(
            f"{k} {v}" for k, v in list(versions.items())[:5]
        )

        # Query CVE database
        cve_context = ""
        try:
            results = self.chroma.get_rag_context(
                f"{version_query} CVE vulnerability",
                collections=["cve_database"],
                n=4,
            )
            cve_context = "\n".join(
                r.get("text", "")[:250] for r in results
            )
        except Exception as e:
            self.log_warning(f"CVE RAG lookup failed during analysis: {e}")

        # Query Exploit-DB
        exploit_context = ""
        try:
            results = self.chroma.get_rag_context(
                f"{version_query} exploit",
                collections=["exploitdb"],
                n=3,
            )
            exploit_context = "\n".join(
                r.get("text", "")[:200] for r in results
            )
        except Exception as e:
            self.log_warning(f"ExploitDB RAG lookup failed during analysis: {e}")

        # Query MITRE ATT&CK
        mitre_context = ""
        try:
            results = self.chroma.get_rag_context(
                "MITRE ATT&CK T1190 T1110 T1083 T1135 exploit vulnerability",
                collections=["mitre_attack"],
                n=3,
            )
            mitre_context = "\n".join(
                r.get("text", "")[:150] for r in results
            )
        except Exception as e:
            self.log_warning(f"MITRE RAG lookup failed during analysis: {e}")

        # Query HackTricks
        hacktricks_context = ""
        try:
            results = self.chroma.get_rag_context(
                f"{version_query} pentest attack",
                collections=["hacktricks"],
                n=2,
            )
            hacktricks_context = "\n".join(
                r.get("text", "")[:200] for r in results
            )
        except Exception as e:
            self.log_warning(f"HackTricks RAG lookup failed during analysis: {e}")

        # Query Nuclei templates
        nuclei_context = ""
        try:
            results = self.chroma.get_rag_context(
                version_query or "web vulnerability misconfiguration",
                collections=["nuclei_templates"],
                n=2,
            )
            nuclei_context = "\n".join(
                r.get("text", "")[:150] for r in results
            )
        except Exception as e:
            self.log_warning(f"Nuclei RAG lookup failed during analysis: {e}")

        prompt = (
            f"Senior penetration tester final analysis.\n"
            f"Target: {self.target} (Linux server, authorized pentest)\n\n"
            f"Complete tool output summary:\n{summary}\n\n"
            f"NVD CVE database matches:\n{cve_context[:500] if cve_context else 'no matches found'}\n\n"
            f"Exploit-DB entries:\n{exploit_context[:400] if exploit_context else 'no matches found'}\n\n"
            f"HackTricks techniques:\n{hacktricks_context[:300] if hacktricks_context else 'standard techniques'}\n\n"
            f"Nuclei template matches:\n{nuclei_context[:200] if nuclei_context else 'standard templates'}\n\n"
            f"MITRE ATT&CK context:\n{mitre_context[:250] if mitre_context else 'T1190 T1110 applicable'}\n\n"
            "Analyze everything above. Be specific and accurate.\n"
            "Only report confirmed findings with evidence from tool output.\n"
            "Do not invent CVEs — use only those appearing in the CVE context.\n"
            "Classify severity using CVSS scores from NVD data.\n\n"
            "Return JSON only:\n"
            '{"ports":[{"port":80,"service":"http","version":"Apache 2.x","confidence":"high"}],'
            '"vulnerabilities":[{"title":"string","service":"string","cve":"CVE-YYYY-NNNN or CVE-UNKNOWN",'
            '"cvss_score":0.0,"severity":"critical|high|medium|low|info","confirmed":false,'
            '"evidence":"string","exploitable":false,"exploit_reference":"EDB-XXXXX or null",'
            '"mitre_technique":"T1190","remediation":"string"}],'
            '"misconfigurations":[{"type":"string","service":"string","detail":"string","severity":"high"}],'
            '"firewall_analysis":"detected or not",'
            '"risk_summary":"string","attack_priority":"string","mitre_chain":["T1046","T1190"]}'
        )

        # TRY LLM FIRST with timeout, THEN fall back to regex
        # This preserves AGI capability while avoiding blocking
        self.log_info("Attempting LLM vulnerability analysis (120s timeout)...")
        deterministic_analysis = self._regex_analysis_fallback()
        
        try:
            raw = self._llm_with_timeout(prompt, timeout=120)
            if raw and raw.strip():
                analysis = self._extract_json_robust(raw)
                if analysis and isinstance(analysis, dict):
                    # Validate the LLM response has useful content
                    if analysis.get("ports") or analysis.get("vulnerabilities"):
                        self.log_info(f"✓ LLM analysis complete: {len(analysis.get('vulnerabilities', []))} vulns found")
                        return self._merge_analysis_results(analysis, deterministic_analysis)
                    else:
                        self.log_warning("LLM returned empty analysis, falling back to regex")
        except Exception as e:
            self.log_warning(f"LLM analysis failed: {e}")
        
        # FALLBACK: Regex-based analysis
        self.log_info("Running regex-based vulnerability analysis (fallback)...")
        return deterministic_analysis

    def _merge_analysis_results(
        self,
        llm_analysis: dict[str, Any],
        deterministic_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Merge LLM analysis with deterministic findings.
        Deterministic critical findings are never dropped.
        """
        merged: dict[str, Any] = dict(llm_analysis or {})

        # Merge ports
        merged_ports: list[dict[str, Any]] = []
        port_index: dict[tuple[int, str], int] = {}
        for source in (
            llm_analysis.get("ports", []) if isinstance(llm_analysis, dict) else [],
            deterministic_analysis.get("ports", []) if isinstance(deterministic_analysis, dict) else [],
        ):
            if not isinstance(source, list):
                continue
            for item in source:
                if not isinstance(item, dict):
                    continue
                try:
                    pnum = int(item.get("port", 0) or 0)
                except Exception:
                    continue
                if not (1 <= pnum <= 65535):
                    continue
                proto = str(item.get("protocol", "tcp") or "tcp").lower()
                key = (pnum, proto)
                if key not in port_index:
                    merged_ports.append(dict(item))
                    port_index[key] = len(merged_ports) - 1
                    continue
                existing = merged_ports[port_index[key]]
                if not existing.get("version") and item.get("version"):
                    existing["version"] = item.get("version")
                if not existing.get("service") and item.get("service"):
                    existing["service"] = item.get("service")

        # Merge vulnerabilities (favor deterministic confirmed/high-confidence findings)
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        vuln_map: dict[tuple[str, str, int], dict[str, Any]] = {}

        def _vuln_key(v: dict[str, Any]) -> tuple[str, str, int]:
            cve = str(v.get("cve", "CVE-UNKNOWN")).upper()
            service = str(v.get("service", "unknown")).lower()
            try:
                port = int(v.get("port", 0) or 0)
            except Exception:
                port = 0
            return cve, service, port

        for source in (
            llm_analysis.get("vulnerabilities", []) if isinstance(llm_analysis, dict) else [],
            deterministic_analysis.get("vulnerabilities", []) if isinstance(deterministic_analysis, dict) else [],
        ):
            if not isinstance(source, list):
                continue
            for vuln in source:
                if not isinstance(vuln, dict):
                    continue
                key = _vuln_key(vuln)
                existing = vuln_map.get(key)
                if not existing:
                    vuln_map[key] = dict(vuln)
                    continue
                old_sev = severity_rank.get(str(existing.get("severity", "info")).lower(), 0)
                new_sev = severity_rank.get(str(vuln.get("severity", "info")).lower(), 0)
                if new_sev > old_sev:
                    existing["severity"] = vuln.get("severity")
                    existing["cvss_score"] = vuln.get("cvss_score", existing.get("cvss_score", 0))
                if vuln.get("confirmed"):
                    existing["confirmed"] = True
                if vuln.get("exploitable"):
                    existing["exploitable"] = True
                if not existing.get("version") and vuln.get("version"):
                    existing["version"] = vuln.get("version")
                if not existing.get("evidence") and vuln.get("evidence"):
                    existing["evidence"] = vuln.get("evidence")
                if not existing.get("title") and vuln.get("title"):
                    existing["title"] = vuln.get("title")

        merged["ports"] = merged_ports
        merged["vulnerabilities"] = list(vuln_map.values())

        # Merge misconfigurations
        misconfigs: list[dict[str, Any]] = []
        seen_misconfigs: set[str] = set()
        for source in (
            llm_analysis.get("misconfigurations", []) if isinstance(llm_analysis, dict) else [],
            deterministic_analysis.get("misconfigurations", []) if isinstance(deterministic_analysis, dict) else [],
        ):
            if not isinstance(source, list):
                continue
            for mis in source:
                if not isinstance(mis, dict):
                    continue
                key = "|".join(
                    [
                        str(mis.get("type", "")),
                        str(mis.get("service", "")),
                        str(mis.get("detail", "")),
                    ]
                ).lower()
                if key in seen_misconfigs:
                    continue
                seen_misconfigs.add(key)
                misconfigs.append(dict(mis))
        if misconfigs:
            merged["misconfigurations"] = misconfigs

        # Merge MITRE chain
        mitre_chain: list[str] = []
        seen_mitre: set[str] = set()
        for source in (
            llm_analysis.get("mitre_chain", []) if isinstance(llm_analysis, dict) else [],
            deterministic_analysis.get("mitre_chain", []) if isinstance(deterministic_analysis, dict) else [],
        ):
            if not isinstance(source, list):
                continue
            for item in source:
                tid = str(item).strip()
                if not tid or tid in seen_mitre:
                    continue
                seen_mitre.add(tid)
                mitre_chain.append(tid)
        if mitre_chain:
            merged["mitre_chain"] = mitre_chain

        return merged

    def _plan_initial_attack(self) -> dict[str, Any]:
        """
        Build compact initial hypothesis from recon findings with a tight prompt.
        """
        recon_summary = self._format_recon_for_llm()[:200]
        tech_findings = ", ".join(self._extract_tech_names()[:6])[:200] or "unknown stack"

        rag_hint = ""
        try:
            rag = self.chroma.get_phase_rag_context(
                phase="enum",
                query=f"active enumeration linux {tech_findings}",
                n=1,
            )
            rag_hint = self._format_rag(rag, max_chars=150)
        except Exception as e:
            self.log_warning(f"Enumeration RAG lookup failed: {e}")

        # Query mission collection for intelligence from previous phases
        mission_rag = ""
        try:
            mission_hits = self.chroma.get_mission_context(
                mission_id=self.memory.mission_id,
                query=f"enumeration attack vectors {self.target}",
                n=5,
            )
            if mission_hits:
                mission_rag = "\n".join(
                    h.get("text", "")[:150] for h in mission_hits[:3]
                )
        except Exception:
            pass

        prompt = (
            f"Pentester planning active enumeration of Linux server.\n"
            f"Target: {self.target}\n"
            f"Known from recon: {tech_findings}; {recon_summary}\n"
            f"RAG context: {rag_hint[:150] if rag_hint else 'none'}\n"
            f"Intelligence from previous phases:\n{mission_rag[:300]}\n"
            "What are the 3 highest-priority attack vectors to enumerate?\n"
            "Consider open services, likely vulnerabilities, and MITRE TA0007.\n"
            "JSON only:\n"
            '{"hypothesis":"string","priority_targets":[{"ip":"string","focus":"string"}],'
            '"mitre_techniques":["T1046"],"expected_findings":"string","risk_level":"high|medium|low|unknown"}'
        )

        # FIX 9: Reduced timeout from 240s to 60s (planning)
        raw = self._llm_with_timeout(prompt, timeout=60)
        plan = self._extract_json_robust(raw)

        if not plan:
            self.log_warning("LLM initial planning failed — using compact fallback")
            return {
                "hypothesis": "Start with service and version discovery from current target evidence.",
                "priority_targets": [{"ip": self.target, "focus": "discover services"}],
                "mitre_techniques": ["T1046"],
                "expected_findings": "open ports, service banners, and exposed software versions",
                "risk_level": "unknown",
            }

        for technique in plan.get("mitre_techniques", []):
            if technique:
                self.memory.add_mitre_technique(str(technique))
                self.memory.log_action("EnumVulnAgent", "mitre_planned", str(technique))

        self.log_success(f"Initial hypothesis: {str(plan.get('hypothesis', ''))[:120]}")
        return plan

    # ── Stage 2: intelligent enumeration loop ─────────────────────────────────

    def _enumeration_loop(self, initial_plan: dict[str, Any]):
        current_context: dict[str, Any] = {
            "plan": initial_plan,
            "completed_tools": [],
            "key_findings": [],
            "open_questions": [initial_plan.get("hypothesis", "discover all services")],
            "new_hypotheses": initial_plan.get("expected_findings", ""),
        }

        while not self.done and self.iteration < self.MAX_ITERATIONS:
            self.iteration += 1

            self.console.print(Panel(
                f"[bold cyan]🔄 ITERATION {self.iteration}/{self.MAX_ITERATIONS}[/]\n"
                f"[white]Evidence so far:[/] {len(self.all_results)} tool runs\n"
                f"[white]Vulns found:[/] {len(self.vulnerabilities)}",
                border_style="blue",
            ))

            tool_batch, reasoning, done_signal = self._decide_next_tools(current_context)

            if done_signal:
                self.log_success("LLM declared enumeration complete")
                self.done = True
                break

            if not tool_batch:
                self.log_warning("No tools selected in this iteration — stopping loop")
                break

            self.console.print(Panel(
                f"[bold yellow]⚡ Running {len(tool_batch)} tools in parallel[/]",
                border_style="yellow",
            ))

            batch_results = self._run_tool_batch(tool_batch)
            if not batch_results:
                self.log_warning("Tool batch returned no output — stopping loop")
                break

            self.all_results.update(batch_results)
            for spec in tool_batch:
                hint = str(spec.get("tool_hint", "")).strip().lower()
                if hint:
                    self._completed_tools.add(hint)

            analysis = self._analyze_results(batch_results, reasoning)
            new_vulns = self._classify_vulnerabilities(analysis, batch_results)

            # Deduplicate vulnerabilities by (cve, title, service)
            known_keys = {
                (
                    str(v.get("cve", "")).upper(),
                    str(v.get("title", "")).lower(),
                    str(v.get("target", "")).lower(),
                )
                for v in self.vulnerabilities
            }
            for vuln in new_vulns:
                key = (
                    str(vuln.get("cve", "")).upper(),
                    str(vuln.get("title", "")).lower(),
                    str(vuln.get("target", "")).lower(),
                )
                if key not in known_keys:
                    self.vulnerabilities.append(vuln)
                    known_keys.add(key)

            current_context = self._update_context(current_context, batch_results, analysis, new_vulns)
            self._store_iteration_findings(analysis, new_vulns)

    def _decide_next_tools(
        self,
        context: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], str, bool]:
        """
        LLM + RAG + MITRE decide next tool batch.
        All tool-name and arg resolution happens in this main thread.
        Returns: (tool_specs, reasoning, is_done)
        """
        evidence = self._build_evidence_summary()
        rag_query = self._build_adaptive_rag_query(context)
        rag_hint = ""
        try:
            rag_context = self.chroma.get_phase_rag_context(
                phase="enum",
                query=rag_query,
                n=1,
            )
            rag_hint = self._format_rag(rag_context, max_chars=100)
        except Exception as e:
            self.log_warning(f"Adaptive phase RAG lookup failed: {e}")

        available_tools: list[str] = []
        try:
            available_tools = self.tools.get_tools_for_purpose(
                f"active enumeration {rag_query[:80]}"
            )
        except Exception as e:
            self.log_warning(f"Tool suggestion lookup failed: {e}")

        prompt = (
            f"Pentester. Iteration {self.iteration}/{self.MAX_ITERATIONS}.\n"
            f"Evidence: {evidence[:200]}\n"
            f"RAG hint: {rag_hint[:100] if rag_hint else 'none'}\n"
            f"Done categories: {context.get('completed_tools', [])[:5]}\n"
            f"Available: {available_tools[:6]}\n"
            "Next 1-3 tool purposes? Or done?\n"
            "JSON only:\n"
            '{"done":false,"reasoning":"string","mitre_techniques":["T1046"],'
            '"tool_batch":[{"purpose":"string","tool_hint":"string","target":"string","approach":"string","priority":"high|medium|low"}],'
            '"new_hypotheses":["string"]}'
        )

        # FIX 9: Reduced timeout from 240s to 60s (wave planning)
        raw = self._llm_with_timeout(prompt, timeout=60)
        decision = self._extract_json_robust(raw) if raw else None
        if not decision:
            if self.allow_deterministic_fallback:
                fallback_specs = self._fallback_tool_batch()
                if fallback_specs:
                    return fallback_specs, "Heuristic fallback", False
            return [], "LLM unavailable and no fallback actions", True

        done = bool(decision.get("done", False))
        reasoning = str(decision.get("reasoning", "")).strip()
        tool_specs = decision.get("tool_batch", [])

        normalized_tools: list[dict[str, Any]] = []
        if isinstance(tool_specs, list):
            for spec in tool_specs[: self.MAX_CONCURRENT]:
                if not isinstance(spec, dict):
                    continue
                normalized_tools.append({
                    "purpose": str(spec.get("purpose", "enumeration")).strip() or "enumeration",
                    "tool_hint": str(spec.get("tool_hint", "")).strip(),
                    "target": str(spec.get("target", self.target)).strip() or self.target,
                    "approach": str(spec.get("approach", "")).strip(),
                    "expected_output": str(spec.get("expected_output", "")).strip(),
                    "priority": str(spec.get("priority", "medium")).strip().lower(),
                })

        for technique in decision.get("mitre_techniques", []):
            if technique:
                self.memory.add_mitre_technique(str(technique))
                self.memory.log_action("EnumVulnAgent", "mitre_technique", str(technique))

        if reasoning:
            self.log_info(f"🧠 {reasoning[:200]}")

        if done:
            return [], reasoning, True

        if not normalized_tools:
            if self.allow_deterministic_fallback:
                fallback_specs = self._fallback_tool_batch()
                return fallback_specs, reasoning or "No tools selected", False
            return [], reasoning or "No tools selected by LLM", True

        priority_weight = {"high": 0, "medium": 1, "low": 2}
        normalized_tools.sort(key=lambda s: priority_weight.get(s.get("priority", "medium"), 1))
        resolved_specs: list[dict[str, Any]] = []
        for spec in normalized_tools[: self.MAX_CONCURRENT]:
            try:
                resolved_specs.append(self._resolve_spec(spec))
            except Exception as e:
                self.log_warning(f"Spec resolution failed for '{spec.get('purpose', 'unknown')}': {e}")

        if not resolved_specs:
            if self.allow_deterministic_fallback:
                return self._fallback_tool_batch(), reasoning or "Resolution failed", False
            return [], reasoning or "LLM-selected tools could not be resolved", True

        return resolved_specs, reasoning, False

    def _run_tool_batch(self, tool_specs: list[dict[str, Any]]) -> dict[str, str]:
        """
        Run tools in parallel with pre-resolved arguments.
        ZERO LLM calls are allowed inside worker threads.
        """
        results: dict[str, str] = {}
        if not tool_specs:
            return results

        with _DaemonThreadPoolExecutor(max_workers=self.MAX_CONCURRENT) as executor:
            futures: dict[concurrent.futures.Future, dict[str, Any]] = {}

            for spec in tool_specs[: self.MAX_CONCURRENT]:
                future = executor.submit(
                    self._run_intelligent_tool,
                    str(spec.get("tool_hint", "nmap")),
                    spec.get("_resolved_args", [self.target]),
                    int(spec.get("_timeout", self.DEFAULT_TIMEOUT)),
                )
                futures[future] = spec

            max_wait = (
                max(int(s.get("_timeout", self.DEFAULT_TIMEOUT)) for s in tool_specs[: self.MAX_CONCURRENT])
                + 10
            )
            try:
                for future in concurrent.futures.as_completed(futures, timeout=max_wait):
                    spec = futures.get(future, {})
                    label = str(spec.get("purpose", "unknown"))
                    try:
                        tool_name, output = future.result()
                        key = f"{label}::{tool_name}"
                        results[key] = output
                        preview = output[:120].replace("\n", " ") if output else "[no output]"
                        self.log_info(f"  ✓ {tool_name}: {preview}")
                    except Exception as e:
                        results[f"{label}::error"] = f"[FAILED: {e}]"
                        self.log_warning(f"  ✗ [{label}] failed: {e}")
            except concurrent.futures.TimeoutError:
                self.log_warning(f"Tool batch exceeded wait budget ({max_wait}s); collecting partial results")

            for future, spec in futures.items():
                if future.done():
                    continue
                label = str(spec.get("purpose", "unknown"))
                future.cancel()
                results[f"{label}::timeout"] = f"[TIMEOUT after {max_wait}s]"

        return results

    def _run_intelligent_tool(
        self,
        tool_hint: str,
        resolved_args: list[str],
        timeout: int,
    ) -> tuple[str, str]:
        """
        Runs one tool with pre-resolved args.
        No LLM and no RAG calls are allowed in this worker thread.
        """
        import os

        tool_name = str(tool_hint or "").strip().split()[0] or "nmap"
        tool_path = self.tools.find(tool_name)
        if not tool_path:
            return tool_name, f"[TOOL_NOT_FOUND: {tool_name}]"
        if not os.access(tool_path, os.X_OK):
            return tool_name, f"[TOOL_NOT_EXECUTABLE: {tool_name}]"

        target_value = str(getattr(self, "target", "") or "")
        ip_value = str(getattr(self, "resolved_ip", "") or target_value)
        args = [
            str(a)
            .replace("{target}", target_value)
            .replace("{ip}", ip_value)
            .replace("TARGET", target_value)
            .replace("IP_ADDR", ip_value)
            for a in (resolved_args or [self.target])
        ]
        
        # VERBOSE: Log tool call before execution
        self._verbose_tool_call(tool_name, args)

        # ══════════════════════════════════════════════════════════════════════
        # PROXY/IPS BYPASS: route selected tools via proxychains when recommended
        # ══════════════════════════════════════════════════════════════════════
        try:
            evasion = self.memory.get_evasion_config()
            use_proxy = bool(evasion.get("config", {}).get("use_proxy", False))
        except Exception:
            use_proxy = False
        if use_proxy and tool_name not in {"dig", "host", "whois"}:
            proxy_bin = None
            try:
                proxy_bin = self.tools.find("proxychains4") or self.tools.find("proxychains")
            except Exception:
                proxy_bin = None
            if proxy_bin:
                args = [tool_name] + args
                tool_name = "proxychains4" if "proxychains4" in str(proxy_bin) else "proxychains"

        result = self.tools.use(
            tool_name=tool_name,
            args=args,
            timeout=timeout,
            purpose=f"EnumVulnAgent: {tool_name}",
        )
        output = (
            result.get("stdout", "")
            or result.get("output", "")
            or result.get("stderr", "")
            or "[no output]"
        )
        
        # VERBOSE: Log tool output
        self._verbose_tool_output(output)

        self.memory.log_action(
            agent_name="EnumVulnAgent",
            action=tool_name,
            result=str(output)[:300],
        )

        return tool_name, str(output)[:20000]

    def _resolve_spec(self, spec: dict[str, Any]) -> dict[str, Any]:
        """
        Resolve best tool + args in the main thread before worker execution.
        """
        purpose = str(spec.get("purpose", "")).strip()
        approach = str(spec.get("approach", "")).strip()
        target = str(spec.get("target", self.target)).strip() or self.target
        purpose_lower = purpose.lower()
        target_lower = target.lower()
        if target_lower in ("ip", "target", "target_ip", "<target_ip>", "{target}", "{ip}"):
            target = self.target
        if any(tok in target_lower for tok in ("example.com", "<target", "<ip", "{ip}", "/path/to", "<web_server_url>", "<ftp_server_url>")):
            target = self.target
        if re.match(r"^https?://", target, re.IGNORECASE):
            host = re.sub(r"^https?://", "", target, flags=re.IGNORECASE).split("/", 1)[0].strip()
            if host and "example.com" not in host.lower() and "<" not in host:
                target = host
            else:
                target = self.target

        best_tool = str(spec.get("tool_hint", "")).strip().split()[0]
        try:
            candidates = self.tools.get_tools_for_purpose(purpose or "enumeration")
            for candidate in candidates:
                c = str(candidate).strip()
                if not c:
                    continue
                if self.tools.find(c):
                    best_tool = c
                    break
        except Exception as e:
            self.log_warning(f"Tool candidate resolution failed for '{purpose}': {e}")

        WEB_TOOLS = {"dirb", "dirsearch", "gobuster", "ffuf", "nikto", "wfuzz"}
        NON_WEB_SERVICE_HINTS = (
            "ftp", "ssh", "telnet", "smtp", "dns", "domain", "rpc",
            "nfs", "smb", "mysql", "postgres", "irc", "vnc"
        )
        WEB_HINTS = ("http", "https", "web", "directory", "endpoint", "path", "vhost")

        if any(h in purpose_lower for h in NON_WEB_SERVICE_HINTS) and best_tool in WEB_TOOLS:
            best_tool = "nmap"
        elif any(h in purpose_lower for h in WEB_HINTS) and best_tool in {"nmap", "hydra", ""}:
            if self.tools.find("gobuster"):
                best_tool = "gobuster"
            elif self.tools.find("ffuf"):
                best_tool = "ffuf"
            elif self.tools.find("dirb"):
                best_tool = "dirb"

        if not best_tool:
            best_tool = "nmap"
        spec["tool_hint"] = best_tool

        tool_help = ""
        try:
            help_result = self.tools.use(
                tool_name=best_tool,
                args=["--help"],
                timeout=5,
                purpose=f"help lookup for {best_tool}",
            )
            tool_help = str(help_result.get("stdout", "") or help_result.get("stderr", ""))[:300]
        except Exception:
            tool_help = ""

        rag_hint = ""
        try:
            rag = self.chroma.get_rag_context(
                f"{best_tool} {purpose} usage",
                collections=["hacktricks"],
                n=1,
            )
            rag_hint = self._format_rag(rag, max_chars=120)
        except Exception:
            rag_hint = ""

        arg_prompt = (
            f"You are configuring {best_tool} for authorized pentesting.\n"
            f"Target: {target} (Linux)\n"
            f"Purpose: {purpose[:120]}\n"
            f"Approach: {approach[:120]}\n"
            f"Evidence: {self._build_evidence_summary()[:200]}\n"
            f"RAG hint: {rag_hint[:120] if rag_hint else 'none'}\n"
            f"Tool help: {tool_help[:220] if tool_help else 'standard flags'}\n"
            "Return ONLY a JSON array of args. No tool name.\n"
            f'Example: ["-sV","-sC","--top-ports","1000","{target}"]'
        )
        
        # Known tools: deterministic args, no LLM needed
        # This saves 30s × n_tools per wave
        def _nmap_args_with_evasion(target: str, port: str | None = None, **_) -> list[str]:
            """Build nmap args with evasion profile from MissionMemory."""
            base_args = (
                [target, "-sV", "-sC", "-p", str(port)]
                if port else
                [target, "-sV", "-sC", "--top-ports", "1000", "--open"]
            )
            
            # Check for evasion config from FirewallDetectionAgent
            try:
                evasion_state = self.memory._state.get("evasion", {})
                if evasion_state:
                    profile = evasion_state.get("profile", "none")
                    config = evasion_state.get("config", {})
                    
                    if profile != "none" and config:
                        self.log_info(f"[EVASION] Applying '{profile}' profile to nmap")
                        
                        # Add evasion timing
                        timing = config.get("nmap_timing", "-T4")
                        base_args.append(timing)
                        
                        # Add extra evasion flags
                        for flag in config.get("nmap_flags", []):
                            if flag not in base_args:
                                base_args.append(flag)

                        # Translate recommended delays into nmap scan-delay for IPS/WAF bypass.
                        try:
                            delay = float(config.get("delay_between_requests", 0) or 0)
                            if delay >= 0.5 and "--scan-delay" not in base_args:
                                base_args.extend(["--scan-delay", f"{int(delay * 1000)}ms"])
                        except Exception:
                            pass
                        
                        return base_args
            except Exception:
                pass
            
            # Default: -T4 timing
            base_args.append("-T4")
            return base_args

        def _normalize_web_target(raw_target: str, purpose_text: str = "") -> str:
            value = str(raw_target or "").strip()
            low = value.lower()
            if not value or any(
                tok in low
                for tok in (
                    "example.com",
                    "<target",
                    "<web_server_url>",
                    "<ftp_server_url>",
                    "/path/to",
                )
            ):
                value = self.target
            if re.match(r"^https?://", value, re.IGNORECASE):
                return value.rstrip("/") + "/"
            scheme = "https" if "https" in purpose_text.lower() or ":443" in value else "http"
            return f"{scheme}://{value.rstrip('/')}/"

        def _dirb_args(target: str, purpose: str = "", **_) -> list[str]:
            base_url = _normalize_web_target(target, purpose)
            return [base_url, "/usr/share/wordlists/dirb/common.txt", "-S"]

        def _web_brute_args_with_rag(target: str, tool: str = "gobuster", purpose: str = "", **_) -> list[str]:
            """
            P2-2: Adaptive wordlists.
            Queries RAG for service-specific endpoints and combines them with a standard list.
            """
            import tempfile
            import os
            
            # Use RAG to find paths
            custom_paths = set()
            try:
                # Look for service/tech name in purpose
                tech_match = re.search(r'(wordpress|joomla|drupal|apache|tomcat|nginx|iis|jenkins|jira)', purpose, re.IGNORECASE)
                tech = tech_match.group(1).lower() if tech_match else "web"
                
                hits = self.chroma.get_rag_context(f"{tech} common paths endpoints default directories", collections=["hacktricks", "payloads"], n=3)
                for hit in hits:
                    text = hit.get("text", "")
                    # Extract anything that looks like a path (starts with /)
                    for match in re.finditer(r'(?:^|\s)(/[a-zA-Z0-9_.-]+/?)(?:\s|$)', text):
                        path = match.group(1).strip()
                        if len(path) > 1: # avoid just '/'
                            custom_paths.add(path[1:] if path.startswith('/') else path)
            except Exception as e:
                self.log_warning(f"RAG wordlist generation failed: {e}")
                
            # Create a combined temporary wordlist
            wordlist_path = "/usr/share/wordlists/dirb/common.txt"
            if custom_paths:
                try:
                    fd, temp_path = tempfile.mkstemp(prefix="ca_wordlist_", suffix=".txt")
                    with os.fdopen(fd, 'w') as f:
                        for p in custom_paths:
                            f.write(f"{p}\n")
                        # Include standard dirb common list if it exists
                        if os.path.exists(wordlist_path):
                            with open(wordlist_path, 'r', errors='ignore') as base:
                                f.write(base.read())
                    wordlist_path = temp_path
                    self.log_info(f"[WORDLIST] Generated adaptive wordlist with {len(custom_paths)} RAG entries: {temp_path}")
                except Exception as e:
                    self.log_warning(f"Failed to create temp wordlist: {e}")
            
            if tool == "gobuster":
                url = _normalize_web_target(target, purpose).rstrip("/")
                return ["dir", "-u", url, "-w", wordlist_path, "-t", "20", "-q"]
            else: # ffuf
                url = _normalize_web_target(target, purpose).rstrip("/")
                return ["-u", f"{url}/FUZZ", "-w", wordlist_path, "-t", "20", "-s"]

        DETERMINISTIC_TOOLS = {
            "nmap": _nmap_args_with_evasion,
            "enum4linux": lambda target, **_: ["-a", target],
            "smbclient":  lambda target, **_: ["-L", f"//{target}/", "-N"],
            "smbmap":     lambda target, **_: ["-H", target],
            "nikto":      lambda target, **_: ["-h", f"http://{target}", "-Tuning", "13"],
            "dirb":       lambda target, purpose="", **_: _dirb_args(target, purpose),
            "dirsearch":  lambda target, purpose="", **_: [
                "-u", _normalize_web_target(target, purpose).rstrip("/"),
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-q",
            ],
            "gobuster":   lambda target, purpose="", **_: _web_brute_args_with_rag(target, "gobuster", purpose),
            "ffuf":       lambda target, purpose="", **_: _web_brute_args_with_rag(target, "ffuf", purpose),
            "hydra":      lambda target, **_: [
                "-L", "/usr/share/wordlists/metasploit/unix_users.txt",
                "-P", "/usr/share/wordlists/metasploit/unix_passwords.txt",
                "-t", "4", "-f", target, "ssh"
            ],
            "curl":       lambda target, **_: ["-sI", "--max-time", "10", f"http://{target}"],
            "nc":         lambda target, **_: ["-zv", target, "1-1024"],
            "netcat":     lambda target, **_: ["-zv", target, "1-1024"],
        }

        # Extract port hint from purpose if present
        port_hint = None
        port_match = re.search(r'\bport\s+(\d+)\b', purpose, re.IGNORECASE)
        if port_match:
            port_hint = port_match.group(1)
        else:
            service_port_hints = {
                "ftp": "21",
                "ssh": "22",
                "telnet": "23",
                "smtp": "25",
                "domain": "53",
                "dns": "53",
                "rpc": "111",
                "nfs": "2049",
                "smb": "445",
                "netbios": "445",
                "mysql": "3306",
                "postgres": "5432",
                "vnc": "5900",
                "irc": "6667",
                "tomcat": "8180",
            }
            for svc_kw, svc_port in service_port_hints.items():
                if svc_kw in purpose_lower:
                    port_hint = svc_port
                    break

        if best_tool in DETERMINISTIC_TOOLS:
            try:
                kwargs = {"target": target, "purpose": purpose}
                if port_hint:
                    kwargs["port"] = port_hint
                args = DETERMINISTIC_TOOLS[best_tool](**kwargs)
                spec["_resolved_args"] = [str(a) for a in args]
                spec["_timeout"] = self._get_tool_timeout(purpose)
                self.log_info(
                    f"  → {best_tool} "
                    f"{' '.join(str(a) for a in args[:5])}"
                )
                return spec  # ← RETURN EARLY, no LLM call
            except Exception as e:
                self.log_warning(f"Deterministic tool resolution failed for {best_tool}: {e}")

        # FIX 9: Reduced timeout from 240s to 45s (arg resolution)
        raw = self._llm_with_timeout(arg_prompt, timeout=45)
        args = self._extract_args_from_llm(raw, target, best_tool, purpose)

        spec["_resolved_args"] = args
        spec["_timeout"] = self._get_tool_timeout(purpose)
        self.log_info(f"  → {best_tool} {' '.join(str(a) for a in args[:5])}")
        return spec

    def _extract_args_from_llm(
        self,
        raw: str,
        target: str,
        tool_name: str = "",
        purpose: str = "",
    ) -> list[str]:
        """
        Extract command arguments from LLM JSON-array output.
        Never raises; falls back to [target].
        """
        if not raw:
            return [target]

        cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        match = re.search(r"\[.*?\]", cleaned, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if isinstance(parsed, list):
                    resolved: list[str] = []
                    for value in parsed:
                        item = str(value)
                        item = (
                            item.replace("{target}", target)
                            .replace("{ip}", target)
                            .replace("TARGET", target)
                            .replace("target_ip", target)
                            .replace("<target_ip>", target)
                            .replace("<ip>", target)
                        )
                        if "example.com" in item.lower() or "<" in item or "/path/to" in item.lower():
                            item = target
                        resolved.append(item)
                    if not resolved:
                        return [target]

                    # Ensure target is present for scanner tools
                    tool_lower = (tool_name or "").lower()
                    if tool_lower in {"nmap", "nikto"} and not any(target == a or a.endswith(target) for a in resolved):
                        resolved.append(target)

                    # Keep web-enum tools bound to HTTP/HTTPS URLs only
                    if tool_lower in {"dirb", "gobuster", "ffuf", "dirsearch"}:
                        if not any(str(a).startswith(("http://", "https://")) for a in resolved):
                            url = f"http://{target}"
                            if tool_lower == "gobuster":
                                return ["dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
                            if tool_lower == "ffuf":
                                return ["-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-s"]
                            if tool_lower == "dirsearch":
                                return ["-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
                            return [f"{url}/", "/usr/share/wordlists/dirb/common.txt", "-S"]

                    return resolved
            except Exception:
                pass
        return [target]

    def _get_tool_timeout(self, purpose: str) -> int:
        """
        LLM-free timeout estimation based on purpose keywords.
        """
        purpose_lower = (purpose or "").lower()
        slow_keywords = ["full", "all ports", "complete", "deep", "brute", "fuzz", "nuclei", "crawl"]
        fast_keywords = ["quick", "fast", "top", "banner", "ping", "detect", "check", "ssl", "single"]
        if any(k in purpose_lower for k in slow_keywords):
            return 300
        if any(k in purpose_lower for k in fast_keywords):
            return 60
        return self.DEFAULT_TIMEOUT

    def _analyze_results(self, batch_results: dict[str, str], reasoning: str) -> dict[str, Any]:
        """Compact LLM + RAG analysis of fresh tool outputs."""
        output_summary = self._summarize_batch_for_llm(batch_results)[:600]

        versions_found = self._extract_versions_from_outputs(batch_results)
        cve_hint = ""
        if versions_found:
            first_service = next(iter(versions_found.items()))
            try:
                hits = self.chroma.get_rag_context(
                    f"{first_service[0]} {first_service[1]} CVE",
                    collections=["cve_database"],
                    n=1,
                )
                cve_hint = self._format_rag(hits, max_chars=150)
            except Exception as e:
                self.log_warning(f"CVE hint lookup failed: {e}")

        prompt = (
            "Analyze these pentest tool outputs.\n"
            f"Target: Linux server at {self.target}\n"
            f"Reasoning: {reasoning[:120]}\n"
            f"Output summary: {output_summary}\n"
            f"CVE context: {cve_hint[:150] if cve_hint else 'none'}\n"
            "Extract ports, services, versions, vulnerability indicators.\n"
            "Classify severity and tag MITRE techniques.\n"
            "JSON only:\n"
            '{"ports_found":[{"port":80,"protocol":"tcp","service":"http","version":"x","confidence":"high"}],'
            '"technologies":[{"name":"Apache","version":"2.4","confidence":"medium","source":"tool","cves_applicable":[]}],'
            '"firewall_detected":false,"firewall_type":null,'
            '"vulnerability_indicators":[{"type":"version_exposure","service":"http","detail":"string","severity":"medium","confidence":"medium"}],'
            '"misconfigurations":[{"type":"string","service":"string","detail":"string","exploitability":"medium"}],'
            '"new_attack_vectors":["string"],"open_questions":["string"],"mitre_techniques_observed":["T1046"]}'
        )

        # FIX 9: Reduced timeout from 240s to 60s (analysis)
        raw = self._llm_with_timeout(prompt, timeout=60)
        analysis = self._extract_json_robust(raw)

        if not analysis:
            analysis = self._regex_analysis_fallback(batch_results)

        if not isinstance(analysis, dict):
            return {}

        return analysis

    def _classify_vulnerabilities(
        self,
        analysis: dict[str, Any],
        batch_results: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Classify vulnerability indicators using RAG + LLM + hallucination guard."""
        if not isinstance(analysis, dict):
            return []

        vulns: list[dict[str, Any]] = []
        indicators = analysis.get("vulnerability_indicators", [])
        misconfigs = analysis.get("misconfigurations", [])

        all_items: list[dict[str, Any]] = []
        if isinstance(indicators, list):
            all_items.extend([x for x in indicators if isinstance(x, dict)])
        if isinstance(misconfigs, list):
            for m in misconfigs:
                if not isinstance(m, dict):
                    continue
                all_items.append({
                    "type": "misconfiguration",
                    "severity": m.get("exploitability", "medium"),
                    "detail": m.get("detail", ""),
                    "service": m.get("service", ""),
                    "confidence": m.get("exploitability", "medium"),
                })

        for item in all_items:
            service = str(item.get("service", "")).strip()
            detail = str(item.get("detail", "")).strip()

            cve_results: list[dict[str, Any]] = []
            exploit_results: list[dict[str, Any]] = []
            try:
                cve_results = self.chroma.get_rag_context(
                    f"{service} {detail} CVE CVSS",
                    collections=["cve_database"],
                    n=1,
                )
            except Exception as e:
                self.log_warning(f"CVE lookup failed for '{service}': {e}")

            try:
                exploit_results = self.chroma.get_rag_context(
                    f"{service} {detail} exploit",
                    collections=["exploitdb"],
                    n=1,
                )
            except Exception as e:
                self.log_warning(f"Exploit lookup failed for '{service}': {e}")

            cve_context = self._format_rag(cve_results, max_chars=120)
            exploit_context = self._format_rag(exploit_results, max_chars=120)

            classify_prompt = (
                "Classify this pentest vulnerability indicator.\n"
                f"Service: {service or 'unknown'}\n"
                f"Indicator: {detail[:140]}\n"
                f"Evidence: {json.dumps(item, default=str)[:180]}\n"
                f"CVE hint: {cve_context[:120] if cve_context else 'none'}\n"
                f"Exploit hint: {exploit_context[:120] if exploit_context else 'none'}\n"
                "Return JSON only:\n"
                '{"title":"string","description":"string","cve":"CVE-YYYY-NNNN or CVE-UNKNOWN","cvss_score":0.0,'
                '"severity":"critical|high|medium|low|info","confirmed":false,"evidence":"string","exploitable":false,'
                '"exploit_available":false,"exploit_reference":"EDB-ID:NNNNN or null","mitre_technique":"T1190",'
                '"remediation":"string"}'
            )

            # FIX 9: Reduced timeout from 240s to 45s (vuln classification)
            raw = self._llm_with_timeout(classify_prompt, timeout=45)
            vuln = self._extract_json_robust(raw)

            if not vuln:
                fallback_sev = str(item.get("severity", "low")).lower()
                if fallback_sev not in {"critical", "high", "medium", "low", "info"}:
                    fallback_sev = "low"
                vuln = {
                    "title": f"Potential {service or 'service'} issue",
                    "description": detail or "Potential vulnerability inferred from active enumeration",
                    "cve": "CVE-UNKNOWN",
                    "cvss_score": 0.0,
                    "severity": fallback_sev,
                    "confirmed": False,
                    "evidence": detail[:200],
                    "exploitable": False,
                    "exploit_available": bool(exploit_results),
                    "exploit_reference": None,
                    "mitre_technique": "T1190",
                    "remediation": "Validate service version and patch to latest stable release.",
                }

            if not isinstance(vuln, dict):
                continue
            
            # ── VERSION-AWARE CVE FILTERING ────────────────────────────
            # Check if detected CVE actually applies to this service version
            cve = vuln.get("cve", "")
            if cve and cve != "CVE-UNKNOWN":
                # Get service version from detected ports
                service_version = str(item.get("version", ""))
                if not service_version:
                    # Try to find version from ports list
                    for p in ports:
                        if str(p.get("service", "")).lower() == service.lower():
                            service_version = str(p.get("version", ""))
                            break
                
                # If we have version, check if CVE applies
                if service_version:
                    # Query RAG for CVE affected versions
                    try:
                        cve_detail = self.chroma.cve_lookup(cve, n=1)
                        if cve_detail:
                            affected_versions = cve_detail[0].get("text", "")
                            
                            # Check version match
                            if not self._version_matches(service_version, affected_versions):
                                self.log_warning(
                                    f"CVE {cve} filtered out: version mismatch "
                                    f"(detected={service_version}, affected={affected_versions[:60]})"
                                )
                                # Mark as low confidence instead of removing
                                vuln["confirmed"] = False
                                vuln["exploitable"] = False
                                vuln["evidence"] = f"Version mismatch: {service_version} not in affected range"
                                if vuln.get("severity") in ["critical", "high"]:
                                    vuln["severity"] = "low"
                                vuln["cvss_score"] = max(0.0, float(vuln.get("cvss_score", 0.0)) - 5.0)
                    except Exception as e:
                        # Can't verify version, keep the vuln but note it
                        self.log_warning(f"Version check failed for {cve}: {e}")

            guarded = self.hallucination_guard(vuln, "vuln_scan")
            if isinstance(guarded, dict):
                vuln = guarded

            vuln["target"] = service or self.target
            vuln["iteration_found"] = self.iteration
            vuln["source_tools"] = list(batch_results.keys())

            mitre_id = str(vuln.get("mitre_technique", "")).strip()
            if mitre_id:
                self.memory.add_mitre_technique(mitre_id)
                self.memory.log_action("EnumVulnAgent", "mitre_technique", mitre_id)

            should_store = bool(vuln.get("confirmed")) or str(vuln.get("cve", "")).upper().startswith("CVE-")
            if should_store:
                try:
                    self.memory.add_vulnerability(
                        ip=self._find_ip_for_service(service),
                        cve=str(vuln.get("cve", "CVE-UNKNOWN")),
                        cvss=float(vuln.get("cvss_score", 0.0) or 0.0),
                        description=str(vuln.get("description", detail or "Potential vulnerability")),
                        exploitable=bool(vuln.get("exploitable", False)),
                        port=vuln.get("port"),
                        service=service,
                        version=vuln.get("version"),
                    )
                except Exception as e:
                    self.log_warning(f"Failed to persist vulnerability: {e}")

            vulns.append(vuln)
            severity = str(vuln.get("severity", "info")).upper()
            self.log_success(f"[{severity}] {str(vuln.get('title', detail))[:140]}")

        return vulns

    # ── Stage 4: final report + persistence ───────────────────────────────────

    def _reason_about_exploitability(self, vuln: dict) -> dict:
        """Replaced by _batch_exploitability_reasoning(). Stub only."""
        return vuln

    def _batch_exploitability_reasoning(
        self,
        vulns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        One LLM call to reason about exploitability for all high/critical vulns.
        """
        if not isinstance(vulns, list) or not vulns:
            return vulns if isinstance(vulns, list) else []

        candidate_indexes = [
            i
            for i, v in enumerate(vulns)
            if isinstance(v, dict)
            and str(v.get("severity", "info")).lower() in {"critical", "high"}
        ]
        if not candidate_indexes:
            return vulns

        target_vulns = [vulns[i] for i in candidate_indexes]
        service_list = " ".join(sorted({
            str(v.get("service", "")).strip()
            for v in target_vulns[:8]
            if isinstance(v, dict) and v.get("service")
        }))
        cve_list = " ".join(sorted({
            str(v.get("cve", "")).strip()
            for v in target_vulns[:8]
            if isinstance(v, dict)
            and str(v.get("cve", "")).startswith("CVE-")
        }))

        rag_context = ""
        for collection, query in [
            ("cve_database", f"{cve_list} CVSS severity exploit"),
            ("exploitdb", f"{service_list} exploit public"),
            ("hacktricks", f"{service_list} attack exploitation"),
        ]:
            try:
                hits = self.chroma.get_rag_context(query, collections=[collection], n=3)
            except Exception:
                hits = []
            if hits:
                rag_context += f"\n[{collection}]\n"
                rag_context += "\n".join(str(h.get("text", ""))[:200] for h in hits)

        vuln_summaries: list[dict[str, Any]] = []
        for idx in candidate_indexes:
            vuln = vulns[idx]
            if not isinstance(vuln, dict):
                continue
            vuln_summaries.append({
                "index": idx,
                "cve": vuln.get("cve", "CVE-UNKNOWN"),
                "service": vuln.get("service", ""),
                "severity": vuln.get("severity", "info"),
                "cvss": vuln.get("cvss_score", 0.0),
                "evidence": str(vuln.get("evidence", ""))[:100],
                "exploit_available": vuln.get("exploit_available", False),
            })

        tool_evidence = self._build_full_output_summary()
        tool_evidence_upper = tool_evidence.upper()

        def _is_grounded_exploitable(v: dict[str, Any]) -> bool:
            cve = str(v.get("cve", "")).upper()
            if cve.startswith("CVE-") and cve in tool_evidence_upper:
                return True
            if bool(v.get("confirmed")):
                return True
            if bool(v.get("exploit_available")):
                return True
            title = str(v.get("title", "")).lower()
            evidence = str(v.get("evidence", "")).lower()
            high_signal = ("backdoor", "bindshell", "anonymous ftp", "nuclei confirmed")
            return any(sig in title or sig in evidence for sig in high_signal)

        prompt = f"""Evaluate exploitability of these vulnerabilities
found on a Linux target during authorized penetration testing.

Tool output evidence (what was actually observed):
{tool_evidence[:600]}

Knowledge base context:
{rag_context[:600] if rag_context else 'standard CVE data applies'}

Vulnerabilities to evaluate:
{json.dumps(vuln_summaries, indent=2, default=str)[:1200]}

For each vulnerability, reason about:
- Is there concrete evidence of this version in the tool output?
- Does the knowledge base show a working exploit exists?
- Can it be exploited without authentication?
- What is the attack complexity?

Return JSON array with one entry per vuln index.
Use only evidence above — do not invent:
[
  {{
    "index": 0,
    "exploitable": true,
    "confidence": "high|medium|low",
    "reasoning": "what evidence supports this"
  }}
]"""

        def _extract_json_array(text: str) -> list[dict[str, Any]] | None:
            if not text or not text.strip():
                return None

            cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
            fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", cleaned, re.DOTALL)
            if fence:
                cleaned = fence.group(1)

            for candidate in (cleaned, text.strip()):
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, list):
                        return [x for x in parsed if isinstance(x, dict)]
                except Exception:
                    pass

            starts = [m.start() for m in re.finditer(r"\[", cleaned)]
            for start in starts:
                depth = 0
                for i, ch in enumerate(cleaned[start:], start):
                    if ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            candidate = cleaned[start:i + 1]
                            try:
                                parsed = json.loads(candidate)
                                if isinstance(parsed, list):
                                    return [x for x in parsed if isinstance(x, dict)]
                            except Exception:
                                break
            return None

        # TRY LLM for exploitability reasoning with timeout
        # FIX 9: Reduced timeout to 45s
        self.log_info("Attempting LLM exploitability reasoning (45s timeout)...")
        batch_result = None
        
        try:
            raw = self._llm_with_timeout(prompt, timeout=45)  # FIX 9: Reduced from 180s
            if raw and raw.strip():
                batch_result = _extract_json_array(raw)
                if batch_result:
                    self.log_info(f"✓ LLM exploitability analysis: {len(batch_result)} vulns evaluated")
        except Exception as e:
            self.log_warning(f"LLM exploitability reasoning failed: {e}")
        
        # FALLBACK: CVSS-based heuristic
        if not batch_result:
            self.log_info("Using CVSS-based exploitability heuristic (fallback)")

        if isinstance(batch_result, list):
            result_map = {
                item.get("index"): item
                for item in batch_result
                if isinstance(item, dict)
            }
            for idx in candidate_indexes:
                vuln = vulns[idx]
                if not isinstance(vuln, dict):
                    continue
                item = result_map.get(idx, {})
                confidence = str(item.get("confidence", "low")).lower()
                llm_exploitable = bool(item.get("exploitable", False))
                grounded = _is_grounded_exploitable(vuln)

                if llm_exploitable and confidence in ["high", "medium"] and grounded:
                    vuln["exploitable"] = True
                    vuln["confidence"] = confidence
                    vuln["exploitability_reasoning"] = str(item.get("reasoning", ""))
                    try:
                        self.memory.add_vulnerability(
                            ip=self._find_ip_for_service(str(vuln.get("service", ""))),
                            cve=str(vuln.get("cve", "CVE-UNKNOWN")),
                            cvss=float(vuln.get("cvss_score", 0.0) or 0),
                            description=str(vuln.get("description", vuln.get("title", ""))),
                            exploitable=True,
                            port=vuln.get("port"),
                            service=vuln.get("service"),
                            version=vuln.get("version"),
                        )
                    except Exception:
                        pass

                    mitre = str(vuln.get("mitre_technique", "")).strip()
                    if mitre:
                        self.memory.log_action(
                            "EnumVulnAgent", "mitre_technique", mitre
                        )
                else:
                    vuln["exploitable"] = False
                    vuln["confidence"] = confidence
                    if llm_exploitable and confidence == "low":
                        self.log_info(
                            f"  ℹ️  {vuln.get('cve', '?')} skipped: low confidence"
                        )
        else:
            self.log_warning("Batch exploitability LLM failed — using CVSS fallback")
            for idx in candidate_indexes:
                vuln = vulns[idx]
                if not isinstance(vuln, dict):
                    continue
                cvss = float(vuln.get("cvss_score", 0.0) or 0)
                cve = str(vuln.get("cve", ""))
                severity = str(vuln.get("severity", "")).lower()
                confirmed = bool(vuln.get("confirmed"))
                grounded_cve = cve.startswith("CVE-") and cve.upper() in tool_evidence_upper
                if (cvss >= 7.0 and grounded_cve) or (
                    confirmed and severity in ["critical", "high"]
                ):
                    vuln["exploitable"] = True
                    vuln["confidence"] = "medium"
                    if cvss >= 7.0 and cve.startswith("CVE-"):
                        vuln["exploitability_reasoning"] = (
                            f"CVSS {cvss} >= 7.0 with confirmed CVE"
                        )
                    else:
                        vuln["exploitability_reasoning"] = (
                            f"Confirmed {severity} scanner finding"
                        )

        exploitable_count = len([v for v in vulns if isinstance(v, dict) and v.get("exploitable")])
        self.log_info(
            f"Exploitability assessment: {exploitable_count}/{len(vulns)} exploitable"
        )
        return vulns

    def _compile_vuln_report(self, analysis: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(analysis, dict):
            analysis = {}

        parsed_ports = analysis.get("ports", [])
        ports: list[dict[str, Any]] = []
        if isinstance(parsed_ports, list):
            for item in parsed_ports:
                if not isinstance(item, dict):
                    continue
                try:
                    port_num = int(item.get("port", 0))
                except Exception:
                    continue
                if not (1 <= port_num <= 65535):
                    continue
                normalized_ip = self._normalize_host_ip(
                    str(item.get("ip", self.target) or self.target)
                )
                ports.append({
                    "ip": normalized_ip,
                    "port": port_num,
                    "protocol": str(item.get("protocol", "tcp") or "tcp"),
                    "service": str(item.get("service", "unknown") or "unknown"),
                    "version": str(item.get("version", "")),
                    "banner": str(item.get("banner", "")),
                    "confidence": str(item.get("confidence", "medium")),
                })

        if not ports:
            ports = self._extract_all_ports()

        raw_vulns = analysis.get("vulnerabilities", [])
        cleaned_vulns: list[dict[str, Any]] = []
        if isinstance(raw_vulns, list):
            for vuln in raw_vulns:
                if not isinstance(vuln, dict):
                    continue
                guarded = self.hallucination_guard(dict(vuln), "vuln_scan")
                vuln_obj = guarded if isinstance(guarded, dict) else dict(vuln)
                severity = str(vuln_obj.get("severity", "info")).lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    vuln_obj["severity"] = "info"
                cleaned_vulns.append(vuln_obj)

        cleaned_vulns = self._batch_exploitability_reasoning(cleaned_vulns)

        self.vulnerabilities = cleaned_vulns

        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in severity_order}
        for vuln in cleaned_vulns:
            sev = str(vuln.get("severity", "info")).lower()
            if sev not in grouped:
                sev = "info"
            grouped[sev].append(vuln)
        stats = {s: len(grouped[s]) for s in severity_order}

        services: dict[str, str] = {}
        for p in ports:
            service = str(p.get("service", "")).strip()
            version = str(p.get("version", "")).strip()
            if not service:
                continue
            if service not in services or (version and not services[service]):
                services[service] = version
        if not services:
            services = self._extract_all_services()

        table = Table(title=f"Vulnerability Report — {self.target}", border_style="magenta")
        table.add_column("Critical", justify="right", style="bold red")
        table.add_column("High", justify="right", style="red")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="cyan")
        table.add_column("Info", justify="right", style="white")
        table.add_column("Total", justify="right", style="bold")
        table.add_row(
            str(stats["critical"]),
            str(stats["high"]),
            str(stats["medium"]),
            str(stats["low"]),
            str(stats["info"]),
            str(sum(stats.values())),
        )
        self.console.print(table)

        color_map = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "white",
        }
        for sev in severity_order:
            for vuln in grouped[sev]:
                title = str(vuln.get("title", "Unnamed finding"))
                cve = str(vuln.get("cve", "CVE-UNKNOWN"))
                self.console.print(f"[{color_map[sev]}]{sev.upper()}[/] {title} ({cve})")

        mitre_chain: list[str] = []
        if isinstance(analysis.get("mitre_chain"), list):
            mitre_chain.extend([str(x) for x in analysis.get("mitre_chain", []) if x])
        for vuln in cleaned_vulns:
            tid = str(vuln.get("mitre_technique", "")).strip()
            if tid:
                mitre_chain.append(tid)
        mitre_chain.extend([str(x) for x in self.memory.state.get("mitre_techniques", []) if x])

        dedup_chain: list[str] = []
        seen_chain: set[str] = set()
        for item in mitre_chain:
            if item in seen_chain:
                continue
            seen_chain.add(item)
            dedup_chain.append(item)

        risk_score = "low"
        if stats["critical"] > 0:
            risk_score = "critical"
        elif stats["high"] > 0:
            risk_score = "high"
        elif stats["medium"] > 0:
            risk_score = "medium"

        # TRY LLM for critical path analysis with timeout
        attack_summary = {}
        
        if cleaned_vulns:
            # Build prompt for LLM attack path analysis
            vuln_summary = json.dumps(
                [{"cve": v.get("cve"), "service": v.get("service"), 
                  "cvss": v.get("cvss_score"), "exploitable": v.get("exploitable")}
                 for v in cleaned_vulns[:10]],
                indent=2
            )
            
            attack_prompt = f"""Given these vulnerabilities on target {self.target}:
{vuln_summary}

Recommend the optimal attack path. Consider:
1. Which vulnerability gives initial access fastest?
2. What's the escalation path to root?
3. Which exploits are most reliable?

Return JSON:
{{"critical_path":{{"service":"","port":0,"cve":"","why_first":""}},
"attack_sequence":["step1","step2"],"confidence":"high|medium|low"}}"""
            
            try:
                # FIX 9: Reduced timeout from 180s to 60s (attack path)
                self.log_info("Attempting LLM attack path analysis (60s timeout)...")
                raw = self._llm_with_timeout(attack_prompt, timeout=60)
                if raw:
                    llm_attack = self._extract_json_robust(raw)
                    if llm_attack and isinstance(llm_attack, dict) and llm_attack.get("critical_path"):
                        attack_summary = llm_attack
                        self.log_info("✓ LLM attack path analysis complete")
            except Exception as e:
                self.log_warning(f"LLM attack path analysis failed: {e}")
            
            # FALLBACK: Build attack path from sorted vulns by severity and exploitability
            if not attack_summary:
                self.log_info("Using heuristic attack path (fallback)")
                # Sort vulns: exploitable first, then by CVSS score
                sorted_vulns = sorted(
                    [v for v in cleaned_vulns if isinstance(v, dict)],
                    key=lambda v: (
                        not v.get("exploitable", False),  # exploitable first
                        -float(v.get("cvss_score", 0) or 0),  # higher CVSS first
                    ),
                )
                
                if sorted_vulns:
                    top = sorted_vulns[0]
                    attack_summary = {
                        "critical_path": {
                            "service": str(top.get("service", "unknown")),
                            "port": int(top.get("port", 0) or 0),
                            "cve": str(top.get("cve", "CVE-UNKNOWN")),
                            "confidence": str(top.get("confidence", "medium")),
                            "why_first": f"Highest priority: CVSS {top.get('cvss_score', 0)}, exploitable={top.get('exploitable')}",
                        },
                        "all_attack_vectors": [
                            {
                                "service": str(v.get("service", "")),
                                "vector_type": str(v.get("title", "")),
                                "priority": i + 1,
                                "requires": "standard exploitation",
                            }
                            for i, v in enumerate(sorted_vulns[:5])
                        ],
                        "recommended_exploits": [
                            str(v.get("cve", "")) for v in sorted_vulns[:3]
                            if v.get("cve", "").startswith("CVE-")
                        ],
                    "evasion_needed": bool(self._security_controls.get("firewall")),
                    "exploitation_guidance": f"Target {len([v for v in sorted_vulns if v.get('exploitable')])} exploitable vulns in priority order",
                }

        result = {
            "agent": "EnumVulnAgent",
            "success": True,
            "result": {
                "target": self.target,
                "ports_found": ports,
                "services_found": len(services),
                "services": services,
                "vulnerabilities": cleaned_vulns,
                "vuln_count_by_severity": stats,
                "exploitable_vulns": len([v for v in cleaned_vulns if v.get("exploitable")]),
                "summary": str(analysis.get("risk_summary", "")),
                "attack_priority": "",
                "recommended_next": "exploit" if any(v.get("exploitable") for v in cleaned_vulns) else "further_validation",
                "risk_score": risk_score,
                "mitre_attack_chain": dedup_chain,
                "iterations_completed": self.iteration,
                "tools_used": list(self.all_results.keys()),
                "critical_path": attack_summary.get("critical_path", {}),
                "all_attack_vectors": attack_summary.get("all_attack_vectors", []),
                "recommended_exploits": attack_summary.get("recommended_exploits", []),
                "security_controls": self._security_controls,
                "exploitation_guidance": attack_summary.get("exploitation_guidance", ""),
                "intelligence_log": self.intelligence_log,
            },
            "raw_outputs": self.all_results,
        }

        # Store full enumeration context in ChromaDB for ExploitationAgent
        try:
            self.chroma.store_mission_finding(
                mission_id=self.memory.mission_id,
                agent="EnumVulnAgent",
                finding=self._build_full_output_summary(),
                metadata={
                    "type": "enumeration_complete",
                    "target": self.target,
                    "ports_found": len(ports),
                    "vulns_found": len(cleaned_vulns),
                    "exploitable_count": len([
                        v for v in cleaned_vulns if v.get("exploitable")
                    ]),
                },
            )
        except Exception as e:
            self.log_warning(f"Failed to store enumeration findings in ChromaDB: {e}")

        return result

    def _write_findings_to_memory(self, findings: dict[str, Any]):
        result = findings.get("result", {}) if isinstance(findings, dict) else {}
        ports = result.get("ports_found", []) if isinstance(result, dict) else []
        vulns = result.get("vulnerabilities", []) if isinstance(result, dict) else []
        mitre_chain = result.get("mitre_attack_chain", []) if isinstance(result, dict) else []

        for port_info in ports if isinstance(ports, list) else []:
            if not isinstance(port_info, dict):
                continue
            try:
                resolved_ip = self._normalize_host_ip(
                    str(port_info.get("ip", self.target))
                )
                self.memory.add_port(
                    ip=resolved_ip,
                    port=int(port_info.get("port", 0)),
                    service=str(port_info.get("service", "unknown")),
                    version=str(port_info.get("version", "")),
                    banner=str(port_info.get("banner", "")),
                )
            except Exception as e:
                self.log_warning(f"Failed to persist port finding: {e}")

        for vuln in vulns if isinstance(vulns, list) else []:
            if not isinstance(vuln, dict):
                continue
            try:
                self.memory.add_vulnerability(
                    ip=self._find_ip_for_service(str(vuln.get("service", ""))),
                    cve=str(vuln.get("cve", "CVE-UNKNOWN")),
                    cvss=float(vuln.get("cvss_score", 0.0) or 0.0),
                    description=str(vuln.get("title", vuln.get("description", "Potential vulnerability"))),
                    exploitable=bool(vuln.get("exploitable", False)),
                    port=vuln.get("port"),
                    service=vuln.get("service"),
                    version=vuln.get("version"),
                )
            except Exception as e:
                self.log_warning(f"Failed to persist vulnerability: {e}")

        for technique in mitre_chain if isinstance(mitre_chain, list) else []:
            if not technique:
                continue
            tid = str(technique)
            self.memory.add_mitre_technique(tid)
            self.memory.log_action("EnumVulnAgent", "mitre_technique", tid)

        self.memory.save_state()

    # ── Helpers: formatting + extraction ──────────────────────────────────────

    def _format_recon_for_llm(self) -> str:
        """Format recon context for LLM in <= 400 chars."""
        hosts = self.recon_findings.get("hosts", {}) if isinstance(self.recon_findings, dict) else {}
        ips = list(hosts.keys())[:5]
        techs = self._extract_tech_names()[:8]

        osint_items = self.recon_findings.get("osint_context", []) if isinstance(self.recon_findings, dict) else []
        osint_preview_parts: list[str] = []
        if isinstance(osint_items, list):
            for entry in osint_items[:3]:
                text = str(entry.get("text", "")).strip() if isinstance(entry, dict) else str(entry)
                if text:
                    osint_preview_parts.append(text[:60])

        summary = (
            f"hosts={ips}; tech={techs}; "
            f"mission_ctx={'; '.join(osint_preview_parts) if osint_preview_parts else 'none'}"
        )
        return summary[:400]

    def _extract_tech_names(self) -> list[str]:
        """Extract and deduplicate technology names from recon and accumulated findings."""
        names: list[str] = []

        for host_data in self.attack_surface.values():
            for tech in host_data.get("technologies", []) if isinstance(host_data, dict) else []:
                if isinstance(tech, dict):
                    candidate = str(tech.get("name", "")).strip()
                else:
                    candidate = str(tech).strip()
                if candidate:
                    names.append(candidate)

        for item in self.recon_findings.get("tech_findings", []) if isinstance(self.recon_findings, dict) else []:
            result = str(item.get("result", "")).strip() if isinstance(item, dict) else str(item).strip()
            if not result:
                continue
            token = re.split(r"\s+|/", result)[0]
            if token:
                names.append(token)

        version_map = self._extract_versions_from_outputs(self.all_results)
        names.extend(version_map.keys())

        dedup: list[str] = []
        seen: set[str] = set()
        for name in names:
            key = name.lower().strip()
            if not key or key in seen:
                continue
            seen.add(key)
            dedup.append(name.strip())
        return dedup

    def _build_adaptive_rag_query(self, context: dict[str, Any]) -> str:
        """Build adaptive RAG query based on current evidence + open questions."""
        ports = self._extract_all_ports()
        services = self._extract_all_services()
        techs = self._extract_tech_names()
        questions = context.get("open_questions", []) if isinstance(context, dict) else []
        questions_text = " ".join([str(q) for q in questions[:2]])

        if not ports:
            return "active enumeration port scan linux service discovery"

        components = [
            "active enumeration",
            " ".join(list(services.keys())[:5]),
            " ".join(techs[:4]),
            questions_text,
            "vulnerability exploit misconfiguration",
        ]
        query = " ".join([c for c in components if c]).strip()
        return query[:240]

    def _query_cve_for_confirmed_services(self) -> str:
        """Query cve_database for confirmed services and versions."""
        services = self._extract_all_services()
        if not services:
            return ""

        lines: list[str] = []
        for service, version in list(services.items())[:6]:
            query = f"{service} {version} CVE".strip()
            try:
                hits = self.chroma.get_rag_context(query, collections=["cve_database"], n=2)
                for hit in hits:
                    snippet = str(hit.get("text", ""))[:140]
                    if snippet:
                        lines.append(f"[{service} {version}] {snippet}")
            except Exception as e:
                self.log_warning(f"CVE query failed for '{query}': {e}")
        return "\n".join(lines)[:800]

    def _query_nuclei_templates(self) -> str:
        """Query nuclei_templates relevant to current technologies."""
        techs = self._extract_tech_names()
        if not techs:
            techs = list(self._extract_all_services().keys())

        lines: list[str] = []
        for tech in techs[:6]:
            try:
                hits = self.chroma.get_rag_context(
                    f"{tech} nuclei template",
                    collections=["nuclei_templates"],
                    n=2,
                )
                for hit in hits:
                    snippet = str(hit.get("text", "")).replace("\n", " ")[:120]
                    if snippet:
                        lines.append(f"[{tech}] {snippet}")
            except Exception as e:
                self.log_warning(f"Nuclei query failed for '{tech}': {e}")

        return "\n".join(lines)[:700]

    def _extract_versions_from_outputs(self, results: dict[str, str]) -> dict[str, str]:
        """Regex-extract common service/version pairs from tool outputs."""
        patterns = {
            "Apache": r"Apache[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "nginx": r"nginx[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "PHP": r"PHP[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "OpenSSH": r"OpenSSH[\s/_-]*([0-9]+(?:\.[0-9p]+)+)",
            "MySQL": r"MySQL[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "PostgreSQL": r"PostgreSQL[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "vsftpd": r"vsftpd[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "ProFTPD": r"ProFTPD[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "Samba": r"Samba[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
            "IIS": r"Microsoft-IIS[\s/_-]*([0-9]+(?:\.[0-9a-zA-Z]+)+)",
        }

        found: dict[str, str] = {}
        for output in results.values():
            if not output:
                continue

            for service, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
                    if version and service not in found:
                        found[service] = version

            for m in re.finditer(
                r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+([a-zA-Z0-9\-_]+)\s*(.*)$",
                output,
            ):
                service = m.group(3).strip()
                tail = m.group(4).strip()
                if tail and service and service not in found:
                    version_guess = tail.split(" ")[0][:40]
                    if re.search(r"\d", version_guess):
                        found[service] = version_guess

        return found

    def _summarize_batch_for_llm(self, results: dict[str, str]) -> str:
        """Compact but information-rich tool output summary for LLM analysis."""
        blocks: list[str] = []
        for key, output in results.items():
            preview = (output or "").replace("\n", " ")[:450]
            blocks.append(f"{key}:\n{preview}\n")
        summary = "\n".join(blocks)
        return summary[:3000]

    def _extract_versions_from_all_outputs(self) -> dict[str, str]:
        """Convenience wrapper to extract versions from accumulated outputs."""
        return self._extract_versions_from_outputs(self.all_results)

    def _build_full_output_summary(self) -> str:
        """
        Build a compact, signal-heavy summary from all gathered tool outputs.
        """
        important_lines: list[str] = []
        patterns = [
            r"\d+/tcp\s+open",
            r"\d+/udp\s+open",
            r"[Vv]ersion[:\s]+\S+",
            r"CVE-\d{4}-\d{4,7}",
            r"\bVULNERABLE\b",
            r"[Ee]xploit",
            r"\bcritical\b|\bhigh\b",
            r"\b401\b|\b403\b|\b500\b",
            r"[Aa]uth",
        ]

        for tool_name, output in self.all_results.items():
            tool_label = tool_name.split("::")[-1]
            for raw_line in str(output).splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if any(re.search(p, line) for p in patterns):
                    important_lines.append(f"[{tool_label}] {line[:110]}")

        for tool_name, output in list(self.all_results.items())[:4]:
            tool_label = tool_name.split("::")[-1]
            for raw_line in str(output).splitlines()[:5]:
                line = raw_line.strip()
                if not line:
                    continue
                entry = f"[{tool_label}] {line[:100]}"
                if entry not in important_lines:
                    important_lines.append(entry)

        summary = "\n".join(important_lines[:35])
        return summary[:1500]

    def _build_evidence_summary(self) -> str:
        """One-paragraph summary of collected evidence (max 300 chars)."""
        ports = self._extract_all_ports()
        services = self._extract_all_services()
        techs = self._extract_tech_names()
        exploitable = len([v for v in self.vulnerabilities if v.get("exploitable")])
        summary = (
            f"ports={len(ports)}:{[p.get('port') for p in ports[:6]]}; "
            f"services={list(services.keys())[:6]}; techs={techs[:6]}; "
            f"vulns={len(self.vulnerabilities)}; exploitable={exploitable}"
        )
        return summary[:300]

    def _update_context(
        self,
        context: dict[str, Any],
        batch_results: dict[str, str],
        analysis: dict[str, Any],
        new_vulns: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Merge new findings into iterative context."""
        updated = dict(context)

        completed_tools = list(updated.get("completed_tools", []))
        completed_tools.extend(list(batch_results.keys()))
        updated["completed_tools"] = list(dict.fromkeys(completed_tools))

        key_findings = list(updated.get("key_findings", []))
        for port in analysis.get("ports_found", []) if isinstance(analysis, dict) else []:
            if isinstance(port, dict):
                key_findings.append(f"port:{port.get('port')}/{port.get('service')}")
        for vuln in new_vulns:
            key_findings.append(str(vuln.get("title", "vulnerability")))
        updated["key_findings"] = list(dict.fromkeys(key_findings))[-20:]

        open_questions = list(updated.get("open_questions", []))
        if isinstance(analysis, dict) and isinstance(analysis.get("open_questions"), list):
            open_questions.extend([str(q) for q in analysis.get("open_questions", [])])
        if not open_questions:
            open_questions = ["Validate service versions and confirm exploitability"]
        updated["open_questions"] = list(dict.fromkeys(open_questions))[-8:]

        new_hypotheses = list(updated.get("new_hypotheses", []))
        if isinstance(analysis, dict) and isinstance(analysis.get("new_attack_vectors"), list):
            new_hypotheses.extend([str(x) for x in analysis.get("new_attack_vectors", [])])
        updated["new_hypotheses"] = list(dict.fromkeys(new_hypotheses))[-10:]

        return updated

    def _store_iteration_findings(self, analysis: dict[str, Any], vulns: list[dict[str, Any]]):
        """Persist per-iteration findings into MissionMemory."""
        for port_info in analysis.get("ports_found", []) if isinstance(analysis, dict) else []:
            if not isinstance(port_info, dict):
                continue
            try:
                resolved_ip = self._normalize_host_ip(
                    str(port_info.get("ip", self.target))
                )
                self.memory.add_port(
                    ip=resolved_ip,
                    port=int(port_info.get("port", 0)),
                    service=str(port_info.get("service", "unknown")),
                    version=str(port_info.get("version", "")),
                    banner=str(port_info.get("banner", "")),
                )
            except Exception as e:
                self.log_warning(f"Failed to store iteration port: {e}")

        for tech in analysis.get("technologies", []) if isinstance(analysis, dict) else []:
            if not isinstance(tech, dict):
                continue
            label = f"{tech.get('name', '')} {tech.get('version', '')}".strip()
            if label:
                self.memory.log_action("EnumVulnAgent", "technology_confirmed", label)

        for technique in analysis.get("mitre_techniques_observed", []) if isinstance(analysis, dict) else []:
            if not technique:
                continue
            tid = str(technique)
            self.memory.add_mitre_technique(tid)
            self.memory.log_action("EnumVulnAgent", "mitre_technique", tid)

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            tid = str(vuln.get("mitre_technique", "")).strip()
            if tid:
                self.memory.add_mitre_technique(tid)

        self.memory.save_state()

    def _extract_all_ports(self) -> list[dict[str, Any]]:
        """Parse and deduplicate ports from all raw outputs."""
        seen: set[tuple[str, int, str]] = set()
        ports: list[dict[str, Any]] = []
        normalized_target_ip = self._normalize_host_ip(self.target)

        for output in self.all_results.values():
            if not output:
                continue

            for match in re.finditer(
                r"(?m)^(\d{1,5})/(tcp|udp)\s+open(?:\|filtered)?\s+([a-zA-Z0-9\-_\.]+)\s*(.*)$",
                output,
            ):
                port = int(match.group(1))
                proto = match.group(2)
                service = match.group(3).strip() or "unknown"
                version = match.group(4).strip()[:100]
                ip = normalized_target_ip
                key = (ip, port, proto)
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "ip": ip,
                    "port": port,
                    "protocol": proto,
                    "service": service,
                    "version": version,
                    "banner": "",
                })

            # Generic fallback parsing: "port 80" + service mention
            for match in re.finditer(r"(?i)port\s+(\d{1,5})", output):
                port = int(match.group(1))
                if not (1 <= port <= 65535):
                    continue
                key = (normalized_target_ip, port, "tcp")
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "ip": normalized_target_ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "unknown",
                    "version": "",
                    "banner": "",
                })

        # Merge known ports from attack surface in case they were not in raw outputs
        for ip, host_data in self.attack_surface.items():
            for p in host_data.get("ports", []) if isinstance(host_data, dict) else []:
                if not isinstance(p, dict):
                    continue
                try:
                    port = int(p.get("port", 0))
                except Exception:
                    continue
                if not (1 <= port <= 65535):
                    continue
                normalized_ip = self._normalize_host_ip(str(ip))
                key = (normalized_ip, port, "tcp")
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "ip": normalized_ip,
                    "port": port,
                    "protocol": str(p.get("protocol", "tcp") or "tcp"),
                    "service": str(p.get("service", "unknown")),
                    "version": str(p.get("version", "")),
                    "banner": str(p.get("banner", "")),
                })

        return sorted(ports, key=lambda x: int(x.get("port", 0)))

    def _extract_all_services(self) -> dict[str, str]:
        """Build service->version map from confirmed findings."""
        services: dict[str, str] = {}

        for port_info in self._extract_all_ports():
            service = str(port_info.get("service", "")).strip()
            version = str(port_info.get("version", "")).strip()
            if not service:
                continue
            if service not in services or (version and not services[service]):
                services[service] = version

        for service, version in self._extract_versions_from_outputs(self.all_results).items():
            if service not in services or (version and not services[service]):
                services[service] = version

        return services

    def _normalize_host_ip(self, raw_host: str | None) -> str:
        """
        Normalize a host identifier to an IPv4 key from attack_surface when possible.
        """
        candidate = str(raw_host or "").strip()
        ip_pattern = r"^\d{1,3}(?:\.\d{1,3}){3}$"

        if re.match(ip_pattern, candidate):
            return candidate

        target = str(self.target or "").strip()
        candidate_l = candidate.lower()
        target_l = target.lower()

        for ip_addr, host_data in self.attack_surface.items():
            ip_str = str(ip_addr).strip()
            if not re.match(ip_pattern, ip_str):
                continue

            hostname = ""
            if isinstance(host_data, dict):
                hostname = str(host_data.get("hostname", "")).strip().lower()

            if candidate_l in {hostname, target_l} or candidate_l == ip_str.lower():
                return ip_str

        if re.match(ip_pattern, target):
            return target

        for ip_addr in self.attack_surface.keys():
            ip_str = str(ip_addr).strip()
            if re.match(ip_pattern, ip_str):
                return ip_str

        return candidate or target

    def _find_ip_for_service(self, service: str) -> str:
        """Resolve host IP for service context, fallback to target."""
        service_l = str(service).lower().strip()
        if not service_l:
            return self._normalize_host_ip(self.target)

        for ip, host_data in self.attack_surface.items():
            ports = host_data.get("ports", []) if isinstance(host_data, dict) else []
            for p in ports:
                if not isinstance(p, dict):
                    continue
                if service_l in str(p.get("service", "")).lower():
                    return self._normalize_host_ip(str(ip))

        return self._normalize_host_ip(self.target)

    def _format_rag(self, results: list[dict[str, Any]], max_chars: int = 500) -> str:
        """Compact formatting for RAG snippets."""
        if not results:
            return ""
        chunks: list[str] = []
        total = 0
        for item in results:
            text = str(item.get("text", "")).replace("\n", " ")[:150]
            source = str(item.get("source_collection", "rag"))
            line = f"[{source}] {text}"
            if total + len(line) > max_chars:
                break
            chunks.append(line)
            total += len(line)
        return "\n".join(chunks)

    def _fallback_tool_batch(self) -> list[dict[str, Any]]:
        """Minimal safe fallback when LLM planning fails."""
        return [{
            "purpose": "tcp port scan",
            "tool_hint": "nmap",
            "target": self.target,
            "approach": "fast scan",
            "priority": "high",
            "_resolved_args": [self.target],
            "_timeout": self._get_tool_timeout("fast scan"),
        }]

    def _has_port_findings(self) -> bool:
        """Return True when prior outputs already include open-port evidence."""
        for output in self.all_results.values():
            if re.search(r"\d+/tcp\s+open", str(output)):
                return True
        return False

    def _should_skip_llm_enum_loop(self) -> bool:
        """
        Decide whether deterministic gather already produced enough signal.
        """
        port_services = self._extract_port_services()
        if not port_services:
            return False

        high_risk_ports = {21, 23, 139, 445, 512, 513, 514, 1099, 1524, 2049, 3306, 5432, 5900, 6667, 8180}
        if any(p in high_risk_ports for p in port_services.keys()):
            return True

        if len(port_services) >= 8:
            return True

        all_output = "\n".join(str(v) for v in self.all_results.values()).lower()
        signatures = [
            "vsftpd 2.3.4",
            "samba 3.0.",
            "unrealircd",
            "distccd",
            "anonymous ftp login allowed",
            "backdoor",
        ]
        return any(sig in all_output for sig in signatures)

    def _run_subprocess_fallback(
        self,
        tool_hint: str,
        context: dict[str, Any],
        timeout: int,
    ) -> tuple[str, str]:
        """Direct subprocess fallback when use_intelligent() is unavailable."""
        candidate = str(tool_hint).strip().split()[0] if tool_hint else ""
        path = self.tools.find(candidate) if candidate else None

        if not path:
            try:
                alternatives = self.tools.get_tools_for_purpose(str(context.get("purpose", "enumeration")))
            except Exception as e:
                self.log_warning(f"Fallback alternatives lookup failed: {e}")
                alternatives = []

            for alt in alternatives:
                path = self.tools.find(str(alt))
                if path:
                    candidate = str(alt)
                    break

        if not path:
            return candidate or "unknown", "[TOOL_NOT_AVAILABLE]"

        target = str(context.get("target", self.target)).strip()
        cmd = [path]
        if target:
            cmd.append(target)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = proc.stdout or proc.stderr or ""
            if proc.returncode != 0 and not output:
                output = f"[ERROR] return code {proc.returncode}"
            self.memory.log_action("EnumVulnAgent", f"fallback_{candidate}", output[:300])
            return Path(path).name, output[:5000]
        except subprocess.TimeoutExpired:
            return Path(path).name, f"[TIMEOUT after {timeout}s]"
        except Exception as e:
            return Path(path).name, f"[ERROR] {e}"

    def _regex_analysis_fallback(self, batch_results: dict[str, str] | None = None) -> dict[str, Any]:
        """
        Analyze outputs with regex + RAG when LLM analysis is unavailable.
        """
        outputs = batch_results if isinstance(batch_results, dict) else self.all_results
        # Strip ANSI escape codes before parsing
        # Nuclei embeds color codes even with -silent flag
        _raw = "\n".join(str(v) for v in outputs.values())
        all_output = re.sub(
            r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', _raw
        )

        ports: list[dict[str, Any]] = []
        seen_ports: set[int] = set()
        for m in re.finditer(r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+([a-zA-Z0-9\-_\.]+)\s*(.*)$", all_output):
            port_num = int(m.group(1))
            if port_num in seen_ports:
                continue
            seen_ports.add(port_num)
            ports.append({
                "ip": self._normalize_host_ip(self.target),
                "port": port_num,
                "protocol": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip()[:80],
                "banner": "",
                "confidence": "high",
            })

        versions = self._extract_versions_from_outputs(outputs)
        vulnerabilities: list[dict[str, Any]] = []
        seen_cves: set[str] = set()
        nuclei_pattern = re.compile(
            r"(?m)^\s*\[([A-Za-z0-9_\-\.]+)\]\s*"
            r"\[([a-z]+)\]\s*"
            r"\[(critical|high|medium|low|info)\]\s*"
            r"(https?://\S+)?",
            re.IGNORECASE,
        )
        cvss_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        seen_nuclei: set[str] = set()

        # Use sanitized all_output to avoid ANSI issues
        for output in [all_output]:
            for m in nuclei_pattern.finditer(str(output)):
                template = m.group(1).strip()
                protocol = m.group(2).strip().lower()
                severity = m.group(3).strip().lower()
                url = (m.group(4) or "").strip()
                cvss = float(cvss_map.get(severity, 0.0))

                cve_match = re.search(r"CVE-(\d{4})-(\d{4,7})", template, re.IGNORECASE)
                cve_id = (
                    f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
                    if cve_match else "CVE-UNKNOWN"
                )

                key = f"{template}:{url}"
                if key in seen_nuclei:
                    continue
                seen_nuclei.add(key)

                if cve_id != "CVE-UNKNOWN":
                    seen_cves.add(cve_id)

                # Try to extract port from URL
                port = 0
                if url:
                    port_match = re.search(r':(\d+)', url)
                    if port_match:
                        port = int(port_match.group(1))
                    elif 'https://' in url:
                        port = 443
                    elif 'http://' in url:
                        port = 80

                vulnerabilities.append({
                    "title": f"Nuclei: {template}",
                    "service": protocol,
                    "cve": cve_id,
                    "cvss_score": cvss,
                    "severity": severity,
                    "confirmed": True,
                    "evidence": f"Nuclei confirmed: {url or template}",
                    "exploitable": severity in ["critical", "high"],
                    "exploit_available": cve_id != "CVE-UNKNOWN",
                    "mitre_technique": "T1190",
                    "port": port if port else None,
                })

        # Detect backdoor/critical services from nmap output
        backdoor_patterns = [
            (r'vsftpd\s+2\.3\.4', 'vsftpd 2.3.4 backdoor',
             'CVE-2011-2523', 9.8, 'ftp'),
            (r'Bash\s+shell.*BACKDOOR', 'bindshell root backdoor',
             'CVE-UNKNOWN', 10.0, 'bindshell'),
            (r'UnrealIRCd.*3\.2', 'UnrealIRCd backdoor',
             'CVE-2010-2075', 9.8, 'irc'),
            (r'distccd.*4\.2', 'distccd remote code execution',
             'CVE-2004-2687', 9.3, 'distccd'),
            (r'Samba.*3\.0\.(1[0-9]|20)', 'Samba username map RCE',
             'CVE-2007-2447', 10.0, 'smb'),
        ]
        
        # Map services to their typical ports
        service_port_map = {
            "ftp": 21,
            "ssh": 22,
            "telnet": 23,
            "smtp": 25,
            "http": 80,
            "smb": 445,
            "irc": 6667,
            "distccd": 3632,
            "java-rmi": 1099,
            "mysql": 3306,
            "postgresql": 5432,
            "vnc": 5900,
            "tomcat": 8180,
            "bindshell": 1524,
            "rexec": 512,
            "rlogin": 513,
            "rsh": 514,
            "nfs": 2049,
        }
        
        # Build port lookup from discovered ports
        port_by_service: dict[str, int] = {}
        version_by_port: dict[int, str] = {}
        for p in ports:
            svc = str(p.get("service", "")).lower()
            pnum = int(p.get("port", 0) or 0)
            ver = str(p.get("version", ""))
            if svc and pnum:
                port_by_service[svc] = pnum
            if pnum and ver:
                version_by_port[pnum] = ver
        
        for pattern, title, cve, cvss, service in backdoor_patterns:
            for output in outputs.values():
                if re.search(pattern, str(output), re.IGNORECASE):
                    cve_key = f"{cve}:{service}"
                    if cve_key in seen_cves:
                        continue
                    seen_cves.add(cve_key)
                    # Get port from discovered ports or default
                    port = port_by_service.get(service, service_port_map.get(service, 0))
                    version = version_by_port.get(port, "")
                    vulnerabilities.append({
                        "title": title,
                        "service": service,
                        "cve": cve,
                        "cvss_score": cvss,
                        "severity": "critical",
                        "confirmed": True,
                        "evidence": f"Version string detected in scan output",
                        "exploitable": True,
                        "mitre_technique": "T1190",
                        "port": port,
                        "version": version,
                    })
                    break

        for service, version in list(versions.items())[:6]:
            try:
                cve_hits = self.chroma.get_rag_context(
                    f"{service} {version} CVE exploit vulnerability",
                    collections=["cve_database", "exploitdb"],
                    n=3,
                )
            except Exception as e:
                self.log_warning(f"Regex fallback CVE lookup failed for '{service} {version}': {e}")
                cve_hits = []

            matched = False
            for hit in cve_hits:
                text = str(hit.get("text", ""))
                cve_match = re.search(r"CVE-(\d{4})-(\d{4,7})", text)
                if not cve_match:
                    continue
                # Keep only CVEs whose affected-version text matches detected service version.
                if version and not self._version_matches(version, text):
                    continue
                cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                cvss_match = re.search(r"(?:cvss|score)[:\s]+(\d+(?:\.\d+)?)", text, re.IGNORECASE)
                cvss = float(cvss_match.group(1)) if cvss_match else 0.0
                cvss = min(10.0, max(0.0, cvss))
                if cvss >= 9.0:
                    severity = "critical"
                elif cvss >= 7.0:
                    severity = "high"
                elif cvss >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

                vulnerabilities.append({
                    "title": f"{service} {version} vulnerability",
                    "service": service,
                    "cve": cve_id,
                    "cvss_score": cvss,
                    "severity": severity,
                    "confirmed": False,
                    "evidence": f"Version {service} {version} detected in gathered outputs",
                    "exploitable": cvss >= 9.0,
                    "mitre_technique": "T1190",
                })
                matched = True

            if not matched:
                vulnerabilities.append({
                    "title": f"Potential {service} exposure",
                    "service": service,
                    "cve": "CVE-UNKNOWN",
                    "cvss_score": 0.0,
                    "severity": "medium",
                    "confirmed": False,
                    "evidence": f"Detected version: {service} {version}",
                    "exploitable": False,
                    "mitre_technique": "T1190",
                })

        misconfigurations: list[dict[str, Any]] = []
        if re.search(r"(?i)anonymous\s+ftp\s+login\s+allowed", all_output):
            misconfigurations.append({
                "type": "anonymous_ftp",
                "service": "ftp",
                "detail": "Anonymous FTP login appears enabled",
            })
        if re.search(r"(?i)\bwebdav\b", all_output):
            misconfigurations.append({
                "type": "webdav_enabled",
                "service": "http",
                "detail": "WebDAV appears exposed",
            })

        # ── Build AttackGraph from exploitable vulns ──────────────────────
        # Confidence scoring:
        #   nuclei confirmed → 1.0
        #   backdoor pattern match → 0.85
        #   CVSS >= 9.0 + CVE → 0.8
        #   CVSS >= 7.0 + CVE → 0.6
        # Impact mapping:
        #   bindshell/backdoor → "root"
        #   vsftpd backdoor → "root"
        #   Samba usermap → "root"
        #   distccd → "user"
        #   MySQL empty root → "service"
        #   PHP CGI → "user"
        _IMPACT_MAP = {
            "bindshell": "root",
            "vsftpd": "root",
            "unrealircd": "root",
            "samba": "root",
            "smb": "root",
            "distccd": "user",
            "mysql": "service",
            "php": "user",
            "http": "user",
        }
        target_ip = self._normalize_host_ip(self.target)
        
        for vuln in vulnerabilities:
            if not vuln.get("exploitable"):
                continue
            
            # Determine confidence
            evidence = vuln.get("evidence", "")
            title = vuln.get("title", "").lower()
            cvss = float(vuln.get("cvss_score", 0))
            cve = vuln.get("cve", "CVE-UNKNOWN")
            service = vuln.get("service", "unknown").lower()
            
            if "nuclei confirmed" in evidence.lower() or vuln.get("confirmed"):
                confidence = 1.0
            elif any(kw in title for kw in ["backdoor", "bindshell", "unrealircd"]):
                confidence = 0.85
            elif cvss >= 9.0 and cve != "CVE-UNKNOWN":
                confidence = 0.8
            elif cvss >= 7.0 and cve != "CVE-UNKNOWN":
                confidence = 0.6
            else:
                confidence = 0.5
            
            # Determine impact
            impact = "user"  # default
            for svc_key, imp_val in _IMPACT_MAP.items():
                if svc_key in service or svc_key in title:
                    impact = imp_val
                    break
            # Special backdoor detection
            if "backdoor" in title or "bindshell" in title:
                impact = "root"
            
            # Find port for this service from extracted ports
            vuln_port = 0
            for p in ports:
                if p.get("service", "").lower() == service:
                    vuln_port = p.get("port", 0)
                    break
            # Fallback port mapping
            if not vuln_port:
                _SERVICE_PORTS = {
                    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
                    "http": 80, "smb": 445, "samba": 445, "mysql": 3306,
                    "distccd": 3632, "irc": 6667,
                }
                vuln_port = _SERVICE_PORTS.get(service, 0)
            
            version = ""
            # Try to extract version from evidence/title
            import re as _re
            ver_match = _re.search(r'(\d+\.\d+(?:\.\d+)?)', evidence + " " + title)
            if ver_match:
                version = ver_match.group(1)
            
            # Add to attack graph
            try:
                self.memory.add_attack_node(
                    ip=target_ip,
                    port=vuln_port,
                    service=service,
                    version=version,
                    cve=cve,
                    confidence=confidence,
                    impact=impact,
                    evidence=evidence[:200] if evidence else title[:100],
                )
            except Exception as e:
                self.log_warning(f"Failed to add attack node: {e}")

        return {
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "risk_summary": f"Found {len(ports)} open port(s), {len(vulnerabilities)} potential vulnerabilit(y/ies).",
            "mitre_chain": ["T1046", "T1190"] if ports else ["T1046"],
        }

    def _regex_fallback_analysis(self, batch_results: dict[str, str]) -> dict[str, Any]:
        """Compatibility alias for legacy call-sites."""
        return self._regex_analysis_fallback(batch_results)

    def _resolve_tool_timeout(self, purpose: str, tool_hint: str) -> int:
        """Compatibility shim for older call-sites."""
        return self._get_tool_timeout(f"{purpose} {tool_hint}")

    # ── JSON extraction + LLM timeout helpers ─────────────────────────────────

    def _extract_json_robust(self, text: str) -> dict[str, Any] | None:
        """
        Bulletproof JSON extraction from DeepSeek-R1/Qwen output.

        Same 7-step extractor used by OrchestratorAgent.
        """
        if not text or not text.strip():
            self.log_warning("JSON extraction failed: empty response")
            return None

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.DOTALL)
        cleaned = cleaned.strip()

        # Try to extract from markdown code fence (greedy to handle nested braces)
        fence_m = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", cleaned)
        if fence_m:
            try:
                parsed = json.loads(fence_m.group(1))
                return parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Also try array extraction from fence
        fence_arr = re.search(r"```(?:json)?\s*(\[[\s\S]*\])\s*```", cleaned)
        if fence_arr:
            try:
                parsed = json.loads(fence_arr.group(1))
                if isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
                    return parsed[0]  # Return first dict from array
            except (json.JSONDecodeError, ValueError):
                pass

        try:
            parsed = json.loads(cleaned)
            return parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, ValueError):
            pass

        brace_start = cleaned.rfind("{")
        if brace_start != -1:
            depth = 0
            for i, ch in enumerate(cleaned[brace_start:], brace_start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = cleaned[brace_start : i + 1]
                        try:
                            parsed = json.loads(candidate)
                            return parsed if isinstance(parsed, dict) else None
                        except (json.JSONDecodeError, ValueError):
                            break

        brace_start = cleaned.find("{")
        if brace_start != -1:
            depth = 0
            for i, ch in enumerate(cleaned[brace_start:], brace_start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = cleaned[brace_start : i + 1]
                        try:
                            parsed = json.loads(candidate)
                            return parsed if isinstance(parsed, dict) else None
                        except (json.JSONDecodeError, ValueError):
                            break

        for attempt in [text, text.strip()]:
            try:
                parsed = json.loads(attempt)
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                pass

        try:
            fixed = re.sub(r",\s*}", "}", cleaned)
            fixed = re.sub(r",\s*]", "]", fixed)
            fixed = fixed.replace("'", '"')
            fixed = re.sub(r'(\b\w+\b)\s*:', r'"\1":', fixed)
            fixed = re.sub(r'""(\w+)"":', r'"\1":', fixed)
            parsed = json.loads(fixed)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            pass

        self.log_warning(f"JSON extraction failed from: {text[:200]!r}")
        return None
