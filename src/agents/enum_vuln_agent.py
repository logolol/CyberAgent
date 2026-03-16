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

        # Warm the model NOW — before any agent logic runs
        # This ensures subsequent LLM calls find model already in RAM
        from utils.llm_factory import warm_model
        self.log_info("Pre-warming Qwen2.5:14b for enumeration...")
        warm_model(role="default")

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, target: str, briefing: dict = {}) -> dict:
        self.target = target
        self.briefing = briefing or {}
        self.recon_findings = {}
        self.attack_surface = {}
        self.all_results = {}
        self.vulnerabilities = []
        self.iteration = 0
        self.done = False
        self._completed_tools = set()

        self.console.print(Panel(
            f"[bold cyan]🔎 EnumVulnAgent — Active Enum + Vuln Detection[/]\n"
            f"[white]Target:[/] [cyan]{target}[/]\n"
            f"[white]Model:[/] Qwen2.5:14b | [white]RAG:[/] 147K docs\n"
            f"[white]Concurrency:[/] {self.MAX_CONCURRENT} parallel tools",
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

            # Stage 2: gather raw evidence through deterministic tool waves
            self._run_gather_phase()

            # Stage 3: single analysis pass over all outputs
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
                    "vulnerabilities": self.vulnerabilities,
                    "exploitable_vulns": len([v for v in self.vulnerabilities if v.get("exploitable")]),
                    "tools_used": list(self.all_results.keys()),
                },
                "raw_outputs": self.all_results,
            }

    # ── Stage 1: mission briefing ─────────────────────────────────────────────

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
                wave1_args = [self.target, "-sV", "-sC", "--top-ports", "1000", "-T4", "--open"]
            elif scanner_name == "masscan":
                wave1_args = [self.target, "-p1-1000", "--rate", "1000"]
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

        # Wave 2: LLM-driven service probing based on discovered ports.
        port_services = self._extract_port_services()
        if port_services:
            self.log_info("Asking LLM+RAG what to enumerate next...")
            wave2_specs = self._decide_wave2_with_llm(port_services)
        else:
            wave2_specs = []
        if wave2_specs:
            wave2_results = self._run_tool_batch(wave2_specs)
            self.all_results.update(wave2_results)
            self.log_success(f"Wave 2 complete: {len(wave2_results)} result(s)")
            self._update_intelligence_log(2, wave2_results, {})
        else:
            self.log_info("Wave 2 skipped: no service probing specs generated")

        # Wave 3: vulnerability-oriented scans.
        wave3_specs = self._build_wave3_vuln_scan()
        if wave3_specs:
            wave3_results = self._run_tool_batch(wave3_specs)
            self.all_results.update(wave3_results)
            self.log_success(f"Wave 3 complete: {len(wave3_results)} result(s)")
            self._update_intelligence_log(3, wave3_results, {})
        else:
            self.log_info("Wave 3 skipped: no vulnerability scanning tools available")

        self.log_success(f"Gather phase complete: {len(self.all_results)} total tool output(s)")

    def _analyze_security_controls(self) -> dict:
        """
        Analyzes wave 1 tool outputs to detect security controls.

        The LLM reads real tool output and reasons about:
          - What patterns in the output suggest filtering or blocking?
          - What inconsistencies suggest stateful inspection?
          - What response behaviors suggest active monitoring?
          - What anomalies suggest honeypots or deception?

        The LLM then queries its own reasoning + RAG to determine:
          - What evasion techniques are appropriate?
          - What scanning adjustments should wave 2 make?
          - What MITRE techniques cover this situation?

        Never assumes what controls exist — derives from evidence only.
        """
        raw_evidence = self._build_full_output_summary()

        detection_context = ""
        evasion_context = ""
        mitre_context = ""

        try:
            observed_patterns = self._extract_anomaly_patterns()

            detection_context = self._format_rag(
                self.chroma.get_rag_context(
                    f"linux firewall detection {observed_patterns} "
                    f"IDS IPS evasion scanning techniques",
                    collections=["hacktricks", "mitre_attack"],
                    n=3,
                ),
                max_chars=400,
            )

            evasion_context = self._format_rag(
                self.chroma.get_rag_context(
                    f"firewall bypass evasion nmap techniques "
                    f"packet fragmentation slow scan decoy",
                    collections=["payloads", "hacktricks"],
                    n=2,
                ),
                max_chars=300,
            )

            mitre_context = self._format_rag(
                self.chroma.get_rag_context(
                    "MITRE ATT&CK T1562 impair defenses "
                    "T1027 obfuscation T1090 proxy evasion",
                    collections=["mitre_attack"],
                    n=2,
                ),
                max_chars=200,
            )
        except Exception as e:
            self.log_warning(f"Security control RAG query failed: {e}")

        prompt = f"""You are analyzing the output of active scanning tools
against a Linux server. Your task is to reason about what the
tool outputs reveal about security controls on the target.

Raw tool output evidence:
{raw_evidence[:800]}

Security control detection methodology from knowledge base:
{detection_context}

Evasion technique references:
{evasion_context}

MITRE ATT&CK defensive evasion context:
{mitre_context}

Reasoning task:
Read the tool outputs carefully. Look for patterns that reveal
the presence or absence of security controls. Consider:
  - Port response consistency (all open? some filtered? mixed?)
  - Response timing patterns (uniform? variable? slowdown?)
  - Unexpected closures or resets mid-scan
  - HTTP response codes that suggest active filtering
  - Absence of expected services that should be present

Based ONLY on what the evidence shows, determine:
1. What security controls appear to be present?
2. How confident are you in each detection? What evidence supports it?
3. What does this mean for our scanning strategy?
4. What adjustments should we make to maximize discovery?
5. Which MITRE techniques apply to this evasion scenario?

Return JSON only. All fields must be derived from evidence above.
Do not invent controls that have no evidence:
{{
  "controls_detected": [
    {{
      "control_type": "derived from evidence",
      "confidence": "high|medium|low",
      "evidence": "exact observation from tool output",
      "implication": "what this means for our scanning"
    }}
  ],
  "evasion_strategy": "derived from detected controls + RAG",
  "scan_adjustments": "specific technical adjustments needed",
  "detection_risk": "our estimated risk of being detected/blocked",
  "mitre_techniques": [],
  "wave2_guidance": "how wave 2 should adapt based on findings"
}}"""

        raw = self._llm_with_timeout(prompt, timeout=90)
        result = self._extract_json_robust(raw)

        if result:
            self._security_controls = result

            for control in result.get("controls_detected", []):
                if control.get("confidence") in ["high", "medium"]:
                    self.memory.log_action(
                        "EnumVulnAgent",
                        "security_control_detected",
                        f"{control.get('control_type')} "
                        f"[{control.get('confidence')}]: "
                        f"{control.get('evidence', '')[:100]}",
                    )

            for technique in result.get("mitre_techniques", []):
                self.memory.log_action(
                    "EnumVulnAgent", "mitre_technique", str(technique)
                )

            if result.get("evasion_strategy"):
                self.log_info(
                    f"🛡️ Security analysis: {result.get('wave2_guidance', '')[:150]}"
                )

            self.memory.save_state()
        else:
            self._security_controls = {}
            self.log_warning("Security control analysis failed — proceeding without evasion")

        return self._security_controls

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
        """
        import os

        open_ports: dict[int, str] = {}
        for output in self.all_results.values():
            for match in re.finditer(
                r"(?m)(\d{1,5})/(tcp|udp)\s+open(?:\|filtered)?\s+([^\s]+)",
                str(output),
            ):
                try:
                    port = int(match.group(1))
                except Exception:
                    continue
                service = str(match.group(3)).strip().lower() or "unknown"
                if 1 <= port <= 65535:
                    open_ports[port] = service

        if not open_ports:
            return []

        self.log_info(f"Wave 2 planning from discovered ports: {sorted(list(open_ports.keys()))[:10]}")

        specs: list[dict[str, Any]] = []
        for port, service in list(open_ports.items())[: self.MAX_CONCURRENT * 2]:
            purpose = f"enumerate {service} service on port {port}"
            best_tool = ""

            try:
                candidates = self.tools.get_tools_for_purpose(purpose)
            except Exception as e:
                self.log_warning(f"Tool suggestion lookup failed for '{purpose}': {e}")
                candidates = []

            for candidate in candidates or []:
                candidate_name = str(candidate).strip().split()[0]
                if not candidate_name or candidate_name.lower() in self._completed_tools:
                    continue
                candidate_path = self.tools.find(candidate_name)
                if candidate_path and os.access(candidate_path, os.X_OK):
                    best_tool = Path(candidate_path).name
                    break

            resolved_args = [self.target]
            timeout = 60
            if best_tool == "nmap":
                resolved_args = [self.target, "-sV", "-sC", "-p", str(port), "-T4"]
                timeout = 120
            elif not best_tool:
                nmap_path = self.tools.find("nmap")
                if nmap_path and os.access(nmap_path, os.X_OK):
                    best_tool = "nmap"
                    resolved_args = [self.target, "-sV", "-sC", "-p", str(port), "-T4"]
                    timeout = 120

            if not best_tool:
                continue

            specs.append({
                "tool_hint": best_tool,
                "purpose": purpose,
                "_resolved_args": resolved_args,
                "_timeout": timeout,
            })

        return specs[: self.MAX_CONCURRENT]

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
        import os

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
            if path and os.access(path, os.X_OK):
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

        raw = self._llm_with_timeout(prompt, timeout=90)
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
            if path and os.access(path, os.X_OK):
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
        Asks the LLM to summarize what this wave taught us.

        The LLM reads tool outputs and its own analysis.
        It derives conclusions — they are not pre-filled fields.
        The summary is stored and injected into the next wave's
        decision prompt so each wave builds on the previous.
        """
        output_summary = self._summarize_batch_for_llm(batch_results)

        prompt = f"""You just completed wave {wave_num} of active
enumeration. Summarize what this wave taught you.

Tools run and their outputs:
{output_summary[:800]}

Analysis conclusions from this wave:
{json.dumps(analysis, default=str)[:400] if analysis else 'none'}

Intelligence from previous waves:
{self._format_intelligence_history()[:300]}

Summarize the intelligence gained from wave {wave_num}.
Be specific about what was confirmed, what was ruled out,
and what new questions emerged. Your summary will guide
the next wave's decisions — make it actionable.

Return JSON:
{{
  "wave": {wave_num},
  "tools_run": [],
  "what_was_confirmed": "derived from tool output",
  "what_was_ruled_out": "derived from failed/empty tool runs",
  "new_questions": "what the evidence raises but doesn't answer",
  "next_wave_priority": "what deserves focused attention next",
  "mitre_techniques_applied": []
}}"""

        raw = self._llm_with_timeout(prompt, timeout=60)
        summary = self._extract_json_robust(raw)

        if not summary:
            ports = self._extract_all_ports()
            summary = {
                "wave": wave_num,
                "tools_run": list(batch_results.keys()),
                "what_was_confirmed": f"{len(ports)} ports found",
                "what_was_ruled_out": "",
                "new_questions": "",
                "next_wave_priority": "continue enumeration",
                "mitre_techniques_applied": [],
            }

        self.intelligence_log.append(summary)

        self.memory.log_action(
            "EnumVulnAgent",
            f"wave_{wave_num}_intelligence",
            str(summary.get("next_wave_priority", ""))[:200],
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

        self.log_info("Running final LLM+RAG vulnerability analysis...")
        raw = self._llm_with_timeout(prompt, timeout=180)
        analysis = self._extract_json_robust(raw)
        if isinstance(analysis, dict):
            self.log_success("LLM analysis complete with RAG grounding")
            return analysis

        self.log_warning("Analysis LLM unavailable/unparseable — using regex analysis fallback")
        return self._regex_analysis_fallback()

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

        raw = self._llm_with_timeout(prompt, timeout=45)
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

        raw = self._llm_with_timeout(prompt, timeout=45)
        decision = self._extract_json_robust(raw) if raw else None
        if not decision:
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
            fallback_specs = self._fallback_tool_batch()
            return fallback_specs, reasoning or "No tools selected", False

        priority_weight = {"high": 0, "medium": 1, "low": 2}
        normalized_tools.sort(key=lambda s: priority_weight.get(s.get("priority", "medium"), 1))
        resolved_specs: list[dict[str, Any]] = []
        for spec in normalized_tools[: self.MAX_CONCURRENT]:
            try:
                resolved_specs.append(self._resolve_spec(spec))
            except Exception as e:
                self.log_warning(f"Spec resolution failed for '{spec.get('purpose', 'unknown')}': {e}")

        if not resolved_specs:
            return self._fallback_tool_batch(), reasoning or "Resolution failed", False

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

        args = [str(a) for a in (resolved_args or [self.target])]

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

        self.memory.log_action(
            agent_name="EnumVulnAgent",
            action=tool_name,
            result=str(output)[:300],
        )

        return tool_name, str(output)[:8000]

    def _resolve_spec(self, spec: dict[str, Any]) -> dict[str, Any]:
        """
        Resolve best tool + args in the main thread before worker execution.
        """
        purpose = str(spec.get("purpose", "")).strip()
        approach = str(spec.get("approach", "")).strip()
        target = str(spec.get("target", self.target)).strip() or self.target

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
        raw = self._llm_with_timeout(arg_prompt, timeout=30)
        args = self._extract_args_from_llm(raw, target)

        spec["_resolved_args"] = args
        spec["_timeout"] = self._get_tool_timeout(purpose)
        self.log_info(f"  → {best_tool} {' '.join(str(a) for a in args[:5])}")
        return spec

    def _extract_args_from_llm(self, raw: str, target: str) -> list[str]:
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
                        item = item.replace("{target}", target).replace("TARGET", target)
                        resolved.append(item)
                    return resolved if resolved else [target]
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

        raw = self._llm_with_timeout(prompt, timeout=45)
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
                    )
                except Exception as e:
                    self.log_warning(f"Failed to persist vulnerability: {e}")

            vulns.append(vuln)
            severity = str(vuln.get("severity", "info")).upper()
            self.log_success(f"[{severity}] {str(vuln.get('title', detail))[:140]}")

        return vulns

    # ── Stage 4: final report + persistence ───────────────────────────────────

    def _reason_about_exploitability(self, vuln: dict) -> dict:
        """
        Reasons about whether a detected vulnerability is actually
        exploitable given the evidence collected so far.

        The LLM does not look up a static answer.
        It reads evidence + RAG and REASONS to a conclusion.

        Only vulnerabilities that pass this reasoning gate
        get marked exploitable=True and reach ExploitationAgent.
        """
        cve = vuln.get("cve", "CVE-UNKNOWN")
        service = vuln.get("service", "")
        evidence = vuln.get("evidence", "")

        rag_collections_to_query = [
            ("cve_database", f"{cve} {service} affected versions CVSS vector"),
            ("exploitdb", f"{cve} {service} exploit proof of concept"),
            ("nuclei_templates", f"{service} detection template"),
            ("hacktricks", f"{service} exploitation manual technique"),
            ("payloads", f"{service} payload attack vector"),
        ]

        rag_context_parts = []
        for collection, query in rag_collections_to_query:
            try:
                hits = self.chroma.get_rag_context(
                    query,
                    collections=[collection],
                    n=2,
                )
                if hits:
                    text = self._format_rag(hits, max_chars=200)
                    rag_context_parts.append(f"[{collection}]\n{text}")
            except Exception:
                pass

        combined_rag = "\n\n".join(rag_context_parts)

        tool_evidence = self._build_full_output_summary()

        prompt = f"""You are evaluating whether a vulnerability finding
is genuinely exploitable. Your job is to reason carefully,
not to confirm or deny reflexively.

Vulnerability under evaluation:
{json.dumps(vuln, default=str, indent=2)[:400]}

Evidence from tool execution that detected this:
{tool_evidence[:600]}

Knowledge base context for this vulnerability:
{combined_rag[:800] if combined_rag else 'No RAG matches found'}

Reasoning task:
Evaluate this vulnerability finding critically. Consider:

1. VERSION EVIDENCE: Does the tool output actually confirm
   the specific version that is vulnerable? Quote the exact
   line that provides version evidence.

2. EXPLOITABILITY CONDITIONS: Based on the knowledge base,
   what conditions must be met for exploitation?
   Are those conditions present in the evidence?

3. EXPLOIT AVAILABILITY: Does the knowledge base show a
   working exploit or only a vulnerability description?

4. ATTACK PATH: What would an attacker need to do step by step?
   How complex is this path? What could block it?

5. FALSE POSITIVE RISK: What would cause this to be a false
   positive? Is there any evidence that reduces confidence?

Based on this reasoning, return your assessment:
{{
  "exploitable": true,
  "confidence": "high|medium|low",
  "confidence_reasoning": "what evidence drives this confidence",
  "version_evidence": "exact line from tool output or null",
  "exploit_availability": "what the knowledge base shows",
  "attack_path_complexity": "what is required to exploit",
  "false_positive_risk": "what could make this wrong",
  "exploitation_context": "what ExploitationAgent needs to know",
  "mitre_technique": "most applicable T-code"
}}"""

        raw = self._llm_with_timeout(prompt, timeout=90)
        reasoning = self._extract_json_robust(raw)

        if reasoning:
            vuln["exploitable"] = bool(reasoning.get("exploitable", False))
            vuln["confidence"] = reasoning.get("confidence", "low")
            vuln["exploitability_reasoning"] = reasoning.get(
                "confidence_reasoning", ""
            )
            vuln["exploitation_context"] = reasoning.get(
                "exploitation_context", ""
            )
            vuln["false_positive_risk"] = reasoning.get(
                "false_positive_risk", ""
            )

            mitre = reasoning.get("mitre_technique", "").strip()
            if mitre:
                vuln["mitre_technique"] = mitre
                self.memory.log_action(
                    "EnumVulnAgent", "mitre_technique", mitre
                )

            if (reasoning.get("exploitable")
                    and reasoning.get("confidence") == "high"):
                self.log_success(
                    f"⚡ HIGH CONFIDENCE EXPLOITABLE: "
                    f"{vuln.get('cve', '?')} [{service}]"
                )
            else:
                self.log_info(
                    f"ℹ️ Not marked exploitable: "
                    f"{vuln.get('cve', '?')} "
                    f"[confidence: {reasoning.get('confidence', '?')}]"
                )

        return vuln

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
                ports.append({
                    "ip": str(item.get("ip", self.target) or self.target),
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

        # Exploitability reasoning: LLM evaluates critical/high vulns
        enriched_vulns = []
        for vuln in cleaned_vulns:
            sev = vuln.get("severity", "info").lower()
            if sev in ["critical", "high"]:
                vuln = self._reason_about_exploitability(vuln)
            enriched_vulns.append(vuln)
        cleaned_vulns = enriched_vulns

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

        # LLM-derived critical path analysis for ExploitationAgent
        attack_summary = {}
        if cleaned_vulns:
            critical_path_prompt = f"""Given these vulnerability findings
from active enumeration of {self.target}:

{json.dumps([{
    'cve': v.get('cve'),
    'service': v.get('service'),
    'severity': v.get('severity'),
    'confidence': v.get('confidence'),
    'exploitable': v.get('exploitable'),
    'exploitation_context': v.get('exploitation_context', '')
} for v in cleaned_vulns[:10]], default=str, indent=2)[:1200]}

Security controls detected:
{json.dumps(self._security_controls, default=str)[:300]}

Determine the optimal attack path for ExploitationAgent.
Reason about: which vulnerability has the highest probability
of success? Which provides the most valuable access?
What is the complete picture of attack vectors available?

Return JSON:
{{
  "critical_path": {{
    "service": "derived from findings",
    "port": 0,
    "cve": "derived from findings",
    "confidence": "derived from exploitability reasoning",
    "why_first": "reasoning for this priority"
  }},
  "all_attack_vectors": [
    {{
      "service": "from findings",
      "vector_type": "from knowledge base",
      "priority": 1,
      "requires": "what conditions must hold"
    }}
  ],
  "recommended_exploits": [],
  "evasion_needed": false,
  "exploitation_guidance": "overall strategy for next phase"
}}"""

            raw = self._llm_with_timeout(critical_path_prompt, timeout=90)
            attack_summary = self._extract_json_robust(raw) or {}

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
        except Exception:
            pass

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
                self.memory.add_port(
                    ip=str(port_info.get("ip", self.target)),
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
        """Compact tool output summary (max 1500 chars)."""
        blocks: list[str] = []
        for key, output in results.items():
            preview = (output or "").replace("\n", " ")[:300]
            blocks.append(f"{key}:\n{preview}\n")
        summary = "\n".join(blocks)
        return summary[:1500]

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
                self.memory.add_port(
                    ip=str(port_info.get("ip", self.target)),
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
                ip = self.target
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
                key = (self.target, port, "tcp")
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "ip": self.target,
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
                key = (ip, port, "tcp")
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "ip": ip,
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

    def _find_ip_for_service(self, service: str) -> str:
        """Resolve host IP for service context, fallback to target."""
        service_l = str(service).lower().strip()
        if not service_l:
            return self.target

        for ip, host_data in self.attack_surface.items():
            ports = host_data.get("ports", []) if isinstance(host_data, dict) else []
            for p in ports:
                if not isinstance(p, dict):
                    continue
                if service_l in str(p.get("service", "")).lower():
                    return ip

        return self.target

    def _format_rag(self, results: list[dict[str, Any]], max_chars: int) -> str:
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
        all_output = "\n".join(str(v) for v in outputs.values())

        ports: list[dict[str, Any]] = []
        seen_ports: set[int] = set()
        for m in re.finditer(r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+([a-zA-Z0-9\-_\.]+)\s*(.*)$", all_output):
            port_num = int(m.group(1))
            if port_num in seen_ports:
                continue
            seen_ports.add(port_num)
            ports.append({
                "ip": self.target,
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

        fence_m = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", cleaned, re.DOTALL)
        if fence_m:
            cleaned = fence_m.group(1)

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

    def _llm_with_timeout(self, prompt: str, timeout: int = 45) -> str:
        """
        Run self.llm.invoke(prompt) in a daemonized thread with timeout.
        Returns raw response string or "" on timeout/failure.
        """
        ex = _DaemonThreadPoolExecutor(max_workers=1)
        future = ex.submit(self.llm.invoke, prompt)
        try:
            response = future.result(timeout=timeout)
            return response.content if hasattr(response, "content") else str(response)
        except concurrent.futures.TimeoutError:
            self.log_warning(f"LLM decision timed out after {timeout}s")
            future.cancel()
            return ""
        except Exception as e:
            self.log_warning(f"LLM call failed: {e}")
            return ""
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
