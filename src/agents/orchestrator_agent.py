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


class OrchestratorAgent(BaseAgent):
    """
    Mission commander. Uses DeepSeek-R1 (reasoning model) for every decision.
    Delegates work to specialist agents and reacts to their findings.
    """

    # Ordered attack chain — phases run in this sequence
    ATTACK_CHAIN = [
        "recon",
        "enumeration",
        "vuln_scan",
        "exploitation",
        "privesc",
        "postexploit",
        "reporting",
    ]

    # Static phase gates: (description, result_field_to_check, minimum_value)
    PHASE_GATES: dict[str, tuple] = {
        "enumeration":  ("recon found live hosts",       "hosts_found",       1),
        "vuln_scan":    ("enum found open services",     "services_found",    1),
        "exploitation": ("vulnscan found exploitable",   "exploitable_vulns", 1),
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
        try:
            import ollama as _ollama
            client = _ollama.Client(host="http://localhost:11434")
            resp = client.chat(
                model=params["model"],
                messages=[
                    {"role": "user", "content": "/no_think\n\n" + prompt},
                ],
                options=params["options"],
            )
            raw = resp["message"]["content"]
        except Exception as e:
            self.log_error(f"Direct LLM call failed: {e}")
            return {"error": "llm_failed", "raw": ""}

        cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        if expect_json:
            return self._extract_json_robust(cleaned)
        return {"raw": cleaned}

    def _extract_json_robust(self, text: str) -> dict:
        """
        Extract JSON from LLM output using 3 strategies. Never raises.
        Strategy 1: direct json.loads
        Strategy 2: regex — first { ... } block
        Strategy 3: ```json ... ``` code fence
        Strategy 4: fallback error dict (logged as warning)
        """
        # Strategy 1: direct parse (model returned clean JSON)
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: find outermost { ... }
        json_m = re.search(r"\{.*\}", text, re.DOTALL)
        if json_m:
            try:
                return json.loads(json_m.group())
            except (json.JSONDecodeError, ValueError):
                pass

        # Strategy 3: ```json { ... } ``` fence
        block_m = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", text, re.DOTALL)
        if block_m:
            try:
                return json.loads(block_m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # Strategy 4: give up gracefully
        self.log_warning(f"JSON extraction failed from: {text[:200]}")
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
        # ── STEP 1: Mission banner ────────────────────────────────────────────
        self.console.print(Panel.fit(
            f"[bold white]🎯  Target :[/] [cyan]{target}[/]\n"
            f"[bold white]   Mission:[/] [cyan]{self.memory.mission_id}[/]\n"
            f"[bold white]   Models :[/] cyberagent-pentest:14b + cyberagent-reasoning:8b\n"
            f"[bold white]   RAG    :[/] 147,029 docs | Tools: 4,309+\n"
            f"[bold white]   Phase  :[/] [yellow]{phase}[/]",
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
          vuln_scan   → need ≥1 open port across all hosts
          exploitation→ need ≥1 exploitable vuln confirmed by tool
          privesc     → need ≥1 confirmed shell (any user)
          postexploit → need ≥1 confirmed shell (any user is enough)
          reporting   → always runs
        """
        hosts = self.memory._state.get("hosts", {})

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
            "vuln_scan": lambda: (
                any(len(h.get("ports", [])) > 0 for h in hosts.values()),
                f"Need open ports. Found: "
                f"{sum(len(h.get('ports', [])) for h in hosts.values())} total",
            ),
            "exploitation": lambda: (
                any(
                    any(v.get("exploitable") for v in h.get("vulnerabilities", []))
                    for h in hosts.values()
                ),
                "Need ≥1 exploitable vulnerability confirmed by tool evidence",
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
        Ask DeepSeek-R1 to compose a targeted briefing for the next specialist.
        Uses medium complexity (1024 token budget).
        """
        hosts_summary = {ip: {"ports": len(h.get("ports", [])), "vulns": len(h.get("vulnerabilities", []))}
                         for ip, h in self.memory._state.get("hosts", {}).items()}
        prev_results = {k: v.get("result", {}) for k, v in list(self.phase_results.items())[-2:]}

        prompt = (
            f"Briefing for pentest agent '{phase_name}' against {self.memory.target}.\n"
            f"Known: {json.dumps(hosts_summary)}\n"
            f"Recent: {json.dumps(prev_results)}\n"
            'Return JSON: {"priority_targets":[],"known_info":{},"attack_vectors":[],'
            '"avoid":[],"rag_queries":["q1"],"special_instructions":"string"}'
        )
        result = self._direct_llm(prompt, task_complexity="medium")
        if "error" in result:
            return {"special_instructions": f"Focus on {phase_name} for {self.memory.target}"}
        return result

    def _analyze_phase_result(self, phase: str, result: dict) -> dict:
        """
        Ask DeepSeek-R1 to analyse what a specialist agent returned.
        Uses medium complexity (1024 token budget).
        """
        inner = result.get("result", {})
        prompt = (
            f"Phase '{phase}' done. Success: {result.get('success')}. "
            f"Results: {json.dumps(inner)[:300]}\n"
            'Return JSON: {"success":true,"findings_count":0,"key_insight":"string",'
            '"critical_finding":false,"recommended_next":"string",'
            '"strategy_update":null,"attack_chain_adjustment":null}'
        )
        data = self._direct_llm(prompt, task_complexity="medium")
        if "error" in data:
            return {
                "success": bool(result.get("success")),
                "findings_count": len(inner) if isinstance(inner, dict) else 0,
                "key_insight": f"Phase {phase} {'succeeded' if result.get('success') else 'failed'}",
                "critical_finding": False,
                "recommended_next": "continue",
            }
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
            "enumeration": ("agents.enumeration_agent", "EnumerationAgent"),
            "vuln_scan":   ("agents.vuln_scan_agent",   "VulnScanAgent"),
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
                detail = f"{inner.get('services_found', '?')} services"
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
