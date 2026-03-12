"""
BaseAgent — parent class for ALL CyberAgent specialist agents.

Implements:
  - ReAct loop  (Thought → Action → Observation × N, then FINAL_ANSWER)
  - RAG context injection on every LLM call via ChromaManager
  - MissionMemory read/write
  - DynamicToolManager access (never subprocess directly)
  - Structured output validation via output_schemas.py
  - Rich terminal logging (no plain print() anywhere)

Architecture rule: every specialist agent inherits BaseAgent and overrides run().
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Add src/ to sys.path so sibling packages (memory, utils, mcp, prompts) resolve
# whether this module is loaded as `src.agents.base_agent` or `agents.base_agent`.
_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from memory.mission_memory import MissionMemory
from memory.chroma_manager import ChromaManager
from utils.llm_factory import get_llm
from mcp.tool_manager import DynamicToolManager
from prompts.agent_prompts import get_agent_prompt, AGENT_PROMPTS

_log = logging.getLogger(__name__)


class BaseAgent:
    """
    Parent class for every CyberAgent specialist.

    Sub-classes must implement:
        run(self, target: str, briefing: dict = {}) -> dict
    """

    def __init__(
        self,
        agent_name: str,
        mission_memory: MissionMemory,
        llm_role: str = "default",
        max_react_iterations: int = 10,
    ):
        self.agent_name = agent_name
        self.llm = get_llm(role=llm_role)
        self.memory = mission_memory
        self.chroma = ChromaManager()
        self.tools = DynamicToolManager()
        self.console = Console()
        self.logger = logging.getLogger(f"agent.{agent_name}")
        self.max_iterations = max_react_iterations

    # ── Prompt helpers ────────────────────────────────────────────────────────

    def _format_rag(self, results: list[dict], max_per_hit: int = 250) -> str:
        """Convert ChromaDB result list into a prompt-injectable string."""
        if not results:
            return "No RAG results available."
        lines = []
        for r in results[:8]:
            src = r.get("source_collection", "unknown")
            text = r["text"][:max_per_hit].replace("\n", " ")
            lines.append(f"[{src}] {text}")
        return "\n---\n".join(lines)

    def _messages_to_prompt(self, messages: list[dict]) -> str:
        """
        Flatten a messages list (OpenAI format) into a single prompt string
        compatible with OllamaLLM (completion model, not chat model).
        """
        parts = []
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            parts.append(f"<|{role}|>\n{content}")
        return "\n\n".join(parts) + "\n\n<|ASSISTANT|>\n"

    def _build_system_prompt(self, task: str) -> str:
        """Build the full system prompt with injected RAG and mission state."""
        rag_hits = self.chroma.get_rag_context(task[:300])
        rag_str = self._format_rag(rag_hits)

        # Resolve the AGENT_PROMPTS key: try as-is, then CamelCase→snake_case
        prompt_key = self.agent_name
        if prompt_key not in AGENT_PROMPTS:
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", self.agent_name).lower()
            prompt_key = snake if snake in AGENT_PROMPTS else None

        if prompt_key:
            return get_agent_prompt(
                agent_name=prompt_key,
                target=self.memory.target,
                mission_state=self.memory.get_full_context(),
                rag_context=rag_str,
            )
        # Graceful fallback for agents without a registered prompt
        return (
            f"You are {self.agent_name}, an expert penetration tester.\n"
            f"Target: {self.memory.target}\n\n"
            f"ANTI-HALLUCINATION: Only cite CVEs returned by RAG. Never invent findings.\n\n"
            f"RAG CONTEXT:\n{rag_str}"
        )

    # ── Response parser ───────────────────────────────────────────────────────

    def _parse_react_response(self, raw: str) -> dict:
        """
        Parse THOUGHT / ACTION / ACTION_INPUT / FINAL_ANSWER from raw LLM text.
        Returns dict with keys: thought, action, action_input, final_answer.
        """
        result: dict[str, Any] = {
            "thought": "",
            "action": None,
            "action_input": None,
            "final_answer": None,
        }

        # Strip DeepSeek-R1 <think>...</think> chain-of-thought wrapper
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        # THOUGHT
        thought_m = re.search(
            r"THOUGHT:\s*(.+?)(?=ACTION:|FINAL_ANSWER:|$)", raw,
            re.DOTALL | re.IGNORECASE,
        )
        if thought_m:
            result["thought"] = thought_m.group(1).strip()

        # FINAL_ANSWER (JSON block) — check this first so we short-circuit
        final_m = re.search(
            r"FINAL_ANSWER:\s*(\{.+\})", raw, re.DOTALL | re.IGNORECASE
        )
        if final_m:
            try:
                result["final_answer"] = json.loads(final_m.group(1))
            except json.JSONDecodeError:
                result["final_answer"] = {"raw": final_m.group(1).strip()[:500]}
            return result

        # Try bare JSON block as FINAL_ANSWER (LLM sometimes skips the keyword)
        bare_json = re.search(r"```json\s*(\{.+?\})\s*```", raw, re.DOTALL)
        if bare_json:
            try:
                result["final_answer"] = json.loads(bare_json.group(1))
                result["thought"] = result["thought"] or "JSON block returned"
                return result
            except json.JSONDecodeError:
                pass

        # ACTION
        action_m = re.search(
            r"ACTION:\s*(\S+)", raw, re.IGNORECASE
        )
        if action_m:
            result["action"] = action_m.group(1).strip()

        # ACTION_INPUT
        input_m = re.search(
            r"ACTION_INPUT:\s*(\{.+?\})", raw, re.DOTALL | re.IGNORECASE
        )
        if input_m:
            try:
                result["action_input"] = json.loads(input_m.group(1))
            except json.JSONDecodeError:
                result["action_input"] = {"raw": input_m.group(1).strip()[:300]}

        return result

    # ── Action executor ───────────────────────────────────────────────────────

    def _execute_action(self, action: str, action_input: dict) -> Any:
        """
        Dispatch a parsed ACTION to the correct handler.
        Never raises — always returns a dict.
        """
        action = action.strip().lower()

        if action == "search_rag":
            query = action_input.get("query", "")
            results = self.chroma.get_rag_context(query)
            return {"results": [r["text"][:300] for r in results[:5]]}

        if action == "read_memory":
            phase = action_input.get("phase", "recon")
            return {"memory": self.memory.get_phase_summary(phase)}

        if action == "store_finding":
            try:
                self.memory.add_finding_from_dict(action_input)
                return {"stored": True}
            except Exception as e:
                return {"stored": False, "error": str(e)}

        # Default: try DynamicToolManager
        tool_args = action_input.get("args", [])
        if not isinstance(tool_args, list):
            tool_args = [str(tool_args)]
        purpose = action_input.get("purpose", f"{self.agent_name} task")
        try:
            return self.tools.use(action, args=tool_args, purpose=purpose)
        except Exception as e:
            return {"error": str(e), "tool": action}

    # ── Core ReAct loop ───────────────────────────────────────────────────────

    def react(self, task: str, context: dict = {}) -> dict:
        """
        ReAct loop: Thought → Action → Observation, up to max_iterations.

        Returns:
            {
              "agent": str,
              "success": bool,
              "result": dict,        # content of FINAL_ANSWER
              "iterations": int,
              "actions_taken": list,
              "error": str | None,
            }
        """
        system_prompt = self._build_system_prompt(task)
        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task},
        ]
        actions_taken: list[str] = []
        reformat_attempts = 0

        for i in range(self.max_iterations):
            prompt = self._messages_to_prompt(messages)

            # ── LLM call ────────────────────────────────────────────────
            try:
                raw = self.llm.invoke(prompt)
            except Exception as e:
                self.log_error(f"LLM call failed on iteration {i}: {e}")
                return self._fail_result(actions_taken, i, str(e))

            # ── Parse ────────────────────────────────────────────────────
            parsed = self._parse_react_response(raw)

            # Print thought
            if parsed["thought"]:
                self.console.print(Panel(
                    f"[white]{parsed['thought'][:400]}[/]",
                    title=f"[cyan]🤔 {self.agent_name} THOUGHT (iter {i+1})[/]",
                    border_style="cyan",
                ))

            # ── FINAL_ANSWER ─────────────────────────────────────────────
            if parsed["final_answer"] is not None:
                self.log_success(f"Done after {i+1} iteration(s)")
                return {
                    "agent": self.agent_name,
                    "success": True,
                    "result": parsed["final_answer"],
                    "iterations": i + 1,
                    "actions_taken": actions_taken,
                    "error": None,
                }

            # ── No action parsed — ask LLM to reformat ───────────────────
            if not parsed["action"]:
                reformat_attempts += 1
                if reformat_attempts >= 2:
                    self.log_warning("LLM did not produce valid ReAct format after 2 attempts")
                    return self._fail_result(actions_taken, i, "invalid_react_format")
                messages.append({
                    "role": "user",
                    "content": (
                        "Please respond using exactly this format:\n"
                        "THOUGHT: <your reasoning>\n"
                        "ACTION: <tool_name>\n"
                        "ACTION_INPUT: {\"key\": \"value\"}\n\n"
                        "Or if finished:\n"
                        "THOUGHT: <reasoning>\n"
                        "FINAL_ANSWER: {<json result>}"
                    ),
                })
                continue

            # ── Execute action ───────────────────────────────────────────
            action_input = parsed["action_input"] or {}
            self.console.print(Panel(
                f"[yellow]Tool:[/] {parsed['action']}\n"
                f"[yellow]Input:[/] {str(action_input)[:300]}",
                title="[yellow]⚡ ACTION[/]",
                border_style="yellow",
            ))

            result = self._execute_action(parsed["action"], action_input)
            actions_taken.append(parsed["action"])

            self.console.print(Panel(
                f"[green]{str(result)[:300]}[/]",
                title="[green]👁 OBSERVATION[/]",
                border_style="green",
            ))

            # Log and store observation
            observation = {
                "iteration": i,
                "action": parsed["action"],
                "input": action_input,
                "output": str(result)[:500],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.memory.log_action(
                agent_name=self.agent_name,
                action=parsed["action"],
                result=str(result)[:500],
            )
            messages.append({
                "role": "user",
                "content": f"OBSERVATION: {json.dumps(observation)}",
            })

        # Max iterations reached
        self.log_warning(f"Max iterations ({self.max_iterations}) reached without FINAL_ANSWER")
        return self._fail_result(actions_taken, self.max_iterations, "max_iterations_reached")

    def _fail_result(self, actions_taken: list, iterations: int, error: str) -> dict:
        return {
            "agent": self.agent_name,
            "success": False,
            "result": {},
            "iterations": iterations,
            "actions_taken": actions_taken,
            "error": error,
        }

    # ── Logging helpers ───────────────────────────────────────────────────────

    def log_info(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[cyan]ℹ {self.agent_name}[/]",
            border_style="cyan",
        ))

    def log_success(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[green]✓ {self.agent_name}[/]",
            border_style="green",
        ))

    def log_warning(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[yellow]⚠ {self.agent_name}[/]",
            border_style="yellow",
        ))

    def log_error(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[red]✗ {self.agent_name}[/]",
            border_style="red",
        ))

    # ── Public helper methods (inherited by all specialists) ──────────────────

    def get_rag_for_task(self, task: str, n: int = 5) -> str:
        """Semantic RAG lookup, returns formatted string for prompt injection."""
        results = self.chroma.get_rag_context(task, n=n)
        return self._format_rag(results)

    def store_finding(self, finding_type: str, data: dict):
        """
        Store a finding in both MissionMemory and ChromaDB.
        finding_type: "host" | "port" | "vuln" | "shell" | "cred" | "loot"
        """
        data_with_type = {"finding_type": finding_type, **data}
        self.memory.add_finding_from_dict(data_with_type)
        self.memory.store_in_chroma(
            str(data),
            {"finding_type": finding_type, "agent": self.agent_name},
        )

    def run_tool(self, tool: str, context: dict) -> dict:
        """
        Execute a tool via DynamicToolManager.
        Logs result to MissionMemory. Never raises.
        """
        args = context.pop("args", [])
        if not isinstance(args, list):
            args = [str(args)]
        purpose = context.get("purpose", f"{self.agent_name}: {tool}")
        try:
            result = self.tools.use(tool, args=args, purpose=purpose)
            self.memory.log_action(self.agent_name, tool, str(result)[:300])
            return result if isinstance(result, dict) else {"output": str(result)}
        except Exception as e:
            self.log_error(f"Tool '{tool}' failed: {e}")
            return {"error": str(e), "tool": tool}
