"""
ReportingAgent — STUB implementation.

This agent is fully specified in src/prompts/agent_prompts.py under "report_agent".
Implementation is planned for the next sprint (Day 4+).
The stub returns realistic-looking data so the OrchestratorAgent phase gates pass
and the full attack chain can be exercised end-to-end today.
"""
from __future__ import annotations
import sys
from pathlib import Path

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class ReportingAgent(BaseAgent):
    """Stub — returns pre-canned realistic data. Implement in Day 4+."""

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="ReportingAgent",
            mission_memory=mission_memory,
            llm_role="default",
        )

    def run(self, target: str, briefing: dict = {}) -> dict:
        self.log_info(f"[STUB] {self.__class__.__name__} called for {target}")
        self.log_warning("This agent is not yet implemented — returning stub result")
        self.memory.log_action(self.agent_name, "stub_run", f"target={target}")

        stub_result = {
            "report_path": "reports/mission_report.md",
            "total_vulns": 2,
            "critical": 1,
            "high": 1
}

        return {
            "agent": self.agent_name,
            "success": True,
            "stub": True,
            "result": stub_result,
        }
