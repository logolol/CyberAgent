"""
PhaseBudget — per-phase resource budget for the pentesting agent.

Tracks time, tool calls, and LLM calls per phase.
Enforcement is *soft* (warning-only) so CTF speed is preserved,
but provides clear signals when a phase is running over-budget.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

# Default budgets per phase.  All values can be overridden by the orchestrator.
PHASE_DEFAULTS: dict[str, dict] = {
    "recon":       {"max_time_secs": 300,  "max_tool_calls": 15, "max_llm_calls": 8},
    "enumeration": {"max_time_secs": 480,  "max_tool_calls": 20, "max_llm_calls": 10},
    "vuln_scan":   {"max_time_secs": 480,  "max_tool_calls": 20, "max_llm_calls": 10},
    "exploitation":{"max_time_secs": 720,  "max_tool_calls": 25, "max_llm_calls": 15},
    "privesc":     {"max_time_secs": 360,  "max_tool_calls": 15, "max_llm_calls": 8},
    "postexploit": {"max_time_secs": 240,  "max_tool_calls": 12, "max_llm_calls": 6},
    "reporting":   {"max_time_secs": 120,  "max_tool_calls": 5,  "max_llm_calls": 4},
    "_default":    {"max_time_secs": 300,  "max_tool_calls": 15, "max_llm_calls": 8},
}


@dataclass
class PhaseBudget:
    """
    Tracks resource consumption for a single mission phase.

    Usage::

        budget = PhaseBudget.for_phase("exploitation")
        budget.start()
        ...
        budget.record_tool_call(duration=12.3)
        budget.record_llm_call()
        if budget.is_over_budget():
            agent.log_warning(budget.over_budget_reason())
    """

    phase: str
    max_time_secs: int = 300
    max_tool_calls: int = 15
    max_llm_calls: int = 8

    # Runtime counters
    used_time: float = field(default=0.0, init=False)
    used_tool_calls: int = field(default=0, init=False)
    used_llm_calls: int = field(default=0, init=False)
    _started_at: Optional[float] = field(default=None, init=False, repr=False)
    _warned: bool = field(default=False, init=False, repr=False)

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def for_phase(cls, phase: str) -> "PhaseBudget":
        """Create a PhaseBudget with default values for *phase*."""
        defaults = PHASE_DEFAULTS.get(phase) or PHASE_DEFAULTS["_default"]
        return cls(
            phase=phase,
            max_time_secs=defaults["max_time_secs"],
            max_tool_calls=defaults["max_tool_calls"],
            max_llm_calls=defaults["max_llm_calls"],
        )

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> "PhaseBudget":
        """Record phase start time."""
        self._started_at = time.monotonic()
        _log.info(
            "[Budget] %s started — limits: %ds / %d tools / %d LLM calls",
            self.phase, self.max_time_secs, self.max_tool_calls, self.max_llm_calls,
        )
        return self

    def elapsed(self) -> float:
        """Seconds elapsed since start()."""
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    # ── Recording ──────────────────────────────────────────────────────────────

    def record_tool_call(self, duration: float = 0.0) -> None:
        """Record one tool execution."""
        self.used_tool_calls += 1
        self.used_time += duration
        if self.is_over_budget() and not self._warned:
            _log.warning("[Budget] %s OVER-BUDGET: %s", self.phase, self.over_budget_reason())
            self._warned = True

    def record_llm_call(self) -> None:
        """Record one LLM inference call."""
        self.used_llm_calls += 1
        if self.is_over_budget() and not self._warned:
            _log.warning("[Budget] %s OVER-BUDGET: %s", self.phase, self.over_budget_reason())
            self._warned = True

    # ── Status ─────────────────────────────────────────────────────────────────

    def is_exhausted(self) -> bool:
        """
        True when the phase has consumed ALL three budget dimensions.
        Only triggers a hard stop when every limit is exceeded simultaneously.
        Soft enforcement: individual limit warnings come from is_over_budget().
        """
        return (
            self.used_tool_calls >= self.max_tool_calls
            and self.used_llm_calls >= self.max_llm_calls
            and self.elapsed() >= self.max_time_secs
        )

    def is_over_budget(self) -> bool:
        """True if ANY single budget dimension is exceeded."""
        return (
            self.elapsed() > self.max_time_secs
            or self.used_tool_calls > self.max_tool_calls
            or self.used_llm_calls > self.max_llm_calls
        )

    def remaining_time(self) -> float:
        """Seconds remaining before time budget expires."""
        return max(0.0, self.max_time_secs - self.elapsed())

    def over_budget_reason(self) -> str:
        """Human-readable explanation of which dimension is exceeded."""
        reasons = []
        elapsed = self.elapsed()
        if elapsed > self.max_time_secs:
            reasons.append(f"time ({elapsed:.0f}s > {self.max_time_secs}s)")
        if self.used_tool_calls > self.max_tool_calls:
            reasons.append(f"tool_calls ({self.used_tool_calls} > {self.max_tool_calls})")
        if self.used_llm_calls > self.max_llm_calls:
            reasons.append(f"llm_calls ({self.used_llm_calls} > {self.max_llm_calls})")
        return "; ".join(reasons) if reasons else "within budget"

    def to_dict(self) -> dict:
        """Serialise to dict for injection into agent briefings."""
        return {
            "phase": self.phase,
            "max_time_secs": self.max_time_secs,
            "max_tool_calls": self.max_tool_calls,
            "max_llm_calls": self.max_llm_calls,
            "remaining_time_secs": int(self.remaining_time()),
            "used_tool_calls": self.used_tool_calls,
            "used_llm_calls": self.used_llm_calls,
            "is_over_budget": self.is_over_budget(),
        }

    def __str__(self) -> str:
        return (
            f"PhaseBudget({self.phase}: "
            f"{self.elapsed():.0f}/{self.max_time_secs}s, "
            f"{self.used_tool_calls}/{self.max_tool_calls} tools, "
            f"{self.used_llm_calls}/{self.max_llm_calls} LLM)"
        )
