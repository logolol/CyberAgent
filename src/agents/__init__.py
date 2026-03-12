"""
src/agents/__init__.py

Public exports for the agents package.
Only BaseAgent and OrchestratorAgent are exported here.
Specialist agents are imported lazily inside OrchestratorAgent._get_agent()
to prevent circular imports.
"""

__all__ = [
    "BaseAgent",
    "OrchestratorAgent",
]

from .base_agent import BaseAgent
from .orchestrator_agent import OrchestratorAgent
