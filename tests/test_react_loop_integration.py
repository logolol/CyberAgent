"""
Integration tests for the ReAct loop with validation and evidence-based execution.

Tests the full Thought → Action → Observation loop with:
- Command validation before execution
- Retry logic for transient failures
- Hallucination guard on final answers
- Multi-source verification
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class TestReActLoopIntegration(unittest.TestCase):
    """Integration tests for the full ReAct loop."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_memory = Mock(spec=MissionMemory)
        self.mock_memory.target = "test.example.com"
        self.mock_memory.get_full_context.return_value = {
            "mission_id": "test_mission",
            "target": "test.example.com",
            "phase": "recon",
            "hosts": {}
        }
        self.mock_memory.log_action = Mock()

        with patch('agents.base_agent.get_llm') as mock_llm, \
             patch('agents.base_agent.ChromaManager') as mock_chroma, \
             patch('agents.base_agent.DynamicToolManager') as mock_tools:

            self.mock_llm_instance = Mock()
            mock_llm.return_value = self.mock_llm_instance

            self.mock_chroma_instance = Mock()
            mock_chroma.return_value = self.mock_chroma_instance
            self.mock_chroma_instance.get_rag_context.return_value = [
                {"text": "Example RAG context", "source_collection": "test"}
            ]

            self.mock_tools_instance = Mock()
            mock_tools.return_value = self.mock_tools_instance

            self.agent = BaseAgent(
                agent_name="test_agent",
                mission_memory=self.mock_memory,
                llm_role="default",
                max_react_iterations=5
            )

    def test_successful_react_loop_with_validation(self):
        """Test successful ReAct loop with command validation."""
        # Simulate LLM responses: Action → Final Answer
        self.mock_llm_instance.invoke.side_effect = [
            # First iteration: propose an action
            """
            THOUGHT: I need to scan the target for open ports.
            ACTION: nmap
            ACTION_INPUT: {"args": ["-sV", "-p", "80,443", "10.0.0.1"], "purpose": "Port scan"}
            """,
            # Second iteration: provide final answer
            """
            THOUGHT: Scan complete, summarizing results.
            FINAL_ANSWER: {"ports_found": [80, 443], "services": ["http", "https"], "confidence": 0.95}
            """
        ]

        # Mock tool execution
        self.mock_tools_instance.use.return_value = {
            "output": "PORT   STATE SERVICE\n80/tcp  open  http\n443/tcp open  https"
        }

        result = self.agent.react(task="Scan target for open ports")

        # Verify success
        self.assertTrue(result["success"])
        self.assertEqual(result["agent"], "test_agent")
        self.assertIn("ports_found", result["result"])

        # Verify hallucination guard was applied
        self.assertIn("_hallucination_flags", result["result"])
        self.assertIn("_guard_passed", result["result"])

    def test_react_loop_invalid_command_gets_retry(self):
        """Test that invalid commands trigger LLM to retry with feedback."""
        self.mock_llm_instance.invoke.side_effect = [
            # First attempt: invalid command (missing args)
            """
            THOUGHT: I'll scan the target.
            ACTION: nmap
            ACTION_INPUT: {"args": []}
            """,
            # Second attempt: corrected command
            """
            THOUGHT: I need to provide target and flags.
            ACTION: nmap
            ACTION_INPUT: {"args": ["-sV", "10.0.0.1"]}
            """,
            # Final answer
            """
            FINAL_ANSWER: {"scan_complete": true}
            """
        ]

        self.mock_tools_instance.use.return_value = {"output": "Scan complete"}

        result = self.agent.react(task="Scan target")

        # Should succeed after retry
        self.assertTrue(result["success"])
        # Should have made multiple LLM calls due to validation failure
        self.assertGreater(self.mock_llm_instance.invoke.call_count, 1)

    def test_react_loop_transient_error_retry(self):
        """Test that transient errors trigger automatic retry."""
        self.mock_llm_instance.invoke.side_effect = [
            # Propose action
            """
            ACTION: nmap
            ACTION_INPUT: {"args": ["-sV", "10.0.0.1"]}
            """,
            # After retry, final answer
            """
            FINAL_ANSWER: {"retry_success": true}
            """
        ]

        # Mock transient failure then success
        self.mock_tools_instance.use.side_effect = [
            {"error": "Connection timeout"},  # First attempt fails
            {"error": "Connection timeout"},  # Second attempt fails
            {"output": "Scan complete"}  # Third attempt succeeds
        ]

        with patch('time.sleep'):  # Skip actual sleep in tests
            result = self.agent.react(task="Scan target")

        # Should succeed after retries
        self.assertTrue(result["success"])
        # Tool should have been called multiple times
        self.assertEqual(self.mock_tools_instance.use.call_count, 3)

    def test_react_loop_hallucination_guard_on_final_answer(self):
        """Test that hallucination guard validates final answers."""
        self.mock_llm_instance.invoke.return_value = """
        FINAL_ANSWER: {
            "cve": "CVE-INVALID-99999",
            "cvss": 15.0,
            "ip": "999.999.999.999",
            "vulnerabilities": [
                {"confirmed": true, "evidence": ""}
            ]
        }
        """

        result = self.agent.react(task="Test task")

        # Should complete but with hallucination flags
        self.assertTrue(result["success"])
        self.assertFalse(result["result"]["_guard_passed"])
        self.assertGreater(len(result["result"]["_hallucination_flags"]), 0)

        # Invalid data should be cleaned
        self.assertNotEqual(result["result"]["cve"], "CVE-INVALID-99999")

    def test_react_loop_max_iterations_reached(self):
        """Test behavior when max iterations is reached without final answer."""
        # Always return actions, never final answer
        self.mock_llm_instance.invoke.return_value = """
        ACTION: nmap
        ACTION_INPUT: {"args": ["-sV", "10.0.0.1"]}
        """

        self.mock_tools_instance.use.return_value = {"output": "Scan result"}

        result = self.agent.react(task="Scan target", context={})

        # Should fail with max iterations error
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "max_iterations_reached")
        self.assertEqual(result["iterations"], self.agent.max_iterations)

    def test_react_loop_llm_failure_handling(self):
        """Test graceful handling of LLM failures."""
        self.mock_llm_instance.invoke.side_effect = Exception("LLM connection error")

        result = self.agent.react(task="Test task")

        # Should fail gracefully
        self.assertFalse(result["success"])
        self.assertIn("LLM connection error", result["error"])

    def test_react_loop_multi_source_validation(self):
        """Test that multi-source validation occurs during execution."""
        self.mock_llm_instance.invoke.return_value = """
        FINAL_ANSWER: {
            "cve": "CVE-2021-41773",
            "cvss": 9.8,
            "exploit_path": "EDB-ID:50383"
        }
        """

        # Mock RAG returning validation sources
        self.mock_chroma_instance.get_rag_context.return_value = [
            {"text": "CVE-2021-41773: Apache HTTP Server 2.4.49 path traversal"},
            {"text": "EDB-ID:50383 - Apache 2.4.49/2.4.50 exploit"}
        ]

        result = self.agent.react(task="Check vulnerability")

        # Should include validation sources
        self.assertIn("_validation_sources", result["result"])

    def test_react_loop_evidence_logging(self):
        """Test that all actions and observations are logged to mission memory."""
        self.mock_llm_instance.invoke.side_effect = [
            """
            ACTION: nmap
            ACTION_INPUT: {"args": ["-sV", "10.0.0.1"]}
            """,
            """
            FINAL_ANSWER: {"complete": true}
            """
        ]

        self.mock_tools_instance.use.return_value = {"output": "Scan complete"}

        result = self.agent.react(task="Scan target")

        # Verify actions were logged to mission memory
        self.mock_memory.log_action.assert_called()
        # Should have logged the nmap action
        call_args = [call[0] for call in self.mock_memory.log_action.call_args_list]
        self.assertTrue(any("nmap" in str(args) for args in call_args))


class TestMultiSourceValidation(unittest.TestCase):
    """Test multi-source validation and cross-referencing."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_memory = Mock(spec=MissionMemory)
        self.mock_memory.target = "test.example.com"
        self.mock_memory.get_full_context.return_value = {}

        with patch('agents.base_agent.get_llm'), \
             patch('agents.base_agent.ChromaManager') as mock_chroma, \
             patch('agents.base_agent.DynamicToolManager'):

            self.mock_chroma_instance = Mock()
            mock_chroma.return_value = self.mock_chroma_instance

            self.agent = BaseAgent(
                agent_name="test_agent",
                mission_memory=self.mock_memory,
                llm_role="default",
                max_react_iterations=5
            )

    def test_cve_cross_reference_with_multiple_sources(self):
        """Test CVE validation against multiple RAG sources."""
        output = {"cve": "CVE-2021-41773"}

        # Mock RAG returning results from multiple collections
        self.mock_chroma_instance.get_rag_context.return_value = [
            {
                "text": "CVE-2021-41773: Apache HTTP Server vulnerability",
                "source_collection": "cve_database"
            },
            {
                "text": "Exploit for CVE-2021-41773",
                "source_collection": "exploitdb"
            }
        ]

        result = self.agent.hallucination_guard(output, "vuln")

        # Should have validation sources from multiple collections
        self.assertIn("_validation_sources", result)
        sources_str = str(result["_validation_sources"])
        self.assertIn("cve_database", sources_str)

    def test_exploit_verification_against_exploitdb(self):
        """Test exploit path verification against ExploitDB."""
        output = {"exploit_path": "EDB-ID:50383"}

        self.mock_chroma_instance.get_rag_context.return_value = [
            {"text": "EDB-ID: 50383 - Apache 2.4.49 Path Traversal"}
        ]

        result = self.agent.hallucination_guard(output, "exploit")

        # Should validate against ExploitDB
        sources_str = str(result.get("_validation_sources", []))
        self.assertIn("exploitdb", sources_str.lower())


if __name__ == "__main__":
    unittest.main()
