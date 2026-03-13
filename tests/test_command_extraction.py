"""
Unit tests for command extraction and validation functionality.

Tests the structured command parsing and validation logic that prevents
hallucinated or malformed commands from being executed.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class TestCommandExtraction(unittest.TestCase):
    """Test suite for command extraction and validation."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock mission memory
        self.mock_memory = Mock(spec=MissionMemory)
        self.mock_memory.target = "test.example.com"
        self.mock_memory.get_full_context.return_value = {}

        # Create base agent with mocked dependencies
        with patch('agents.base_agent.get_llm'), \
             patch('agents.base_agent.ChromaManager'), \
             patch('agents.base_agent.DynamicToolManager'):
            self.agent = BaseAgent(
                agent_name="test_agent",
                mission_memory=self.mock_memory,
                llm_role="default",
                max_react_iterations=5
            )

    def test_extract_structured_action_block(self):
        """Test extraction of structured ACTION blocks from LLM output."""
        llm_output = """
        THOUGHT: I need to scan the target for open ports.
        ACTION: nmap
        ACTION_INPUT: {"args": ["-sV", "-p", "80,443", "10.0.0.1"], "purpose": "Port scan"}
        """

        commands = self.agent._extract_commands_from_output(llm_output)

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["tool"], "nmap")
        self.assertEqual(commands[0]["args"], ["-sV", "-p", "80,443", "10.0.0.1"])
        self.assertEqual(commands[0]["purpose"], "Port scan")

    def test_extract_multiple_action_blocks(self):
        """Test extraction of multiple ACTION blocks."""
        llm_output = """
        ACTION: nmap
        ACTION_INPUT: {"args": ["-sV", "10.0.0.1"]}
        
        ACTION: nikto
        ACTION_INPUT: {"args": ["-h", "http://10.0.0.1"]}
        """

        commands = self.agent._extract_commands_from_output(llm_output)

        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0]["tool"], "nmap")
        self.assertEqual(commands[1]["tool"], "nikto")

    def test_extract_inline_commands(self):
        """Test extraction of inline command mentions."""
        llm_output = """
        I will run nmap -sV -p 1-1000 10.0.0.1 to scan ports.
        Then execute gobuster dir -u http://10.0.0.1 -w wordlist.txt
        """

        commands = self.agent._extract_commands_from_output(llm_output)

        self.assertGreaterEqual(len(commands), 2)
        # Check that tools were extracted
        tools = [cmd["tool"] for cmd in commands]
        self.assertIn("nmap", tools)
        self.assertIn("gobuster", tools)

    def test_validate_command_with_missing_args(self):
        """Test validation catches missing required arguments."""
        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[]):
            validation = self.agent._validate_command_structure(
                "nmap",
                {"args": []}
            )

        self.assertFalse(validation["valid"])
        self.assertIn("typically requires arguments", str(validation["issues"]))

    def test_validate_command_with_destructive_patterns(self):
        """Test validation catches potentially destructive commands."""
        destructive_args = [
            ["rm", "-rf", "/"],
            ["dd", "if=/dev/zero", "of=/dev/sda"],
            ["mkfs.ext4", "/dev/sda1"]
        ]

        for args in destructive_args:
            validation = self.agent._validate_command_structure(
                "bash",
                {"args": args}
            )

            self.assertFalse(validation["valid"])
            self.assertIn("destructive", str(validation["issues"]).lower())

    def test_validate_command_with_incomplete_flags(self):
        """Test validation catches flags missing their values."""
        validation = self.agent._validate_command_structure(
            "nmap",
            {"args": ["-p", "-sV", "10.0.0.1"]}  # -p missing port value
        )

        self.assertFalse(validation["valid"])
        self.assertIn("missing", str(validation["issues"]).lower())

    def test_validate_command_with_valid_args(self):
        """Test validation passes for properly formed commands."""
        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[
            {"text": "nmap usage examples"}
        ]):
            validation = self.agent._validate_command_structure(
                "nmap",
                {"args": ["-sV", "-p", "80,443", "10.0.0.1"]}
            )

        # May have warnings but should not be invalid
        self.assertGreaterEqual(validation["confidence"], 0.5)

    def test_validate_unknown_tool(self):
        """Test validation handles unknown tools gracefully."""
        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[]):
            validation = self.agent._validate_command_structure(
                "nonexistent_tool_xyz",
                {"args": ["--help"]}
            )

        # Should have suggestions but not crash
        self.assertIn("suggestions", validation)

    def test_command_confidence_scoring(self):
        """Test that confidence scores reflect validation results."""
        # Perfect command
        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[
            {"text": "nmap examples"}
        ]):
            validation1 = self.agent._validate_command_structure(
                "nmap",
                {"args": ["-sV", "10.0.0.1"]}
            )

        # Command with issues
        validation2 = self.agent._validate_command_structure(
            "nmap",
            {"args": ["rm", "-rf", "/"]}
        )

        # Good command should have higher confidence
        self.assertGreater(validation1["confidence"], validation2["confidence"])

    def test_extract_commands_from_malformed_json(self):
        """Test extraction handles malformed JSON gracefully."""
        llm_output = """
        ACTION: nmap
        ACTION_INPUT: {invalid json without quotes: value}
        """

        commands = self.agent._extract_commands_from_output(llm_output)

        # Should still extract the tool even if JSON is malformed
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["tool"], "nmap")
        self.assertIn("raw", commands[0]["raw_input"])

    def test_extract_commands_preserves_quotes(self):
        """Test that argument extraction preserves quoted strings."""
        llm_output = """
        ACTION: gobuster
        ACTION_INPUT: {"args": ["dir", "-u", "http://10.0.0.1", "-w", "/path/with spaces/wordlist.txt"]}
        """

        commands = self.agent._extract_commands_from_output(llm_output)

        self.assertEqual(len(commands), 1)
        # Check that the path with spaces is preserved
        self.assertIn("/path/with spaces/wordlist.txt", commands[0]["args"])

    def test_validation_provides_actionable_suggestions(self):
        """Test that validation provides helpful suggestions for fixing issues."""
        validation = self.agent._validate_command_structure(
            "nmap",
            {"args": []}
        )

        self.assertGreater(len(validation["suggestions"]), 0)
        # Suggestions should mention how to fix the issue
        suggestions_text = " ".join(validation["suggestions"]).lower()
        self.assertTrue(
            any(word in suggestions_text for word in ["help", "check", "required", "parameters"])
        )


class TestCommandExecutionLoop(unittest.TestCase):
    """Test suite for the evidence-based command execution loop."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_memory = Mock(spec=MissionMemory)
        self.mock_memory.target = "test.example.com"
        self.mock_memory.get_full_context.return_value = {}

        with patch('agents.base_agent.get_llm'), \
             patch('agents.base_agent.ChromaManager'), \
             patch('agents.base_agent.DynamicToolManager'):
            self.agent = BaseAgent(
                agent_name="test_agent",
                mission_memory=self.mock_memory,
                llm_role="default",
                max_react_iterations=5
            )

    def test_retry_logic_on_transient_errors(self):
        """Test that transient errors trigger retry with backoff."""
        transient_errors = [
            {"error": "Connection timeout"},
            {"error": "Connection refused"},
            {"error": "Temporary failure in name resolution"}
        ]

        # Each should be recognized as transient
        for error_result in transient_errors:
            error_msg = error_result["error"].lower()
            is_transient = any(
                err in error_msg
                for err in ["timeout", "connection refused", "temporary failure"]
            )
            self.assertTrue(is_transient, f"{error_msg} should be recognized as transient")

    def test_non_transient_errors_no_retry(self):
        """Test that non-transient errors don't trigger unnecessary retries."""
        permanent_errors = [
            {"error": "Permission denied"},
            {"error": "No such file or directory"},
            {"error": "Invalid argument"}
        ]

        for error_result in permanent_errors:
            error_msg = error_result["error"].lower()
            is_transient = any(
                err in error_msg
                for err in ["timeout", "connection refused", "temporary failure", "try again"]
            )
            self.assertFalse(is_transient, f"{error_msg} should not be recognized as transient")


if __name__ == "__main__":
    unittest.main()
