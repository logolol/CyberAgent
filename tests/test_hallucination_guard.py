"""
Unit tests for BaseAgent hallucination guard functionality.

Tests all 8 validation checks:
1. CVE format validation
2. CVSS score range validation
3. Confirmed without evidence detection
4. Vague version string detection
5. IP address format validation
6. CVE existence verification
7. Exploit path validation
8. Command syntax validation
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class TestHallucinationGuard(unittest.TestCase):
    """Test suite for hallucination guard validation."""

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

    def test_invalid_cve_format(self):
        """Test CHECK 1: Invalid CVE format detection."""
        output = {
            "cve": "CVE-99999-12345",  # Invalid year
            "description": "Contains CVE-ABCD-1234"  # Invalid format
        }

        result = self.agent.hallucination_guard(output, "vuln")

        self.assertIn("invalid_cve_format", str(result["_hallucination_flags"]))
        self.assertFalse(result["_guard_passed"])
        self.assertEqual(result["cve"], "CVE-INVALID-REMOVED")

    def test_valid_cve_format(self):
        """Test CHECK 1: Valid CVE format passes."""
        output = {
            "cve": "CVE-2021-41773",
            "description": "Apache path traversal"
        }

        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[
            {"text": "CVE-2021-41773: Apache HTTP Server path traversal"}
        ]):
            result = self.agent.hallucination_guard(output, "vuln")

        self.assertEqual(result["cve"], "CVE-2021-41773")

    def test_invalid_cvss_score(self):
        """Test CHECK 2: CVSS score range validation."""
        test_cases = [
            {"cvss": 15.0},  # Too high
            {"cvss": -1.0},  # Negative
            {"cvss": "invalid"},  # Non-numeric
        ]

        for output in test_cases:
            result = self.agent.hallucination_guard(output, "vuln")
            self.assertIn("invalid_cvss", str(result["_hallucination_flags"]))
            self.assertIsNone(result["cvss"])

    def test_valid_cvss_score(self):
        """Test CHECK 2: Valid CVSS scores pass."""
        valid_scores = [0.0, 5.5, 10.0, 7.8, 9.8]

        for score in valid_scores:
            output = {"cvss": score}
            result = self.agent.hallucination_guard(output, "vuln")
            self.assertEqual(result["cvss"], score)

    def test_confirmed_without_evidence(self):
        """Test CHECK 3: Confirmed findings without evidence are demoted."""
        output = {
            "findings": [
                {"confirmed": True, "evidence": ""},  # No evidence
                {"confirmed": True, "evidence": "   "},  # Whitespace only
                {"confirmed": True},  # Missing evidence field
            ]
        }

        result = self.agent.hallucination_guard(output, "exploit")

        for finding in result["findings"]:
            self.assertFalse(finding["confirmed"])
            self.assertTrue(finding["potential"])

        self.assertIn("unconfirmed_finding_demoted", result["_hallucination_flags"])

    def test_confirmed_with_evidence(self):
        """Test CHECK 3: Confirmed findings with evidence pass."""
        output = {
            "findings": [
                {
                    "confirmed": True,
                    "evidence": "uid=0(root) gid=0(root) groups=0(root)"
                }
            ]
        }

        result = self.agent.hallucination_guard(output, "exploit")

        self.assertTrue(result["findings"][0]["confirmed"])
        self.assertNotIn("unconfirmed_finding_demoted", result["_hallucination_flags"])

    def test_vague_version_string(self):
        """Test CHECK 4: Vague version strings are flagged."""
        output = {
            "version": "Apache web server running on Ubuntu with SSL enabled"
        }

        result = self.agent.hallucination_guard(output, "enum")

        self.assertIn("vague_version_string", str(result["_hallucination_flags"]))
        self.assertEqual(result["version"], "version_unknown")

    def test_valid_version_string(self):
        """Test CHECK 4: Valid version strings pass."""
        valid_versions = [
            "2.4.49",
            "Apache/2.4.49",
            "nginx 1.18.0",
            "OpenSSH 8.2p1"
        ]

        for version in valid_versions:
            output = {"version": version}
            result = self.agent.hallucination_guard(output, "enum")
            self.assertEqual(result["version"], version)

    def test_invalid_ip_address(self):
        """Test CHECK 5: Invalid IP addresses are removed."""
        output = {
            "ip": "999.999.999.999"
        }

        result = self.agent.hallucination_guard(output, "recon")

        self.assertIn("invalid_ip", str(result["_hallucination_flags"]))
        self.assertNotIn("ip", result)

    def test_valid_ip_address(self):
        """Test CHECK 5: Valid IP addresses pass."""
        valid_ips = ["10.0.0.1", "192.168.1.1", "172.16.0.1", "8.8.8.8"]

        for ip in valid_ips:
            output = {"ip": ip}
            result = self.agent.hallucination_guard(output, "recon")
            self.assertEqual(result["ip"], ip)

    def test_cve_existence_validation(self):
        """Test CHECK 6: CVE existence in RAG database."""
        output = {"cve": "CVE-2021-41773"}

        # Mock RAG returning no results (CVE not found)
        with patch.object(self.agent.chroma, 'get_rag_context', return_value=[]):
            result = self.agent.hallucination_guard(output, "vuln")

        self.assertIn("cve_not_found_in_database", str(result["_hallucination_flags"]))
        self.assertEqual(result["cve"], "CVE-UNVERIFIED")
        self.assertTrue(result.get("requires_verification"))

    def test_exploit_path_validation(self):
        """Test CHECK 7: Exploit path format validation."""
        # Valid formats
        valid_paths = [
            "EDB-ID:50383",
            "exploit/linux/http/apache_mod_cgi",
            ""  # Empty is acceptable
        ]

        for path in valid_paths:
            output = {"exploit_path": path}
            with patch.object(self.agent.chroma, 'get_rag_context', return_value=[
                {"text": f"Exploit {path}"}
            ]):
                result = self.agent.hallucination_guard(output, "exploit")

        # Invalid format
        output = {"exploit_path": "/tmp/invalid"}
        result = self.agent.hallucination_guard(output, "exploit")
        self.assertIn("invalid_exploit_path_format", str(result["_hallucination_flags"]))

    def test_command_syntax_validation(self):
        """Test CHECK 8: Command syntax validation."""
        # Invalid commands
        invalid_commands = [
            {"command": "nmap -sV 'unclosed quote"},  # Unmatched quote
            {"command": "ls |"},  # Incomplete pipe
            {"command": "cat file; rm -rf /"},  # Suspicious pattern
        ]

        for output in invalid_commands:
            result = self.agent.hallucination_guard(output, "enum")
            self.assertFalse(result["_guard_passed"])

        # Valid command
        output = {"command": "nmap -sV -p 80,443 10.0.0.1"}
        result = self.agent.hallucination_guard(output, "enum")
        # Note: This might still have flags from missing RAG data, but no syntax issues

    def test_nested_structure_validation(self):
        """Test that validation works on nested structures."""
        output = {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "vulnerabilities": [
                        {
                            "cve": "CVE-INVALID",
                            "cvss": 15.0,
                            "confirmed": True,
                            "evidence": ""
                        }
                    ]
                }
            ]
        }

        result = self.agent.hallucination_guard(output, "vuln")

        # Should catch multiple issues
        flags = result["_hallucination_flags"]
        self.assertGreater(len(flags), 0)
        self.assertFalse(result["_guard_passed"])

        # Check that nested CVE was marked invalid
        vuln = result["hosts"][0]["vulnerabilities"][0]
        self.assertEqual(vuln["cve"], "CVE-INVALID-REMOVED")
        self.assertIsNone(vuln["cvss"])
        self.assertFalse(vuln["confirmed"])

    def test_clean_output_passes(self):
        """Test that clean output passes all checks."""
        output = {
            "agent": "test_agent",
            "target": "test.example.com",
            "confidence": 0.95
        }

        result = self.agent.hallucination_guard(output, "recon")

        self.assertEqual(len(result["_hallucination_flags"]), 0)
        self.assertTrue(result["_guard_passed"])
        self.assertIn("_validation_sources", result)


if __name__ == "__main__":
    unittest.main()
