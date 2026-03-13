"""
Day 4 tests — Orchestrator completeness, MCP integration, external intel fallback.

Tests:
  1. MCP PentestAI wrapper availability check
  2. MCP exploit search with ChromaDB fallback
  3. MCP CVE lookup with ChromaDB fallback
  4. ExternalIntel CVE lookup (mocked NVD API)
  5. ExternalIntel exploit search (mocked ExploitDB)
  6. ChromaManager.get_phase_rag_context() phase routing
  7. Orchestrator briefing includes RAG context + tool commands
  8. Orchestrator briefing fallback when LLM fails
  9. _enrich_with_external_intel fills empty attack_vectors
 10. _direct_llm anti-hallucination JSON instruction
 11. MCP status in run() banner (smoke test)
"""
import sys
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ── 1. MCP PentestAI — availability check ─────────────────────────────────────

class TestPentestAIMCPAvailability(unittest.TestCase):
    """MCP wrapper correctly reports availability and caches result."""

    def setUp(self):
        from mcp.pentestai_mcp import PentestAIMCP
        self.mcp = PentestAIMCP(base_url="http://localhost:4090")

    def test_unavailable_server_returns_false(self):
        """Server not running → is_available() is False, no exception."""
        with patch.object(self.mcp._session, "get", side_effect=ConnectionRefusedError):
            result = self.mcp.is_available()
        self.assertFalse(result)

    def test_availability_cached_after_first_call(self):
        """Second call uses cached value, no extra network call."""
        self.mcp._available = False  # pre-set cache
        with patch.object(self.mcp._session, "get") as mock_get:
            result = self.mcp.is_available()
            mock_get.assert_not_called()
        self.assertFalse(result)

    def test_available_server_returns_true(self):
        """Server responds 200 → is_available() is True."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        with patch.object(self.mcp._session, "get", return_value=mock_resp):
            result = self.mcp.is_available()
        self.assertTrue(result)

    def test_status_returns_dict(self):
        """status() always returns a dict with required keys."""
        self.mcp._available = False
        status = self.mcp.status()
        self.assertIn("mcp_available", status)
        self.assertIn("mcp_url", status)
        self.assertIn("collections_active", status)


# ── 2. MCP exploit search with ChromaDB fallback ─────────────────────────────

class TestPentestAIMCPExploitSearch(unittest.TestCase):
    """MCP exploit search falls back to ChromaDB when server unavailable."""

    def setUp(self):
        from mcp.pentestai_mcp import PentestAIMCP
        self.mcp = PentestAIMCP()
        self.mcp._available = False  # Force fallback path

    def test_exploit_search_fallback_returns_list(self):
        """ChromaDB fallback returns a list (may be empty in test env)."""
        mock_chroma = Mock()
        mock_chroma.get_rag_context.return_value = [
            {
                "text": "Apache mod_cgi RCE via PATH_INFO",
                "metadata": {"title": "Apache RCE", "cve": "CVE-2021-41773", "cvss": "9.8"},
                "source_collection": "exploitdb",
                "distance": 0.1,
            }
        ]
        with patch("mcp.pentestai_mcp._ChromaManager", return_value=mock_chroma):
            results = self.mcp.search_exploits("Apache RCE 2021", limit=5)
        self.assertIsInstance(results, list)
        if results:
            self.assertIn("title", results[0])
            self.assertIn("source", results[0])

    def test_exploit_search_handles_chroma_error(self):
        """ChromaDB failure returns empty list, never raises."""
        with patch("mcp.pentestai_mcp._ChromaManager", side_effect=Exception("DB error")):
            results = self.mcp.search_exploits("test query")
        self.assertEqual(results, [])


# ── 3. MCP CVE lookup fallback ────────────────────────────────────────────────

class TestPentestAIMCPCVELookup(unittest.TestCase):
    """MCP CVE lookup falls back to ChromaDB."""

    def setUp(self):
        from mcp.pentestai_mcp import PentestAIMCP
        self.mcp = PentestAIMCP()
        self.mcp._available = False

    def test_cve_lookup_fallback_found(self):
        """ChromaDB hit returns structured dict with cve_id."""
        mock_chroma = Mock()
        mock_chroma.get_rag_context.return_value = [
            {
                "text": "CVE-2021-41773 Apache path traversal CVSS 9.8",
                "metadata": {"cvss": "9.8"},
                "source_collection": "cve_database",
                "distance": 0.05,
            }
        ]
        with patch("mcp.pentestai_mcp._ChromaManager", return_value=mock_chroma):
            result = self.mcp.lookup_cve("CVE-2021-41773")
        self.assertIn("cve_id", result)
        self.assertEqual(result["cve_id"], "CVE-2021-41773")

    def test_cve_lookup_not_found(self):
        """CVE not in ChromaDB returns error dict."""
        mock_chroma = Mock()
        mock_chroma.get_rag_context.return_value = []
        with patch("mcp.pentestai_mcp._ChromaManager", return_value=mock_chroma):
            result = self.mcp.lookup_cve("CVE-2099-99999")
        self.assertIn("error", result)


# ── 4. ExternalIntel CVE lookup ───────────────────────────────────────────────

class TestExternalIntelCVELookup(unittest.TestCase):
    """ExternalIntel correctly parses NVD API v2 responses."""

    def setUp(self):
        from utils.external_intel import ExternalIntel
        self.intel = ExternalIntel()

    def test_lookup_cve_success(self):
        """NVD API 200 response is correctly parsed into structured dict."""
        mock_nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-41773",
                    "descriptions": [{"lang": "en", "value": "Apache path traversal RCE"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                        }]
                    },
                    "configurations": [],
                    "references": [{"url": "https://httpd.apache.org/security/"}],
                    "published": "2021-10-05",
                    "lastModified": "2021-10-07",
                }
            }]
        }
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_nvd_response

        with patch("utils.external_intel._SESSION") as mock_session:
            mock_session.get.return_value = mock_resp
            # Bypass cache
            self.intel._save_cache = Mock()
            self.intel._load_cache = Mock(return_value=None)
            result = self.intel.lookup_cve("CVE-2021-41773")

        self.assertEqual(result["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cvss_v3"], 9.8)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertIn("Apache", result["description"])

    def test_lookup_cve_not_found(self):
        """NVD API returns empty vulnerabilities list → error dict."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("utils.external_intel._SESSION") as mock_session:
            mock_session.get.return_value = mock_resp
            self.intel._load_cache = Mock(return_value=None)
            result = self.intel.lookup_cve("CVE-2099-99999")

        self.assertIn("error", result)

    def test_lookup_cve_timeout_returns_error(self):
        """NVD API timeout returns error dict, never raises."""
        import requests
        with patch("utils.external_intel._SESSION") as mock_session:
            mock_session.get.side_effect = requests.Timeout
            self.intel._load_cache = Mock(return_value=None)
            result = self.intel.lookup_cve("CVE-2021-41773")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "nvd_timeout")

    def test_lookup_cve_uses_cache(self):
        """Cached result is returned without network call."""
        cached_data = {"cve_id": "CVE-2021-41773", "cvss_v3": 9.8, "source": "cache"}
        self.intel._load_cache = Mock(return_value=cached_data)

        with patch("utils.external_intel._SESSION") as mock_session:
            result = self.intel.lookup_cve("CVE-2021-41773")
            mock_session.get.assert_not_called()

        self.assertEqual(result["cvss_v3"], 9.8)


# ── 5. ExternalIntel exploit search ──────────────────────────────────────────

class TestExternalIntelExploitSearch(unittest.TestCase):
    """ExternalIntel exploit search uses cache and parses ExploitDB response."""

    def setUp(self):
        from utils.external_intel import ExternalIntel
        self.intel = ExternalIntel()

    def test_exploit_search_returns_list(self):
        """ExploitDB search returns a list of exploit dicts."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": "50383",
                    "description": "Apache HTTP Server 2.4.49 - Path Traversal & RCE",
                    "cve": {"cve_id": "CVE-2021-41773"},
                    "platform": {"val": "Linux"},
                    "type": {"val": "remote"},
                    "date_published": "2021-10-07",
                }
            ]
        }
        with patch("utils.external_intel._SESSION") as mock_session:
            mock_session.get.return_value = mock_resp
            self.intel._load_cache = Mock(return_value=None)
            self.intel._save_cache = Mock()
            results = self.intel.search_exploits("Apache RCE 2021")

        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["edb_id"], "50383")

    def test_exploit_search_network_failure_returns_empty(self):
        """Network failure returns empty list, never raises."""
        with patch("utils.external_intel._SESSION") as mock_session:
            mock_session.get.side_effect = Exception("Connection refused")
            self.intel._load_cache = Mock(return_value=None)
            results = self.intel.search_exploits("test query")
        self.assertEqual(results, [])


# ── 6. ChromaManager phase-specific RAG ──────────────────────────────────────

class TestChromaManagerPhaseRAG(unittest.TestCase):
    """get_phase_rag_context() routes to correct collections per phase."""

    def test_recon_hits_correct_collections(self):
        """Recon phase queries hacktricks + mitre_attack first."""
        from memory.chroma_manager import ChromaManager
        # Access the class-level mapping
        phase_cols = ChromaManager._PHASE_COLLECTIONS
        self.assertIn("recon", phase_cols)
        recon_cols = phase_cols["recon"]
        self.assertIn("hacktricks", recon_cols)
        self.assertIn("mitre_attack", recon_cols)

    def test_exploit_hits_exploitdb_first(self):
        """Exploit phase queries exploitdb first."""
        from memory.chroma_manager import ChromaManager
        phase_cols = ChromaManager._PHASE_COLLECTIONS
        exploit_cols = phase_cols.get("exploit", [])
        self.assertGreater(len(exploit_cols), 0)
        self.assertEqual(exploit_cols[0], "exploitdb")

    def test_privesc_hits_gtfobins(self):
        """PrivEsc phase includes gtfobins."""
        from memory.chroma_manager import ChromaManager
        phase_cols = ChromaManager._PHASE_COLLECTIONS
        privesc_cols = phase_cols.get("privesc", [])
        self.assertIn("gtfobins", privesc_cols)

    def test_get_phase_rag_context_deduplicates(self):
        """Results from multiple collections are deduplicated by text prefix."""
        from memory.chroma_manager import ChromaManager
        with patch.object(ChromaManager, "semantic_search") as mock_search:
            # Return identical text from two different collections
            hit = {"text": "A" * 200, "metadata": {}, "distance": 0.1}
            mock_search.return_value = [hit]
            chroma = ChromaManager.__new__(ChromaManager)
            chroma.client = Mock()
            results = chroma.get_phase_rag_context("recon", "test query", n=3)
        # Same text from multiple collections → only 1 result
        texts = [r["text"][:120] for r in results]
        self.assertEqual(len(texts), len(set(texts)))


# ── 7. Orchestrator briefing includes RAG + tool commands ─────────────────────

class TestOrchestratorBriefing(unittest.TestCase):
    """_build_agent_briefing() injects RAG context and tool commands."""

    def _make_orchestrator(self):
        from memory.mission_memory import MissionMemory
        from agents.orchestrator_agent import OrchestratorAgent

        mock_mem = Mock(spec=MissionMemory)
        mock_mem.target = "192.168.1.100"
        mock_mem.mission_id = "test_mission"
        mock_mem._state = {"hosts": {}, "phase": "recon", "attack_chain": []}
        mock_mem.get_full_context.return_value = {}

        with patch("agents.base_agent.get_llm"), \
             patch("agents.base_agent.ChromaManager"), \
             patch("agents.base_agent.DynamicToolManager"):
            orch = OrchestratorAgent.__new__(OrchestratorAgent)
            orch.agent_name = "OrchestratorAgent"
            orch.memory = mock_mem
            orch.phase_results = {}
            orch.current_phase = None
            orch._mcp = None
            orch._external_intel = None
            orch._PHASE_MAP = {
                "recon": "recon", "enumeration": "enum", "vuln_scan": "vuln",
                "exploitation": "exploit", "privesc": "privesc",
                "postexploit": "postexploit", "reporting": "report",
            }
            from rich.console import Console
            orch.console = Console(quiet=True)
            import logging
            orch._log = logging.getLogger("test")
            orch.log_warning = lambda m: None
            orch.log_error = lambda m: None
            orch.log_info = lambda m: None
            orch.log_success = lambda m: None
            # Attach real chroma mock
            mock_chroma = Mock()
            mock_chroma.get_phase_rag_context.return_value = [
                {"text": "Apache CVE-2021-41773 RCE", "source_collection": "exploitdb",
                 "metadata": {}, "distance": 0.1},
            ]
            orch.chroma = mock_chroma
        return orch

    def test_briefing_includes_tool_commands(self):
        """Briefing fallback always includes tool_commands for the phase."""
        orch = self._make_orchestrator()
        # Force LLM to fail → use fallback
        orch._direct_llm = Mock(return_value={"error": "llm_failed"})
        result = orch._build_agent_briefing("recon")
        self.assertIn("tool_commands", result)
        self.assertIsInstance(result["tool_commands"], list)
        self.assertGreater(len(result["tool_commands"]), 0)

    def test_briefing_target_injected_in_tool_commands(self):
        """Tool command examples have {target} substituted with actual target."""
        orch = self._make_orchestrator()
        orch._direct_llm = Mock(return_value={"error": "llm_failed"})
        result = orch._build_agent_briefing("enumeration")
        target = orch.memory.target
        for cmd in result.get("tool_commands", []):
            self.assertNotIn("{target}", cmd)
            self.assertIn(target, cmd)

    def test_briefing_rag_context_queried(self):
        """Briefing calls get_phase_rag_context() for context injection."""
        orch = self._make_orchestrator()
        llm_result = {
            "priority_targets": ["192.168.1.100"],
            "known_info": {},
            "attack_vectors": ["nmap scan"],
            "avoid": [],
            "rag_queries": ["Apache RCE"],
            "tool_commands": [],
            "special_instructions": "Focus on recon.",
        }
        orch._direct_llm = Mock(return_value=llm_result)
        orch._build_agent_briefing("recon")
        orch.chroma.get_phase_rag_context.assert_called_once()

    def test_briefing_llm_result_has_tool_commands_injected(self):
        """If LLM omits tool_commands, they are injected from phase examples."""
        orch = self._make_orchestrator()
        llm_result = {
            "priority_targets": ["192.168.1.100"],
            "known_info": {},
            "attack_vectors": ["scan"],
            "avoid": [],
            "rag_queries": [],
            "special_instructions": "Scan target.",
            # No tool_commands key
        }
        orch._direct_llm = Mock(return_value=llm_result)
        result = orch._build_agent_briefing("recon")
        self.assertIn("tool_commands", result)
        self.assertIsInstance(result["tool_commands"], list)


# ── 8. _enrich_with_external_intel ────────────────────────────────────────────

class TestExternalIntelEnrichment(unittest.TestCase):
    """_enrich_with_external_intel() fills CVE details and attack vectors."""

    def _make_orchestrator(self):
        from memory.mission_memory import MissionMemory
        from agents.orchestrator_agent import OrchestratorAgent

        mock_mem = Mock(spec=MissionMemory)
        mock_mem.target = "192.168.1.100"
        mock_mem._state = {"hosts": {}}

        with patch("agents.base_agent.get_llm"), \
             patch("agents.base_agent.ChromaManager"), \
             patch("agents.base_agent.DynamicToolManager"):
            orch = OrchestratorAgent.__new__(OrchestratorAgent)
            orch.agent_name = "OrchestratorAgent"
            orch.memory = mock_mem
            orch._mcp = None
            orch._external_intel = None
            orch.log_warning = lambda m: None
        return orch

    def test_cve_details_filled_from_nvd(self):
        """External intel adds cvss_v3/severity for known CVE IDs."""
        orch = self._make_orchestrator()
        mock_intel = Mock()
        mock_intel.lookup_cve.return_value = {
            "cve_id": "CVE-2021-41773",
            "cvss_v3": 9.8,
            "severity": "CRITICAL",
            "description": "Apache path traversal",
        }
        mock_intel.search_exploits.return_value = []
        orch._external_intel = mock_intel

        result = orch._enrich_with_external_intel(
            {"cve": "CVE-2021-41773"},
            "vuln_scan",
        )
        self.assertEqual(result.get("cvss_v3"), 9.8)
        self.assertEqual(result.get("severity"), "CRITICAL")

    def test_attack_vectors_filled_from_exploitdb(self):
        """Empty attack_vectors filled from ExploitDB in exploit phase."""
        orch = self._make_orchestrator()
        mock_intel = Mock()
        mock_intel.lookup_cve.return_value = {"error": "no cve field"}
        mock_intel.search_exploits.return_value = [
            {"title": "Apache RCE", "cve": "CVE-2021-41773"},
            {"title": "Log4Shell", "cve": "CVE-2021-44228"},
        ]
        orch._external_intel = mock_intel

        result = orch._enrich_with_external_intel(
            {"attack_vectors": []},
            "exploitation",
        )
        self.assertGreater(len(result.get("attack_vectors", [])), 0)

    def test_no_external_intel_passes_through(self):
        """If ExternalIntel unavailable, result passes through unchanged."""
        orch = self._make_orchestrator()
        orch._external_intel = None
        orch._get_external_intel = Mock(return_value=None)
        original = {"key": "value"}
        result = orch._enrich_with_external_intel(dict(original), "recon")
        self.assertEqual(result, original)


# ── 9. direct_llm anti-hallucination JSON instruction ─────────────────────────

class TestDirectLLMAntiHallucination(unittest.TestCase):
    """_direct_llm() injects strict JSON instruction to prevent hallucination."""

    def _make_orchestrator(self):
        from agents.orchestrator_agent import OrchestratorAgent
        from memory.mission_memory import MissionMemory

        mock_mem = Mock(spec=MissionMemory)
        mock_mem.target = "test"
        mock_mem._state = {"hosts": {}}
        mock_mem.get_full_context.return_value = {}

        with patch("agents.base_agent.get_llm"), \
             patch("agents.base_agent.ChromaManager"), \
             patch("agents.base_agent.DynamicToolManager"):
            orch = OrchestratorAgent.__new__(OrchestratorAgent)
            orch.agent_name = "OrchestratorAgent"
            orch.memory = mock_mem
            orch._mcp = None
            orch._external_intel = None
            orch.log_warning = lambda m: None
            orch.log_error = lambda m: None
        return orch

    def test_json_instruction_appended_when_expect_json(self):
        """Prompt passed to LLM contains anti-hallucination JSON instruction."""
        orch = self._make_orchestrator()
        captured_messages = []

        def mock_chat(**kwargs):
            captured_messages.extend(kwargs.get("messages", []))
            return {"message": {"content": '{"key": "value"}'}}

        mock_client = Mock()
        mock_client.chat.side_effect = mock_chat

        with patch("utils.llm_factory.get_reasoning_llm") as mock_llm_params, \
             patch("ollama.Client", return_value=mock_client):
            mock_llm_params.return_value = {
                "model": "test-model",
                "options": {"num_predict": 512},
            }
            orch._direct_llm("test prompt", expect_json=True)

        self.assertTrue(len(captured_messages) > 0)
        user_content = captured_messages[0]["content"]
        self.assertIn("json.loads()", user_content.lower())

    def test_direct_llm_strips_think_tags(self):
        """<think> blocks are removed before JSON parsing."""
        orch = self._make_orchestrator()
        raw_response = '<think>I need to think...\n</think>\n{"result": "found_it"}'

        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": raw_response}}

        with patch("utils.llm_factory.get_reasoning_llm") as mock_llm_params, \
             patch("ollama.Client", return_value=mock_client):
            mock_llm_params.return_value = {"model": "test", "options": {}}
            result = orch._direct_llm("test prompt")

        self.assertNotIn("error", result)
        self.assertEqual(result.get("result"), "found_it")

    def test_direct_llm_llm_failure_returns_error_dict(self):
        """LLM connection failure returns error dict, never raises."""
        orch = self._make_orchestrator()
        with patch("utils.llm_factory.get_reasoning_llm") as mock_llm_params, \
             patch("ollama.Client", side_effect=Exception("connection refused")):
            mock_llm_params.return_value = {"model": "test", "options": {}}
            result = orch._direct_llm("test")
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
