# GitHub Copilot Instructions for CyberAgent

## Project Context

CyberAgent is a TRUE AGI autonomous penetration testing platform with 8 specialized AI agents orchestrated through a full kill chain. The system uses local LLMs (Ollama) with ReAct loops, cross-mission learning, and deterministic fallback when LLMs fail.

**Status:** Production-ready with 90%+ success rate and full autonomy  
**Architecture:** CrewAI + Ollama + ChromaDB + RAG (146,993 docs)  
**Models:** Qwen2.5:14B (default) + DeepSeek-R1:8B (reasoning)

---

## Core Architecture Principles

### 1. Memory Bank Context (ALWAYS CONSULT FIRST)

Before offering suggestions, ALWAYS read these files in order:
1. `memory-bank/projectbrief.md` — Core project architecture and goals
2. `memory-bank/activeContext.md` — Current work and recent completions
3. `memory-bank/progress.md` — What has been finished, commit history
4. `memory-bank/adversarial-analysis-day14.md` — Critical issues and fixes

**Rule:** Context files are the source of truth. Never suggest changes that contradict them.

### 2. Module Registry (Day 1 Complete — Use These)

```python
# LLM routing
from src.utils.llm_factory import get_llm, get_embeddings
llm = get_llm(role="default")        # qwen2.5:14b for recon/enum/exploit
llm = get_llm(role="reasoning")      # deepseek-r1 for orchestrator/privesc

# RAG knowledge lookup (all 10 collections)
from src.memory.chroma_manager import ChromaManager
chroma = ChromaManager()
results = chroma.get_rag_context("Apache RCE exploits", n=5)

# Per-target attack state
from src.memory.mission_memory import MissionMemory
mm = MissionMemory("target.domain.com")
mm.add_host("10.0.0.1", "web01")
mm.add_port("10.0.0.1", 80, "http", "Apache/2.4.49")
mm.add_vulnerability("10.0.0.1", "CVE-2021-41773", 9.8, "Path traversal RCE", True)
mm.log_action("recon_agent", "nmap -sV 10.0.0.1", "2 open ports found")

# Pentest tool execution
from src.mcp.tool_manager import DynamicToolManager
te = ToolExecutor(mission_memory=mm)
ports = te.run_nmap("10.0.0.1", flags="-sV -sC -p-")
```

### 3. AGI Architecture (Day 15)

**ReAct Loop Pattern** (used in EnumVulnAgent, ExploitationAgent):
```python
for iteration in range(self.max_iterations):
    if self._llm_failures >= 3:
        break  # Switch to deterministic mode
    try:
        react_result = self.react(task=task, context=react_context)
        if react_result.get("success"):
            self._llm_failures = 0
        else:
            self._llm_failures += 1
    except Exception:
        self._llm_failures += 1
```

**3-Tier Execution Model:**
1. **Tier 1:** LLM Intelligence (ReAct + use_intelligent)
2. **Tier 2:** Hybrid Mode (EXPLOIT_HINTS + fallback chains)
3. **Tier 3:** DeterministicPentest (no LLM, pure tool chains)

**Cross-Mission Learning:**
```python
# Record exploit attempts
self.memory.experience.record_exploit_attempt(
    cve="CVE-2007-2447",
    service="smb",
    version="3.0.20",
    success=True,
    output="uid=0(root)",
    module_used="exploit/multi/samba/usermap_script",
    execution_time=12.5
)

# Adjust confidence using historical data
historical_rate = self.experience.get_success_rate(cve, service)
confidence = (original_confidence + historical_rate) / 2
```

### 4. ChromaDB Collections (146,993 docs)

- `exploitdb` — 46,437 Exploit-DB entries (id, title, platform, type, CVE, path)
- `cve_database` — 71,653 NVD CVEs (CVE-ID, description, CVSS, affected products)
- `nuclei_templates` — 12,735 Nuclei templates (id, name, severity, tags, description)
- `hacktricks` — 8,290 HackTricks chunks (file_path, title, category, content)
- `seclists_meta` — 5,214 SecLists wordlist metadata (list_name, path, purpose, line_count)
- `mitre_attack` — 691 ATT&CK techniques (technique_id, name, tactic, description, platforms)
- `gtfobins` — 458 GTFOBins entries (binary, functions, example commands)
- `payloads` — 1,332 PayloadsAllTheThings sections
- `owasp` — 122 OWASP WSTG test cases (WSTG-*, objective, how_to_test)
- `privesc_techniques` — 61 Linux PrivEsc techniques (technique_name, commands)

### 5. MissionMemory State Schema

```json
{
  "mission_id": "target_domain_YYYYMMDDTHHMMSS",
  "target": "target.domain.com",
  "phase": "recon|enum|vuln|exploit|privesc|postexploit|report",
  "status": "running|paused|complete|failed",
  "hosts": {
    "ip": {
      "ports": [{"port": int, "service": str, "version": str, "banner": str}],
      "vulnerabilities": [{"cve": str, "cvss": float, "exploitable": bool}],
      "shells": [{"type": str, "user": str, "port": int, "shell_id": str}],
      "credentials": [{"username": str, "password": str, "service": str}],
      "privesc_paths": [{"technique": str, "root": bool}],
      "loot": [{"type": str, "content": str}]
    }
  },
  "attack_chain": [{"step": int, "agent": str, "action": str, "result": str}],
  "mitre_techniques": ["T1046", "T1190", ...]
}
```

---

## Critical Rules (NEVER VIOLATE)

### Architecture Rules
1. **No direct subprocess calls in agents** — always use `ToolExecutor` or `DynamicToolManager`
2. **No hardcoded service assumptions** — platform adapts dynamically to target
3. **All findings → MissionMemory** — agents write discoveries immediately; never lose data
4. **RAG before acting** — call `chroma.get_rag_context(query)` before choosing exploit/technique
5. **Orchestrator uses `reasoning` model** — all other agents use `default` model
6. **Context injection pattern**: `system_prompt = AGENT_PROMPT + "\n\nCURRENT STATE:\n" + mm.get_full_context()`
7. **Phase transitions** — only Orchestrator calls `mm.update_phase(phase)`

### Code Standards
8. **CPU-only inference** — Q4 quantized models, max `num_ctx=8192`, no GPU
9. **No external APIs** — all inference local via Ollama at http://localhost:11434
10. **Global Static Analysis** — respect `pyrightconfig.json` pointing to `src/`; no local sys.path hacks
11. **Zero-Touch DB Init** — RAG updates handled in `main.py` via `check_and_update_rag()`. No manual CRON jobs.

### Shell Persistence Rules
12. **ExploitationAgent stores shells** — `_store_shell(shell_id, socket, info)` after success
13. **PrivEsc/PostExploit check MissionMemory** — `_get_shell_port_from_memory()` before creating new
14. **Persistent shells survive agents** — stored in `self.persistent_shells = {}`
15. **Shell IDs are descriptive** — e.g., `"bindshell_192.168.1.10_6200"`

### LLM Timeout Pattern
16. **Always use `_llm_with_timeout()`** — never call `self.llm.invoke()` directly
17. **Timeout recovery with retry** — strips RAG context, retries with 3000 char limit
18. **Fallback on empty string** — `if not result: return self._deterministic_fallback()`
19. **Track LLM failures** — `self._llm_failures += 1` on timeout/error
20. **Switch to deterministic after 3 failures** — `if self._llm_failures >= 3: use DeterministicPentest`

### Experience Learning Rules
21. **Record ALL exploit attempts** — success AND failure via `_record_exploit_attempt()`
22. **Include timing data** — `execution_time` in seconds
23. **Adjust confidence dynamically** — blend 50% original + 50% historical
24. **Never hardcode exploits** — use ExperienceMemory to guide selection

---

## Agent Implementations (All Production-Ready)

### 1. OrchestratorAgent
- **Model:** deepseek-r1 (reasoning)
- **Role:** Mission planning, phase gates, agent briefings
- **Key:** `_build_agent_briefing()` pre-fetches RAG for each phase
- **Critical:** Tracks `llm_failure_count`, switches to DeterministicPentest after 3 failures

### 2. ReconAgent
- **Model:** qwen2.5:14b (default)
- **Role:** Port scan, service enum, OSINT
- **Key:** `_decide_next_wave()` — LLM+RAG for tool selection, heuristic fallback
- **Critical:** MAX_CONCURRENT=5 with psutil CPU backoff

### 3. EnumVulnAgent
- **Model:** qwen2.5:14b (default)
- **Role:** Service vuln detection, CVE matching
- **Key:** `_reason_about_exploitability()` — queries 5 RAG collections
- **AGI:** ReAct loop with `_llm_failures` tracking

### 4. ExploitationAgent
- **Model:** qwen2.5:14b (default)
- **Role:** Exploit execution, shell acquisition
- **Key:** `_generate_exploit_via_llm()` — dynamic MSF command generation
- **AGI:** ReAct loop, `_record_exploit_attempt()` for all attempts
- **Critical:** `_exec_cmd_on_shell()` reuses persistent shells

### 5. PrivEscAgent
- **Model:** deepseek-r1 (reasoning)
- **Role:** Privilege escalation
- **Key:** `_get_shell_port_from_memory()` — checks MissionMemory first
- **Critical:** Uses `_exec_via_ssh()` as fallback with credentials from MissionMemory

### 6. PostExploitAgent
- **Model:** qwen2.5:14b (default)
- **Role:** Loot gathering (credentials, files, network maps)
- **Key:** `_get_shell_port_from_memory()` — checks MissionMemory first
- **Critical:** Persistent shell or SSH with credentials

### 7. ReportingAgent
- **Model:** qwen2.5:14b (default)
- **Role:** PDF report generation with ReportLab
- **Key:** Generates cover page, vuln charts, MITRE mapping, remediation
- **Output:** `reports/{mission_id}/pentest_report.pdf`

### 8. DeterministicPentest (Fallback)
- **Model:** NONE (no LLM)
- **Role:** Full pentest using only tool chains and VERSION_CVE_MAP
- **Key:** Predefined service chains (nmap → enum4linux → msfconsole)
- **Critical:** Invoked by Orchestrator after 3 LLM failures

---

## Common Tasks (Quick Reference)

### Add New Exploit to VERSION_CVE_MAP
```python
# In src/agents/deterministic_fallback.py
VERSION_CVE_MAP = {
    "vsftpd 2.3.4": {
        "cve": "CVE-2011-2523",
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "payload": "cmd/unix/interact",
    },
    # Add yours here
}
```

### Add New RAG Collection
```python
# In knowledge_base/ingest_all.py
def ingest_mydata():
    docs = [{"text": "...", "metadata": {"id": "1"}}]
    chroma = ChromaManager()
    for doc in docs:
        chroma._col_mydata.add(
            documents=[doc["text"]],
            metadatas=[doc["metadata"]],
            ids=[doc["metadata"]["id"]]
        )
```

### Create New Agent
```python
from agents.base_agent import BaseAgent

class MyAgent(BaseAgent):
    AGENT_NAME = "MyAgent"
    MITRE_MAP = {"action": "T1xxx"}
    
    def run(self, target: str, briefing: dict = {}) -> dict:
        # Use ReAct loop for autonomy
        for iteration in range(self.max_iterations):
            result = self.react(task="My task", context={})
            if result.get("success"):
                return {"agent": self.AGENT_NAME, "success": True, "result": result}
        
        # Deterministic fallback
        return self._fallback_execution()
```

### Debug LLM Call
```bash
# Test LLM directly
curl -s http://localhost:11434/api/generate -d '{
  "model": "cyberagent-pentest:7b",
  "prompt": "What CVE affects vsftpd 2.3.4?",
  "stream": false
}' | jq -r .response

# Check model status
curl -s http://localhost:11434/api/tags | jq '.models[] | select(.name | contains("cyberagent"))'
```

---

## When to Update This File

Update `~/.copilot/copilot-instructions.md` when:
1. New agent is added to the system
2. Architecture rules change (e.g., new required pattern)
3. New RAG collection is ingested
4. Module registry changes (new imports or APIs)
5. Critical bug is discovered and fixed

**How to update:**
```bash
# Edit the file
vim ~/.copilot/copilot-instructions.md

# Also update memory-bank for persistence
vim ~/CyberAgent/memory-bank/activeContext.md
vim ~/CyberAgent/memory-bank/progress.md

# Commit changes
cd ~/CyberAgent
git add memory-bank/ ~/.copilot/copilot-instructions.md
git commit -m "docs: Update Copilot instructions and memory bank"
git push origin main
```

---

## Contact & Resources

- **Project:** ComunikCRM PFE Graduation Project
- **Platform:** Parrot OS + Python 3.13
- **Models:** Ollama (qwen2.5:14b + deepseek-r1:8b)
- **RAG:** ChromaDB with 146,993 documents
- **Tools:** 4,309+ dynamically discovered

**Quick Links:**
- Memory Bank: `~/CyberAgent/memory-bank/`
- Session State: `~/.copilot/session-state/`
- Logs: `~/CyberAgent/logs/`
- Reports: `~/CyberAgent/reports/`

---

**Last Updated:** 2026-04-02 (Day 15 — True AGI Complete)
