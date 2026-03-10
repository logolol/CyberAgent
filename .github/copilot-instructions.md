# GitHub Copilot Instructions

For this project, we maintain a "memory bank" to provide context and track progress. Before offering suggestions, please consult the following contexts:
- `memory-bank/projectbrief.md` - Core project context, architecture, and goals.
- `memory-bank/activeContext.md` - What we are currently working on today.
- `memory-bank/progress.md` - What has already been finished.
- Other contextual files in the `memory-bank/` directory.

Use this context to ensure suggestions align strictly with the project's architecture (e.g., CrewAI, local Ollama, Parrot OS, Ansible integration, etc.).

---

## 🏗️ Module Registry (Day 1 Complete)

### Key imports for agent development:
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
ctx = mm.get_full_context()          # inject into LLM system prompt

# Pentest tool execution
from src.mcp.tool_executor import ToolExecutor
te = ToolExecutor(mission_memory=mm)
ports = te.run_nmap("10.0.0.1", flags="-sV -sC -p-")
creds = te.run_hydra("10.0.0.1", "ssh", "users.txt", "rockyou.txt")
paths = te.run_gobuster("http://10.0.0.1", "/usr/share/wordlists/dirb/common.txt")
```

### ChromaDB Collections Available:
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

### MissionMemory State Schema:
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
      "shells": [{"type": str, "user": str}],
      "credentials": [{"username": str, "password": str, "service": str}],
      "privesc_paths": [{"technique": str, "root": bool}],
      "loot": [{"type": str, "content": str}]
    }
  },
  "attack_chain": [{"step": int, "agent": str, "action": str, "result": str}],
  "mitre_techniques": ["T1046", "T1190", ...]
}
```

### Architecture Rules (ALWAYS follow):
- **No direct subprocess calls in agents** — always use `ToolExecutor`
- **No hardcoded service assumptions** — platform adapts dynamically to target
- **All findings → MissionMemory** — agents write discoveries immediately; never lose data
- **RAG before acting** — call `chroma.get_rag_context(query)` before choosing exploit/technique
- **Orchestrator uses `reasoning` model** — all other agents use `default` model
- **Context injection pattern**: `system_prompt = AGENT_PROMPT + "\n\nCURRENT STATE:\n" + mm.get_full_context()`
- **Phase transitions** — only Orchestrator calls `mm.update_phase(phase)`
- **CPU-only inference** — Q4 quantized models, max `num_ctx=8192`, no GPU
- **No external APIs** — all inference local via Ollama at http://localhost:11434

