# Active Context — Multi-Agent PentestAI

## Current Phase
**S3-S4: Orchestrator Agent** — Environment fully operational, moving to agent development

## What Was Just Completed (Day 1 — S1-S2)

### Full Environment Setup ✅
- **Ollama:** 3 models running (qwen2.5:14b-instruct-q4_K_M / deepseek-r1:8b-llama-distill-q4_K_M / nomic-embed-text)
- **RAG Knowledge Base:** 146,993 docs across 10 ChromaDB collections
- **87 pentest tools** catalogued in config/tools.yaml
- **All core Python modules** implemented and validated (24/24 PASS)

### ChromaDB Collections (memory/chromadb/)
| Collection | Docs |
|---|---|
| cve_database | 71,653 |
| exploitdb | 46,437 |
| nuclei_templates | 12,735 |
| hacktricks | 8,290 |
| seclists_meta | 5,214 |
| mitre_attack | 691 |
| gtfobins | 458 |
| payloads | 1,332 |
| owasp | 122 |
| privesc_techniques | 61 |

### Implemented Modules
- `src/utils/llm_factory.py` — get_llm(role) with ping/fallback, get_embeddings()
- `src/memory/chroma_manager.py` — CRUD + get_rag_context() across all 10 collections
- `src/memory/mission_memory.py` — full per-target state (JSON + ChromaDB), tracks hosts/ports/vulns/shells/creds/loot/MITRE TTPs
- `src/mcp/tool_executor.py` — subprocess wrappers for nmap, hydra, sqlmap, gobuster, nikto, ffuf, sipvicious, wpscan, nxc, linpeas
- `src/mcp/shodan_wrapper.py` — Shodan free-tier host/CVE lookup
- `src/mcp/fetch_wrapper.py` — HTTP fetch for OSINT
- `config/models.yaml` — role-based LLM routing
- `config/tools.yaml` — 87 tools with category/purpose/example_command
- `validate_env.py` — 24-check rich table validator

## Current Focus (Next: S3-S4)
Build the **Orchestrator Agent** with:
1. CrewAI Manager LLM setup
2. ReAct loop engine (Thought → Action → Observation)
3. Mission state initialization + phase management
4. Agent delegation: Orchestrator dispatches to specialized agents
5. Target intake: `domain_name` → MissionMemory init → start recon phase

## Key Architecture Decisions (Confirmed)
- All agents get context via: `mission_memory.get_full_context()` + `chroma_manager.get_rag_context(query)`
- `ToolExecutor` is the universal tool runner — agents never call subprocess directly
- `MissionMemory` is the single source of truth — all findings stored there + ChromaDB
- Model routing: Orchestrator uses `reasoning` model, all others use `default` model
- Context window: 8192 tokens — agents must summarize before injecting full state

## Open Questions for S3-S4
- CrewAI Process type: `hierarchical` (manager delegates) vs `sequential` for Phase 1?
- How to handle very long nmap output → chunking strategy for LLM injection
- Parallelism model: ThreadPoolExecutor per recon vector vs CrewAI async tasks
- Timeout strategy: per-tool (ToolExecutor) + per-phase (MissionMemory) + total (86400s)


## Current Focus
- Project fully specified and understood from PFE PDF
- Memory bank initialized with full project architecture
- Next step: Set up the development environment (Ollama, ChromaDB, CrewAI, Python 3.11+)
- MCP integration planning (free pentest MCP servers to identify and integrate)

## Key Decisions Made
- Primary framework: **CrewAI** (LangChain as fallback)
- LLMs: **Qwen2.5:8B** (default) and **DeepSeek-R1:8B** (deep reasoning) via Ollama, CPU Q4 quantized
- Embedding: **nomic-embed-text** via Ollama
- Vector store: **ChromaDB**
- State: **JSON files + SQLite**
- MCP: **Free/open-source MCP servers** for pentest tool integration (added requirement, not in PDF)
- No GPU → all inference CPU-bound, Q4 quantization mandatory

## Architecture Decisions
- All agents follow **ReAct loop** (Thought → Action → Observation)
- Context passed between agents via **ChromaDB semantic search + JSON state file**
- Parallelism via **Python threading / asyncio** (per agent, per vector)
- No hardcoded service assumptions — platform adapts dynamically to target
- Phase 1: terminal-only, no UI
- Phase 2: Ansible-driven, admin dashboard, Human-in-the-Loop mitigation

## Open Questions / To Resolve
- Which free MCP servers to use for pentest? (nmap-mcp, metasploit-mcp, etc.)
- Exact Ollama model quantization level for RAM budget (23GB available)
- Docker containerization strategy for Phase 2 Ansible dispatch
- Admin Dashboard tech for Phase 2 (minimal web UI or CLI-based?)
