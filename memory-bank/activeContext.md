# CyberAgent — Active Context

Last updated: Day 7+ (AGI Transformation Phase 1 Complete)

## Current Phase

Sprint S9-S11 COMPLETE — ExploitationAgent built, tested, and full chain verified.
**NEW:** AGI Transformation Phase 1 COMPLETE — ExploitReasoner + ServiceAnalyzer integrated.

Current status: ExploitationAgent now 75% AGI-capable with adaptive reasoning.
Next: PrivEscAgent reasoning loop + PayloadFactory (Phase 2).

## AGI Transformation Status

**Phase 1 Complete (3/10 todos done):**
- ✅ ExploitReasoner - RAG-driven exploit discovery (zero hardcoded CVEs)
- ✅ ServiceAnalyzer - Unknown service behavior reasoning
- ✅ ExploitationAgent refactor - Removed hardcoded fast path, added AGI flow

**Adaptability Scores:**
- ExploitationAgent: 5/10 → 7.5/10 (target: 9/10)
- System Overall: 6.5/10 → 7.2/10 (target: 9/10)

**Phase 2 Planned:**
- PrivEscAgent reasoning loop
- PayloadFactory (dynamic shellcode generation)
- AttackGraph (exploit chain combination)
- ZeroDayAnalyzer (root cause analysis)

## LLM Validation ✅

All Ollama models tested and validated:
- **qwen2.5:14b (cyberagent-pentest:14b):** ✓ No hallucinations, no timeouts, no empty responses
- **deepseek-r1:8b (cyberagent-reasoning:8b):** ✓ JSON parsing works, reasoning intact
- **nomic-embed-text:** ✓ 768-dim embeddings working (RAG operational)

Test results (latest validation):
- Response quality: ✅ Accurate, concise, no hallucinations
- Timeout handling: ✅ 120s HTTP timeout, 60s per LLM call
- Empty response detection: ✅ Zero empty responses in 3-test batch
- Embeddings: ✅ Correct dimensionality, proper vector generation

## Agent Intelligence Architecture (ALL agents)

Every specialist agent follows this loop:

Tool output  
↓  
RAG context injection (phase-aware ChromaDB query)  
↓  
MITRE ATT&CK context lookup (`mitre_attack` collection)  
↓  
LLM reasoning (`cyberagent-pentest:14b`)  
↓  
Structured decision (next tool / next action)  
↓  
Tool execution (`DynamicToolManager`)  
↓  
`hallucination_guard()` on extracted output  
↓  
MissionMemory write (orchestrator consumes evidence)

Heuristic fallback is used only when the LLM response is unavailable or not parseable.

## LLM Roles

- OrchestratorAgent: `cyberagent-reasoning:8b`
  - Mission planning, phase briefings, phase analysis
  - Uses `get_reasoning_llm(low|medium|high)` for token budgeting

- Specialist agents: `cyberagent-pentest:14b`
  - Tool-selection and phase-local decisions
  - Prompt includes wave summary + phase RAG + MITRE context
  - Outputs are validated before MissionMemory persistence

## RAG Integration

- `get_phase_rag_context(phase, query, n)` drives phase-priority retrieval.
  - recon → `hacktricks`, `mitre_attack`, `owasp`, `seclists_meta`
  - enum → `hacktricks`, `nuclei_templates`, `seclists_meta`, `owasp`, `mitre_attack`
  - vuln → `cve_database`, `nuclei_templates`, `exploitdb`, `owasp`, `hacktricks`
  - exploit → `exploitdb`, `cve_database`, `payloads`, `hacktricks`, `mitre_attack`
  - privesc → `privesc_techniques`, `gtfobins`, `exploitdb`, `mitre_attack`, `hacktricks`
  - postexploit → `mitre_attack`, `gtfobins`, `payloads`, `hacktricks`, `privesc_techniques`

- Recon also runs a dedicated MITRE query:
  - `get_rag_context(..., collections=["mitre_attack"])`

## What Was Built — ReconAgent

### `src/agents/recon_agent.py`

Wave-based passive reconnaissance engine with bounded parallelism and dynamic tool availability checks.

Execution model:
- Wave 1 baseline passive checks
- Wave 2-3 selected by `_intelligent_next_wave()`
- `MAX_CONCURRENT = 5` with CPU backoff via `psutil` (`>80%` → 2 workers)
- Per-tool timeout overrides (`TOOL_TIMEOUTS`) from 10s to 60s

Decision loop per wave:
1. Run tools in parallel
2. Build compact wave summary
3. Query phase-aware RAG (`phase="recon"`)
4. Query MITRE ATT&CK context
5. Ask LLM for JSON decision: `done`, `next_tools`, `reasoning`, `mitre_technique`
6. Validate tool choices against available+unused whitelist
7. Fallback to `_heuristic_next_wave()` only on hard failure

Parsing model:
- Regex extractors only (LLM never parses raw tool output)
- Outputs stored as structured findings (`hosts`, `technologies`, `osint_intel`, `network_info`, `web_info`)
- MITRE findings tracked in `mitre_techniques`

MITRE tool mapping in recon:
- DNS tools → `T1590.002`
- WHOIS tools → `T1590.001`
- Certificate transparency → `T1596.003`
- Subdomain discovery → `T1583.001`
- TheHarvester → `T1591`
- Header intelligence → `T1592`
- Technology fingerprinting → `T1592.002`
- WAF fingerprinting → `T1590.006`

## Orchestrator ↔ Recon Data Flow

- Recon writes hosts and findings into MissionMemory.
- Orchestrator reads phase gate evidence from MissionMemory state.
- Enumeration gate opens only after recon stores concrete host evidence.

## Performance Snapshot

- Internal/lab target recon completes in ~30 seconds under current timeout policy.
- LLM remains in decision loop with compact prompts and 60s bound.

## Known Minor Issue

- `curl_headers` currently uses `--follow`; some curl builds require `-L`.
- This does not block recon completion and can be normalized in a follow-up cleanup.

## Next Sprint: EnumerationAgent (S7-S8)

Priority vectors from recon outputs:
- Service and version enumeration expansion
- Web stack-specific enumeration paths
- Method and misconfiguration checks
- Port/service enrichment for downstream vulnerability scoring
