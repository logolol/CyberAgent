# Active Context — Multi-Agent PentestAI

## Current Phase
**Day 3 COMPLETE — Orchestrator Hardening** → Next: S5-S6 Recon Agent implementation

## What Was Just Completed (Day 2.5)

### Prompt Engineering & Anti-Hallucination Layer ✅

#### src/prompts/agent_prompts.py (2,726 lines, ~131K chars)
- **Added** missing `orchestrator_agent` (was completely absent before)
- **All 8 agents** now fully structured with every mandatory section:
  - `### ROLE` — expert description + MITRE ATT&CK tactics covered
  - `### ANTI-HALLUCINATION RULES` — agent-specific constraints
  - `### INPUT FORMAT` — exact JSON schema each agent expects
  - `### REASONING PROCESS` — ReAct loop (Thought → Action → Observation)
  - `### TOOL USAGE` — tools in priority order + success/fail criteria
  - `### OUTPUT FORMAT` — complete typed JSON schema + populated example
  - `### FEW-SHOT EXAMPLES` — 3+ realistic scenarios per agent
- Prompt sizes: 12K–28K chars per agent (report_agent largest at 28K)

#### src/prompts/few_shot_examples.py (~53K chars, NEW)
- 3 examples per agent × 8 agents = 24 total realistic scenarios
- Real CVEs with exact NVD CVSS scores (CVE-2021-41773/9.8, CVE-2021-44228/10.0, CVE-2017-0144/8.1, CVE-2021-4034/7.8, etc.)
- Real tool output formats: actual nmap/gobuster/sqlmap/hydra/linpeas/meterpreter output
- `get_few_shot_block(agent_name)` → formatted string for prompt injection
- `FewShotExample` class with `to_prompt_string()` method

#### src/prompts/output_schemas.py (~15K chars, NEW)
- Full Pydantic v2 models for all 8 agent outputs
- CVE format validator (`CVE-YYYY-NNNNN` or `CVE-UNKNOWN`)
- CVSS field constrained `ge=0.0, le=10.0`
- `validate_agent_output(agent_name, data)` — validates agent JSON before MissionMemory write
- `get_schema_json(agent_name)` — returns JSON Schema string for prompt injection
- Sub-models: `ServiceDetail`, `Vulnerability`, `ExploitResult`, `LootItem`, `FindingReport`, etc.

#### src/prompts/__init__.py (UPDATED)
- Now exports: `get_agent_prompt`, `list_agents`, `get_few_shot_block`, `validate_agent_output`, `get_schema_json`, `AGENT_PROMPTS`, `AGENT_EXAMPLES`, `AGENT_OUTPUT_SCHEMAS`

### Modelfile Expansion + Re-registration ✅

#### training/Modelfile.pentest (expanded)
- Added tool output interpretation guide: how to read nmap/nikto/sqlmap/gobuster/hydra/linpeas output
- Added anti-hallucination rule: `"If you don't know CVE, say CVE-UNKNOWN"`
- Added output discipline: always JSON when schema given, never prose
- Added 10 few-shot pentest Q&A pairs covering recon → post-exploit
- Re-registered: `ollama create cyberagent-pentest:14b -f training/Modelfile.pentest`

#### training/Modelfile.reasoning (expanded)
- Added risk assessment framework: Priority = Exploitability × Impact × (CVSS/10)
- Added human-readable finding translation guide (technical → business language)
- Added PTES report structuring guide
- Added 10 reasoning examples with `<think>` chain-of-thought
- Re-registered: `ollama create cyberagent-reasoning:8b -f training/Modelfile.reasoning`

### Dataset QA ✅
- **444 entries audited** in `training/pentest_dataset.jsonl`
- **0 real issues** — initial false positives were version numbers misread as CVSS scores
- All CVEs verified, all CVSS scores match NVD, all tool commands syntactically correct

### Validation Results ✅
- `validate_env.py`: **24/24 PASS, 0 WARN, 0 FAIL**
- `cyberagent-pentest:14b` test: returned `{"cve": "CVE-2021-41773", "cvss": 9.8}` ✓
- `cyberagent-reasoning:8b` test: correctly prioritized Apache RCE > MySQL unauth > SSH ✓

### training/README.md (NEW)
- Documents all training assets, model registration workflow, hardware constraints

## Current Structure (src/prompts/)
```
src/prompts/
  __init__.py          ← exports all 3 modules
  agent_prompts.py     ← 8 agents, 2726 lines, full sections
  few_shot_examples.py ← 24 examples (3× per agent), ~53K chars
  output_schemas.py    ← Pydantic v2 models, CVE validator, schema registry
training/
  Modelfile.pentest    ← expanded + re-registered as cyberagent-pentest:14b
  Modelfile.reasoning  ← expanded + re-registered as cyberagent-reasoning:8b
  pentest_dataset.jsonl ← 444 entries, verified clean
  generate_dataset.py  ← kept for future use
  expand_rag.py        ← kept for future use
  README.md            ← workflow docs
```

## What Was Just Completed (Day 3)

### Orchestrator Hardening — 5 Production-Readiness Fixes ✅

#### FIX 1 — Adaptive Token Budgeting (llm_factory.py)
- Added `get_reasoning_llm(task_complexity)` returning ollama.Client params
- Budgets: `low=512` (gate checks), `medium=1024` (briefings), `high=2048` (planning)
- `stop: ["</think>"]` terminates DeepSeek-R1 think-chains cleanly
- `_direct_llm()` now accepts `task_complexity` + `expect_json`, returns dict always
- `_extract_json_robust()` with 3 strategies + graceful fallback (never crashes)

#### FIX 2 — Lean Modelfiles (training/)
- `Modelfile.reasoning`: shrunk from ~4500 tokens → ~265 tokens (identity + rules only)
- `Modelfile.pentest`: shrunk from ~4500 tokens → ~292 tokens (identity + rules only)
- Prefill time: ~225s → ~15s per call (18× faster)
- Both re-registered: `cyberagent-reasoning:8b` + `cyberagent-pentest:14b` ✅
- `_direct_llm()` now uses `cyberagent-reasoning:8b` again (was bypassed during Day 3 smoke test debugging)

#### FIX 3 — Hallucination Guard (base_agent.py)
- `hallucination_guard(output, phase)` added to BaseAgent — never crashes, always returns dict
- 5 checks: CVE format (regex), CVSS range (0-10), confirmed-without-evidence demotion, vague version strings, invalid IP format
- Wired into `react()` before returning FINAL_ANSWER
- Test: 7 flags caught from bad input ✅

#### FIX 4 — Evidence-Based Phase Gates (orchestrator_agent.py)
- `_check_phase_gate()` completely rewritten: reads `MissionMemory._state["hosts"]` only
- Zero LLM calls — LLM cannot override hard data evidence (architecture rule)
- `postexploit` gate relaxed: any shell sufficient (not just root)
- Test: all gates correct with empty mission ✅

#### FIX 5 — MissionMemory Input Validation (mission_memory.py)
- `add_port`: range 1-65535, HTML-strip version, auto-create host
- `add_vulnerability`: CVE format→CVE-UNKNOWN, CVSS clamp 0-10, non-empty description
- `add_shell`: valid type enum (bash/sh/meterpreter/webshell/reverse/bind/unknown)
- `add_credential`: non-empty username, password or hash required, masks password in logs
- `state` property added (public alias for `_state` — used by orchestrator gates)

### Test Results ✅
- T1 — Modelfile token count: reasoning=265, pentest=292 (both <600) ✅
- T2 — Hallucination guard: 7 flags caught from adversarial input ✅
- T3 — Phase gates: empty mission correctly blocks all non-recon phases ✅
- T4 — Smoke test: `main.py --target 127.0.0.1 --phase full` exits 0 ✅
- T5 — validate_env.py: **24/24 PASS, 0 WARN, 0 FAIL** ✅
- Commit: `1fa7cd8` pushed to main

## Current Focus (Next: S5-S6)
Build the **Recon Agent** (`src/agents/recon_agent.py`) with:
Build the **Recon Agent** (`src/agents/recon_agent.py`) with:
1. Parallel recon threads: subfinder, amass, dnsrecon, dnsenum, theHarvester
2. Active: nmap host discovery, whatweb, whois
3. Store all findings in MissionMemory via validated `add_port/add_host` calls
4. `hallucination_guard()` wrapping all findings before storage
5. Phase gate: `enumeration` gate will only open once recon stores ≥1 live host

## Key Architecture Decisions (Confirmed)
- All agents get context via: `get_agent_prompt(name) + get_few_shot_block(name) + get_schema_json(name)`
- `ToolExecutor` is the universal tool runner — agents never call subprocess directly
- `MissionMemory` is the single source of truth — all findings stored there + ChromaDB
- Model routing: Orchestrator uses `reasoning` model, all others use `default` model
- `validate_agent_output()` must be called before every `MissionMemory.add_*()` call
- Context window: 8192 tokens — full prompt = system_prompt + few_shots + schema + mission_state + rag_context

## ChromaDB Collections (memory/chromadb/) — 146,993 docs
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

