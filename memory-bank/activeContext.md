# Active Context — Multi-Agent PentestAI

## Current Phase
**Day 2.5 COMPLETE — Prompt Engineering & Model Quality** → Next: S3-S4 Orchestrator Agent implementation

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

## Current Focus (Next: S3-S4)
Build the **Orchestrator Agent** (`src/agents/orchestrator.py`) with:
1. CrewAI Manager Agent or standalone ReAct engine
2. `get_agent_prompt("orchestrator_agent")` already ready — just wire it up
3. Phase gate logic: recon → enum → vuln → exploit → privesc → postexploit → report
4. Agent delegation: dispatch specialist agents with structured task JSON
5. `validate_agent_output()` to verify each agent's JSON before MissionMemory write

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

