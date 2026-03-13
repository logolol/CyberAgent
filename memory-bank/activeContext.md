# Active Context — Multi-Agent PentestAI

## Current Phase
**Day 4 COMPLETE — Enhanced Anti-Hallucination & Command Validation** → Next: S5-S6 Recon Agent implementation

## What Was Just Completed (Day 4)

### Enhanced Anti-Hallucination System ✅

#### Expanded Hallucination Guard (src/agents/base_agent.py)
**Upgraded from 5 checks to 8 checks with multi-source validation:**

1. **CVE format validation** — CVE-YYYY-NNNNN regex check (year 1999-2026, id 4-7 digits)
2. **CVSS score range** — Float 0.0–10.0 enforcement
3. **Evidence-based confirmation** — Demote `confirmed: true` without evidence to `potential: true`
4. **Version string sanity** — Reject vague descriptions (>4 words → "version_unknown")
5. **IP address format** — Valid IPv4 dotted-quad validation
6. **CVE existence verification** — Cross-reference with RAG CVE database (71,653 NVD entries)
7. **Exploit path validation** — Verify EDB-ID or Metasploit module paths exist
8. **Command syntax validation** — Check for unmatched quotes, incomplete pipes, suspicious patterns

**New features:**
- `_validation_sources` field tracks which RAG collections verified each finding
- CVE marked as `CVE-UNVERIFIED` if not found in database, sets `requires_verification: true`
- Exploit paths validated against ExploitDB (46,437 entries) and Metasploit module format
- Command syntax checker prevents:
  - Unmatched quotes (`'` or `"`)
  - Incomplete pipes/redirects (`|`, `>>`, `&&` at end)
  - Suspicious patterns (`rm -rf`, `dd if=`, `mkfs`, etc.)

**Example output:**
```json
{
  "cve": "CVE-2021-41773",
  "cvss": 9.8,
  "exploit_path": "EDB-ID:50383",
  "_hallucination_flags": [],
  "_guard_passed": true,
  "_validation_sources": [
    "cve_database:CVE-2021-41773",
    "exploitdb:EDB-50383"
  ]
}
```

#### Structured Command Extraction (src/agents/base_agent.py)
**New methods for extracting and validating commands from LLM output:**

- `_extract_commands_from_output(llm_output)` — Parses structured ACTION blocks and inline commands
  - Pattern 1: `ACTION: tool\nACTION_INPUT: {...}`
  - Pattern 2: Inline mentions like "run nmap -sV 10.0.0.1"
  - Returns list of `{tool, args, purpose, validation, raw_input}`

- `_validate_command_structure(tool, action_input)` — Pre-execution validation
  - Check 1: Tool exists in RAG knowledge base
  - Check 2: Required arguments present (nmap/hydra/sqlmap need args)
  - Check 3: No destructive patterns (`rm -rf`, `dd if=`, `mkfs`)
  - Check 4: Flag-value pairs complete (`-p` not missing port value)
  - Check 5: Cross-reference syntax with RAG examples
  - Returns `{valid: bool, issues: list, suggestions: list, confidence: float}`

**Example validation failure:**
```json
{
  "valid": false,
  "issues": ["Tool 'nmap' typically requires arguments"],
  "suggestions": ["Check nmap --help for required parameters"],
  "tool": "nmap",
  "confidence": 0.0
}
```

#### Evidence-Based Command Execution Loop (src/agents/base_agent.py)
**Enhanced ReAct loop with validation gates and retry logic:**

1. **Pre-execution validation** — All commands validated before execution
   - Invalid commands → LLM receives `VALIDATION ERROR` feedback with issues + suggestions
   - LLM gets a chance to fix the command or choose different approach
   - Prevents hallucinated/malformed commands from ever executing

2. **Automatic retry for transient failures** — Exponential backoff for network errors
   - Recognizes: `"timeout"`, `"connection refused"`, `"temporary failure"`, `"try again"`
   - Max 3 retries with 1s, 2s, 4s backoff (2^retry)
   - Non-transient errors (permission denied, invalid arg) fail immediately

3. **Hallucination guard on all final answers** — Applied before returning to orchestrator
   - Every `FINAL_ANSWER` passes through `hallucination_guard()`
   - Multi-source validation adds `_validation_sources` list
   - Invalid data cleaned/removed before storage in MissionMemory

**Execution flow with validation:**
```
THOUGHT → ACTION → [VALIDATION] ─✓→ [EXECUTE] ─transient error?→ [RETRY with backoff]
                          │                           │
                          └─✗→ VALIDATION ERROR      └─permanent error→ OBSERVATION
                                      ↓
                                   LLM feedback: "Issues: ... Suggestions: ..."
```

### Comprehensive Test Suite ✅

#### tests/test_hallucination_guard.py (~350 lines)
**Unit tests for all 8 hallucination guard checks:**
- `test_invalid_cve_format` / `test_valid_cve_format`
- `test_invalid_cvss_score` / `test_valid_cvss_score`
- `test_confirmed_without_evidence` / `test_confirmed_with_evidence`
- `test_vague_version_string` / `test_valid_version_string`
- `test_invalid_ip_address` / `test_valid_ip_address`
- `test_cve_existence_validation` — Cross-reference with RAG
- `test_exploit_path_validation` — EDB-ID and Metasploit paths
- `test_command_syntax_validation` — Unmatched quotes, incomplete pipes, suspicious patterns
- `test_nested_structure_validation` — Recursive checking of dicts/lists
- `test_clean_output_passes` — Verify false positive rate is 0%

#### tests/test_command_extraction.py (~300 lines)
**Unit tests for command extraction and validation:**
- `test_extract_structured_action_block` — Parse ACTION/ACTION_INPUT blocks
- `test_extract_multiple_action_blocks` — Handle multiple commands in one output
- `test_extract_inline_commands` — Parse "run nmap -sV 10.0.0.1" format
- `test_validate_command_with_missing_args` — Catch missing required arguments
- `test_validate_command_with_destructive_patterns` — Block `rm -rf`, `dd if=`, `mkfs`
- `test_validate_command_with_incomplete_flags` — Detect `-p` missing value
- `test_validate_command_with_valid_args` — Accept well-formed commands
- `test_command_confidence_scoring` — Validate confidence decreases with issues
- `test_extract_commands_from_malformed_json` — Graceful handling of bad JSON
- `test_validation_provides_actionable_suggestions` — Helpful error messages

#### tests/test_react_loop_integration.py (~400 lines)
**Integration tests for full ReAct loop:**
- `test_successful_react_loop_with_validation` — End-to-end success path
- `test_react_loop_invalid_command_gets_retry` — LLM fixes invalid command after feedback
- `test_react_loop_transient_error_retry` — Automatic retry with exponential backoff
- `test_react_loop_hallucination_guard_on_final_answer` — Guard applied to results
- `test_react_loop_max_iterations_reached` — Graceful failure after max iterations
- `test_react_loop_llm_failure_handling` — Handle LLM connection errors
- `test_react_loop_multi_source_validation` — Cross-reference findings with multiple RAG sources
- `test_react_loop_evidence_logging` — All actions logged to MissionMemory
- `test_cve_cross_reference_with_multiple_sources` — Validate against cve_database + exploitdb
- `test_exploit_verification_against_exploitdb` — EDB-ID path verification

**Test infrastructure:**
- `tests/__init__.py` — Package init with docstring
- All tests use `unittest` (no external dependencies beyond src/)
- Mock LLM/ChromaDB/DynamicToolManager to avoid external calls
- Can be run with: `python -m unittest tests.test_*` (requires venv with deps)

### Architecture Improvements ✅

**Zero-hallucination pipeline now enforced at 4 layers:**
1. **Prompt layer** — Anti-hallucination rules in agent_prompts.py (Day 2.5)
2. **Pydantic schemas** — output_schemas.py validates structure (Day 2.5)
3. **Command validation** — Pre-execution checking NEW
4. **Hallucination guard** — Post-LLM output cleaning with RAG cross-reference ENHANCED

**Multi-source verification workflow:**
```
LLM Output
    ↓
[Parse JSON]
    ↓
[Pydantic validation] ← output_schemas.py
    ↓
[Hallucination guard] ← 8 checks + RAG cross-reference
    ↓
    ├─ CVE → Query cve_database (71,653 docs)
    ├─ Exploit → Query exploitdb (46,437 docs)
    ├─ Command → Query hacktricks (8,290 docs) for syntax examples
    └─ Technique → Query mitre_attack (691 techniques)
    ↓
[Store in MissionMemory] ← Only validated data with _validation_sources
```

**Result metadata now includes:**
- `_hallucination_flags: list[str]` — Issues detected (empty if clean)
- `_guard_passed: bool` — True if zero issues found
- `_validation_sources: list[str]` — Which RAG collections verified the data
  - Format: `"collection_name:identifier"` (e.g., `"cve_database:CVE-2021-41773"`)

### Files Modified/Created ✅

**Modified:**
- `src/agents/base_agent.py` — +185 lines (hallucination guard expansion, command validation, retry logic)

**Created:**
- `tests/__init__.py` — Test package init
- `tests/test_hallucination_guard.py` — 17 test cases, ~350 lines
- `tests/test_command_extraction.py` — 15 test cases, ~300 lines
- `tests/test_react_loop_integration.py` — 11 test cases, ~400 lines

**Total new code:** ~1,235 lines (src/ + tests/)

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

### JSON Extraction Fix (Day 3 follow-up) ✅

#### Root cause
`stop=["</think>"]` in `get_reasoning_llm()` consumed the stop token before JSON was generated. `/no_think` prefix in `_direct_llm()` caused empty `""` responses on the distilled LLaMA-based model.

#### Fix (orchestrator_agent.py + llm_factory.py)
- Removed `stop=["</think>"]` from options — let model complete naturally
- Removed `/no_think` prefix — lean Modelfile OUTPUT DISCIPLINE already enforces JSON-only
- Rewrote `_extract_json_robust()` with 7-step extraction:
  1. Strip `<think>…</think>` blocks (handles nested + unclosed)
  2. Strip ` ```json ``` ` fences
  3. `json.loads()` direct parse
  4. Brace-depth walk for LAST `{…}` block
  5. Brace-depth walk for FIRST `{…}` block
  6. Try original pre-strip text
  7. Fix trailing commas / single quotes / unquoted keys
- Added JSON discipline instruction to every `expect_json` prompt
- **Result:** Smoke test runs with zero "JSON extraction failed" messages
- Commit: `9765b45`

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

