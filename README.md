# 🕵️ CyberAgent — Multi-Agent PentestAI & Mitigation Platform

> **PFE Graduation Project** | ComunikCRM | Parrot OS | CrewAI + Ollama + ChromaDB  
> Fully autonomous end-to-end penetration testing platform powered by local LLMs.

---

## 📋 Project Overview

CyberAgent is an autonomous multi-agent penetration testing system. Given a single domain name, it orchestrates 8 specialized AI agents through the full kill chain: **Recon → Enumeration → Vulnerability Scan → Exploitation → PrivEsc → Post-Exploit → Reporting** — entirely local, no cloud APIs, no data leaving the machine.

**Stack:** CrewAI · LangChain · Ollama (Qwen2.5:14B + DeepSeek-R1:8B) · ChromaDB · Python 3.13  
**Target:** ComunikCRM Linux infrastructure (VoIP/SIP, Apache/PHP, MySQL, SMTP, DNS, REST APIs)  
**Phases:** Phase 1 (18w) = autonomous pentest | Phase 2 (4w) = Ansible remediation + admin dashboard

---

## 🗓️ Day 1 — Full Environment Setup (Complete)

### What was built on Day 1

Day 1 covered the complete foundation of the platform: from a bare Python venv to a fully operational RAG-enabled AI pentest environment with 146,993 indexed knowledge documents, 87+ tools catalogued, and all core Python modules implemented.

---

### 1. LLM Configuration & Factory

**Files:** `config/models.yaml`, `src/utils/llm_factory.py`

Configured three Ollama models with role-based routing:

| Role | Model | Use For |
|---|---|---|
| `default` | `qwen2.5:14b-instruct-q4_K_M` | recon, enum, vuln_scan, exploitation, post_exploit, reporting |
| `reasoning` | `deepseek-r1:8b-llama-distill-q4_K_M` | orchestrator, privesc, exploit chaining, report generation |
| `embedding` | `nomic-embed-text` | ChromaDB RAG (768-dim vectors) |

`llm_factory.py` features:
- `get_llm(role="default"|"reasoning")` — ping-tests the model before returning; auto-falls back to the other model if unresponsive
- `get_embeddings()` — returns `OllamaEmbeddings(nomic-embed-text)` (768 dims)
- Prints which model was loaded on every call (for agent debugging)

---

### 2. Pentest Tool Inventory

**File:** `config/tools.yaml`

Auto-discovered and catalogued **87 tools** across system paths. Categories: `recon`, `enumeration`, `vuln_scan`, `exploitation`, `brute_force`, `web_attack`, `voip_attack`, `wireless`, `post_exploit`, `privesc`, `credential_attack`, `forensics`.

Key tools: nmap, masscan, amass, subfinder, theHarvester, hydra, sqlmap, gobuster, ffuf, nikto, wpscan, nuclei, searchsploit, msfconsole, enum4linux, smbclient, svmap, svwar, svcrack, john, hashcat, chisel, responder, linpeas, binwalk, radare2.

Special installs: `wpscan` (gem), `theHarvester` (pip from source), `subfinder` (binary), `linpeas.sh`, `nuclei` (apt v3.6.1).

---

### 3. RAG Knowledge Base — 146,993 Documents

**Path:** `memory/chromadb/`  
**Ingest:** `python3 knowledge_base/ingest_all.py`

| Collection | Source | Documents |
|---|---|---|
| `cve_database` | NVD API 2.0 (2023–2024, monthly chunks) | **71,653** |
| `exploitdb` | /usr/share/exploitdb Exploit-DB CSV | **46,437** |
| `nuclei_templates` | projectdiscovery/nuclei-templates | **12,735** |
| `hacktricks` | HackTricks-wiki/hacktricks | **8,290** |
| `seclists_meta` | danielmiessler/SecLists (metadata only) | **5,214** |
| `mitre_attack` | MITRE ATT&CK Enterprise JSON (local) | **691** |
| `gtfobins` | GTFOBins _gtfobins/ directory | **458** |
| `payloads` | swisskyrepo/PayloadsAllTheThings | **1,332** |
| `owasp` | OWASP WSTG Checklist | **122** |
| `privesc_techniques` | swisskyrepo/InternalAllTheThings | **61** |
| **TOTAL** | | **146,993** |

---

### 4. Core Python Modules

| Module | Purpose |
|---|---|
| `src/utils/llm_factory.py` | LLM role routing, ping/fallback, embeddings |
| `src/memory/chroma_manager.py` | ChromaDB CRUD + cross-collection `get_rag_context()` |
| `src/memory/mission_memory.py` | Full per-target attack state (JSON + ChromaDB) |
| `src/mcp/tool_executor.py` | Subprocess wrappers for all pentest tools |
| `src/mcp/shodan_wrapper.py` | Shodan free-tier host/CVE lookup |
| `src/mcp/fetch_wrapper.py` | HTTP fetch for OSINT recon |

**MissionMemory** tracks per-target: hosts, ports, vulns, exploits, shells, credentials, privesc paths, loot, MITRE TTPs, full attack chain log.

**ToolExecutor** supports: `run_nmap`, `run_searchsploit`, `run_hydra`, `run_sqlmap`, `run_gobuster`, `run_nikto`, `run_sipvicious`, `run_ffuf`, `run_wpscan`, `run_nxc`, `run_linpeas`

**ChromaManager.get_rag_context(query)** — searches ALL 10 knowledge collections simultaneously and returns merged cosine-ranked results. This is the main agent knowledge lookup call.

---

### 5. MCP Servers & Wrappers

- `mcp-server-filesystem` — installed globally (npm) at `/usr/local/bin/mcp-server-filesystem` — agents read/write files
- `src/mcp/fetch_wrapper.py` — Python HTTP fetch for OSINT recon phase
- `src/mcp/shodan_wrapper.py` — Shodan API wrapper (set `SHODAN_API_KEY` in `.env`)

---

### 6. Validation — 24/24 PASS

Run: `python3 validate_env.py`

```
✓ Ollama service              3 models loaded
✓ qwen2.5 default             qwen2.5:14b-instruct-q4_K_M  PING OK
✓ deepseek reasoning          deepseek-r1:8b-llama-distill-q4_K_M  PING OK
✓ nomic-embed-text            768 dims
✓ LLM Factory (default)       model switching OK
✓ LLM Factory (reasoning)     model switching OK
✓ ChromaDB:exploitdb          46,437 docs
✓ ChromaDB:cve_database       71,653 docs
✓ ChromaDB:mitre_attack       691 docs
✓ ChromaDB:gtfobins           458 docs
✓ ChromaDB:payloads           1,332 docs
✓ ChromaDB:hacktricks         8,290 docs
✓ ChromaDB:owasp              122 docs
✓ ChromaDB:nuclei_templates   12,735 docs
✓ ChromaDB:privesc_techniques 61 docs
✓ ChromaDB:seclists_meta      5,214 docs
✓ ChromaDB total              146,993 docs across 10 collections
✓ MissionMemory               state.json created OK
✓ ToolExecutor                12/12 key tools found
✓ MCP filesystem server       /usr/local/bin/mcp-server-filesystem
✓ Python imports              9/9 ok
✓ .env config                 7/7 vars set
✓ nuclei binary               /usr/bin/nuclei
✓ Knowledge base files        7/7 present

Results: 24 PASS  0 WARN  0 FAIL / 24 checks
Total RAG docs: 146,993
```

---

## 🏗️ Project Structure

```
CyberAgent/
├── .env                         # Environment variables
├── validate_env.py              # 24-check environment validator
├── config/
│   ├── models.yaml              # LLM role routing (default/reasoning/embedding)
│   └── tools.yaml               # 87 pentest tools catalogue
├── knowledge_base/
│   ├── ingest_all.py            # Master ingest runner (all 10 collections)
│   ├── ingest_exploitdb.py      # Exploit-DB CSV → exploitdb
│   ├── ingest_mitre.py          # MITRE ATT&CK JSON → mitre_attack
│   ├── ingest_cve.py            # NVD API 2.0 → cve_database
│   ├── ingest_gtfobins.py       # GTFOBins YAML → gtfobins
│   ├── ingest_payloads.py       # PayloadsAllTheThings → payloads
│   ├── ingest_hacktricks.py     # HackTricks .md → hacktricks
│   ├── ingest_seclists.py       # SecLists metadata → seclists_meta
│   ├── ingest_owasp.py          # OWASP WSTG → owasp
│   ├── ingest_nuclei.py         # Nuclei YAML → nuclei_templates
│   ├── ingest_privesc.py        # Linux PrivEsc .md → privesc_techniques
│   ├── mitre_attack.json        # 45MB MITRE ATT&CK Enterprise (local)
│   ├── owasp_wstg.md
│   ├── linux_privesc.md
│   ├── hacktricks/              # 1,947 .md files (git --depth=1)
│   ├── SecLists/                # Discovery, Fuzzing, Passwords, Usernames, Payloads
│   ├── nuclei-templates/        # 13,113 .yaml attack templates
│   └── PayloadsAllTheThings/
├── memory/
│   ├── chromadb/                # Persistent ChromaDB (146,993 docs)
│   └── missions/                # Per-target JSON state files
├── src/
│   ├── utils/
│   │   └── llm_factory.py       # get_llm(role) / get_embeddings() + ping/fallback
│   ├── memory/
│   │   ├── chroma_manager.py    # ChromaDB client + cross-collection RAG search
│   │   └── mission_memory.py    # Per-target attack state (JSON + ChromaDB)
│   ├── mcp/
│   │   ├── tool_manager.py      # DynamicToolManager: auto-discover, install & execute tools
│   │   ├── shodan_wrapper.py    # Shodan free-tier: host lookup, CVE search
│   │   └── fetch_wrapper.py     # HTTP fetch for OSINT recon
│   ├── agents/                  # 🔜 Next: 8 CrewAI agents
│   ├── reporting/               # 🔜 Phase 1 report generator
│   └── tools/                   # 🔜 LangChain tool wrappers
└── tools/
    ├── linpeas.sh               # Linux PrivEsc script (982 KB)
    ├── subfinder                # Go binary
    └── theHarvester/            # OSINT framework (pip installed from source)
```

---

## 🚀 Quick Start

```bash
# Activate venv
source ~/CyberAgent/.venv/bin/activate

# Verify environment (24 checks)
python3 validate_env.py

# Re-ingest knowledge base (idempotent — skips existing collections)
python3 knowledge_base/ingest_all.py

# Test LLM factory (model ping + switch)
python3 src/utils/llm_factory.py

# Test mission memory (creates state.json)
python3 src/memory/mission_memory.py
```

---

## 🗓️ Roadmap

| Sprint | Focus | Status |
|---|---|---|
| **S1-S2** | Environment, RAG (146K docs), core modules | ✅ **DONE** |
| S3-S4 | Orchestrator Agent + ReAct engine + JSON state | 🔜 Next |
| S5-S6 | Recon Agent (parallel: DNS, OSINT, active) | ⏳ |
| S7-S8 | Enumeration + VulnScan Agents | ⏳ |
| S9-S11 | Exploitation Agent (parallel vectors) | ⏳ |
| S12-S13 | PrivEsc + Post-Exploit Agents | ⏳ |
| S14-S15 | Reporting Agent (CVSS + MITRE ATT&CK) | ⏳ |
| S16-S17 | Full run on Metasploitable2 + ComunikCRM | ⏳ |
| S18 | Benchmarks + Phase 1 docs | ⏳ |
| S19-S20 | Ansible playbooks + Mitigation Agent | ⏳ |
| S21-S22 | Phase 2 end-to-end test + PFE defense | ⏳ |

---

## ⚠️ Constraints

- **No cloud APIs** — all LLM inference is local via Ollama
- **CPU-only** — Q4 quantized models (no dedicated GPU, Intel Iris Xe only)
- **No data exfiltration** — strict local-only operation
- **Mitigation Agent (Phase 2)** — executes ONLY admin-approved actions, zero autonomous authority
- **Legal** — written authorization from ComunikCRM required before Phase 1B and Phase 2

---

*Parrot OS 7.1 · i5-13500H 16T · 23GB RAM · CPU-only Q4 · Python 3.13*