# CyberAgent Training Assets — README

This directory contains all model training, fine-tuning, and knowledge expansion assets for the CyberAgent pentest platform.

## Files

### `Modelfile.pentest`
Ollama Modelfile for `cyberagent-pentest:14b`.

**Base model**: `qwen2.5:14b-instruct-q4_K_M`  
**Purpose**: Technical execution brain for Recon, Enum, VulnScan, Exploitation, PostExploit, and Reporting agents.

**System prompt contains**:
- Full 7-phase pentest methodology (PTES + OWASP WSTG + MITRE ATT&CK)
- Real CVE examples per service type (SSH, HTTP, SMB, MySQL, VoIP, etc.)
- Tool output interpretation guide (nmap, nikto, sqlmap, gobuster, hydra, linpeas)
- Anti-hallucination rules: "If you don't know the CVE, say CVE-UNKNOWN"
- Output discipline: always JSON when schema given
- 10 few-shot pentest Q&A pairs (recon through post-exploit)

**Register/update with Ollama**:
```bash
ollama create cyberagent-pentest:14b -f training/Modelfile.pentest
```

---

### `Modelfile.reasoning`
Ollama Modelfile for `cyberagent-reasoning:8b`.

**Base model**: `deepseek-r1:8b-llama-distill-q4_K_M`  
**Purpose**: Orchestrator reasoning engine — mission planning, phase transitions, attack prioritization, and report generation.

**System prompt contains**:
- Orchestrator mindset: plan → delegate → evaluate → decide
- Phase gate rules (recon→enum→vuln→exploit→privesc→postexploit→report)
- Risk assessment framework: Exploitability × Impact × CVSS scoring
- Attack chain logic: proceed / stop / pivot decision tree
- Human-readable translation of technical findings for executive reports
- Report structuring guide (PTES standard)
- 10 few-shot reasoning examples with `<think>` chain-of-thought

**Register/update with Ollama**:
```bash
ollama create cyberagent-reasoning:8b -f training/Modelfile.reasoning
```

---

### `pentest_dataset.jsonl`
ChatML-format fine-tuning dataset for pentest knowledge.

**Stats**: 444 Q&A pairs, ~150KB  
**Format**: `{"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}`

**Coverage**:
- Recon techniques (OSINT, DNS, port scanning)
- Enumeration (service fingerprinting, web directory brute-force, SMB, VoIP)
- Vulnerability assessment (CVE identification, CVSS scoring, exploit matching)
- Exploitation (web attacks, network service attacks, metasploit)
- Privilege escalation (Linux SUID/sudo/cron/kernel, Windows token impersonation)
- Post-exploitation (credential harvesting, lateral movement, persistence)
- Report generation (CVSS vectors, MITRE mapping, executive summaries)

**Quality standards**:
- All CVE numbers verified against NVD
- All CVSS scores match NVD exactly
- All tool commands syntactically correct for Parrot OS
- Anti-hallucination examples included (when to say "unknown")

**To expand dataset**:
```bash
source ~/CyberAgent/.venv/bin/activate
python3 training/generate_dataset.py
```

---

### `generate_dataset.py`
Dataset generation script — creates additional ChatML training pairs.

**Usage**: Extend `pentest_dataset.jsonl` with new scenarios.  
**Do not delete** — needed for future dataset expansion.

---

### `expand_rag.py`
RAG knowledge base expansion script.

**Purpose**: Adds new documents to ChromaDB collections.  
**Collections managed**: all 15 ChromaDB collections in `memory/chromadb/`  
**Do not delete** — needed for future knowledge base updates.

**Usage**:
```bash
source ~/CyberAgent/.venv/bin/activate
python3 training/expand_rag.py
```

---

## Model Registration Workflow

After editing either Modelfile:

```bash
# Activate venv
source ~/CyberAgent/.venv/bin/activate
cd ~/CyberAgent

# Re-register models
ollama create cyberagent-pentest:14b -f training/Modelfile.pentest
ollama create cyberagent-reasoning:8b -f training/Modelfile.reasoning

# Verify registration
ollama list | grep cyberagent

# Test models
python3 -c "
import ollama
c = ollama.Client(host='http://localhost:11434')
r = c.chat(model='cyberagent-pentest:14b', messages=[
    {'role': 'user', 'content': 'Apache 2.4.49 found. What CVE? Return JSON.'}
], options={'num_predict': 100})
print(r['message']['content'])
"
```

## Hardware Constraints

- **CPU only**: Intel i5-13500H, 23GB RAM, Parrot OS
- **No GPU**: All inference via Ollama with Q4 quantized models
- **Context limit**: `num_ctx: 8192` — keep prompts within this
- **Concurrency**: Run one model at a time to avoid OOM
