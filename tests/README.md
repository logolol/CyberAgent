# CyberAgent Test Suite

Comprehensive test suite for the enhanced anti-hallucination and command validation system.

## Overview

The test suite validates three critical components:
1. **Hallucination Guard** - 8 validation checks with multi-source verification
2. **Command Extraction** - Structured parsing and pre-execution validation
3. **ReAct Loop Integration** - Full Thought→Action→Observation cycle with evidence-based execution

## Test Structure

```
tests/
├── __init__.py                         # Test package initialization
├── test_hallucination_guard.py         # 17 test cases (~350 lines)
├── test_command_extraction.py          # 15 test cases (~300 lines)
├── test_react_loop_integration.py      # 11 test cases (~400 lines)
└── README.md                           # This file
```

**Total:** 43 test cases, ~1,050 lines of test code

## Running Tests

### Prerequisites
```bash
# Activate virtual environment with dependencies
source ~/CyberAgent/.venv/bin/activate

# Ensure all dependencies are installed
pip install -r requirements.txt
```

### Run All Tests
```bash
cd /home/runner/work/CyberAgent/CyberAgent
python -m unittest discover tests -v
```

### Run Specific Test Module
```bash
# Hallucination guard tests
python -m unittest tests.test_hallucination_guard -v

# Command extraction tests
python -m unittest tests.test_command_extraction -v

# ReAct loop integration tests
python -m unittest tests.test_react_loop_integration -v
```

### Run Specific Test Case
```bash
python -m unittest tests.test_hallucination_guard.TestHallucinationGuard.test_invalid_cve_format -v
```

## Test Coverage

### 1. Hallucination Guard Tests (`test_hallucination_guard.py`)

**CHECK 1: CVE Format Validation**
- `test_invalid_cve_format` - Reject CVE-99999-12345, CVE-ABCD-1234
- `test_valid_cve_format` - Accept CVE-2021-41773

**CHECK 2: CVSS Score Range**
- `test_invalid_cvss_score` - Reject 15.0, -1.0, "invalid"
- `test_valid_cvss_score` - Accept 0.0, 5.5, 10.0, 7.8, 9.8

**CHECK 3: Evidence-Based Confirmation**
- `test_confirmed_without_evidence` - Demote `confirmed: true` with empty evidence
- `test_confirmed_with_evidence` - Accept confirmed with valid evidence

**CHECK 4: Version String Sanity**
- `test_vague_version_string` - Reject "Apache web server running on Ubuntu..."
- `test_valid_version_string` - Accept "2.4.49", "Apache/2.4.49", "nginx 1.18.0"

**CHECK 5: IP Address Format**
- `test_invalid_ip_address` - Remove 999.999.999.999
- `test_valid_ip_address` - Accept 10.0.0.1, 192.168.1.1

**CHECK 6: CVE Existence Verification**
- `test_cve_existence_validation` - Cross-reference with RAG CVE database

**CHECK 7: Exploit Path Validation**
- `test_exploit_path_validation` - Verify EDB-ID and Metasploit module paths

**CHECK 8: Command Syntax Validation**
- `test_command_syntax_validation` - Detect unmatched quotes, incomplete pipes, suspicious patterns

**Additional:**
- `test_nested_structure_validation` - Recursive checking of nested dicts/lists
- `test_clean_output_passes` - Verify 0% false positive rate

### 2. Command Extraction Tests (`test_command_extraction.py`)

**Extraction:**
- `test_extract_structured_action_block` - Parse ACTION/ACTION_INPUT blocks
- `test_extract_multiple_action_blocks` - Handle multiple commands
- `test_extract_inline_commands` - Parse "run nmap -sV 10.0.0.1"
- `test_extract_commands_from_malformed_json` - Graceful handling of bad JSON
- `test_extract_commands_preserves_quotes` - Preserve quoted strings with spaces

**Validation:**
- `test_validate_command_with_missing_args` - Catch missing required arguments
- `test_validate_command_with_destructive_patterns` - Block rm -rf, dd if=, mkfs
- `test_validate_command_with_incomplete_flags` - Detect flags missing values
- `test_validate_command_with_valid_args` - Accept well-formed commands
- `test_validate_unknown_tool` - Handle unknown tools gracefully

**Scoring:**
- `test_command_confidence_scoring` - Confidence decreases with issues
- `test_validation_provides_actionable_suggestions` - Helpful error messages

**Execution Loop:**
- `test_retry_logic_on_transient_errors` - Recognize transient failures
- `test_non_transient_errors_no_retry` - No retry for permanent errors

### 3. ReAct Loop Integration Tests (`test_react_loop_integration.py`)

**Success Paths:**
- `test_successful_react_loop_with_validation` - End-to-end success with validation
- `test_react_loop_evidence_logging` - All actions logged to MissionMemory

**Validation Gates:**
- `test_react_loop_invalid_command_gets_retry` - LLM fixes command after feedback
- `test_react_loop_hallucination_guard_on_final_answer` - Guard applied to results

**Retry Logic:**
- `test_react_loop_transient_error_retry` - Automatic retry with exponential backoff
- `test_react_loop_llm_failure_handling` - Handle LLM connection errors

**Limits:**
- `test_react_loop_max_iterations_reached` - Graceful failure after max iterations

**Multi-Source Validation:**
- `test_react_loop_multi_source_validation` - Cross-reference with multiple RAG collections
- `test_cve_cross_reference_with_multiple_sources` - Validate against cve_database + exploitdb
- `test_exploit_verification_against_exploitdb` - EDB-ID path verification

## Test Architecture

All tests use `unittest` with mocked dependencies:

```python
# Mock LLM to avoid Ollama calls
with patch('agents.base_agent.get_llm') as mock_llm:
    mock_llm_instance = Mock()
    mock_llm.return_value = mock_llm_instance

# Mock ChromaDB to avoid disk I/O
with patch('agents.base_agent.ChromaManager') as mock_chroma:
    mock_chroma_instance = Mock()
    mock_chroma.return_value = mock_chroma_instance
    mock_chroma_instance.get_rag_context.return_value = [...]

# Mock DynamicToolManager to avoid subprocess calls
with patch('agents.base_agent.DynamicToolManager') as mock_tools:
    mock_tools_instance = Mock()
    mock_tools.return_value = mock_tools_instance
```

**Benefits:**
- Fast execution (no network/disk I/O)
- No external dependencies during tests
- Deterministic results
- Can test error conditions easily

## Expected Results

All 43 tests should pass:

```
test_invalid_cve_format (__main__.TestHallucinationGuard) ... ok
test_valid_cve_format (__main__.TestHallucinationGuard) ... ok
...
test_exploit_verification_against_exploitdb (__main__.TestMultiSourceValidation) ... ok

----------------------------------------------------------------------
Ran 43 tests in X.XXXs

OK
```

## Troubleshooting

### Import Errors
```
ModuleNotFoundError: No module named 'chromadb'
```
**Solution:** Activate venv and install dependencies:
```bash
source ~/CyberAgent/.venv/bin/activate
pip install chromadb rich pyyaml
```

### Path Issues
```
ImportError: Failed to import test module
```
**Solution:** Run tests from project root:
```bash
cd /home/runner/work/CyberAgent/CyberAgent
python -m unittest tests.test_hallucination_guard -v
```

## Integration with CI/CD

These tests can be integrated into CI/CD pipelines:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Run tests
        run: python -m unittest discover tests -v
```

## Future Enhancements

Potential additions to the test suite:
- [ ] Performance benchmarks (time per validation check)
- [ ] Stress tests (large nested structures)
- [ ] Fuzzing tests (random invalid inputs)
- [ ] Coverage analysis (aim for 90%+ coverage)
- [ ] Integration tests with real Ollama models (slow tests)
- [ ] End-to-end tests with real MissionMemory/ChromaDB

## Contributing

When adding new features to base_agent.py:
1. Write tests first (TDD approach)
2. Ensure new code has 80%+ test coverage
3. Run all tests before committing: `python -m unittest discover tests -v`
4. Update this README with new test descriptions

## References

- [unittest documentation](https://docs.python.org/3/library/unittest.html)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
- BaseAgent implementation: `src/agents/base_agent.py`
- Hallucination guard: `base_agent.py:350-531`
- Command extraction: `base_agent.py:183-302`
