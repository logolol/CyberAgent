"""
CyberAgent Prompts Package
"""
from .agent_prompts import (
    get_agent_prompt,
    list_agents,
    AGENT_PROMPTS,
    BASE_ANTI_HALLUCINATION,
    BASE_OUTPUT_SCHEMA,
)
from .few_shot_examples import (
    get_few_shot_block,
    list_example_agents,
    AGENT_EXAMPLES,
)
from .output_schemas import (
    validate_agent_output,
    get_schema_json,
    list_schemas,
    AGENT_OUTPUT_SCHEMAS,
)

__all__ = [
    # Core prompts
    "get_agent_prompt",
    "list_agents",
    "AGENT_PROMPTS",
    "BASE_ANTI_HALLUCINATION",
    "BASE_OUTPUT_SCHEMA",
    # Few-shot examples
    "get_few_shot_block",
    "list_example_agents",
    "AGENT_EXAMPLES",
    # Output schemas
    "validate_agent_output",
    "get_schema_json",
    "list_schemas",
    "AGENT_OUTPUT_SCHEMAS",
]
