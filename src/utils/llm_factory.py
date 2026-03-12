"""
LLM Factory — model routing with ping validation and fallback.
get_llm(role="default"|"reasoning") → OllamaLLM (cyberagent-tuned models)
get_embeddings() → OllamaEmbeddings(nomic-embed-text)

Model hierarchy:
  default  → cyberagent-pentest:14b  (falls back to qwen2.5:14b-instruct-q4_K_M)
  reasoning → cyberagent-reasoning:8b (falls back to deepseek-r1:8b-llama-distill-q4_K_M)
"""
import logging
import os
from pathlib import Path
from typing import Literal

import yaml

_log = logging.getLogger(__name__)
_CONFIG = Path(__file__).parent.parent.parent / "config" / "models.yaml"


def _load_config() -> dict:
    with open(_CONFIG) as f:
        return yaml.safe_load(f)


def _ping_model(model_name: str, base_url: str) -> bool:
    """
    Check if a model is available via ollama.list() — no inference, instant.
    Avoids the multi-minute prefill cost of running a chat request against
    models with large Modelfile SYSTEM prompts (e.g. cyberagent-reasoning:8b).
    """
    try:
        import ollama
        client = ollama.Client(host=base_url)
        models = client.list()
        available = {m["model"] for m in models.get("models", [])}
        # Normalise: "cyberagent-reasoning:8b" may appear as "cyberagent-reasoning:8b"
        # or without the digest suffix — check prefix match too
        if model_name in available:
            return True
        return any(a.startswith(model_name.split(":")[0] + ":") and model_name in a
                   or a == model_name for a in available)
    except Exception as e:
        _log.warning(f"Model availability check failed [{model_name}]: {e}")
        return False


def get_llm(role: Literal["default", "reasoning"] = "default"):
    """
    Return LangChain OllamaLLM for the given role.
    Uses cyberagent-tuned models (pentest Modelfile). Falls back to base models
    if tuned models are unavailable, then falls back to the other role's model.
    """
    from langchain_ollama import OllamaLLM

    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    role_cfg = cfg["models"].get(role, cfg["models"]["default"])
    temperature = role_cfg.get("temperature", 0.1)
    num_ctx = role_cfg.get("num_ctx", 8192)
    num_predict = role_cfg.get("num_predict", None)  # None = model default

    # Fallback chain: tuned → base → other role's base
    tuned_model = role_cfg["name"]
    base_model = role_cfg.get("base_model", tuned_model)

    fallback_role = "default" if role == "reasoning" else "reasoning"
    fallback_base = cfg["models"].get(f"{fallback_role}_base", cfg["models"][fallback_role])["name"]

    model = None
    for candidate in [tuned_model, base_model, fallback_base]:
        if _ping_model(candidate, base_url):
            model = candidate
            break

    if model is None:
        raise RuntimeError(f"[LLMFactory] ALL models unreachable. Check Ollama service at {base_url}")

    if model == tuned_model:
        print(f"[LLMFactory] ✓ [{role}] → {model} (pentest-tuned)")
    elif model == base_model:
        print(f"[LLMFactory] ⚠ [{role}] → {model} (base fallback — tuned model unavailable)")
    else:
        print(f"[LLMFactory] ⚠ [{role}] → {model} (cross-role fallback)")

    kwargs = dict(model=model, base_url=base_url, temperature=temperature, num_ctx=num_ctx)
    if num_predict is not None:
        kwargs["num_predict"] = num_predict
    return OllamaLLM(**kwargs)


def get_embeddings():
    """Return OllamaEmbeddings with nomic-embed-text (768 dims)."""
    from langchain_ollama import OllamaEmbeddings
    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    model = cfg["models"]["embedding"]["name"]
    print(f"[LLMFactory] ✓ Embeddings → {model}")
    return OllamaEmbeddings(model=model, base_url=base_url)


def get_reasoning_llm(task_complexity: str = "medium") -> dict:
    """
    Return ollama.Client chat params tuned for DeepSeek-R1 reasoning tasks.
    Uses cyberagent-reasoning:8b (lean Modelfile, ~300-token system prompt).

    task_complexity:
        "low"    → 512 tokens   — simple gate checks, yes/no decisions
        "medium" → 1024 tokens  — phase briefings, result analysis
        "high"   → 2048 tokens  — complex exploit chain planning

    Returns dict ready for ollama.Client().chat():
        {"model": ..., "options": {"num_predict": ..., ...}}
    """
    cfg = _load_config()
    # Use tuned model; fall back to base if unavailable
    tuned = cfg["models"]["reasoning"]["name"]          # cyberagent-reasoning:8b
    base  = cfg["models"]["reasoning_base"]["name"]     # deepseek-r1:8b-llama-distill-q4_K_M
    available = {tuned, base}
    try:
        import ollama
        client = ollama.Client(host=cfg["ollama_base_url"])
        listed = {m["model"] for m in client.list().get("models", [])}
        model = tuned if tuned in listed else base
    except Exception:
        model = base

    budgets = {"low": 512, "medium": 1024, "high": 2048}
    return {
        "model": model,
        "options": {
            "num_predict": budgets.get(task_complexity, 1024),
            "temperature": 0.1,
            "num_ctx": 8192,
            # NOTE: do NOT add stop=["</think>"] here.
            # The stop token is consumed and never appears in the response,
            # so the think-stripping regex finds nothing and JSON is lost.
            # Let the model complete naturally; _extract_json_robust strips think blocks.
        },
    }


def get_ollama_client():
    import ollama
    cfg = _load_config()
    return ollama.Client(host=cfg["ollama_base_url"])


def ping_all_models() -> dict:
    """Ping every configured model and return status dict."""
    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    results = {}
    for role, role_cfg in cfg["models"].items():
        name = role_cfg["name"]
        ok = _ping_model(name, base_url)
        results[role] = {"model": name, "ok": ok}
        status = "✓" if ok else "✗"
        print(f"[LLMFactory] {status} {role}: {name}")
    return results


if __name__ == "__main__":
    from rich.table import Table
    from rich.console import Console
    console = Console()
    results = ping_all_models()
    t = Table(title="LLM Factory — Model Status")
    t.add_column("Role"); t.add_column("Model"); t.add_column("Status")
    for role, info in results.items():
        st = "[green]✓ OK[/]" if info["ok"] else "[red]✗ DOWN[/]"
        t.add_row(role, info["model"], st)
    console.print(t)
