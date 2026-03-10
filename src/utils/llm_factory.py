"""
LLM Factory — model routing with ping validation and fallback.
get_llm(role="default"|"reasoning") → OllamaLLM
get_embeddings() → OllamaEmbeddings(nomic-embed-text)
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
    """Test if a model responds via ollama.chat with a tiny prompt."""
    try:
        import ollama
        client = ollama.Client(host=base_url)
        client.chat(model=model_name,
                    messages=[{"role": "user", "content": "ping"}],
                    options={"num_predict": 1})
        return True
    except Exception as e:
        _log.warning(f"Model ping failed [{model_name}]: {e}")
        return False


def get_llm(role: Literal["default", "reasoning"] = "default"):
    """
    Return LangChain OllamaLLM for the given role.
    Falls back to the other model if the requested one is unresponsive.
    Prints which model was loaded.
    """
    from langchain_ollama import OllamaLLM

    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    role_cfg = cfg["models"].get(role, cfg["models"]["default"])
    fallback_role = "default" if role == "reasoning" else "reasoning"
    fallback_cfg = cfg["models"][fallback_role]

    primary = role_cfg["name"]
    fallback = fallback_cfg["name"]
    temperature = role_cfg.get("temperature", 0.1)
    num_ctx = role_cfg.get("num_ctx", 8192)

    # Ping primary
    if _ping_model(primary, base_url):
        model = primary
        print(f"[LLMFactory] ✓ Loaded [{role}] → {model}")
    else:
        _log.warning(f"[LLMFactory] ⚠ {primary} unresponsive — falling back to {fallback}")
        print(f"[LLMFactory] ⚠ FALLBACK [{role}] → {fallback} (primary {primary} down)")
        model = fallback

    return OllamaLLM(
        model=model,
        base_url=base_url,
        temperature=temperature,
        num_ctx=num_ctx,
    )


def get_embeddings():
    """Return OllamaEmbeddings with nomic-embed-text (768 dims)."""
    from langchain_ollama import OllamaEmbeddings
    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    model = cfg["models"]["embedding"]["name"]
    print(f"[LLMFactory] ✓ Embeddings → {model}")
    return OllamaEmbeddings(model=model, base_url=base_url)


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
