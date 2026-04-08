"""
LLM Factory — model routing with ping validation and fallback.
get_llm(role="default"|"reasoning") → OllamaLLM (cyberagent-tuned models)
get_embeddings() → OllamaEmbeddings(nomic-embed-text)

Model hierarchy:
  default  → cyberagent-pentest:7b  (falls back to qwen2.5:7b-instruct-q4_K_M)
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

    kwargs = dict(
        model=model,
        base_url=base_url,
        temperature=temperature,
        num_ctx=num_ctx,
        keep_alive="2h",  # Keep model loaded for 2 hours between calls
        # HTTP client timeout — must be >= thread timeout (180s) to avoid premature cancellation
        client_kwargs={"timeout": 300.0},  # 5 minutes max per request
    )
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
    # Keep this path deterministic/non-blocking for orchestrator calls.
    # Model availability checks can hang under load, so use configured model
    # directly and let upstream timeout handling/fallback deal with failures.
    tuned = cfg["models"]["reasoning"]["name"]
    model = tuned

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


def get_gemma4_llm(task: Literal["pentest", "reasoning"] = "pentest"):
    """
    Return Gemma 4 model for high-accuracy tasks (exploitation, strategic planning).
    
    WARNING: Gemma 4 is slower than qwen2.5:7b on CPU-only inference.
    Use as optional high-accuracy mode, not as the default runtime model.
    
    Args:
        task: "pentest" for exploitation tasks, "reasoning" for strategic planning
    
    Returns:
        OllamaLLM configured for Gemma 4
    """
    from langchain_ollama import OllamaLLM

    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    
    role_key = f"gemma4_{task}"
    role_cfg = cfg["models"].get(role_key)
    
    if not role_cfg:
        _log.warning(f"Gemma4 {task} config not found, falling back to default")
        return get_llm()
    
    model = role_cfg["name"]
    base_model = role_cfg.get("base_model", model)
    temperature = role_cfg.get("temperature", 0.3)
    num_ctx = role_cfg.get("num_ctx", 4096)
    num_predict = role_cfg.get("num_predict", 1024)
    
    # Check if tuned model is available, fall back to base
    if not _ping_model(model, base_url):
        if _ping_model(base_model, base_url):
            print(f"[LLMFactory] ⚠ Gemma4 {task} → {base_model} (base fallback)")
            model = base_model
        else:
            print(f"[LLMFactory] ⚠ Gemma4 unavailable, using default model")
            return get_llm()
    else:
        print(f"[LLMFactory] ✓ Gemma4 {task} → {model} (high-accuracy mode)")
    
    return OllamaLLM(
        model=model,
        base_url=base_url,
        temperature=temperature,
        num_ctx=num_ctx,
        num_predict=num_predict,
        keep_alive="15m",
        client_kwargs={"timeout": 180.0},
    )


def warm_model(role: str = "default", keep_alive: str = "2h") -> bool:
    """
    Pre-loads the model into Ollama's RAM by sending
    a minimal keep-alive request.

    Call this ONCE before starting any agent that uses LLM.
    Subsequent LLM calls will find the model already loaded
    and will complete in ~30-60s instead of timing out.

    Args:
        role: "default" (7B pentest model) or "reasoning" (8B orchestrator model)
        keep_alive: How long to keep the model loaded (default: 2h)

    Returns True if model is warm and responding.
    """
    import ollama
    import time
    from rich.console import Console

    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    role_cfg = cfg["models"].get(role, cfg["models"]["default"])
    
    # Try tuned model first, fall back to base model
    tuned_model = role_cfg.get("name")
    base_model = role_cfg.get("base_model", tuned_model)
    
    console = Console()
    
    for model_name in [tuned_model, base_model]:
        if not model_name:
            continue
            
        console.print(f"[cyan]⚡ Warming model {model_name} (keep_alive={keep_alive})...[/]", end=" ")

        try:
            c = ollama.Client(host=base_url)
            start = time.time()

            # Minimal prompt — just loads the model into RAM
            c.chat(
                model=model_name,
                messages=[{"role": "user", "content": "ready"}],
                options={
                    "num_predict": 3,
                    "temperature": 0.0,
                },
                keep_alive=keep_alive,  # Keep warm for 2 hours by default
            )
            elapsed = time.time() - start
            console.print(f"[green]✓ warm ({elapsed:.1f}s)[/]")
            return True

        except Exception as e:
            console.print(f"[yellow]⚠ {model_name} failed: {e}[/]")
            continue
    
    console.print(f"[red]✗ Could not warm any model for role '{role}'[/]")
    return False


def get_ollama_client():
    import ollama
    cfg = _load_config()
    return ollama.Client(host=cfg["ollama_base_url"])


def stream_llm_response(
    prompt: str,
    role: Literal["default", "reasoning"] = "default",
    callback: callable = None,
    timeout: int = 300,
) -> str:
    """
    Stream LLM response with real-time output.
    
    This shows tokens as they're generated, providing visual feedback
    during long reasoning chains. Much better UX than waiting 2+ minutes
    with no output.
    
    Args:
        prompt: The prompt to send to the LLM
        role: "default" (pentest model) or "reasoning" (orchestrator model)
        callback: Optional function(chunk: str) called for each token
        timeout: Maximum time to wait for complete response
    
    Returns:
        Complete response as string
    
    Example:
        >>> response = stream_llm_response(
        ...     "Analyze this CVE",
        ...     role="reasoning",
        ...     callback=lambda c: print(c, end="", flush=True)
        ... )
    """
    import ollama
    import time
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    
    cfg = _load_config()
    base_url = cfg["ollama_base_url"]
    role_cfg = cfg["models"].get(role, cfg["models"]["default"])
    
    model = role_cfg["name"]
    temperature = role_cfg.get("temperature", 0.1)
    num_ctx = role_cfg.get("num_ctx", 8192)
    
    console = Console()
    full_response = []
    start_time = time.time()
    
    try:
        client = ollama.Client(host=base_url)
        
        # Stream the response
        stream = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={
                "temperature": temperature,
                "num_ctx": num_ctx,
            },
            stream=True,
        )
        
        for chunk in stream:
            # Check timeout
            if time.time() - start_time > timeout:
                break
            
            content = chunk.get("message", {}).get("content", "")
            if content:
                full_response.append(content)
                
                # Call user callback if provided
                if callback:
                    try:
                        callback(content)
                    except Exception:
                        pass
        
        return "".join(full_response)
        
    except Exception as e:
        console.print(f"[red]Streaming error: {e}[/]")
        return "".join(full_response) if full_response else ""


def stream_with_spinner(
    prompt: str,
    role: Literal["default", "reasoning"] = "default",
    message: str = "Thinking...",
    timeout: int = 300,
) -> str:
    """
    Stream LLM response with a Rich spinner showing progress.
    
    This is the recommended way to call LLM for long operations.
    Shows a spinner with token count while waiting.
    
    Args:
        prompt: The prompt to send to the LLM
        role: "default" or "reasoning"
        message: Status message to show during streaming
        timeout: Maximum time to wait
    
    Returns:
        Complete response as string
    """
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import time
    
    console = Console()
    token_count = [0]  # Use list for closure
    
    def count_callback(chunk: str):
        token_count[0] += 1
    
    # Run streaming with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]{message}[/] {{task.description}}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=None)
        
        response = []
        start_time = time.time()
        
        def update_callback(chunk: str):
            response.append(chunk)
            token_count[0] += 1
            elapsed = time.time() - start_time
            progress.update(
                task,
                description=f"[dim]{token_count[0]} tokens, {elapsed:.0f}s[/]"
            )
        
        result = stream_llm_response(
            prompt=prompt,
            role=role,
            callback=update_callback,
            timeout=timeout,
        )
    
    return result


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
