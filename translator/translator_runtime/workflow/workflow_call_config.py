from typing import Any, Optional, Sequence

from google.genai import types


DEFAULT_MODEL = "gemini-3.1-pro-preview"


def get_workflow_model(operation: str | None = None) -> str:
    """Returns the direct workflow model fallback used outside the artifact runner."""
    import os

    return os.getenv("TRANSLATOR_MODEL", os.getenv("GEMINI_MODEL", DEFAULT_MODEL))


def build_workflow_call_config(
    *,
    tools: Optional[Sequence[types.Tool]] = None,
    json_response: bool = False,
    response_schema: Optional[Any] = None,
    response_modalities: Optional[Sequence[str]] = None,
) -> types.GenerateContentConfig:
    """Builds workflow-owned per-call output format config."""
    config: dict[str, Any] = {}

    if tools:
        config["tools"] = list(tools)
    if json_response or response_schema is not None:
        config["response_mime_type"] = "application/json"
    if response_schema is not None:
        config["response_schema"] = response_schema
    if response_modalities:
        config["response_modalities"] = list(response_modalities)

    return types.GenerateContentConfig(**config)
