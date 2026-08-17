from __future__ import annotations

from copy import deepcopy
from typing import Any

from .providers.base import TextProvider
from .providers.gemini_provider import GeminiProvider
from .providers.openai_provider import OpenAIProvider


WORKFLOW_CONTROLLED_GENERATION_CONFIG_KEYS = {
    "format",
    "input",
    "messages",
    "model",
    "prompt",
    "response_schema",
    "response_modalities",
    "stream",
    "tools",
    "text",
    "response_json_schema",
    "response_mime_type",
    "response_format",
    "web_search_options",
}

OPERATION_IDS = {
    "generate_outline",
    "extract_section_content",
    "extract_policies",
    "generate_leaf_specs",
    "reconcile_coupled_leaves",
    "assemble_hierarchy",
    "correct_hierarchy_json",
    "determine_optionality",
}

PROVIDER_OVERRIDE_KEYS = {
    "kind",
    "model",
    "api_key_env",
    "temperature",
    "generation_config",
    "web_search",
    "api_mode",
}


def build_provider(config: dict[str, Any]) -> TextProvider:
    provider_config = config.get("provider", {}) or {}
    return build_provider_from_config(provider_config)


def build_provider_from_config(provider_config: dict[str, Any]) -> TextProvider:
    kind = provider_config.get("kind")
    model = provider_config.get("model")
    if not kind:
        raise ValueError("provider.kind is required")
    if not model:
        raise ValueError("provider.model is required")

    raw_temperature = provider_config.get("temperature")
    temperature = None if raw_temperature is None else float(raw_temperature)
    generation_config = provider_config.get("generation_config", {}) or {}
    if not isinstance(generation_config, dict):
        raise ValueError("provider.generation_config must be a mapping when provided")
    reserved_generation_keys = sorted(WORKFLOW_CONTROLLED_GENERATION_CONFIG_KEYS & set(generation_config))
    if reserved_generation_keys:
        joined = ", ".join(reserved_generation_keys)
        raise ValueError(f"provider.generation_config cannot set workflow-controlled keys: {joined}")
    web_search = provider_config.get("web_search", {}) or {}

    if kind == "gemini":
        return GeminiProvider(
            model=model,
            api_key_env=provider_config.get("api_key_env", "GEMINI_API_KEY"),
            temperature=temperature,
            generation_config=generation_config,
        )
    if kind == "openai":
        return OpenAIProvider(
            model=model,
            api_key_env=provider_config.get("api_key_env", "OPENAI_API_KEY"),
            api_mode=provider_config.get("api_mode", "responses"),
            temperature=temperature,
            generation_config=generation_config,
        )
    raise ValueError(f"Unsupported provider.kind: {kind}")


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def operation_overrides(
    config: dict[str, Any],
    *,
    allowed_operation_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    raw = config.get("operation_overrides", {}) or {}
    if not isinstance(raw, dict):
        raise ValueError("operation_overrides must be a mapping when provided")

    allowed = allowed_operation_ids or OPERATION_IDS
    unknown = sorted(set(raw) - allowed)
    if unknown:
        joined = ", ".join(unknown)
        allowed_text = ", ".join(sorted(allowed))
        raise ValueError(f"Unknown operation_overrides keys: {joined}. Allowed operations: {allowed_text}")

    overrides: dict[str, dict[str, Any]] = {}
    for operation, override in raw.items():
        if not isinstance(override, dict):
            raise ValueError(f"operation_overrides.{operation} must be a mapping")
        overrides[operation] = normalize_operation_override(override)
    return overrides


def normalize_operation_override(override: dict[str, Any]) -> dict[str, Any]:
    nested_provider = override.get("provider", {}) or {}
    if nested_provider and not isinstance(nested_provider, dict):
        raise ValueError("operation override provider must be a mapping")

    direct_provider = {
        key: value
        for key, value in override.items()
        if key in PROVIDER_OVERRIDE_KEYS
    }
    return deep_merge(nested_provider, direct_provider)


def provider_config_for_operation(
    config: dict[str, Any],
    operation: str,
    *,
    allowed_operation_ids: set[str] | None = None,
) -> dict[str, Any]:
    base_provider_config = config.get("provider", {}) or {}
    overrides = operation_overrides(config, allowed_operation_ids=allowed_operation_ids)
    override = overrides.get(operation)
    if not override:
        return deepcopy(base_provider_config)

    base_kind = base_provider_config.get("kind")
    override_kind = override.get("kind")
    if override_kind and override_kind != base_kind:
        merged: dict[str, Any] = {"kind": override_kind}
        if "temperature" in base_provider_config:
            merged["temperature"] = deepcopy(base_provider_config["temperature"])
        if "web_search" in base_provider_config:
            merged["web_search"] = deepcopy(base_provider_config["web_search"])
        return deep_merge(merged, override)

    return deep_merge(base_provider_config, override)


def operation_provider_plan(
    config: dict[str, Any],
    *,
    operation_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    operation_ids = operation_ids or OPERATION_IDS
    plan: dict[str, dict[str, Any]] = {}
    for operation in sorted(operation_ids):
        provider_config = provider_config_for_operation(
            config,
            operation,
            allowed_operation_ids=operation_ids,
        )
        build_provider_from_config(provider_config)
        plan[operation] = summarize_provider_config(provider_config)
    return plan


def summarize_provider_config(provider_config: dict[str, Any]) -> dict[str, Any]:
    web_search = provider_config.get("web_search", {}) or {}
    summary = {
        "kind": provider_config.get("kind", ""),
        "model": provider_config.get("model", ""),
        "generation_config_keys": sorted((provider_config.get("generation_config", {}) or {}).keys()),
        "web_search_enabled": bool(web_search.get("enabled", False)),
    }
    if "temperature" in provider_config:
        summary["temperature"] = provider_config.get("temperature")
    if provider_config.get("kind") == "openai":
        summary["api_mode"] = provider_config.get("api_mode", "responses")
    return summary
