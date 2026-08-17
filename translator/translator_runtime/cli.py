from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from elastispec_llm.provider_factory import (
    WORKFLOW_CONTROLLED_GENERATION_CONFIG_KEYS,
    operation_overrides,
    operation_provider_plan,
)


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if value == "[]":
        return []
    if value == "{}":
        return {}
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip("'\"")


def load_simple_yaml(text: str) -> dict[str, Any]:
    """Small fallback parser for the simple YAML used by artifact configs."""
    rows: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        rows.append((indent, raw_line.strip()))

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(rows):
            return {}, index
        if rows[index][1].startswith("- "):
            values = []
            while index < len(rows) and rows[index][0] == indent and rows[index][1].startswith("- "):
                item = rows[index][1][2:].strip()
                if item:
                    values.append(parse_scalar(item))
                    index += 1
                else:
                    child, index = parse_block(index + 1, indent + 2)
                    values.append(child)
            return values, index

        values: dict[str, Any] = {}
        while index < len(rows) and rows[index][0] == indent and not rows[index][1].startswith("- "):
            line = rows[index][1]
            if ":" not in line:
                raise SystemExit(f"Unsupported config line: {line}")
            key, raw_value = line.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            if raw_value:
                values[key] = parse_scalar(raw_value)
                index += 1
            else:
                child, index = parse_block(index + 1, indent + 2)
                values[key] = child
        return values, index

    parsed, final_index = parse_block(0, 0)
    if final_index != len(rows) or not isinstance(parsed, dict):
        raise SystemExit("Unsupported config shape. Install PyYAML for full YAML support.")
    return parsed


def load_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml
    except ImportError:
        data = load_simple_yaml(text)
    else:
        data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Config must be a YAML object: {path}")
    return data


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    provider = config.get("provider", {}) or {}
    loader = config.get("loader", {}) or {}
    provider_kind = provider.get("kind", "")
    loader_kind = loader.get("kind", "")

    supported_loader_kinds = {
        "gemini_native_pdf",
        "inline_text",
        "langchain",
    }
    if loader_kind not in supported_loader_kinds:
        supported = ", ".join(sorted(supported_loader_kinds))
        raise SystemExit(f"loader.kind must be one of: {supported}")
    if loader_kind == "langchain":
        class_path = str(loader.get("class_path", "")).strip()
        if class_path and "sources" in loader:
            raise SystemExit(
                "loader.kind=langchain accepts either loader.sources or "
                "loader.class_path, not both"
            )
        loader_kwargs = loader.get("kwargs", {}) or {}
        if not isinstance(loader_kwargs, dict):
            raise SystemExit("loader.kwargs must be a mapping when provided")
        if not class_path:
            sources = loader.get("sources", [])
            if isinstance(sources, str):
                sources = [sources]
            if (
                not isinstance(sources, list)
                or not sources
                or any(
                    not isinstance(source, str) or not source.strip()
                    for source in sources
                )
            ):
                raise SystemExit(
                    "loader.kind=langchain requires loader.sources with at least "
                    "one non-empty path or URL when class_path is omitted"
                )
            if "file_path" in loader_kwargs:
                raise SystemExit(
                    "the default LangChain loader uses loader.sources; "
                    "remove loader.kwargs.file_path"
                )
    generation_config = provider.get("generation_config", {}) or {}
    if not isinstance(generation_config, dict):
        raise SystemExit("provider.generation_config must be a mapping when provided")
    reserved_generation_keys = sorted(WORKFLOW_CONTROLLED_GENERATION_CONFIG_KEYS & set(generation_config))
    if reserved_generation_keys:
        joined = ", ".join(reserved_generation_keys)
        raise SystemExit(f"provider.generation_config cannot set workflow-controlled keys: {joined}")
    try:
        overrides = operation_overrides(config)
        provider_plan = operation_provider_plan(config)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if loader_kind == "gemini_native_pdf":
        local_paths = loader.get("local_paths", [])
        if (
            not isinstance(local_paths, list)
            or not local_paths
            or any(
                not isinstance(raw_path, str) or not raw_path.strip()
                for raw_path in local_paths
            )
        ):
            raise SystemExit(
                "loader.kind=gemini_native_pdf requires loader.local_paths with "
                "at least one non-empty PDF path"
            )
        for raw_path in local_paths:
            path = Path(raw_path).expanduser().resolve()
            if not path.is_file():
                raise SystemExit(f"Native PDF file not found: {path}")
            if path.suffix.casefold() != ".pdf":
                raise SystemExit(f"gemini_native_pdf accepts only .pdf files: {path}")

        incompatible = sorted(
            operation
            for operation, operation_provider in provider_plan.items()
            if operation_provider.get("kind") != "gemini"
        )
        if incompatible:
            joined = ", ".join(incompatible)
            raise SystemExit(
                "loader.kind=gemini_native_pdf requires Gemini for every operation. "
                f"Non-Gemini operations: {joined}"
            )

    save = config.get("save", {}) or {}
    if not isinstance(save, dict):
        raise SystemExit("save must be a mapping when provided")
    unknown_save_fields = sorted(set(save) - {"prompts", "llm_responses"})
    if unknown_save_fields:
        joined = ", ".join(unknown_save_fields)
        raise SystemExit(f"Unknown save fields: {joined}")
    unsafe_saves = [
        name
        for name in ("prompts", "llm_responses")
        if save.get(name) is True
    ]
    retry = config.get("retry", {}) or {}
    if not isinstance(retry, dict):
        raise SystemExit("retry must be a mapping when provided")
    try:
        retry_max_attempts = int(retry.get("max_attempts", 3) or 1)
    except (TypeError, ValueError) as exc:
        raise SystemExit("retry.max_attempts must be an integer") from exc
    logging_config = config.get("logging", {}) or {}
    if not isinstance(logging_config, dict):
        raise SystemExit("logging must be a mapping when provided")
    return {
        "provider": provider_kind,
        "model": provider.get("model", ""),
        "loader": loader_kind,
        "unsafe_saves_enabled": unsafe_saves,
        "web_search_requested": bool((provider.get("web_search", {}) or {}).get("enabled")),
        "generation_config_keys": sorted(generation_config),
        "operation_overrides": sorted(overrides),
        "operation_provider_plan": provider_plan,
        "retry": {
            "enabled": bool(retry.get("enabled", True)),
            "max_attempts": retry_max_attempts,
        },
        "logging": {
            "events_jsonl": bool(logging_config.get("events_jsonl", True)),
            "include_error_messages": bool(logging_config.get("include_error_messages", False)),
            "print_run_progress": bool(logging_config.get("print_run_progress", True)),
        },
    }


def resolve_app_name(config: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override

    app_config = config.get("app", {}) or {}
    if isinstance(app_config, str):
        app_name = app_config
    elif isinstance(app_config, dict):
        app_name = app_config.get("name", "")
    else:
        raise SystemExit("app must be a string or a mapping with app.name")

    app_name = str(app_name).strip()
    if not app_name:
        raise SystemExit("Application name is required. Set app.name in config or pass --app.")
    return app_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configurable translator artifact runner.")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--app", help="Override config app.name for this run.")
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate config and print the provider plan without invoking the workflow.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print cumulative token and cost metadata after each provider call.",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    app_name = resolve_app_name(config, args.app)
    summary = validate_config(config)
    summary["app"] = app_name
    summary["config"] = str(args.config)
    summary["status"] = "validated"

    print(json.dumps(summary, indent=2))
    if not args.check_config:
        from .runtime import run_configured_translator

        artifact_root = Path(__file__).resolve().parents[1]
        metadata = asyncio.run(
            run_configured_translator(
                config,
                app_name=app_name,
                artifact_root=artifact_root,
                progress=args.progress,
            )
        )
        print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
