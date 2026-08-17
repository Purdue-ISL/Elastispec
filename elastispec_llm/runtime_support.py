from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .providers.base import GenerationRequest, UnsupportedCapabilityError


RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}
NON_RETRYABLE_ERROR_NAMES = {
    "badrequesterror",
    "jsondecodeerror",
    "systemexit",
    "typeerror",
    "unsupportedcapabilityerror",
    "validationerror",
    "valueerror",
}


class RuntimeEventLogger:
    def __init__(
        self,
        *,
        path: Path,
        enabled: bool = True,
        include_error_messages: bool = False,
    ) -> None:
        self.path = path
        self.enabled = enabled
        self.include_error_messages = include_error_messages
        self._lock = Lock()
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, **payload: Any) -> None:
        if not self.enabled:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": event,
            **to_plain_data(payload),
        }
        line = json.dumps(record, sort_keys=True, ensure_ascii=True, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class ProviderDebugLogger:
    def __init__(
        self,
        *,
        directory: Path,
        save_prompts: bool = False,
        save_llm_responses: bool = False,
        include_error_messages: bool = False,
    ) -> None:
        self.directory = directory
        self.save_prompts = save_prompts
        self.save_llm_responses = save_llm_responses
        self.include_error_messages = include_error_messages
        self.enabled = self.save_prompts or self.save_llm_responses
        self._lock = Lock()
        self._counter = 0
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True)

    def write_success(
        self,
        *,
        operation: str,
        provider: str,
        model: str,
        attempt: int,
        max_attempts: int,
        elapsed_seconds: float,
        request: GenerationRequest,
        response_text: str,
    ) -> dict[str, str]:
        if not self.enabled:
            return {}
        payload: dict[str, Any] = {
            "status": "success",
            "operation": operation,
            "provider": provider,
            "model": model,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "elapsed_seconds": elapsed_seconds,
            "saved_fields": self.saved_fields(),
        }
        if self.save_prompts:
            payload["prompt"] = request.prompt
        if self.save_llm_responses:
            payload["llm_response"] = response_text
        return self._write(operation=operation, attempt=attempt, payload=payload)

    def write_failure(
        self,
        *,
        operation: str,
        provider: str,
        model: str,
        attempt: int,
        max_attempts: int,
        elapsed_seconds: float,
        request: GenerationRequest,
        exc: BaseException,
    ) -> dict[str, str]:
        if not self.enabled:
            return {}
        payload: dict[str, Any] = {
            "status": "failed",
            "operation": operation,
            "provider": provider,
            "model": model,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "elapsed_seconds": elapsed_seconds,
            "saved_fields": ["prompt"] if self.save_prompts else [],
            **safe_error_payload(exc, include_message=self.include_error_messages),
        }
        if self.save_prompts:
            payload["prompt"] = request.prompt
        return self._write(operation=operation, attempt=attempt, payload=payload)

    def saved_fields(self) -> list[str]:
        fields = []
        if self.save_prompts:
            fields.append("prompt")
        if self.save_llm_responses:
            fields.append("llm_response")
        return fields

    def _write(self, *, operation: str, attempt: int, payload: dict[str, Any]) -> dict[str, str]:
        with self._lock:
            self._counter += 1
            call_id = self._counter
        path = self.directory / f"{call_id:06d}_{safe_filename_fragment(operation)}_attempt_{attempt}.json"
        payload = {
            "call_id": call_id,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            **payload,
        }
        path.write_text(json.dumps(to_plain_data(payload), indent=2, ensure_ascii=False), encoding="utf-8")
        return {"llm_debug_path": str(path)}


def safe_filename_fragment(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return cleaned.strip("_") or "provider_call"


def retry_config_from_run_config(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("retry", {}) or {}
    if not isinstance(raw, dict):
        raise ValueError("retry must be a mapping when provided")
    enabled = bool(raw.get("enabled", True))
    max_attempts = int(raw.get("max_attempts", 3) or 1)
    if not enabled:
        max_attempts = 1
    return {
        "enabled": enabled,
        "max_attempts": max(1, max_attempts),
        "initial_backoff_seconds": max(0.0, float(raw.get("initial_backoff_seconds", 2) or 0)),
        "max_backoff_seconds": max(0.0, float(raw.get("max_backoff_seconds", 30) or 0)),
        "backoff_multiplier": max(1.0, float(raw.get("backoff_multiplier", 2) or 1)),
        "jitter": bool(raw.get("jitter", True)),
    }


def logging_config_from_run_config(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("logging", {}) or {}
    if not isinstance(raw, dict):
        raise ValueError("logging must be a mapping when provided")
    return {
        "events_jsonl": bool(raw.get("events_jsonl", True)),
        "include_error_messages": bool(raw.get("include_error_messages", False)),
        "print_run_progress": bool(raw.get("print_run_progress", True)),
    }


def retry_backoff_seconds(retry_config: dict[str, Any], attempt: int) -> float:
    initial = float(retry_config.get("initial_backoff_seconds", 2) or 0)
    multiplier = float(retry_config.get("backoff_multiplier", 2) or 1)
    maximum = float(retry_config.get("max_backoff_seconds", 30) or 0)
    delay = initial * (multiplier ** max(0, attempt - 1))
    if maximum:
        delay = min(delay, maximum)
    if retry_config.get("jitter", True) and delay > 0:
        delay = random.uniform(delay * 0.5, delay)
    return delay


def exception_status_code(exc: BaseException) -> int | None:
    for attr in ("status_code", "status", "code"):
        value = getattr(exc, attr, None)
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    response = getattr(exc, "response", None)
    if response is not None:
        for attr in ("status_code", "status"):
            value = getattr(response, attr, None)
            try:
                if value is not None:
                    return int(value)
            except (TypeError, ValueError):
                continue
    return None


def is_retryable_provider_exception(exc: BaseException) -> bool:
    if isinstance(exc, (KeyboardInterrupt, SystemExit, UnsupportedCapabilityError)):
        return False
    name = type(exc).__name__.lower()
    if name in NON_RETRYABLE_ERROR_NAMES:
        return False
    status_code = exception_status_code(exc)
    if status_code is not None:
        return status_code in RETRYABLE_STATUS_CODES
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    retryable_name_markers = (
        "apiconnection",
        "apitimeout",
        "connection",
        "internalserver",
        "ratelimit",
        "rate_limit",
        "resourceexhausted",
        "servererror",
        "serviceunavailable",
        "timeout",
        "urlerror",
    )
    return any(marker in name for marker in retryable_name_markers)


def safe_error_payload(exc: BaseException, *, include_message: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error_type": type(exc).__name__,
        "status_code": exception_status_code(exc),
    }
    if include_message:
        payload["error_message"] = str(exc)[:500]
    return payload


def build_retry_summary(retry_config: dict[str, Any], retry_records: list[dict[str, Any]]) -> dict[str, Any]:
    retry_events = [record for record in retry_records if record.get("event") == "provider_call_retry"]
    failed_after_retries = [
        {
            "operation": record.get("operation", ""),
            "provider": record.get("provider", ""),
            "model": record.get("model", ""),
            "attempts": record.get("attempt", 0),
            "error_type": record.get("error_type", ""),
            "status_code": record.get("status_code"),
        }
        for record in retry_records
        if record.get("event") == "provider_call_failed" and int(record.get("attempt", 1) or 1) > 1
    ]
    return {
        "enabled": bool(retry_config.get("enabled", True)),
        "max_attempts": int(retry_config.get("max_attempts", 1) or 1),
        "total_retries": len(retry_events),
        "operations_with_retries": sorted({str(record.get("operation", "")) for record in retry_events}),
        "failed_after_retries": failed_after_retries,
        "retryable_status_codes": sorted(RETRYABLE_STATUS_CODES),
    }


def to_plain_data(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [to_plain_data(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain_data(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain_data(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json", exclude_none=True)
        except Exception:
            return value.model_dump(mode="python", exclude_none=True)
    if hasattr(value, "to_json_dict"):
        return value.to_json_dict()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {key: to_plain_data(item) for key, item in value.__dict__.items() if not key.startswith("_")}
    return str(value)


def load_pricing_config(config: dict[str, Any], artifact_root: Path) -> dict[str, Any]:
    pricing_path = ((config.get("cost", {}) or {}).get("pricing_path"))
    if not pricing_path:
        pricing_path = "config/pricing.example.yaml"
    path = Path(pricing_path)
    if not path.is_absolute():
        path = artifact_root / path
    if not path.exists():
        raise SystemExit(f"Pricing config not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        import yaml
    except ImportError:
        return {}
    loaded = yaml.safe_load(text) or {}
    if not isinstance(loaded, dict):
        raise SystemExit(f"Pricing config must be a YAML object: {path}")
    return loaded
