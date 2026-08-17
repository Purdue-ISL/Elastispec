from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from time import perf_counter, sleep
from types import ModuleType, SimpleNamespace
from typing import Any, Iterator

from elastispec_llm.provider_factory import (
    build_provider_from_config,
    operation_overrides,
    operation_provider_plan,
    provider_config_for_operation,
    summarize_provider_config,
)
from elastispec_llm.providers.base import GenerationRequest, TextProvider
from elastispec_llm.runtime_support import (
    ProviderDebugLogger,
    RuntimeEventLogger,
    build_retry_summary,
    is_retryable_provider_exception,
    load_pricing_config,
    logging_config_from_run_config,
    retry_backoff_seconds,
    retry_config_from_run_config,
    safe_error_payload,
    to_plain_data,
)
from elastispec_llm.usage import estimate_cost_for_calls, summarize_provider_calls

from .loader_factory import build_loader
from .loaders.gemini_native_pdf_loader import GeminiNativePdfDocument


REQUEST_CONFIG_EXCLUDE_KEYS = {
    "response_json_schema",
    "response_mime_type",
    "response_modalities",
    "response_schema",
    "tools",
}
NATIVE_PDF_OPERATIONS = {
    "generate_outline",
    "extract_section_content",
    "determine_optionality",
}
_current_operation: ContextVar[str] = ContextVar("current_translator_operation", default="default")


@dataclass
class ShimPart:
    text: str


@dataclass
class ShimContent:
    parts: list[ShimPart]


@dataclass
class ShimCandidate:
    content: ShimContent
    grounding_metadata: dict[str, Any] | None = None


class ShimResponse:
    def __init__(
        self,
        *,
        text: str,
        model: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.text = text
        self.model_version = model
        self.usage_metadata = {}
        self.candidates = [
            ShimCandidate(
                content=ShimContent(parts=[ShimPart(text=text)]),
                grounding_metadata={
                    "web_search_queries": (metadata or {}).get("web_search_queries", []),
                },
            )
        ]


@dataclass
class ProviderSelection:
    operation: str
    provider: TextProvider
    web_search_enabled: bool
    web_search_config: dict[str, Any]
    override_applied: bool
    provider_config_summary: dict[str, Any]


class ProviderRouter:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.overrides = operation_overrides(config)
        self.default_provider_config = config.get("provider", {}) or {}
        self._providers: dict[str, TextProvider] = {}

    def model_for_operation(self, operation: str | None = None) -> str:
        operation_id = operation or "default"
        _current_operation.set(operation_id)
        return self.select(operation_id).provider.model

    def select(self, operation: str | None = None) -> ProviderSelection:
        operation_id = operation or _current_operation.get()
        provider_config = (
            provider_config_for_operation(self.config, operation_id)
            if operation_id != "default"
            else self.default_provider_config
        )
        cache_key = json.dumps(provider_config, sort_keys=True)
        provider = self._providers.get(cache_key)
        if provider is None:
            provider = build_provider_from_config(provider_config)
            self._providers[cache_key] = provider
        web_search = provider_config.get("web_search", {}) or {}
        return ProviderSelection(
            operation=operation_id,
            provider=provider,
            web_search_enabled=bool(web_search.get("enabled", False)),
            web_search_config=dict(web_search),
            override_applied=operation_id in self.overrides,
            provider_config_summary=summarize_provider_config(provider_config),
        )

    def metadata_plan(self) -> dict[str, Any]:
        return {
            "default_provider": summarize_provider_config(self.default_provider_config),
            "operation_overrides": {
                operation: summarize_provider_config(provider_config_for_operation(self.config, operation))
                for operation in sorted(self.overrides)
            },
            "operation_provider_plan": operation_provider_plan(self.config),
        }

    def close(self) -> dict[str, Any]:
        details: list[dict[str, Any]] = []
        failures: list[BaseException] = []
        providers = list(self._providers.values())
        for provider in providers:
            close = getattr(provider, "close", None)
            if not callable(close):
                continue
            try:
                result = close()
                if isinstance(result, dict):
                    details.append(result)
            except Exception as exc:
                failures.append(exc)
        self._providers.clear()
        if failures:
            raise RuntimeError(
                f"Failed to clean up {len(failures)} provider resource(s)"
            ) from failures[0]
        return {
            "status": "completed",
            "provider_instances": len(providers),
            "details": details,
        }


class ProviderModelsShim:
    def __init__(
        self,
        router: ProviderRouter,
        runtime_metadata: list[dict[str, Any]],
        progress_callback: Any | None = None,
        event_logger: RuntimeEventLogger | None = None,
        debug_logger: ProviderDebugLogger | None = None,
        retry_config: dict[str, Any] | None = None,
        retry_records: list[dict[str, Any]] | None = None,
        print_run_progress: bool = True,
        native_pdf_paths: tuple[str, ...] = (),
    ) -> None:
        self.router = router
        self.runtime_metadata = runtime_metadata
        self.progress_callback = progress_callback
        self.event_logger = event_logger
        self.debug_logger = debug_logger
        self.retry_config = retry_config or retry_config_from_run_config({})
        self.retry_records = retry_records if retry_records is not None else []
        self.print_run_progress = print_run_progress
        self.native_pdf_paths = native_pdf_paths
        self._lock = Lock()

    def generate_content(self, *, model: str, contents: Any, config: Any = None) -> ShimResponse:
        selection = self.router.select(_current_operation.get())
        provider = selection.provider
        prompt = flatten_contents(contents)
        generation_config = extract_request_generation_config(config)
        workflow_requested_tools = bool(get_config_attr(config, "tools"))
        native_pdf_paths = (
            self.native_pdf_paths
            if selection.operation in NATIVE_PDF_OPERATIONS
            else ()
        )
        if native_pdf_paths and not provider.supports_native_pdf:
            raise ValueError(
                f"Provider {provider.name} does not support loader.kind=gemini_native_pdf"
            )
        request = GenerationRequest(
            prompt=prompt,
            json_mode=config_requests_json(config),
            response_schema=get_config_attr(config, "response_schema") or get_config_attr(config, "response_json_schema"),
            web_search=selection.web_search_enabled and workflow_requested_tools,
            native_pdf_paths=native_pdf_paths,
            generation_config=generation_config,
            metadata={
                "operation": selection.operation,
                "requested_model": model,
                "workflow_requested_tools": workflow_requested_tools,
                "workflow_generation_config": generation_config,
                "operation_override_applied": selection.override_applied,
                "operation_provider_config": selection.provider_config_summary,
                "web_search_config": selection.web_search_config,
                "native_pdf_count": len(native_pdf_paths),
            },
        )
        max_attempts = int(self.retry_config.get("max_attempts", 1) or 1)
        retry_enabled = bool(self.retry_config.get("enabled", True)) and max_attempts > 1
        attempt = 1
        while True:
            if self.event_logger is not None:
                self.event_logger.emit(
                    "provider_call_start",
                    operation=selection.operation,
                    provider=provider.name,
                    model=provider.model,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    json_mode=request.json_mode,
                    web_search=request.web_search,
                    operation_override_applied=selection.override_applied,
                )
            started_at = perf_counter()
            try:
                result = provider.generate(request)
            except Exception as exc:
                elapsed_seconds = perf_counter() - started_at
                debug_paths = (
                    self.debug_logger.write_failure(
                        operation=selection.operation,
                        provider=provider.name,
                        model=provider.model,
                        attempt=attempt,
                        max_attempts=max_attempts,
                        elapsed_seconds=elapsed_seconds,
                        request=request,
                        exc=exc,
                    )
                    if self.debug_logger is not None
                    else {}
                )
                retryable = retry_enabled and attempt < max_attempts and is_retryable_provider_exception(exc)
                error_payload = safe_error_payload(
                    exc,
                    include_message=bool(
                        self.event_logger.include_error_messages if self.event_logger is not None else False
                    ),
                )
                failure_payload = {
                    "operation": selection.operation,
                    "provider": provider.name,
                    "model": provider.model,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "elapsed_seconds": elapsed_seconds,
                    "retryable": retryable,
                    **error_payload,
                    **debug_paths,
                }
                if retryable:
                    backoff_seconds = retry_backoff_seconds(self.retry_config, attempt)
                    retry_record = {
                        "event": "provider_call_retry",
                        **failure_payload,
                        "backoff_seconds": backoff_seconds,
                    }
                    with self._lock:
                        self.retry_records.append(retry_record)
                    if self.event_logger is not None:
                        self.event_logger.emit("provider_call_retry", **failure_payload, backoff_seconds=backoff_seconds)
                    if self.print_run_progress:
                        print(
                            "PROVIDER_RETRY "
                            + json.dumps(
                                {
                                    "operation": selection.operation,
                                    "provider": provider.name,
                                    "model": provider.model,
                                    "attempt": attempt,
                                    "max_attempts": max_attempts,
                                    "backoff_seconds": backoff_seconds,
                                    "error_type": error_payload.get("error_type"),
                                    "status_code": error_payload.get("status_code"),
                                },
                                sort_keys=True,
                            ),
                            file=sys.stderr,
                            flush=True,
                        )
                    if backoff_seconds > 0:
                        sleep(backoff_seconds)
                    attempt += 1
                    continue

                failed_record = {"event": "provider_call_failed", **failure_payload}
                with self._lock:
                    self.retry_records.append(failed_record)
                if self.event_logger is not None:
                    self.event_logger.emit("provider_call_failed", **failure_payload)
                raise

            elapsed_seconds = perf_counter() - started_at
            debug_paths = (
                self.debug_logger.write_success(
                    operation=selection.operation,
                    provider=result.provider,
                    model=result.model,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    elapsed_seconds=elapsed_seconds,
                    request=request,
                    response_text=result.text,
                )
                if self.debug_logger is not None
                else {}
            )
            call_metadata = {
                **result.metadata,
                "provider": result.provider,
                "model": result.model,
                "elapsed_seconds": elapsed_seconds,
                "usage": result.usage.to_dict(),
                "attempt": attempt,
                "max_attempts": max_attempts,
                "retry_count": attempt - 1,
                "status": "success",
                **debug_paths,
            }
            with self._lock:
                self.runtime_metadata.append(call_metadata)
            if self.event_logger is not None:
                self.event_logger.emit(
                    "provider_call_success",
                    operation=selection.operation,
                    provider=result.provider,
                    model=result.model,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    elapsed_seconds=elapsed_seconds,
                    retry_count=attempt - 1,
                    usage=result.usage.to_dict(),
                    finish_reason=call_metadata.get("finish_reason", ""),
                    response_text_chars=call_metadata.get("response_text_chars", 0),
                    **debug_paths,
                )
            if self.progress_callback is not None:
                self.progress_callback(call_metadata, self.runtime_metadata)
            return ShimResponse(text=result.text, model=result.model, metadata=result.metadata)


class AsyncProviderModelsShim:
    def __init__(self, sync_models: ProviderModelsShim) -> None:
        self._sync_models = sync_models

    async def generate_content(self, *, model: str, contents: Any, config: Any = None) -> ShimResponse:
        return await asyncio.to_thread(
            self._sync_models.generate_content,
            model=model,
            contents=contents,
            config=config,
        )


class ProviderAioShim:
    def __init__(self, sync_models: ProviderModelsShim) -> None:
        self.models = AsyncProviderModelsShim(sync_models)


class ProviderClientShim:
    def __init__(
        self,
        router: ProviderRouter,
        runtime_metadata: list[dict[str, Any]],
        progress_callback: Any | None = None,
        event_logger: RuntimeEventLogger | None = None,
        debug_logger: ProviderDebugLogger | None = None,
        retry_config: dict[str, Any] | None = None,
        retry_records: list[dict[str, Any]] | None = None,
        print_run_progress: bool = True,
        native_pdf_paths: tuple[str, ...] = (),
    ) -> None:
        self.models = ProviderModelsShim(
            router,
            runtime_metadata,
            progress_callback=progress_callback,
            event_logger=event_logger,
            debug_logger=debug_logger,
            retry_config=retry_config,
            retry_records=retry_records,
            print_run_progress=print_run_progress,
            native_pdf_paths=native_pdf_paths,
        )
        self.aio = ProviderAioShim(self.models)


def get_config_attr(config: Any, name: str) -> Any:
    if config is None:
        return None
    if isinstance(config, dict):
        return config.get(name)
    return getattr(config, name, None)


def config_requests_json(config: Any) -> bool:
    return get_config_attr(config, "response_mime_type") == "application/json" or bool(
        get_config_attr(config, "response_schema") or get_config_attr(config, "response_json_schema")
    )


def flatten_contents(contents: Any) -> str:
    if isinstance(contents, str):
        return contents
    if isinstance(contents, list):
        pieces = []
        for item in contents:
            pieces.append(flatten_contents(item))
        return "\n\n".join(piece for piece in pieces if piece)
    if hasattr(contents, "text"):
        return str(contents.text)
    return str(contents)


def extract_request_generation_config(config: Any) -> dict[str, Any]:
    data = to_plain_data(config)
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key not in REQUEST_CONFIG_EXCLUDE_KEYS}


def install_google_stub() -> None:
    if "google.genai" in sys.modules:
        return
    try:
        import importlib.util

        if importlib.util.find_spec("google.genai") is not None:
            return
    except (ImportError, ValueError):
        pass

    google_module = sys.modules.get("google") or ModuleType("google")
    genai_module = ModuleType("google.genai")
    types_module = ModuleType("google.genai.types")

    class ThinkingLevel:
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"

    class ThinkingConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class GenerateContentConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class GoogleSearch:
        pass

    class Tool:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class Client:
        pass

    types_module.ThinkingLevel = ThinkingLevel
    types_module.ThinkingConfig = ThinkingConfig
    types_module.GenerateContentConfig = GenerateContentConfig
    types_module.GoogleSearch = GoogleSearch
    types_module.Tool = Tool
    genai_module.types = types_module
    genai_module.Client = Client
    google_module.genai = genai_module

    sys.modules["google"] = google_module
    sys.modules["google.genai"] = genai_module
    sys.modules["google.genai.types"] = types_module


@contextmanager
def workflow_import_context(workflow_dir: Path, provider_kind: str) -> Iterator[None]:
    if provider_kind != "gemini":
        install_google_stub()
    sys.path.insert(0, str(workflow_dir))
    try:
        yield
    finally:
        try:
            sys.path.remove(str(workflow_dir))
        except ValueError:
            pass


def import_workflow_modules(workflow_dir: Path, provider_kind: str) -> dict[str, Any]:
    with workflow_import_context(workflow_dir, provider_kind):
        modules = {}
        for name in (
            "document_processing",
            "policy_generation",
            "runner",
            "SignatureToFSL",
        ):
            modules[name] = importlib.import_module(name)
        return modules


@contextmanager
def patched_workflow(
    *,
    modules: dict[str, Any],
    router: ProviderRouter,
    runtime_metadata: list[dict[str, Any]],
    progress_callback: Any | None = None,
    event_logger: RuntimeEventLogger | None = None,
    debug_logger: ProviderDebugLogger | None = None,
    retry_config: dict[str, Any] | None = None,
    retry_records: list[dict[str, Any]] | None = None,
    print_run_progress: bool = True,
    native_pdf_paths: tuple[str, ...] = (),
) -> Iterator[None]:
    doc_module = modules["document_processing"]
    policy_module = modules["policy_generation"]
    originals = {
        "doc_genai": doc_module.genai,
        "policy_genai": policy_module.genai,
        "doc_model": doc_module.get_workflow_model,
        "policy_model": policy_module.get_workflow_model,
    }

    def client_factory(*args: Any, **kwargs: Any) -> ProviderClientShim:
        return ProviderClientShim(
            router,
            runtime_metadata,
            progress_callback=progress_callback,
            event_logger=event_logger,
            debug_logger=debug_logger,
            retry_config=retry_config,
            retry_records=retry_records,
            print_run_progress=print_run_progress,
            native_pdf_paths=native_pdf_paths,
        )

    genai_shim = SimpleNamespace(Client=client_factory)
    doc_module.genai = genai_shim
    policy_module.genai = genai_shim
    doc_module.get_workflow_model = router.model_for_operation
    policy_module.get_workflow_model = router.model_for_operation
    try:
        yield
    finally:
        doc_module.genai = originals["doc_genai"]
        policy_module.genai = originals["policy_genai"]
        doc_module.get_workflow_model = originals["doc_model"]
        policy_module.get_workflow_model = originals["policy_model"]


def raw_docs_from_config(config: dict[str, Any]) -> tuple[list[str], tuple[str, ...]]:
    loader = build_loader(config)
    loaded = loader.load()
    raw_docs: list[str] = []
    native_pdf_paths: list[str] = []
    for item in loaded:
        if isinstance(item, GeminiNativePdfDocument):
            path = Path(item.path)
            native_pdf_paths.append(str(path))
            raw_docs.append(f"[Native PDF document attached: {path.name}]")
            continue
        content = str(item.content)
        if content.strip():
            raw_docs.append(content)
    return raw_docs, tuple(native_pdf_paths)


def build_progress_callback(pricing: dict[str, Any]):
    def emit_progress(call: dict[str, Any], calls: list[dict[str, Any]]) -> None:
        summary = summarize_provider_calls(calls)
        cost_summary = estimate_cost_for_calls(calls, pricing)
        payload = {
            "operation": call.get("operation", ""),
            "provider": call.get("provider", ""),
            "model": call.get("model", ""),
            "call_count": summary.get("call_count", 0),
            "call_usage": call.get("usage", {}),
            "cumulative_usage": summary,
            "estimated_cost_usd": cost_summary.get("estimated_cost_usd"),
            "finish_reason": call.get("finish_reason", ""),
            "response_text_chars": call.get("response_text_chars", 0),
        }
        print(f"TOKEN_PROGRESS {json.dumps(payload, sort_keys=True)}", file=sys.stderr, flush=True)

    return emit_progress


async def run_configured_translator(
    config: dict[str, Any],
    *,
    app_name: str,
    artifact_root: Path,
    progress: bool = False,
) -> dict[str, Any]:
    router = ProviderRouter(config)
    default_selection = router.select("default")
    provider = default_selection.provider
    provider_config = config.get("provider", {}) or {}
    web_search_config = provider_config.get("web_search", {}) or {}
    web_search_enabled = bool(web_search_config.get("enabled", False))
    output_dir = Path(config.get("output", {}).get("run_dir", "runs/default"))
    if not output_dir.is_absolute():
        output_dir = artifact_root / output_dir
    output_dir = output_dir / app_name
    intermediate_dir = output_dir / "tmp"
    output_dir.mkdir(parents=True, exist_ok=True)
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    runtime_provider_calls: list[dict[str, Any]] = []
    runtime_retry_records: list[dict[str, Any]] = []
    pricing = load_pricing_config(config, artifact_root.parent)
    progress_callback = build_progress_callback(pricing) if progress else None
    retry_config = retry_config_from_run_config(config)
    logging_config = logging_config_from_run_config(config)
    save_config = config.get("save", {}) or {}
    if not isinstance(save_config, dict):
        raise ValueError("save must be a mapping when provided")
    events_path = intermediate_dir / "events.jsonl"
    event_logger = RuntimeEventLogger(
        path=events_path,
        enabled=bool(logging_config.get("events_jsonl", True)),
        include_error_messages=bool(logging_config.get("include_error_messages", False)),
    )
    debug_logger = ProviderDebugLogger(
        directory=intermediate_dir / "llm_debug",
        save_prompts=bool(save_config.get("prompts", False)),
        save_llm_responses=bool(save_config.get("llm_responses", False)),
        include_error_messages=bool(logging_config.get("include_error_messages", False)),
    )
    log_paths = {"events": str(events_path)} if logging_config.get("events_jsonl", True) else {}
    if debug_logger.enabled:
        log_paths["llm_debug_dir"] = str(debug_logger.directory)
    started = perf_counter()
    status = "completed"
    workflow_result: dict[str, Any] = {}
    native_pdf_paths: tuple[str, ...] = ()
    error: dict[str, str] | None = None
    failure_exception: Exception | None = None
    provider_cleanup: dict[str, Any] = {"status": "pending"}
    event_logger.emit(
        "run_start",
        app=app_name,
        output_dir=str(output_dir),
        intermediate_dir=str(intermediate_dir),
        provider=provider.name,
        model=provider.model,
        retry=retry_config,
        save_policy={
            "prompts": bool(save_config.get("prompts", False)),
            "llm_responses": bool(save_config.get("llm_responses", False)),
        },
    )
    if logging_config.get("print_run_progress", True):
        print(
            "RUN_START "
            + json.dumps(
                {
                    "app": app_name,
                    "output_dir": str(output_dir),
                    "events": log_paths.get("events"),
                    "llm_debug_dir": log_paths.get("llm_debug_dir"),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    try:
        raw_docs, native_pdf_paths = raw_docs_from_config(config)
        if not raw_docs:
            raise SystemExit("No documents were loaded from the configured loader.")
        event_logger.emit(
            "documents_loaded",
            app=app_name,
            document_count=len(raw_docs),
            native_pdf_count=len(native_pdf_paths),
        )

        workflow_dir = artifact_root / "translator_runtime" / "workflow"
        modules = import_workflow_modules(workflow_dir, provider.name)
        workflow_runner_cls = modules["runner"].TranslatorWorkflowRunner

        with patched_workflow(
            modules=modules,
            router=router,
            runtime_metadata=runtime_provider_calls,
            progress_callback=progress_callback,
            event_logger=event_logger,
            debug_logger=debug_logger,
            retry_config=retry_config,
            retry_records=runtime_retry_records,
            print_run_progress=bool(logging_config.get("print_run_progress", True)),
            native_pdf_paths=native_pdf_paths,
        ):
            workflow_result = await workflow_runner_cls(
                app_name,
                raw_docs,
                output_dir,
                intermediate_dir=intermediate_dir,
            ).run()
    except Exception as exc:
        status = "failed"
        failure_exception = exc
        error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
        event_logger.emit(
            "run_failed",
            app=app_name,
            runtime_seconds=perf_counter() - started,
            **safe_error_payload(
                exc,
                include_message=bool(logging_config.get("include_error_messages", False)),
            ),
        )
    finally:
        try:
            provider_cleanup = router.close()
            event_logger.emit("provider_cleanup_completed", **provider_cleanup)
        except Exception as cleanup_exc:
            provider_cleanup = {
                "status": "failed",
                "error_type": type(cleanup_exc).__name__,
            }
            event_logger.emit(
                "provider_cleanup_failed",
                **safe_error_payload(
                    cleanup_exc,
                    include_message=bool(
                        logging_config.get("include_error_messages", False)
                    ),
                ),
            )
            if failure_exception is None:
                status = "failed"
                failure_exception = cleanup_exc
                error = {
                    "type": type(cleanup_exc).__name__,
                    "message": str(cleanup_exc),
                }

    usage_summary = summarize_provider_calls(runtime_provider_calls)
    cost_summary = estimate_cost_for_calls(runtime_provider_calls, pricing)
    retry_summary = build_retry_summary(retry_config, runtime_retry_records)

    metadata = {
        "app": app_name,
        "status": status,
        "provider": provider.name,
        "model": provider.model,
        "loader": (config.get("loader", {}) or {}).get("kind", ""),
        "native_pdf_count": len(native_pdf_paths),
        "web_search_requested": web_search_enabled,
        "provider_generation_config": provider_config.get("generation_config", {}) or {},
        **router.metadata_plan(),
        "runtime_seconds": perf_counter() - started,
        "output_dir": str(output_dir),
        "intermediate_dir": str(intermediate_dir),
        "final_output_paths": {
            **workflow_result.get("final_output_paths", {}),
            "run_metadata_path": str(output_dir / "run_metadata.json"),
        },
        "intermediate_paths": workflow_result.get("intermediate_paths", {}),
        "usage_summary": usage_summary,
        "cost_summary": cost_summary,
        "provider_calls": runtime_provider_calls,
        "retry_summary": retry_summary,
        "log_paths": log_paths,
        "logging": logging_config,
        "save_policy": save_config,
        "provider_cleanup": provider_cleanup,
    }
    if error:
        metadata["error"] = error
    (output_dir / "run_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    if status == "completed":
        event_logger.emit(
            "run_completed",
            app=app_name,
            runtime_seconds=metadata["runtime_seconds"],
            final_output_paths=metadata["final_output_paths"],
            usage_summary=usage_summary,
            cost_summary=cost_summary,
            retry_summary=retry_summary,
        )
        if logging_config.get("print_run_progress", True):
            print(
                "RUN_DONE "
                + json.dumps(
                    {
                        "generated_policy": metadata["final_output_paths"].get("generated_policy_path"),
                        "run_metadata": metadata["final_output_paths"].get("run_metadata_path"),
                        "events": log_paths.get("events"),
                        "llm_debug_dir": log_paths.get("llm_debug_dir"),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    elif logging_config.get("print_run_progress", True):
        print(
            "RUN_FAILED "
            + json.dumps(
                {
                    "error_type": (error or {}).get("type"),
                    "run_metadata": str(output_dir / "run_metadata.json"),
                    "events": log_paths.get("events"),
                    "llm_debug_dir": log_paths.get("llm_debug_dir"),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    if failure_exception:
        raise failure_exception
    return metadata
