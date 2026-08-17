from __future__ import annotations

import os
from typing import Any

from .base import GenerationRequest, GenerationResult, TokenUsage


class GeminiProvider:
    name = "gemini"
    supports_web_search = True
    supports_native_pdf = True

    def __init__(
        self,
        *,
        model: str,
        api_key_env: str = "GEMINI_API_KEY",
        temperature: float | None = None,
        generation_config: dict[str, Any] | None = None,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.temperature = temperature
        self.generation_config = dict(generation_config or {})
        self._uploaded_native_pdfs: dict[str, Any] = {}
        self._client: Any | None = None

    def _get_client(self) -> Any:
        from google import genai

        if self._client is None:
            api_key = os.getenv(self.api_key_env)
            if not api_key:
                raise ValueError(
                    f"Gemini API key environment variable is not set: {self.api_key_env}"
                )
            self._client = genai.Client(api_key=api_key)
        return self._client

    def generate(self, request: GenerationRequest) -> GenerationResult:
        from google.genai import types

        client = self._get_client()

        config: dict[str, Any] = dict(self.generation_config)
        config.update(request.generation_config)
        if self.temperature is not None:
            config.setdefault("temperature", self.temperature)
        if request.json_mode or request.response_schema is not None:
            config["response_mime_type"] = "application/json"
        if request.response_schema is not None:
            config["response_schema"] = _gemini_response_schema(request.response_schema)
        if request.web_search:
            config["tools"] = [gemini_google_search_tool(types, request)]

        contents: Any = request.prompt
        if request.native_pdf_paths:
            uploaded_files = []
            for path in request.native_pdf_paths:
                uploaded = self._uploaded_native_pdfs.get(path)
                if uploaded is None:
                    uploaded = client.files.upload(
                        file=path,
                        config={"mime_type": "application/pdf"},
                    )
                    self._uploaded_native_pdfs[path] = uploaded
                uploaded_files.append(uploaded)
            contents = [*uploaded_files, request.prompt]

        response = client.models.generate_content(
            model=self.model,
            contents=contents,
            config=types.GenerateContentConfig(**_coerce_gemini_config(config)),
        )
        web_search_queries = extract_gemini_web_search_queries(response)
        usage = extract_gemini_usage(response, model=self.model, web_search_queries=web_search_queries)
        response_text = _response_text(response)
        return GenerationResult(
            text=response_text,
            provider=self.name,
            model=self.model,
            usage=usage,
            metadata={
                **request.metadata,
                "web_search_requested": request.web_search,
                "web_search_enabled": request.web_search,
                "web_search_queries": web_search_queries,
                "native_pdf_count": len(request.native_pdf_paths),
                "provider_generation_config": _metadata_generation_config(config),
            },
        )

    def close(self) -> dict[str, Any]:
        client = self._client
        uploaded_count = len(self._uploaded_native_pdfs)
        deleted_count = 0
        failures: list[BaseException] = []
        if client is not None:
            for uploaded in self._uploaded_native_pdfs.values():
                name = str(getattr(uploaded, "name", "") or "").strip()
                if not name:
                    failures.append(RuntimeError("Uploaded Gemini file has no file name"))
                    continue
                try:
                    client.files.delete(name=name)
                    deleted_count += 1
                except Exception as exc:
                    failures.append(exc)
            try:
                client.close()
            except Exception as exc:
                failures.append(exc)

        self._uploaded_native_pdfs.clear()
        self._client = None
        if failures:
            raise RuntimeError(
                f"Failed to clean up {len(failures)} Gemini client or uploaded-file resource(s)"
            ) from failures[0]
        return {
            "provider": self.name,
            "model": self.model,
            "native_pdf_files_uploaded": uploaded_count,
            "native_pdf_files_deleted": deleted_count,
        }


def _coerce_gemini_config(config: dict[str, Any]) -> dict[str, Any]:
    from google.genai import types

    coerced = dict(config)
    thinking_config = coerced.get("thinking_config")
    if isinstance(thinking_config, dict):
        thinking_config = dict(thinking_config)
        if "thinking_level" in thinking_config and isinstance(thinking_config["thinking_level"], str):
            thinking_config["thinking_level"] = getattr(
                types.ThinkingLevel,
                thinking_config["thinking_level"].upper(),
                thinking_config["thinking_level"],
            )
        coerced["thinking_config"] = types.ThinkingConfig(**thinking_config)
    return coerced


def _gemini_response_schema(schema: Any) -> Any:
    if hasattr(schema, "model_json_schema"):
        return _strip_gemini_unsupported_schema_keywords(schema.model_json_schema())
    if isinstance(schema, dict):
        return _strip_gemini_unsupported_schema_keywords(schema)
    return schema


def gemini_google_search_tool(types: Any, request: GenerationRequest) -> Any:
    web_search_config = request.metadata.get("web_search_config", {}) or {}
    google_search_config = dict(web_search_config.get("google_search", {}) or {})
    for key, value in web_search_config.items():
        if key in {"enabled", "unsupported_policy", "google_search"}:
            continue
        google_search_config[key] = value

    alias_map = {
        "searchTypes": "search_types",
        "blockingConfidence": "blocking_confidence",
        "excludeDomains": "exclude_domains",
        "timeRangeFilter": "time_range_filter",
    }
    normalized = {
        alias_map.get(key, key): value
        for key, value in google_search_config.items()
    }
    allowed = {"search_types", "blocking_confidence", "exclude_domains", "time_range_filter"}
    unsupported = sorted(set(normalized) - allowed)
    if unsupported:
        joined = ", ".join(unsupported)
        allowed_joined = ", ".join(sorted(allowed))
        raise ValueError(f"Gemini web_search supports only GoogleSearch fields: {allowed_joined}. Got: {joined}")
    return types.Tool(google_search=types.GoogleSearch(**normalized))


def _strip_gemini_unsupported_schema_keywords(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_gemini_unsupported_schema_keywords(item)
            for key, item in value.items()
            if key != "additionalProperties"
        }
    if isinstance(value, list):
        return [_strip_gemini_unsupported_schema_keywords(item) for item in value]
    return value


def _metadata_generation_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in config.items()
        if key not in {"tools", "response_json_schema", "response_mime_type", "response_schema"}
    }


def _response_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if text:
        return str(text).strip()
    parts: list[str] = []
    for candidate in getattr(response, "candidates", []) or []:
        content = getattr(candidate, "content", None)
        for part in getattr(content, "parts", []) or []:
            part_text = getattr(part, "text", None)
            if part_text:
                parts.append(str(part_text))
    return "".join(parts).strip()


def _get_attr(source: Any, name: str, default: Any = 0) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def extract_gemini_usage(
    response: Any,
    *,
    model: str = "",
    web_search_queries: list[str] | None = None,
) -> TokenUsage:
    raw = _get_attr(response, "usage_metadata", {}) or {}
    web_search_queries = web_search_queries or extract_gemini_web_search_queries(response)
    search_query_count = gemini_search_billing_units(model, web_search_queries)
    return TokenUsage(
        input_tokens=_safe_int(_get_attr(raw, "prompt_token_count")),
        cached_input_tokens=_safe_int(_get_attr(raw, "cached_content_token_count")),
        output_tokens=_safe_int(_get_attr(raw, "candidates_token_count")),
        reasoning_tokens=_safe_int(_get_attr(raw, "thoughts_token_count")),
        tool_tokens=_safe_int(_get_attr(raw, "tool_use_prompt_token_count")),
        total_tokens=_safe_int(_get_attr(raw, "total_token_count")),
        search_queries=search_query_count,
        provider_raw={
            "prompt_token_count": _safe_int(_get_attr(raw, "prompt_token_count")),
            "cached_content_token_count": _safe_int(_get_attr(raw, "cached_content_token_count")),
            "candidates_token_count": _safe_int(_get_attr(raw, "candidates_token_count")),
            "thoughts_token_count": _safe_int(_get_attr(raw, "thoughts_token_count")),
            "tool_use_prompt_token_count": _safe_int(_get_attr(raw, "tool_use_prompt_token_count")),
            "total_token_count": _safe_int(_get_attr(raw, "total_token_count")),
            "web_search_queries": web_search_queries,
            "web_search_billing_units": search_query_count,
        },
    )


def extract_gemini_web_search_queries(response: Any) -> list[str]:
    queries: list[str] = []
    for candidate in _get_attr(response, "candidates", []) or []:
        grounding_metadata = (
            _get_attr(candidate, "grounding_metadata", None)
            or _get_attr(candidate, "groundingMetadata", None)
            or {}
        )
        for key in ("web_search_queries", "webSearchQueries"):
            raw_queries = _get_attr(grounding_metadata, key, []) or []
            if isinstance(raw_queries, str):
                raw_queries = [raw_queries]
            for query in raw_queries:
                query_text = str(query).strip()
                if query_text and query_text not in queries:
                    queries.append(query_text)
    return queries


def gemini_search_billing_units(model: str, queries: list[str]) -> int:
    if not queries:
        return 0
    if model.lower().startswith("gemini-3"):
        return len(queries)
    return 1
