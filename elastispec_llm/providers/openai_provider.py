from __future__ import annotations

import json
import os
from typing import Any

from .base import GenerationRequest, GenerationResult, TokenUsage


class OpenAIProvider:
    name = "openai"
    supports_web_search = True
    supports_native_pdf = False

    def __init__(
        self,
        *,
        model: str,
        api_key_env: str = "OPENAI_API_KEY",
        api_mode: str = "responses",
        temperature: float | None = None,
        generation_config: dict[str, Any] | None = None,
    ) -> None:
        if api_mode not in {"responses", "chat_completions"}:
            raise ValueError("OpenAI provider api_mode must be 'responses' or 'chat_completions'")
        self.model = model
        self.api_key_env = api_key_env
        self.api_mode = api_mode
        self.temperature = temperature
        self.generation_config = dict(generation_config or {})

    def generate(self, request: GenerationRequest) -> GenerationResult:
        from openai import OpenAI

        api_key = os.getenv(self.api_key_env)
        if not api_key:
            raise ValueError(
                f"OpenAI API key environment variable is not set: {self.api_key_env}"
            )
        client = OpenAI(api_key=api_key)
        try:
            if self.api_mode == "chat_completions":
                return self._generate_chat_completions(client, request)
            return self._generate_responses(client, request)
        finally:
            client.close()

    def _generate_responses(self, client, request: GenerationRequest) -> GenerationResult:
        kwargs = {
            **self.generation_config,
            "model": self.model,
            "input": request.prompt,
        }
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if request.web_search:
            kwargs["tools"] = [openai_web_search_tool(request)]
        if request.response_schema is not None:
            if is_pydantic_schema(request.response_schema):
                response = client.responses.parse(
                    **kwargs,
                    text_format=request.response_schema,
                )
                text = extract_openai_text(response).strip()
                if not text:
                    text = serialize_parsed_response(response)
                usage = extract_openai_usage(response)
                return GenerationResult(
                    text=text,
                    provider=self.name,
                    model=self.model,
                    usage=usage,
                    metadata={
                        **request.metadata,
                        "api_mode": self.api_mode,
                        "finish_reason": extract_openai_finish_reason(response),
                        "response_text_chars": len(text),
                        "web_search_requested": request.web_search,
                        "web_search_enabled": request.web_search,
                        "provider_generation_config": dict(self.generation_config),
                        "structured_output": "pydantic",
                    },
                )
            kwargs["text"] = {"format": json_schema_text_format(request.response_schema, request.metadata)}
        elif request.json_mode:
            kwargs["text"] = {"format": {"type": "json_object"}}

        response = client.responses.create(**kwargs)
        text = extract_openai_text(response).strip()
        usage = extract_openai_usage(response)
        return GenerationResult(
            text=text,
            provider=self.name,
            model=self.model,
            usage=usage,
            metadata={
                **request.metadata,
                "api_mode": self.api_mode,
                "finish_reason": extract_openai_finish_reason(response),
                "response_text_chars": len(text),
                "web_search_requested": request.web_search,
                "web_search_enabled": request.web_search,
                "provider_generation_config": dict(self.generation_config),
            },
        )

    def _generate_chat_completions(self, client, request: GenerationRequest) -> GenerationResult:
        if request.web_search:
            raise ValueError(
                "OpenAI provider api_mode=chat_completions does not support workflow web search; "
                "set provider.web_search.enabled=false or use api_mode=responses"
            )

        kwargs = {
            **self.generation_config,
            "model": self.model,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if request.response_schema is not None:
            if is_pydantic_schema(request.response_schema):
                response = client.chat.completions.parse(
                    **kwargs,
                    response_format=request.response_schema,
                )
                text = extract_openai_text(response).strip()
                if not text:
                    text = serialize_parsed_response(response)
                usage = extract_openai_usage(response)
                return GenerationResult(
                    text=text,
                    provider=self.name,
                    model=self.model,
                    usage=usage,
                    metadata={
                        **request.metadata,
                        "api_mode": self.api_mode,
                        "finish_reason": extract_openai_finish_reason(response),
                        "response_text_chars": len(text),
                        "web_search_requested": request.web_search,
                        "web_search_enabled": False,
                        "provider_generation_config": dict(self.generation_config),
                        "structured_output": "pydantic",
                    },
                )
            kwargs["response_format"] = chat_json_schema_response_format(request.response_schema, request.metadata)
        elif request.json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = client.chat.completions.create(**kwargs)
        text = extract_openai_text(response).strip()
        usage = extract_openai_usage(response)
        return GenerationResult(
            text=text,
            provider=self.name,
            model=self.model,
            usage=usage,
            metadata={
                **request.metadata,
                "api_mode": self.api_mode,
                "finish_reason": extract_openai_finish_reason(response),
                "response_text_chars": len(text),
                "web_search_requested": request.web_search,
                "web_search_enabled": False,
                "provider_generation_config": dict(self.generation_config),
            },
        )


def _get_attr(source, name: str, default=0):
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def _safe_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _plain_mapping(value) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {key: item for key, item in value.__dict__.items() if not key.startswith("_")}
    return {}


def is_pydantic_schema(schema: Any) -> bool:
    return isinstance(schema, type) and hasattr(schema, "model_json_schema")


def openai_web_search_tool(request: GenerationRequest) -> dict[str, Any]:
    web_search_config = request.metadata.get("web_search_config", {}) or {}
    tool = {"type": web_search_config.get("type", "web_search")}
    for key in (
        "search_context_size",
        "filters",
        "user_location",
        "external_web_access",
        "return_token_budget",
    ):
        if key in web_search_config:
            tool[key] = web_search_config[key]
    return tool


def schema_name(metadata: dict[str, Any]) -> str:
    raw_name = str(metadata.get("operation") or "structured_response")
    safe = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in raw_name)
    return safe or "structured_response"


def json_schema_text_format(schema: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    if hasattr(schema, "model_json_schema"):
        schema = schema.model_json_schema()
    return {
        "type": "json_schema",
        "name": schema_name(metadata),
        "schema": schema,
        "strict": True,
    }


def chat_json_schema_response_format(schema: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    if hasattr(schema, "model_json_schema"):
        schema = schema.model_json_schema()
    return {
        "type": "json_schema",
        "json_schema": {
            "name": schema_name(metadata),
            "schema": schema,
            "strict": True,
        },
    }


def serialize_parsed_response(response: Any) -> str:
    parsed = _get_attr(response, "output_parsed", None)
    if parsed is None:
        choices = _get_attr(response, "choices", []) or []
        if choices:
            message = _get_attr(choices[0], "message", {}) or {}
            parsed = _get_attr(message, "parsed", None)
    if parsed is None:
        return ""
    if hasattr(parsed, "model_dump_json"):
        return parsed.model_dump_json()
    return json.dumps(to_jsonable(parsed), ensure_ascii=False)


def to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return str(value)


def extract_openai_text(response) -> str:
    output_text = _get_attr(response, "output_text", "")
    if isinstance(output_text, str) and output_text:
        return output_text

    choices = _get_attr(response, "choices", []) or []
    if choices:
        message = _get_attr(choices[0], "message", {}) or {}
        return flatten_openai_content(_get_attr(message, "content", ""))

    output = _get_attr(response, "output", []) or []
    pieces = []
    for item in output:
        content = _get_attr(item, "content", []) or []
        pieces.append(flatten_openai_content(content))
    return "\n".join(piece for piece in pieces if piece)


def extract_openai_finish_reason(response) -> str:
    choices = _get_attr(response, "choices", []) or []
    if choices:
        return str(_get_attr(choices[0], "finish_reason", "") or "")
    status = _get_attr(response, "status", "")
    return str(status or "")


def flatten_openai_content(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        pieces = []
        for item in content:
            if isinstance(item, str):
                pieces.append(item)
            else:
                text = _get_attr(item, "text", "")
                if text:
                    pieces.append(str(text))
        return "\n".join(pieces)
    return str(content or "")


def extract_openai_usage(response) -> TokenUsage:
    raw = _get_attr(response, "usage", {}) or {}
    input_details = (
        _get_attr(raw, "input_tokens_details", None)
        or _get_attr(raw, "prompt_tokens_details", None)
        or {}
    )
    output_details = (
        _get_attr(raw, "output_tokens_details", None)
        or _get_attr(raw, "completion_tokens_details", None)
        or {}
    )
    input_tokens = _safe_int(_get_attr(raw, "input_tokens")) or _safe_int(_get_attr(raw, "prompt_tokens"))
    output_tokens = _safe_int(_get_attr(raw, "output_tokens")) or _safe_int(_get_attr(raw, "completion_tokens"))
    total_tokens = _safe_int(_get_attr(raw, "total_tokens")) or input_tokens + output_tokens
    web_search_calls = _count_response_web_search_calls(response)
    return TokenUsage(
        input_tokens=input_tokens,
        cached_input_tokens=_safe_int(_get_attr(input_details, "cached_tokens")),
        output_tokens=output_tokens,
        reasoning_tokens=_safe_int(_get_attr(output_details, "reasoning_tokens")),
        total_tokens=total_tokens,
        search_queries=web_search_calls,
        provider_raw={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "input_tokens_details": _plain_mapping(input_details),
            "output_tokens_details": _plain_mapping(output_details),
            "web_search_calls": web_search_calls,
        },
    )


def _count_response_web_search_calls(response) -> int:
    output = _get_attr(response, "output", []) or []
    return sum(
        1
        for item in output
        if _get_attr(item, "type", "") in {"web_search_call", "web_search"}
    )
