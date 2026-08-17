from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    tool_tokens: int = 0
    total_tokens: int = 0
    search_queries: int = 0
    provider_raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "tool_tokens": self.tool_tokens,
            "total_tokens": self.total_tokens,
            "search_queries": self.search_queries,
            "provider_raw": self.provider_raw,
        }


@dataclass(frozen=True)
class GenerationRequest:
    prompt: str
    json_mode: bool = False
    response_schema: Any | None = None
    web_search: bool = False
    native_pdf_paths: tuple[str, ...] = ()
    generation_config: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GenerationResult:
    text: str
    provider: str
    model: str
    usage: TokenUsage = field(default_factory=TokenUsage)
    metadata: dict[str, Any] = field(default_factory=dict)


class ProviderError(RuntimeError):
    pass


class UnsupportedCapabilityError(ProviderError):
    pass


class TextProvider(Protocol):
    name: str
    model: str
    supports_web_search: bool
    supports_native_pdf: bool

    def generate(self, request: GenerationRequest) -> GenerationResult:
        ...


def handle_unsupported_capability(
    *,
    capability: str,
    policy: str,
    metadata: dict[str, Any],
) -> bool:
    if policy == "fail_fast":
        raise UnsupportedCapabilityError(f"Provider does not support {capability}")
    if policy in {"disable_and_record", "no_grounding"}:
        metadata["unsupported_capability_policy"] = policy
        metadata[f"{capability}_requested"] = True
        metadata[f"{capability}_enabled"] = False
        return False
    raise ProviderError(f"Unknown unsupported capability policy: {policy}")
