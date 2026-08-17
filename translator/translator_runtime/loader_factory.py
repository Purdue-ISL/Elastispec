from __future__ import annotations

from typing import Any

from .loaders.gemini_native_pdf_loader import GeminiNativePdfLoader
from .loaders.inline_loader import InlineTextLoader
from .loaders.langchain_loader import LangChainLoaderAdapter


def _langchain_sources(value: Any) -> list[str]:
    if isinstance(value, str):
        sources = [value]
    elif isinstance(value, (list, tuple)):
        sources = list(value)
    else:
        raise ValueError("loader.sources must be a string or a list of strings")

    invalid_source = any(
        not isinstance(source, str) or not source.strip() for source in sources
    )
    if not sources or invalid_source:
        raise ValueError("loader.kind=langchain requires at least one non-empty source")
    return sources


def build_loader(config: dict[str, Any]):
    loader_config = config.get("loader", {}) or {}
    kind = loader_config.get("kind")
    if kind == "inline_text":
        return InlineTextLoader(documents=list(loader_config.get("documents", [])))
    if kind == "langchain" and not loader_config.get("class_path"):
        kwargs = dict(loader_config.get("kwargs", {}) or {})
        if "file_path" in kwargs:
            raise ValueError(
                "the default LangChain loader uses loader.sources; "
                "remove kwargs.file_path"
            )
        kwargs["file_path"] = _langchain_sources(loader_config.get("sources", []))
        kwargs.setdefault("export_type", "markdown")
        return LangChainLoaderAdapter(
            class_path="langchain_docling.DoclingLoader",
            kwargs=kwargs,
            method=loader_config.get("method", "load"),
        )
    if kind == "langchain":
        return LangChainLoaderAdapter(
            class_path=loader_config.get("class_path", ""),
            args=list(loader_config.get("args", []) or []),
            kwargs=dict(loader_config.get("kwargs", {}) or {}),
            method=loader_config.get("method", "load"),
        )
    if kind == "gemini_native_pdf":
        return GeminiNativePdfLoader(local_paths=loader_config.get("local_paths", []))
    raise ValueError(f"Unsupported loader.kind: {kind}")
