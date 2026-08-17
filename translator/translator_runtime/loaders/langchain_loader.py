from __future__ import annotations

import importlib
from typing import Any

from .base import LoadedDocument


def import_object(class_path: str):
    module_name, _, object_name = class_path.rpartition(".")
    if not module_name or not object_name:
        raise ValueError(f"Expected a full import path, got: {class_path}")
    module = importlib.import_module(module_name)
    return getattr(module, object_name)


class LangChainLoaderAdapter:
    def __init__(
        self,
        *,
        class_path: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        method: str = "load",
    ) -> None:
        self.class_path = class_path
        self.args = list(args or [])
        self.kwargs = kwargs or {}
        self.method = method

    def load(self) -> list[LoadedDocument]:
        loader_class = import_object(self.class_path)
        loader = loader_class(*self.args, **self.kwargs)
        load_method = getattr(loader, self.method)
        docs = list(load_method())
        return [
            LoadedDocument(
                content=getattr(doc, "page_content", str(doc)),
                metadata=dict(getattr(doc, "metadata", {}) or {}),
            )
            for doc in docs
        ]
