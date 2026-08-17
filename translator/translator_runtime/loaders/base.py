from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class LoadedDocument:
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class DocumentLoader(Protocol):
    def load(self) -> list[LoadedDocument]:
        ...

