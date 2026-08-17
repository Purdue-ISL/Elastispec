from __future__ import annotations

from .base import LoadedDocument


class InlineTextLoader:
    def __init__(self, *, documents: list[str]) -> None:
        self.documents = documents

    def load(self) -> list[LoadedDocument]:
        return [
            LoadedDocument(
                content=document,
                metadata={"source": "inline_text", "index": index},
            )
            for index, document in enumerate(self.documents)
        ]

