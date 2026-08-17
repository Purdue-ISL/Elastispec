from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GeminiNativePdfDocument:
    path: str


class GeminiNativePdfLoader:
    requires_provider = "gemini"

    def __init__(self, *, local_paths: list[str]) -> None:
        if (
            not isinstance(local_paths, list)
            or not local_paths
            or any(
                not isinstance(raw_path, str) or not raw_path.strip()
                for raw_path in local_paths
            )
        ):
            raise ValueError(
                "loader.kind=gemini_native_pdf requires loader.local_paths with "
                "at least one non-empty PDF path"
            )
        self.local_paths = list(local_paths)

    def load(self) -> list[GeminiNativePdfDocument]:
        documents = []
        for raw_path in self.local_paths:
            path = Path(raw_path).expanduser().resolve()
            if not path.is_file():
                raise ValueError(f"Native PDF file not found: {path}")
            if path.suffix.casefold() != ".pdf":
                raise ValueError(f"gemini_native_pdf accepts only .pdf files: {path}")
            documents.append(GeminiNativePdfDocument(path=str(path)))
        return documents
