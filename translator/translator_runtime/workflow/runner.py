from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from document_processing import DocumentProcessor
from policy_generation import PolicyGenerator
from SignatureToFSL import FSLGenerator


class TranslatorWorkflowRunner:
    """
    Runs the fixed translator workflow after documents have been loaded by the
    artifact adapter layer.
    """

    def __init__(
        self,
        app_name: str,
        raw_docs: list[str],
        output_dir: str | Path,
        intermediate_dir: str | Path | None = None,
    ):
        self.app_name = app_name
        self.raw_docs = raw_docs
        self.output_dir = Path(output_dir)
        self.intermediate_dir = Path(intermediate_dir) if intermediate_dir is not None else self.output_dir / "tmp"

    async def run(self) -> dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.intermediate_dir.mkdir(parents=True, exist_ok=True)

        doc_processor = DocumentProcessor(self.app_name, self.raw_docs, output_dir=str(self.intermediate_dir))
        outline, extracted_content, _ = doc_processor.process()
        if not outline or not extracted_content:
            raise RuntimeError("Document processing did not produce outline and extracted content.")

        policy_generator = PolicyGenerator(
            self.app_name,
            self.raw_docs,
            outline,
            extracted_content,
            output_dir=str(self.intermediate_dir),
        )
        final_model = await policy_generator.generate()

        intermediate_paths = self._write_intermediate_signature_files(final_model)
        final_fsl_path = self._write_fsl(
            intermediate_paths["hierarchy_path"],
            intermediate_paths["app_signatures_path"],
        )
        return {
            "final_model": final_model,
            "final_output_paths": {
                "generated_policy_path": str(final_fsl_path),
            },
            "intermediate_paths": {key: str(value) for key, value in intermediate_paths.items()},
        }

    def _write_intermediate_signature_files(self, final_model: dict[str, Any]) -> dict[str, Path]:
        model_copy = final_model.copy()
        hierarchy = model_copy.pop("hierarchical_spec", {})

        outline_path = self.intermediate_dir / "outline.json"
        extracted_content_path = self.intermediate_dir / "extracted_content.json"
        app_signatures_path = self.intermediate_dir / "app_signatures.json"
        hierarchy_path = self.intermediate_dir / "app_signatures_hierarchy.json"
        canonical_model_path = self.intermediate_dir / "canonical_model.json"

        app_signatures_path.write_text(
            json.dumps(
                [
                    {
                        "application": self.app_name,
                        "status": "parsed",
                        "policies": final_model.get("policies", []),
                    }
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        hierarchy_path.write_text(json.dumps({self.app_name: hierarchy}, indent=2), encoding="utf-8")
        canonical_model_path.write_text(json.dumps({self.app_name: model_copy}, indent=2), encoding="utf-8")

        return {
            "outline_path": outline_path,
            "extracted_content_path": extracted_content_path,
            "app_signatures_path": app_signatures_path,
            "hierarchy_path": hierarchy_path,
            "canonical_model_path": canonical_model_path,
        }

    def _write_fsl(self, hierarchy_path: Path, app_signatures_path: Path) -> Path:
        generated_policy_path = self.output_dir / "generated_policy.fsl"
        fsl_generator = FSLGenerator(
            hierarchy_path=str(hierarchy_path),
            policies_path=str(app_signatures_path),
        )
        fsl_generator.generate_fsl(str(generated_policy_path))
        return generated_policy_path
