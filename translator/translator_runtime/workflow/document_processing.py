import json
import logging
import os
from typing import List, Dict, Any, Tuple

os.environ.setdefault("USER_AGENT", "artifact-translator/1.0")

from google import genai

from workflow_call_config import build_workflow_call_config, get_workflow_model
from prompts import build_outline_prompt, build_section_content_prompt


class OutlineGenerator:
    def __init__(self, raw_docs: List[str]):
        self.raw_docs_content = raw_docs
        self.client = genai.Client()

    def generate_structured_outline(self) -> Dict[str, Any]:
        """
        Generates a structured, hierarchical outline from the raw document content.
        """
        document_content = "\n\n".join(self.raw_docs_content) if self.raw_docs_content else ""
        if not document_content:
            return {}

        prompt = build_outline_prompt(document_content)
        try:
            model = get_workflow_model("generate_outline")
            response = self.client.models.generate_content(
                model=model,
                contents=prompt,
                config=build_workflow_call_config(
                    json_response=True,
                    response_modalities=["TEXT"],
                )
            )
            response_text_array = [each.text for each in response.candidates[0].content.parts]
            response_text = "".join(response_text_array).strip().removeprefix("```json").removesuffix("```").strip()
            outline = json.loads(response_text)
            logging.info("Successfully generated structured outline.")
            return outline
        except Exception as e:
            logging.error(f"Error generating document outline: {e}")
            return {}


class ContentRetriever:
    """
    Retrieves content for each section of a document outline by querying a generative model.
    """

    def __init__(self, raw_docs: List[str], outline: Dict[str, Any]):
        self.raw_docs_content = raw_docs
        self.outline = outline
        self.extracted_content = {}
        self.client = genai.Client()

    def extract_content_for_node(self, node_path: str) -> str:
        """
        Queries the generative model to extract content for a specific outline node.
        """
        document_content = "\n\n".join(self.raw_docs_content) if self.raw_docs_content else ""
        if not document_content:
            return "No document content provided."

        prompt = build_section_content_prompt(document_content, self.outline, node_path)
        try:
            model = get_workflow_model("extract_section_content")
            response = self.client.models.generate_content(
                model=model,
                contents=prompt,
                config=build_workflow_call_config(
                    response_modalities=["TEXT"],
                )
            )
            response_text_array = [each.text for each in response.candidates[0].content.parts]
            return "".join(response_text_array).strip()
        except Exception as e:
            logging.error(f"Error extracting content for '{node_path}': {e}")
            return f"Error extracting content: {e}"

    def _traverse_and_extract(self, outline_node: Dict[str, Any], current_path: List[str]):
        """
        Recursively traverses the outline and extracts content for each node.
        """
        for section, subsections in outline_node.items():
            new_path = current_path + [section]
            path_str = " -> ".join(new_path)
            logging.info(f"Extracting content for: {path_str}")

            content = self.extract_content_for_node(path_str)
            self.extracted_content[path_str] = content

            if isinstance(subsections, dict):
                self._traverse_and_extract(subsections, new_path)

    def run(self) -> Dict[str, Any]:
        """
        Executes the content extraction process and returns the results.
        """
        self._traverse_and_extract(self.outline, [])
        return self.extracted_content


class ContentPruner:
    """
    Cleans extracted content by removing subsection text from parent sections, ensuring
    each section's content is exclusive.
    """
    def __init__(self, outline: Dict[str, Any], extracted_content: Dict[str, str]):
        self.outline = outline
        self.extracted_content = extracted_content
        # Start with a copy that we will modify
        self.pruned_content = extracted_content.copy()

    def _traverse_and_prune(self, outline_node: Dict[str, Any], current_path: List[str]):
        """
        Recursively traverses the outline using a post-order traversal. For each parent node,
        it subtracts the (already pruned) content of its direct children.
        """
        for section, subsections in outline_node.items():
            new_path = current_path + [section]
            parent_path_str = " -> ".join(new_path)

            if isinstance(subsections, dict):
                # Step 1: Recurse to the children first (post-order traversal)
                self._traverse_and_prune(subsections, new_path)

                # Step 2: Now that children are pruned, prune the current parent node
                if parent_path_str in self.pruned_content:
                    parent_content = self.pruned_content[parent_path_str]
                    for subsection_name in subsections:
                        child_path_str = " -> ".join(new_path + [subsection_name])
                        if child_path_str in self.pruned_content:
                            child_content = self.pruned_content[child_path_str]
                            if child_content:
                                # This simple string replacement is the core of the pruning
                                parent_content = parent_content.replace(child_content, "")
                    
                    # Clean up whitespace and newlines that might be left after replacement
                    cleaned_parent_content = "\n".join(
                        line for line in parent_content.strip().splitlines() if line.strip()
                    )
                    self.pruned_content[parent_path_str] = cleaned_parent_content

    def run(self) -> Dict[str, str]:
        """
        Executes the pruning process and returns the cleaned content.
        """
        logging.info("Starting content pruning process.")
        self._traverse_and_prune(self.outline, [])
        logging.info("Finished content pruning process.")
        return self.pruned_content


class DocumentProcessor:
    """
    Encapsulates the end-to-end process of document retrieval, outlining,
    content extraction, and pruning.
    """
    def __init__(self, app_name: str, raw_docs: List[str], output_dir: str = "."):
        self.app_name = app_name
        self.raw_docs = raw_docs
        self.outline: Dict[str, Any] = {}
        self.extracted_content: Dict[str, str] = {}
        self.pruned_content: Dict[str, str] = {}
        self.output_dir = output_dir


    def process(self) -> Tuple[Dict[str, Any], Dict[str, str], List[str]]:
        """
        Runs the full document processing pipeline: outline generation, content extraction, and pruning.
        Returns the outline, pruned content, and the raw docs.
        """
        if not self.raw_docs:
            logging.error(f"No documents were provided for {self.app_name}. Aborting.")
            return {}, {}, []

        os.makedirs(self.output_dir, exist_ok=True)
        outline_path = os.path.join(self.output_dir, "outline.json")

        # Step 1: Generate or load the outline
        if os.path.exists(outline_path):
            logging.info(f"--- DocumentProcessor: Loading existing outline from {outline_path} ---")
            with open(outline_path, "r") as f:
                self.outline = json.load(f)
        else:
            logging.info("--- DocumentProcessor: Generating Outline ---")
            outline_generator = OutlineGenerator(self.raw_docs)
            self.outline = outline_generator.generate_structured_outline()
            if self.outline:
                with open(outline_path, "w") as f:
                    json.dump(self.outline, f, indent=2)
                logging.info(f"--- DocumentProcessor: Outline saved to {outline_path} ---")

        if not self.outline:
            logging.error("Failed to generate or load a document outline. Aborting.")
            return {}, {}, self.raw_docs

        # Step 2: Extract and prune content
        content_path = os.path.join(self.output_dir, "extracted_content.json")
        if os.path.exists(content_path):
            logging.info(f"--- DocumentProcessor: Loading existing content from {content_path} ---")
            with open(content_path, "r") as f:
                self.pruned_content = json.load(f)
        else:
            logging.info("--- DocumentProcessor: Extracting Content ---")
            content_retriever = ContentRetriever(self.raw_docs, self.outline)
            self.extracted_content = content_retriever.run()

            logging.info("--- DocumentProcessor: Pruning Content ---")
            content_pruner = ContentPruner(self.outline, self.extracted_content)
            self.pruned_content = content_pruner.run()

            if self.pruned_content:
                with open(content_path, "w") as f:
                    json.dump(self.pruned_content, f, indent=2)
                logging.info(f"--- DocumentProcessor: Pruned content saved to {content_path} ---")

        return self.outline, self.pruned_content, self.raw_docs
