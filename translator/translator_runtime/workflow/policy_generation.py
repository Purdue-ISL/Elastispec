import asyncio
from copy import deepcopy
import json
import logging
import re
from typing import List, Dict, Any, Literal
from datetime import datetime
import os
from google.genai import types
from google import genai
from pydantic import BaseModel, ConfigDict, Field, create_model

from workflow_call_config import build_workflow_call_config, get_workflow_model
from prompts import (
    build_coupled_leaves_prompt,
    build_hierarchy_correction_prompt,
    build_hierarchy_prompt,
    build_leaf_spec_prompt,
    build_optionality_prompt,
    build_policy_extraction_prompt,
)

grounding_tool = types.Tool(google_search=types.GoogleSearch())


class ExtractedFirewallPolicy(BaseModel):
    policy_id: str = Field(description="Unique stable identifier for this exact firewall policy.")
    active_condition: str = Field(description="Condition under which this policy applies.")
    source_entity: str = Field(description="Traffic source entity.")
    destination_entity: str = Field(description="Traffic destination entity.")
    port: List[str] = Field(description="Ports or port ranges used by this policy.")
    protocol: List[Literal["TCP", "UDP", "ICMP"]] = Field(
        description="Transport-layer protocol(s) only. Use only TCP, UDP, or ICMP. If both TCP and UDP are required, output ['TCP', 'UDP']."
    )


class ExtractedEntity(BaseModel):
    name: str = Field(description="Canonical entity name.")
    description: str = Field(description="Short description of the entity.")


class PolicyExtractionUpdate(BaseModel):
    policies: List[ExtractedFirewallPolicy] = Field(description="New policies extracted from this section.")
    entities: List[ExtractedEntity] = Field(description="New entities extracted from this section.")
    groups: Dict[str, List[str]] = Field(description="New or updated group memberships.")


class LeafSpecDefinition(BaseModel):
    is_optional: bool = Field(
        description="Whether this feature is optional for its parent specification.",
    )
    operands: List[str] = Field(
        description="Policy IDs or child spec names used by this specification.",
    )
    logic: str = Field(
        description="Boolean expression over operands using AND, OR, and parentheses.",
    )


class PolicyGenerator:
    TRANSPORT_PROTOCOLS = {"TCP", "UDP", "ICMP"}
    TRANSPORT_PROTOCOL_ORDER = ["TCP", "UDP", "ICMP"]

    def __init__(
        self,
        app_name: str,
        raw_docs: List[str],
        outline: Dict[str, Any],
        extracted_content: Dict[str, str],
        output_dir: str,
    ):
        self.app_name = app_name
        self.raw_docs_content = raw_docs
        self.outline = outline
        self.extracted_content = extracted_content
        self.output_dir = output_dir
        self.policy_field_normalization_records: List[Dict[str, Any]] = []
        self.policy_field_normalization_path = os.path.join(
            self.output_dir,
            "policy_field_normalization.json",
        )
        self.client = genai.Client()
        self.canonical_model = {
            "application_name": self.app_name,
            "outlines": [self.outline],
            "entities": {},
            "groups": {},
            "hierarchical_spec": {},
            "policies": []
        }

    @staticmethod
    def _response_text(response) -> str:
        return response.text.strip().removeprefix("```json").removesuffix("```").strip()

    @staticmethod
    def _normalize_port_value(value: Any) -> tuple[List[str], bool, str]:
        if isinstance(value, list):
            raw_items = value
        elif value is None:
            raw_items = []
        else:
            raw_items = [value]

        normalized: List[str] = []
        for item in raw_items:
            text = str(item or "")
            for part in re.split(r"[,;]", text):
                token = part.strip()
                if token:
                    normalized.append(token)

        old_simple = [str(item or "").strip() for item in raw_items]
        changed = old_simple != normalized
        reason = "Split comma- or semicolon-delimited port lists into separate port tokens."
        return normalized, changed, reason

    @classmethod
    def _normalize_protocol_value(cls, value: Any) -> tuple[List[str], bool, str]:
        if isinstance(value, list):
            raw_items = value
        elif value is None:
            raw_items = []
        else:
            raw_items = [value]

        normalized: set[str] = set()
        for item in raw_items:
            text = str(item or "")
            for match in re.findall(r"\b(TCP|UDP|ICMP)\b", text, flags=re.IGNORECASE):
                normalized.add(match.upper())

        ordered = [protocol for protocol in cls.TRANSPORT_PROTOCOL_ORDER if protocol in normalized]
        if ordered:
            reason = "Kept transport-layer protocol tokens and removed unsupported protocol tokens."
        elif raw_items:
            reason = "Removed unsupported protocol tokens; the normalized protocol list is empty."
        else:
            reason = "Protocol list is empty."

        old_simple = [str(item or "").strip() for item in raw_items]
        changed = old_simple != ordered
        return ordered, changed, reason

    def _normalize_policy_extraction_fields(self, updates: Dict[str, Any], section_path: str) -> Dict[str, Any]:
        normalized_updates = deepcopy(updates)
        policies = normalized_updates.get("policies", [])
        if not isinstance(policies, list):
            return normalized_updates

        for index, policy in enumerate(policies):
            if not isinstance(policy, dict):
                continue
            old_port = deepcopy(policy.get("port"))
            new_port, port_changed, port_reason = self._normalize_port_value(old_port)
            if port_changed:
                policy["port"] = new_port
                self._record_policy_field_normalization({
                    "section_path": section_path,
                    "policy_index": index,
                    "policy_id": policy.get("policy_id"),
                    "field": "port",
                    "old_value": old_port,
                    "new_value": new_port,
                    "reason": port_reason,
                })

            old_protocol = deepcopy(policy.get("protocol"))
            new_protocol, changed, reason = self._normalize_protocol_value(old_protocol)
            if not changed:
                continue
            policy["protocol"] = new_protocol
            self._record_policy_field_normalization({
                "section_path": section_path,
                "policy_index": index,
                "policy_id": policy.get("policy_id"),
                "field": "protocol",
                "old_value": old_protocol,
                "new_value": new_protocol,
                "reason": reason,
            })
        return normalized_updates

    def _record_policy_field_normalization(self, record: Dict[str, Any]) -> None:
        self.policy_field_normalization_records.append(record)
        self._write_policy_field_normalization_records()

    def _write_policy_field_normalization_records(self) -> None:
        if not self.policy_field_normalization_records:
            return
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.policy_field_normalization_path, "w") as f:
            json.dump(self.policy_field_normalization_records, f, indent=2)

    async def _generate_grounded_json(
        self,
        prompt: str,
        operation: str,
        response_schema: Any | None = None,
    ):
        model = get_workflow_model(operation)
        response = await self.client.aio.models.generate_content(
            model=model,
            contents=prompt,
            config=build_workflow_call_config(
                tools=[grounding_tool],
                json_response=True,
                response_schema=response_schema,
            ),
        )
        return response

    def _merge_policy_extraction_updates(self, updates: Dict[str, Any], section_path: str) -> None:
        for policy in updates.get("policies", []):
            policy_copy = dict(policy)
            policy_copy["source_section"] = section_path
            self.canonical_model["policies"].append(policy_copy)

        for entity in updates.get("entities", []):
            self.canonical_model["entities"][entity["name"]] = entity["description"]
        for group_name, members in updates.get("groups", {}).items():
            if group_name not in self.canonical_model["groups"]:
                self.canonical_model["groups"][group_name] = []
            for member in members:
                if member not in self.canonical_model["groups"][group_name]:
                    self.canonical_model["groups"][group_name].append(member)

    async def _populate_model_from_extracted_content(self, section_path: str, section_content: str):
        """
        New, iterative refiner that processes content for one outline section at a time.
        It now also tags each policy with its source section.
        """
        prompt = build_policy_extraction_prompt(self.canonical_model, section_path, section_content)
        try:
            response = await self._generate_grounded_json(
                prompt,
                operation="extract_policies",
                response_schema=PolicyExtractionUpdate,
            )
            response_text = self._response_text(response)
            raw_updates = json.loads(response_text)
            normalized_updates = self._normalize_policy_extraction_fields(raw_updates, section_path)
            updates = PolicyExtractionUpdate.model_validate(normalized_updates).model_dump()
            self._merge_policy_extraction_updates(updates, section_path)

        except Exception as e:
            logging.error(f"Error refining policy from section '{section_path}': {e}")

    def _find_leaf_nodes(self, outline_node: Dict[str, Any], current_path: str) -> List[str]:
        """
        Helper function to recursively find all leaf nodes in the outline.
        A leaf is a section with no further nested subsections.
        """
        leaf_nodes = []
        for section, subsections in outline_node.items():
            new_path = f"{current_path} -> {section}" if current_path else section
            if not isinstance(subsections, dict) or not subsections:
                leaf_nodes.append(new_path)
            else:
                leaf_nodes.extend(self._find_leaf_nodes(subsections, new_path))
        return leaf_nodes

    async def _generate_leaf_specs(self, leaf_node_paths: List[str]) -> tuple[Dict[str, Any], Dict[str, str]]:
        """
        Phase 3a: Iteratively generates specifications for each leaf node in the outline.
        It also now returns a mapping from the full path to the generated spec name.
        """
        leaf_specs = {}
        path_to_spec_name_map = {}
        all_policies = self.canonical_model.get("policies", [])

        for path in leaf_node_paths:
            # Filter policies where the leaf's path starts with the policy's source section.
            # This correctly associates policies from parent sections with their relevant leaf nodes.
            relevant_policies = [p for p in all_policies if path.startswith(p.get("source_section", ""))]
            if not relevant_policies:
                continue

            spec_name = path.replace(" -> ", "_").replace(" ", "").replace("/", "_").replace("-", "_").replace("(",
                                                                                                               "").replace(
                ")", "") + "Spec"

            # Get content for the leaf and its parent to provide richer context
            leaf_content = self.extracted_content.get(path, "")
            parent_path_parts = path.split(" -> ")[:-1]
            parent_path = " -> ".join(parent_path_parts)
            parent_content = self.extracted_content.get(parent_path, "")

            prompt = build_leaf_spec_prompt(parent_content, leaf_content, relevant_policies, spec_name)
            try:
                response = await self._generate_grounded_json(
                    prompt,
                    operation="generate_leaf_specs",
                    response_schema=LeafSpecDefinition,
                )
                response_text = self._response_text(response)
                spec_definition = LeafSpecDefinition.model_validate_json(response_text).model_dump()
                leaf_specs[spec_name] = spec_definition
                path_to_spec_name_map[path] = spec_name
                logging.info(f"Successfully generated spec for leaf node: {path}")

            except Exception as e:
                logging.error(f"Error generating spec for leaf node {path}: {e}")

        return leaf_specs, path_to_spec_name_map

    async def _reconcile_coupled_leaves(self, leaf_specs: Dict[str, Any], path_to_spec_name_map: Dict[str, str]) -> \
    tuple[Dict[str, Any], Dict[str, str]]:
        """
        Phase 3.5: An agent that identifies and refactors "coupled" leaf specs.
        This agent looks for situations where multiple leaf features share a common,
        conditional dependency (e.g., choosing one of several SDKs) and refactors
        them to ensure the choice is consistent across all affected features.
        It returns the reconciled specs and the updated path-to-spec-name map.
        """
        spec_name_to_path_map = {v: k for k, v in path_to_spec_name_map.items()}
        prompt = build_coupled_leaves_prompt(
            self.outline,
            self.canonical_model["policies"],
            leaf_specs,
            spec_name_to_path_map,
        )
        try:
            response = await self._generate_grounded_json(
                prompt,
                operation="reconcile_coupled_leaves",
            )
            response_text = response.text.strip().removeprefix("```json").removesuffix("```").strip()
            reconciliation_plan = json.loads(response_text)

            new_specs = reconciliation_plan.get("newly_created_specs", {})
            specs_to_remove = reconciliation_plan.get("specs_to_remove", [])
            path_updates = reconciliation_plan.get("path_updates", {})

            if not new_specs and not specs_to_remove:
                logging.info("System Coherence Analyst found no coupled leaves to reconcile.")
                return leaf_specs, path_to_spec_name_map

            logging.info(
                f"System Coherence Analyst is reconciling specs. Removing: {specs_to_remove}, Adding: {list(new_specs.keys())}")

            # Create the new set of reconciled specs
            reconciled_specs = {name: spec for name, spec in leaf_specs.items() if name not in specs_to_remove}
            reconciled_specs.update(new_specs)

            # Create the new, updated path map
            updated_path_map = path_to_spec_name_map.copy()
            for path, new_spec_name in path_updates.items():
                if path in updated_path_map:
                    logging.info(
                        f"Updating path map: '{path}' now points to '{new_spec_name}' (was '{updated_path_map[path]}')")
                    updated_path_map[path] = new_spec_name
                else:
                    logging.warning(
                        f"Path '{path}' from reconciliation plan not found in original path map; it will be ignored.")

            # Final validation to prevent dangling references
            final_path_map = {}
            for path, spec_name in updated_path_map.items():
                if spec_name in reconciled_specs:
                    final_path_map[path] = spec_name
                else:
                    logging.warning(
                        f"Dangling reference removed: Path '{path}' pointed to spec '{spec_name}' which was removed or replaced but not updated in path_updates.")

            return reconciled_specs, final_path_map
        except Exception as e:
            logging.error(f"Error during leaf spec reconciliation: {e}")
            return leaf_specs, path_to_spec_name_map  # Return original specs and map on error

    def _inject_leaf_specs_into_outline(self, outline_node: Dict[str, Any], current_path: str,
                                        path_map: Dict[str, str]) -> Dict[str, Any]:
        """
        Recursively walks the outline and injects the corresponding leaf spec name
        at each leaf node using the provided path map.
        """
        annotated_node = {}
        for section, subsections in outline_node.items():
            new_path = f"{current_path} -> {section}" if current_path else section
            is_leaf = not isinstance(subsections, dict) or not subsections

            if is_leaf:
                annotated_node[section] = path_map.get(new_path)  # Inject the name from the map
            else:
                annotated_node[section] = self._inject_leaf_specs_into_outline(subsections, new_path, path_map)

        return annotated_node

    def _reconcile_hierarchy(self, architect_spec: Dict[str, Any], leaf_specs: Dict[str, Any], path_map: Dict[str, str],
                             outline_node: Dict[str, Any], current_path: str) -> Dict[str, Any]:
        """
        Deterministically walks the architect's hierarchy and the outline, replacing any
        incorrectly generated leaf placeholders with the actual, pre-generated leaf specs.
        """
        reconciled_spec = {}
        for spec_name, spec_data in architect_spec.items():
            reconciled_spec[spec_name] = spec_data  # Start with the architect's version

            # Find the corresponding path in the outline for the current spec name
            # This is a simple heuristic; a more robust solution might be needed for complex outlines
            matching_section = next(
                (s for s in outline_node if spec_name.startswith("".join(c for c in s if c.isalnum()))), None)

            if matching_section:
                new_path = f"{current_path} -> {matching_section}" if current_path else matching_section

                # If this node in the outline is a leaf, ensure the spec is a proper leaf spec
                if new_path in path_map:
                    correct_leaf_name = path_map[new_path]
                    if correct_leaf_name in leaf_specs:
                        # Replace the architect's version with the correct, pre-generated one
                        reconciled_spec[spec_name] = leaf_specs[correct_leaf_name]

                # If it's a branch, recurse
                elif "operands" in spec_data and isinstance(outline_node.get(matching_section), dict):
                    child_outline = outline_node[matching_section]
                    child_specs = {op: architect_spec.get(op, {}) for op in spec_data["operands"] if
                                   op in architect_spec}
                    reconciled_spec[spec_name]["operands_data"] = self._reconcile_hierarchy(child_specs, leaf_specs,
                                                                                            path_map, child_outline,
                                                                                            new_path)

        return reconciled_spec

    async def _assemble_hierarchy(self, leaf_specs: Dict[str, Any], path_map: Dict[str, str]) -> Dict[str, Any]:
        """
        Phase 3b: Assembles the high-level hierarchy using a pre-annotated outline.
        """
        # Pre-process the outline to inject leaf spec names directly into the structure
        annotated_outline = self._inject_leaf_specs_into_outline(self.outline, "", path_map)

        prompt = build_hierarchy_prompt(annotated_outline)
        try:
            response = await self._generate_grounded_json(
                prompt,
                operation="assemble_hierarchy",
            )
            response_text = self._response_text(response)
            higher_level_specs = json.loads(response_text)

        except json.JSONDecodeError as e:
            logging.warning(f"Initial JSON parsing failed for hierarchy: {e}. Attempting to self-correct.")
            correction_prompt = build_hierarchy_correction_prompt(response_text)
            try:
                correction_response = await self._generate_grounded_json(
                    correction_prompt,
                    operation="correct_hierarchy_json",
                )
                corrected_text = correction_response.text.strip().removeprefix("```json").removesuffix("```").strip()
                higher_level_specs = json.loads(corrected_text)
                logging.info("Successfully parsed self-corrected JSON for hierarchy.")
            except Exception as final_e:
                logging.error(f"Failed to parse even the corrected JSON for hierarchy: {final_e}")
                return {}  # Return empty if correction also fails

        except Exception as e:
            logging.error(f"An unexpected error occurred during hierarchy assembly: {e}")
            return {}

        # Deterministically merge the high-level structure with the low-level leaf specs
        final_spec = {**higher_level_specs, **leaf_specs}
        self.canonical_model["hierarchical_spec"] = final_spec
        logging.info("Successfully assembled final hierarchical specification.")
        return final_spec

    async def _determine_optionality(self, full_spec: Dict[str, Any]) -> Dict[str, bool]:
        """
        Phase 3c: The "Optionality Agent". This agent inspects the complete hierarchy and
        determines the optionality of every single specification.
        """
        prompt = build_optionality_prompt(self.raw_docs_content[0], full_spec)
        optionality_schema = create_model(
            "OptionalityMap",
            __config__=ConfigDict(extra="forbid"),
            **{
                f"spec_{index}": (bool, Field(alias=spec_name))
                for index, spec_name in enumerate(full_spec)
            },
        )
        try:
            response = await self._generate_grounded_json(
                prompt,
                operation="determine_optionality",
                response_schema=optionality_schema,
            )
            response_text = self._response_text(response)
            optionality_map = optionality_schema.model_validate_json(response_text).model_dump(by_alias=True)
            logging.info("Successfully determined optionality for all specs.")
            return optionality_map
        except Exception as e:
            logging.error(f"Error determining optionality: {e}")
            return {}

    async def generate(self) -> Dict[str, Any]:
        """
        Runs the full, iterative pipeline to generate the application signature,
        with caching for intermediate results.
        """
        canonical_model_path = os.path.join(self.output_dir, "canonical_model.json")
        hierarchy_path = os.path.join(self.output_dir, "app_signatures_hierarchy.json")

        def _unwrap_data(data, key):
            """Repeatedly unwraps a dictionary if it's nested under the same key."""
            while isinstance(data, dict) and len(data) == 1 and key in data:
                data = data[key]
            return data

        # If the final hierarchy file exists, load it and proceed only to the optionality step.
        if os.path.exists(hierarchy_path):
            logging.info(f"--- PolicyGenerator: Loading existing hierarchy from {hierarchy_path} ---")
            with open(hierarchy_path, "r") as f:
                loaded_hierarchy = json.load(f)
                assembled_spec = _unwrap_data(loaded_hierarchy, self.app_name)

            # Also load the canonical model, as it's needed for context and the final return value.
            if os.path.exists(canonical_model_path):
                logging.info(f"--- PolicyGenerator: Loading existing canonical model from {canonical_model_path} ---")
                with open(canonical_model_path, "r") as f:
                    loaded_model = json.load(f)
                    self.canonical_model = _unwrap_data(loaded_model, self.app_name)
            else:
                logging.warning(f"Hierarchy file found, but canonical model at {canonical_model_path} is missing. "
                                f"Final output may be incomplete.")

            self.canonical_model["hierarchical_spec"] = assembled_spec

        else:
            # Hierarchy does not exist. Check if we can skip the policy extraction phase.
            if os.path.exists(canonical_model_path):
                logging.info(f"--- PolicyGenerator: Loading existing policies from {canonical_model_path} ---")
                with open(canonical_model_path, "r") as f:
                    loaded_model = json.load(f)
                    self.canonical_model = _unwrap_data(loaded_model, self.app_name)
            else:
                # Phase 1 & 2: Iterate through all content to extract a flat list of policies
                logging.info("--- PolicyGenerator: Starting Phase 1 & 2: Policy Extraction ---")
                for section_path, section_content in self.extracted_content.items():
                    logging.info(f"Processing section for policy extraction: {section_path}")
                    await self._populate_model_from_extracted_content(section_path, section_content)

                # Log and deduplicate policies
                logging.info(f"Extracted a total of {len(self.canonical_model['policies'])} policies.")
                seen_policies = {}
                unique_policies = []
                for policy in self.canonical_model["policies"]:
                    policy_id = policy.get('policy_id')
                    if policy_id and policy_id not in seen_policies:
                        seen_policies[policy_id] = True
                        unique_policies.append(policy)
                self.canonical_model["policies"] = unique_policies
                logging.info(f"Deduplicated to {len(unique_policies)} unique policies.")

                with open(canonical_model_path, "w") as f:
                    json.dump(self.canonical_model, f, indent=2)
                logging.info(f"--- PolicyGenerator: Saved canonical model to {canonical_model_path} ---")

            # Phase 3a: Generate specs for leaf nodes iteratively
            logging.info("--- PolicyGenerator: Starting Phase 3a: Leaf Spec Generation ---")
            leaf_node_paths = self._find_leaf_nodes(self.outline, "")
            logging.info(f"Found {len(leaf_node_paths)} leaf nodes to process for spec generation.")
            leaf_specs, path_to_spec_name_map = await self._generate_leaf_specs(leaf_node_paths)

            # # Phase 3.5: Reconcile coupled leaf specifications
            # logging.info("--- PolicyGenerator: Starting Phase 3.5: Reconciling coupled leaf specs ---")
            # reconciled_leaf_specs, path_to_spec_name_map = await self._reconcile_coupled_leaves(leaf_specs,
            #                                                                                    path_to_spec_name_map)

            # Phase 3b: Assemble the final hierarchy using the leaf specs and the path map
            logging.info("--- PolicyGenerator: Starting Phase 3b: Assembling Hierarchy ---")
            assembled_spec = await self._assemble_hierarchy(leaf_specs, path_to_spec_name_map)

            if not assembled_spec:
                logging.error("Hierarchy assembly failed. Aborting.")
                return self.canonical_model

            # Save the new hierarchy for next time.
            with open(hierarchy_path, "w") as f:
                json.dump(assembled_spec, f, indent=2)
            logging.info(f"--- PolicyGenerator: Saved hierarchy to {hierarchy_path} ---")


        # Phase 3d: Determine optionality for all specs in the complete hierarchy
        logging.info("--- PolicyGenerator: Starting Phase 3d: Determining Optionality ---")
        optionality_flags = await self._determine_optionality(assembled_spec)

        # Final Step: Integrate the optionality flags into the final spec
        for spec_name, spec_data in assembled_spec.items():
            if spec_name in optionality_flags:
                spec_data["is_optional"] = optionality_flags[spec_name]

        self.canonical_model["hierarchical_spec"] = assembled_spec
        logging.info("Final hierarchy with optionality flags is complete.")

        return self.canonical_model
