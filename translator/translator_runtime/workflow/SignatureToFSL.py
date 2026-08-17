import json
import re
from typing import Dict, Any, List
import logging

class FSLGenerator:
    """
    Translates the hierarchical JSON specification into a human-readable
    Formal Specification Language (FSL) file.
    """
    ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp"}

    def __init__(self, hierarchy_path: str, policies_path: str):
        with open(hierarchy_path, 'r') as f:
            full_hierarchy = json.load(f)
            if not full_hierarchy:
                raise ValueError(f"Hierarchy file at {hierarchy_path} is empty.")
            self.app_name = list(full_hierarchy.keys())[0]
            self.hierarchy = full_hierarchy[self.app_name]
        
        with open(policies_path, 'r') as f:
            # The JSON file is a list containing one object for the app.
            full_policies = json.load(f)
            self.policies = full_policies[0]['policies']

        self.policy_map = {p['policy_id']: p for p in self.policies}
        self.defined_specs = set()
        self.spec_name_map = {long_name: self._clean_spec_name(long_name) for long_name in self.hierarchy.keys()}

    def _clean_spec_name(self, long_spec_name: str) -> str:
        """Generates a clean, short spec name from the unique, long name."""
        # Replace non-alphanumeric characters with underscores.
        cleaned = re.sub(r'[^a-zA-Z0-9]+', '_', long_spec_name)
        # Remove leading/trailing underscores.
        cleaned = cleaned.strip('_')
        # Replace multiple underscores with a single one.
        cleaned = re.sub(r'_+', '_', cleaned)
        if not cleaned.endswith("Spec"):
            cleaned += "Spec"
        return cleaned

    def _clean_entity_name(self, entity_name: str) -> str:
        """Cleans an entity name by replacing special characters and spaces with underscores."""
        if entity_name == '*':
            return '*'
        cleaned = re.sub(r'[^a-zA-Z0-9]+', '_', entity_name)
        cleaned = cleaned.strip('_')
        cleaned = re.sub(r'_+', '_', cleaned)
        return cleaned

    def _simplify_logic_string(self, logic: str) -> str:
        """Simplifies redundant parentheses from a logic string."""
        # Rule 1: Collapse nested parentheses like (((...))) into (...)
        while re.search(r'\(\s*\(([^()]+)\)\s*\)', logic):
             logic = re.sub(r'\(\s*\(([^()]+)\)\s*\)', r'(\1)', logic)

        # Rule 2: Remove parentheses around a single, standalone policy definition
        # A policy definition is identified by the '->' arrow.
        logic = re.sub(r'\(\s*(\(\(.*\)\s*->\s*\(.*\))\s*\)', r'\1', logic)

        # Rule 3: Normalize whitespace for cleanliness
        logic = re.sub(r'\s+', ' ', logic).strip()
        
        return logic

    def _format_policy(self, policy: Dict[str, Any]) -> str:
        """Formats a single policy dictionary into an FSL string."""
        source = self._clean_entity_name(policy.get('source_entity', '*'))
        dest = self._clean_entity_name(policy.get('destination_entity', '*'))
        port = ", ".join(policy.get('port', [])) or '*'
        protocols = [p.lower() for p in policy.get('protocol', [])]
        invalid_protocols = [p for p in protocols if p not in self.ALLOWED_PROTOCOLS]
        if not protocols or invalid_protocols:
            raise ValueError(
                f"Policy '{policy.get('policy_id', '<unknown>')}' has invalid protocols: "
                f"{policy.get('protocol', [])}. Allowed values are TCP, UDP, or ICMP."
            )
        proto = ", ".join(protocols)
        return f"(({source}, *) -> ({dest}, {port}) on {proto})"

    def _generate_spec_definition(self, spec_name: str) -> str:
        """
        Recursively generates the FSL definition string for a given spec.
        Uses post-order traversal to define children before parents.
        """
        if spec_name in self.defined_specs:
            return "" # Avoid re-defining a spec that's already been processed

        spec_info = self.hierarchy.get(spec_name)
        if not spec_info:
            return f"# WARNING: Spec '{spec_name}' not found in hierarchy.\n"

        # Step 1: Recurse to define all child operands first
        child_definitions = []
        for operand in spec_info.get("operands", []):
            if operand in self.hierarchy: # It's another spec
                child_definitions.append(self._generate_spec_definition(operand))

        # Step 2: Now, build the definition for the current spec, using the clean name
        clean_spec_name = self.spec_name_map.get(spec_name, spec_name)
        fsl_string = f"def {clean_spec_name} as\n"
        logic = spec_info.get("logic", " AND ".join(spec_info.get("operands", [])))

        # Replace both policy_ids and long spec names in the logic string with their final representations
        for operand in spec_info.get("operands", []):
            if operand in self.policy_map:
                formatted_policy = self._format_policy(self.policy_map[operand])
                logic = re.sub(r'\b' + re.escape(operand) + r'\b', formatted_policy, logic)
            elif operand in self.spec_name_map:
                clean_operand_name = self.spec_name_map[operand]
                # If the operand spec itself is optional, append a '?' when it's used.
                is_operand_optional = self.hierarchy.get(operand, {}).get("is_optional", False)
                replacement = f"{clean_operand_name}?" if is_operand_optional else clean_operand_name
                logic = re.sub(r'\b' + re.escape(operand) + r'\b', replacement, logic)

        # Simplify the final logic string before adding it to the FSL
        logic = self._simplify_logic_string(logic)

        # Optionality is now handled where the spec is used (as an operand).
        # The definition itself is no longer marked as optional.
        fsl_string += f"    {logic}"
        
        fsl_string += "\n"
        
        self.defined_specs.add(spec_name)
        
        # Combine child definitions with the current spec's definition
        return "".join(child_definitions) + "\n" + fsl_string

    def generate_fsl(self, output_path: str):
        """
        Generates the complete FSL file and saves it to the specified path.
        """
        # Find the root spec (the one not listed as an operand in any other spec)
        all_operands = set()
        all_spec_names = set(self.hierarchy.keys())
        for spec_info in self.hierarchy.values():
            for op in spec_info.get("operands", []):
                if op in all_spec_names:
                    all_operands.add(op)
        
        root_specs = list(all_spec_names - all_operands)

        if root_specs:
            # If there are multiple potential roots, the one containing the app name is likely the main one.
            app_roots = [r for r in root_specs if self.app_name in r]
            if app_roots:
                # Pick the shortest among those that match the app name, as it's likely the top-level one.
                root_spec_name = min(app_roots, key=len)
            else:
                # If no root contains the app name, just pick the shortest overall root.
                root_spec_name = min(root_specs, key=len)
        else:
            # Fallback if no clear root is found (e.g., a circular dependency or unusual structure)
            fallback_roots = [name for name in self.hierarchy.keys() if "FirewallSpec" in name]
            if not fallback_roots:
                raise ValueError("Could not determine the root spec of the hierarchy. No clear root found.")
            root_spec_name = fallback_roots[0]

        logging.info(f"Determined root spec to be: {root_spec_name}")

        # Generate all definitions by starting from the root
        full_fsl_content = self._generate_spec_definition(root_spec_name)

        with open(output_path, 'w') as f:
            f.write(full_fsl_content.lstrip())
        
        print(f"[DONE] FSL file generated at {output_path}")
