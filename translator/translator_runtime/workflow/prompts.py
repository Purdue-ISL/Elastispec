from __future__ import annotations

import json
from typing import Any


def build_outline_prompt(document_content: str) -> str:
    return f"""
You are a technical document analyst. Your task is to create a structured, hierarchical outline (like a table of contents) from the following document text.
Identify all the main sections and their nested subsections that are relevant to firewall rules, network ports, security, and system architecture.

**CRITICAL INSTRUCTION**: The provided text is a raw dump from a website and may include navigational elements like sidebars, headers, and footers. You MUST ignore these navigational sections and focus only on the main content of the article to create the outline. For example, ignore lists of links that appear to be a site-wide menu.

**CRITICAL RULE**: If you encounter sections that are strongly coupled, such as 'inbound' and 'outbound' rules for the same service (e.g., 'HP Inbound' and 'HP Outbound'), treat them as a single conceptual node (e.g., 'HP'). Do not create separate nodes for variations of the same core topic.

Return the result as a JSON object. Each key should be a main section title, and its value can be either another nested JSON object for subsections or a simple `null` if it has no subsections.

**Example JSON Output Format:**
{{
  "Main Section 1": {{
    "Subsection 1.1": null,
    "Subsection 1.2": {{
      "Sub-subsection 1.2.1": null
    }}
  }},
  "Main Section 2": null
}}

**Raw Document Content:**
---
{document_content}
---
"""


def build_section_content_prompt(document_content: str, outline: dict[str, Any], node_path: str) -> str:
    return f"""
You are a technical writer's assistant. Your task is to extract the detailed content for a specific section from a large technical document, based on a provided outline.

**Instructions:**
1. Read the **Full Document Content** provided below.
2. Refer to the **Document Outline** to understand the structure of the document.
3. Extract and return the verbatim text that belongs *only* to the section specified by the **Current Section Path**.
4. **CRITICAL RULE:** Your output must be exclusive to the current section path. It must NOT contain text that belongs to any of its direct subsections. For example, if the current section is 'Card readers', the output must NOT include the text 'Outbound 7778', as that belongs to the 'Elatec TWN3 Reader' subsection. Only return the introductory or general text for the specified section itself. Do not add any extra explanations or summaries.

**Full Document Content:**
---
{document_content}
---

**Document Outline:**
---
{json.dumps(outline, indent=2)}
---

**Current Section Path:**
"{node_path}"

**Extracted Content:**
"""


def build_policy_extraction_prompt(canonical_model: dict[str, Any], section_path: str, section_content: str) -> str:
    return f"""
You are a cybersecurity policy expert. Your task is to analyze a specific section of documentation and extract structured data to update our understanding of an application's architecture.

**Current State of Canonical Model:**
{json.dumps(canonical_model, indent=2)}

**Current Outline Section to Analyze:**
"{section_path}"

**Content for this Section:**
---
{section_content}
---

**INSTRUCTIONS:**
1.  Analyze the documentation chunk for the current section.
2.  Extract any **new** firewall policies not already described in the canonical model. Give each a unique but descriptive `policy_id`. For each policy, describe its **active condition** (e.g., "When using an Oracle database", "If Elatec card readers are deployed").
3.  Identify any **new** entities or groups not already in the model.
4.  **Do NOT duplicate** any information already present in the model.
5.  Respond with a single JSON object containing keys for "policies", "entities", and "groups" for any new information you found. If no new information is found for a key, provide an empty list or object.

**JSON-ONLY OUTPUT FORMAT:**
{{
  "policies": [
    {{
      "policy_id": "...",
      "active_condition": "...",
      "source_entity": "...",
      "destination_entity": "...",
      "port": ["..."],
      "protocol": ["..."]
    }}
  ],
  "entities": [
    {{
        "name": "NewEntityName",
        "description": "..."
    }}
  ],
  "groups": {{
    "GroupName": ["NewEntityName"]
  }}
}}
"""


def build_leaf_spec_prompt(
    parent_content: str,
    leaf_content: str,
    relevant_policies: list[dict[str, Any]],
    spec_name: str,
) -> str:
    return f"""
You are a "Feature Spec Writer". Your task is to define the firewall specification for a single, specific feature of an application based on its policies and documentation.

**Parent Section Content (for context):**
---
{parent_content}
---

**Specific Feature Documentation:**
---
{leaf_content}
---

**Policies Extracted for this Feature (with active conditions):**
---
{json.dumps(relevant_policies, indent=2)}
---

**INSTRUCTIONS:**
Create a single specification for the feature "{spec_name}".

1.  **`operands`**: List all `policy_id`s for this feature.
2.  **`logic`**: Define the relationship between the policies using "AND", "OR", and parentheses. When organizing the logic, carefully consider the active conditions of each policy. Compute and group the logic under different active conditions where applicable. Use **"AND"** if policies must work together for the feature to function (most common logic). Use **"OR"** only if the policies represent choices for the feature (e.g., choosing one of several options under certain conditions). If there is only one policy, the logic is just its `policy_id`.
3.  **`is_optional`**: Determine if this entire feature seems optional based on its description.

**EXAMPLE:**
If the provided policies were:
```json
[
    {{
        "policy_id": "SDK1_PolicyA",
        "active_condition": "..."
    }},
    {{
        "policy_id": "SDK1_PolicyB",
        "active_condition": "..."
    }}
    {{
        "policy_id": "SDK1_PolicyC",
        "active_condition": "..."
    }}
    {{
        "policy_id": "SDK1_PolicyD",
        "active_condition": "..."
    }}
]
```
And by inspecting the active conditions, you decide the correct logic for this spec should be:
```
def SDK1Spec as
(((PolicyA) || (PolicyB)) && (PolicyC) && (PolicyD))
```

Then a good JSON output would be:
```json
{{
  "is_optional": true,
  "operands": ["SDK1_PolicyA", "SDK1_PolicyB", "SDK1_PolicyC", "SDK1_PolicyD"],
  "logic": "((SDK1_PolicyA OR SDK1_PolicyB) AND SDK1_PolicyC AND SDK1_PolicyD)"
}}
```

"""


def build_coupled_leaves_prompt(
    outline: dict[str, Any],
    policies: list[dict[str, Any]],
    leaf_specs: dict[str, Any],
    spec_name_to_path_map: dict[str, str],
) -> str:
    return f"""
You are a "System Coherence Analyst". Your task is to identify and resolve logical dependencies between different feature specifications (leaf specs) of an application.

Sometimes, separate features are mutually exclusive or must be configured coherently. For example, the choice of a cloud provider for 'User Directory' might affect the required firewall rules for 'Data Storage'. Another example is when 'Inbound Traffic' and 'Outbound Traffic' for a specific device (like a printer) must both use the same SDK (e.g., SDK1 or SDK2). Generating their logic independently might accidentally allow an inconsistent state (Inbound using SDK1, Outbound using SDK2).

**Application Outline:**
---
{json.dumps(outline, indent=2)}
---

**All Policies with Active Conditions:**
---
{json.dumps(policies, indent=2)}
---

**Pre-generated Leaf Specifications:**
---
{json.dumps(leaf_specs, indent=2)}
---

**Spec-to-Path Mapping (which leaf spec belongs to which part of the outline):**
---
{json.dumps(spec_name_to_path_map, indent=2)}
---

**INSTRUCTIONS:**
1.  **Identify Coupled Groups:** Analyze the leaf specs, their underlying policies, and the application outline. Find groups of leaf specs that are "coupled" by a shared, conditional choice. Look for patterns in the outline (e.g., "Inbound" and "Outbound" sections under the same parent) and in the policy `active_condition`s (e.g., multiple policies mentioning "SDK1", "SDK2", etc.).

2.  **Create Wrapper Specs:** For each coupled group you identify, create a new "wrapper" specification to manage their shared logic. This wrapper spec should:
    a. Have a descriptive name, e.g., `HP_Printer_SDK_Choice_Spec`.
    b. Define the logic for the choice. For instance, if the choice is between SDK1 and SDK2 for both Inbound and Outbound, the logic might be `(HP_Printer_Inbound_SDK1 AND HP_Printer_Outbound_SDK1) OR (HP_Printer_Inbound_SDK2 AND HP_Printer_Outbound_SDK2)`. This enforces that the same SDK is used for both.

3.  **Restructure Specs:** To implement the wrapper, you might need to break down the original leaf specs into more granular, conditional components (e.g., `HP_Printer_Inbound_SDK1_Spec`, `HP_Printer_Inbound_SDK2_Spec`). The new wrapper spec will then use these components as its operands.

4.  **Output:** Respond with a single JSON object containing:
    - `newly_created_specs`: An object containing all the new wrapper specs and any new granular specs you created.
    - `specs_to_remove`: A list of the original leaf spec names that have been replaced by your new structure and should be removed.
    - `path_updates`: A dictionary mapping the *original outline paths* of the removed specs to the name of the *new spec* that now covers that path. This is crucial for rebuilding the hierarchy correctly.

**EXAMPLE:**
If you find that `HP_Inbound_Spec` and `HP_Outbound_Spec` are coupled by the choice of SDK1 or SDK2.

*Original `leaf_specs` might look like:*
```json
{{
  "HP_Inbound_Spec": {{ "logic": "(PolicyA_SDK1 OR PolicyB_SDK2)", "operands": ["PolicyA_SDK1", "PolicyB_SDK2"]}},
  "HP_Outbound_Spec": {{ "logic": "(PolicyC_SDK1 OR PolicyD_SDK2)", "operands": ["PolicyC_SDK1", "PolicyD_SDK2"]}}
}}
```
*This is flawed because it allows Inbound to use SDK1 while Outbound uses SDK2.*

*Your output should be:*
```json
{{
  "newly_created_specs": {{
    "HP_Printer_Unified_SDK_Spec": {{
        "is_optional": true,
        "operands": ["HP_Printer_SDK1_Spec", "HP_Printer_SDK2_Spec"],
        "logic": "HP_Printer_SDK1_Spec OR HP_Printer_SDK2_Spec"
    }},
    "HP_Printer_SDK1_Spec": {{
        "is_optional": true,
        "operands": ["PolicyA_SDK1", "PolicyC_SDK1"],
        "logic": "PolicyA_SDK1 AND PolicyC_SDK1"
    }},
    "HP_Printer_SDK2_Spec": {{
        "is_optional": true,
        "operands": ["PolicyB_SDK2", "PolicyD_SDK2"],
        "logic": "PolicyB_SDK2 AND PolicyD_SDK2"
    }}
  }},
  "specs_to_remove": ["HP_Inbound_Spec", "HP_Outbound_Spec"],
  "path_updates": {{
    "{spec_name_to_path_map.get('HP_Inbound_Spec', 'PATH_NOT_FOUND')}": "HP_Printer_Unified_SDK_Spec",
    "{spec_name_to_path_map.get('HP_Outbound_Spec', 'PATH_NOT_FOUND')}": "HP_Printer_Unified_SDK_Spec"
  }}
}}
```

**JSON-ONLY OUTPUT FORMAT (If no coupled leaves are found, return empty values):**
```json
{{
  "newly_created_specs": {{...}},
  "specs_to_remove": [...],
  "path_updates": {{...}}
}}
```
"""


def build_hierarchy_prompt(annotated_outline: dict[str, Any]) -> str:
    return f"""
You are a "Chief Architect". Your task is to create the high-level structure of a firewall specification from an "annotated outline". In this outline, the leaf nodes have already been identified and replaced with the name of their corresponding specification.

**Annotated Document Outline (Your primary guide for the structure):**
---
{json.dumps(annotated_outline, indent=2)}
---

**INSTRUCTIONS:**
Convert the annotated outline into the final hierarchical specification.

1.  **Create Parent Specs:** For each key that has a nested object (e.g., "External database"), create a parent specification.
2.  **Assign Operands:** The `operands` for a parent spec are the names of its children specs (which can be other parents you create or the pre-defined leaf spec names from the outline).
3.  **Define Logic:** Define the `logic` between the `operands` using "AND", "OR", and parentheses. Group logic under different conditions where applicable. Use **"AND"** if all child specs are required for the parent feature to work (most common logic). Use **"OR"** only if the child specs represent choices (e.g., choosing one brand of MFD from a list under certain conditions).
4.  **Top-Level Spec:** Ensure there is a single root specification that contains all other specifications.

**EXAMPLE INPUT OUTLINE:**
```json
{{
    "PaperCut": {{
        "Core Functionality": "CoreFunctionalitySpec",
        "User Directory": {{
            "Google Cloud Directory": "GoogleCloudDirectorySpec",
            "Azure AD": "AzureADSpec",
            "LDAP": "LDAPSpec"
        }},
        "MFD": "MFDeviceSpec",
        "SDK1": "SDK1Spec",
        "SDK2": "SDK2Spec",
        "SDK3": "SDK3Spec"
    }}
}}
```

**CORRESPONDING JSON OUTPUT:**
```json
{{
    "PaperCutSpec": {{
        "operands": ["CoreFunctionalitySpec", "UserDirectorySpec", "MFDeviceSpec", "SDK1Spec", "SDK2Spec", "SDK3Spec"],
        "logic": "CoreFunctionalitySpec AND UserDirectorySpec AND MFDeviceSpec AND (SDK1Spec OR SDK2Spec OR SDK3Spec)"
    }},
    "UserDirectorySpec": {{
        "operands": ["GoogleCloudDirectorySpec", "AzureADSpec", "LDAPSpec"],
        "logic": "GoogleCloudDirectorySpec OR AzureADSpec OR LDAPSpec"
    }}
}}
```

**JSON-ONLY OUTPUT FORMAT (for the higher-level specs ONLY):**
"""


def build_hierarchy_correction_prompt(response_text: str) -> str:
    return f"""
You are a JSON correction expert. The following text is a malformed JSON object. Your task is to fix any syntax errors (like missing quotes, commas, or brackets) and return only the corrected, valid JSON object. Do not add any explanations.

**Malformed JSON:**
---
{response_text}
---
"""


def build_optionality_prompt(raw_document_context: str, full_spec: dict[str, Any]) -> str:
    return f"""
You are a product manager analyzing an application's feature set. Your task is to determine the optionality of each feature (spec) within the application's hierarchy.

**Core Principle:**
The `is_optional` flag for a spec determines if it is required for its **parent** spec to be satisfied.
- `is_optional: false` (mandatory): The feature is essential for its parent's functionality.
- `is_optional: true` (optional): The feature is an add-on. The parent can function without it.

**Logical Interpretation:**
Treat the entire specification as a logical expression. Each spec is a boolean value (`true` if satisfied by the real network configuration, `false` otherwise).
Setting a spec to `is_optional: true` makes its value permanently `true` in the logical expression of its parent.

**Crucial Rule for OR Logic:**
If a parent spec `P` requires at least one of its children to be active (e.g., `P.logic = "A OR B OR C"`), then the children `A`, `B`, and `C` must be marked `is_optional: false`.
Why? If `B` were marked `is_optional: true`, the logic would become `A OR true OR C`, making `P` always true, even if no choice is implemented. This is incorrect. By marking them `is_optional: false`, we enforce that at least one must be satisfied in the actual network configuration.

**Example 1: Required Choice (External Database)**
- Hierarchy: `PapercutSpec` -> `ExternalDatabaseSpec` -> (`OracleSpec` OR `MySQLSpec`)
- Context: A database is required for Papercut to work.
- Expected `is_optional` values:
    - `ExternalDatabaseSpec`: `false` (required for `PapercutSpec`).
    - `OracleSpec`: `false` (it's a choice within a required feature).
    - `MySQLSpec`: `false` (it's a choice within a required feature).

**Example 2: Optional Feature (Card Readers)**
- Hierarchy: `PapercutSpec` -> `CardReadersSpec` -> (`LantronixSpec` OR `RFIdeasSpec`)
- Context: Card readers are an optional add-on for Papercut.
- Expected `is_optional` values:
    - `CardReadersSpec`: `true` (optional for `PapercutSpec`).
    - `LantronixSpec`: `false` (it's a choice within the `CardReadersSpec` feature. If you want card readers, you must pick one).
    - `RFIdeasSpec`: `false` (same reason as above).

**Full Documentation Context:**
---
{raw_document_context}
---

**Full Specification Hierarchy:**
---
{json.dumps(full_spec, indent=2)}
---

**INSTRUCTIONS:**
For each parent spec in the hierarchy, analyze its relationship with its children (operands) based on its logic (`AND`/`OR`), the documentation, and the feature's name and description.
Based on this analysis, decide if each child spec is mandatory or optional *for its parent to function correctly*.
Then, compile these decisions into a single JSON object where keys are the `spec_name`s of the children and values are their determined optionality (`true` for optional, `false` for mandatory).
Make a decision for every spec in the hierarchy. The top-level spec should typically be `false`.

**JSON-ONLY OUTPUT FORMAT:**
{{
  "PaperCutSpec": false,
  "ExternalDatabaseSpec": false,
  "OracleSpec": false,
  "MySQLSpec": false,
  "CardReadersSpec": true,
  "LantronixSpec": false,
  "RFIdeasSpec": false
}}
"""
