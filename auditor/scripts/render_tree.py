#!/usr/bin/env python3
"""
Internal renderer for the operator-facing compliance report.

The renderer accepts the three verdicts defined by the paper: VALID, UNSAT,
and CONJECTURED-SAT. Required AND/OR children are composed bottom-up, while
optional subexpressions are reported but do not constrain their parent.

Optional subexpressions (marked with '?') are non-blocking: they are evaluated and displayed,
but do not affect their parents (effective label forced to VALID).
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Parsing helpers (FSL)
# ----------------------------

def _strip_hash_comments(text: str) -> str:
    return "\n".join([ln.split("#", 1)[0] for ln in (text or "").splitlines()])


def _extract_defs(text: str) -> Dict[str, str]:
    """
    Extract "def Name as <expr...>" blocks.
    Very lightweight: joins subsequent lines until next 'def '.
    """
    defs: Dict[str, str] = {}
    cur_name: Optional[str] = None
    cur_buf: List[str] = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("def "):
            if cur_name is not None:
                defs[cur_name] = " ".join(cur_buf).strip()
            m = re.match(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s+as\s*(.*)$", s, flags=re.IGNORECASE)
            if not m:
                cur_name = None
                cur_buf = []
                continue
            cur_name = m.group(1).strip()
            rest = (m.group(2) or "").strip()
            cur_buf = [rest] if rest else []
        else:
            if cur_name is None:
                continue
            cur_buf.append(s)
    if cur_name is not None:
        defs[cur_name] = " ".join(cur_buf).strip()
    return defs


# Leaf connection matcher.
# Match a leaf starting at its leaf-open, i.e. "((Src, *) -> (Dst, Port) on proto)".
#
# Vendor files frequently wrap leaves with extra grouping parentheses like:
#   (((Leaf) OR (Leaf)) AND ...)
# In those cases the leaf begins at the *second-to-last* '(' in the run,
# and the leaf ends at the ')' right after the proto. We intentionally do NOT
# require an extra ')' at the end, because that may close a grouping paren.
LEAF_PAT = re.compile(
    # NOTE: ports expression may contain commas (e.g., "9163, 9164").
    r"\(\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)\s*on\s*([^)]+?)\s*\)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Leaf:
    leaf_str: str  # canonical key: "((Src, *) -> (Dst, PORTS) on proto)"


def _leaf_str_from_match(m: re.Match[str]) -> List[str]:
    src = (m.group(1) or "").strip().strip("()")
    dst = (m.group(2) or "").strip().strip("()")
    ports_raw = (m.group(3) or "").strip().replace(" ", "").rstrip("?")
    proto_raw = (m.group(4) or "").strip().rstrip("?").strip()
    protos = [p.strip().lower() for p in proto_raw.split(",") if p.strip()]
    protos = [p for p in protos if p != "any"]
    if not protos:
        protos = ["ip"]
    # Split comma-separated port lists into separate leaves (user requirement).
    ports_list = [ports_raw] if (not ports_raw or ports_raw == "*" or "," not in ports_raw) else [x for x in ports_raw.split(",") if x.strip()]
    out: list[str] = []
    for port in ports_list:
        port_s = str(port or "").strip()
        if not port_s:
            continue
        for p in protos:
            out.append(f"(({src}, *) -> ({dst}, {port_s}) on {p})")
    return out


Token = Any  # ("LEAF", Leaf) | ("IDENT", str) | "AND" | "OR" | "(" | ")" | "?"


def _tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    s = expr or ""
    i = 0
    while i < len(s):
        ch = s[i]
        if ch.isspace():
            i += 1
            continue
        # Leaf connection: vendor FSL often has extra grouping parens before a leaf.
        # If we're sitting on a run of '(' like "(((" before "SrcRole,...", the leaf
        # starts at the *second-to-last* '(' in that run:
        #   - last '(' is the src-tuple open
        #   - second-to-last '(' is the leaf open
        #   - any earlier '(' are grouping opens and must remain in the token stream
        if ch == "(":
            j = i
            while j < len(s) and s[j] == "(":
                j += 1
            if (j - i) >= 2:
                leaf_start = j - 2
                m = LEAF_PAT.match(s, leaf_start)
                if m:
                    # Emit grouping parens before the leaf-open.
                    for _ in range(i, leaf_start):
                        tokens.append("(")
                    expanded = _leaf_str_from_match(m)
                    for idx, leaf_str in enumerate(expanded):
                        if idx > 0:
                            tokens.append("AND")
                        tokens.append(("LEAF", Leaf(leaf_str=leaf_str)))
                    i = m.end()
                    continue

        # Punctuation
        if ch in "()?":
            tokens.append(ch)
            i += 1
            continue
        if s[i : i + 3].upper() == "AND" and (i + 3 == len(s) or not s[i + 3].isalnum()):
            tokens.append("AND")
            i += 3
            continue
        if s[i : i + 2].upper() == "OR" and (i + 2 == len(s) or not s[i + 2].isalnum()):
            tokens.append("OR")
            i += 2
            continue
        m2 = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i:])
        if m2:
            tokens.append(("IDENT", m2.group(0)))
            i += len(m2.group(0))
            continue
        i += 1
    return tokens


@dataclass
class Node:
    kind: str  # LEAF | IDENT | AND | OR | GROUP
    value: Any = None
    left: Optional["Node"] = None
    right: Optional["Node"] = None
    child: Optional["Node"] = None
    optional: bool = False  # postfix '?'


def _parse_expr(tokens: List[Token]) -> Optional[Node]:
    """Pratt-ish parser: AND has higher precedence than OR; supports postfix '?' and parentheses."""

    def parse_primary(pos: int) -> Tuple[Optional[Node], int]:
        if pos >= len(tokens):
            return None, pos
        t = tokens[pos]
        if t == "(":
            n, pos2 = parse_or(pos + 1)
            if pos2 < len(tokens) and tokens[pos2] == ")":
                pos2 += 1
            node = Node(kind="GROUP", child=n)
            # optional postfix
            if pos2 < len(tokens) and tokens[pos2] == "?":
                node.optional = True
                pos2 += 1
            return node, pos2
        if isinstance(t, tuple) and t and t[0] == "LEAF":
            node = Node(kind="LEAF", value=t[1])
            pos2 = pos + 1
            if pos2 < len(tokens) and tokens[pos2] == "?":
                node.optional = True
                pos2 += 1
            return node, pos2
        if isinstance(t, tuple) and t and t[0] == "IDENT":
            node = Node(kind="IDENT", value=t[1])
            pos2 = pos + 1
            if pos2 < len(tokens) and tokens[pos2] == "?":
                node.optional = True
                pos2 += 1
            return node, pos2
        return None, pos + 1

    def parse_and(pos: int) -> Tuple[Optional[Node], int]:
        left, pos = parse_primary(pos)
        while pos < len(tokens) and tokens[pos] == "AND":
            right, pos2 = parse_primary(pos + 1)
            left = Node(kind="AND", left=left, right=right)
            pos = pos2
            # optional postfix applies to the whole combined node: "(A AND B)?"
            if pos < len(tokens) and tokens[pos] == "?":
                left.optional = True
                pos += 1
        return left, pos

    def parse_or(pos: int) -> Tuple[Optional[Node], int]:
        left, pos = parse_and(pos)
        while pos < len(tokens) and tokens[pos] == "OR":
            right, pos2 = parse_and(pos + 1)
            left = Node(kind="OR", left=left, right=right)
            pos = pos2
            if pos < len(tokens) and tokens[pos] == "?":
                left.optional = True
                pos += 1
        return left, pos

    n, _pos = parse_or(0)
    return n


# ----------------------------
# Parsing helpers (summary)
# ----------------------------

def _load_leaf_truth_from_summary(summary_path: Path) -> Dict[str, Tuple[str, str]]:
    """
    Returns mapping: leaf_str -> (label, status_tag)
    where label is VALID, UNSAT, or CONJECTURED-SAT.
    """
    out: Dict[str, Tuple[str, str]] = {}

    def label_from_tag(tag: str) -> str:
        t = str(tag or "").strip().upper()
        if t not in {"VALID", "UNSAT", "CONJECTURED-SAT"}:
            raise ValueError(f"Unsupported auditor verdict: {tag}")
        return t

    lines = summary_path.read_text().splitlines()
    for ln in lines:
        if "\t" not in ln:
            continue
        parts = ln.split("\t", 2)
        if len(parts) < 2:
            continue
        tag = parts[0].strip()
        val = parts[1].strip()
        leaf = val
        if not (leaf.startswith("((") and ") on " in leaf):
            continue
        label = label_from_tag(tag)
        out[leaf] = (label, tag)
    return out


def _extract_roles_from_leaf(leaf: str) -> Tuple[str, str]:
    m = re.match(r"^\(\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,", str(leaf or "").strip(), flags=re.IGNORECASE)
    if not m:
        return ("", "")
    src = (m.group(1) or "").strip().strip("()")
    dst = (m.group(2) or "").strip().strip("()")
    return (src, dst)


def _load_entity_leaf_states_from_conjectures_detail(
    detail_path: Path,
) -> Tuple[
    Dict[str, str],
    Dict[str, Dict[str, str]],
    Dict[str, Dict[str, List[str]]],
]:
    """
    Parse conjectures detail text and return:
    - entity_root_effective_state: entity -> {"set"|"empty"|"absent"|...}
    - entity_leaf_local_state: entity -> (leaf_str -> {"set"|"empty"|"absent"|...})
    - entity_root_effective_bdd: entity -> (ingress interface -> source prefixes)
    """
    entity_root_effective_state: Dict[str, str] = {}
    entity_leaf_local_state: Dict[str, Dict[str, str]] = {}
    entity_root_effective_bdd: Dict[str, Dict[str, List[str]]] = {}

    if not detail_path.exists():
        return (
            entity_root_effective_state,
            entity_leaf_local_state,
            entity_root_effective_bdd,
        )

    current_entity = ""
    in_leaves = False
    in_root_effective = False
    current_ingress = ""
    current_leaf = ""
    current_leaf_local = ""

    for raw in detail_path.read_text().splitlines():
        line = str(raw or "")
        s = line.strip()

        if s.startswith("## "):
            current_entity = s[3:].strip()
            in_leaves = False
            in_root_effective = False
            current_ingress = ""
            current_leaf = ""
            current_leaf_local = ""
            if current_entity:
                entity_leaf_local_state.setdefault(current_entity, {})
            continue

        if not current_entity:
            continue

        if s.startswith("Root effective: state="):
            state = s.split("state=", 1)[1].strip().lower()
            entity_root_effective_state[current_entity] = state
            in_root_effective = state == "set"
            current_ingress = ""
            continue

        if in_root_effective:
            indent = len(line) - len(line.lstrip())
            if indent == 4 and s.endswith(":"):
                current_ingress = s[:-1].strip()
                if current_ingress:
                    entity_root_effective_bdd.setdefault(current_entity, {}).setdefault(
                        current_ingress, []
                    )
                continue
            if indent >= 6 and current_ingress and s.startswith("- "):
                prefix = s[2:].strip()
                if prefix:
                    entity_root_effective_bdd[current_entity][current_ingress].append(prefix)
                continue
            in_root_effective = False
            current_ingress = ""

        if s == "Leaves:":
            in_leaves = True
            current_leaf = ""
            current_leaf_local = ""
            continue

        if not in_leaves:
            continue

        if s.startswith("- (("):
            current_leaf_local = ""
            leaf_part = s[2:].strip()
            current_leaf = leaf_part.split(" | ", 1)[0].strip()
            continue

        if not current_leaf:
            continue

        if s.startswith("local: state="):
            current_leaf_local = s.split("state=", 1)[1].strip().lower()
            if current_leaf_local:
                entity_leaf_local_state.setdefault(current_entity, {})[current_leaf] = current_leaf_local
            continue

    return (
        entity_root_effective_state,
        entity_leaf_local_state,
        entity_root_effective_bdd,
    )


# ----------------------------
# Evaluation + rendering
# ----------------------------

@dataclass
class Eval:
    # Intrinsic label of the node itself (what we show/color).
    state: str  # VALID | UNSAT | CONJECTURED-SAT
    # Effective label propagated to parent. For optional `?`, this is forced to VALID.
    effective_state: str  # VALID | UNSAT | CONJECTURED-SAT
    kind: str  # valid | unsat | conjectured
    label: str


def _eval_node(
    node: Optional[Node],
    defs: Dict[str, str],
    leaf_truth: Dict[str, Tuple[str, str]],
    entity_root_effective_state: Optional[Dict[str, str]] = None,
    entity_leaf_local_state: Optional[Dict[str, Dict[str, str]]] = None,
    under_optional_ctx: bool = False,
    visiting: Optional[set[str]] = None,
) -> Tuple[Eval, List[Tuple[Node, Eval]]]:
    """
    Returns:
      - Eval for this node
      - A list of (node, eval) pairs to help downstream renderers if needed
    """
    if visiting is None:
        visiting = set()

    if node is None:
        e = Eval(state="UNSAT", effective_state="UNSAT", kind="unsat", label="(empty)")
        return e, []

    def wrap_optional(base_eval: Eval, is_optional: bool) -> Eval:
        if not is_optional:
            return base_eval
        # Optional nodes:
        # - intrinsic label is preserved (for display)
        # - effective label is forced VALID (so parents are not impacted)
        return Eval(
            state=base_eval.state,
            effective_state="VALID",
            kind=base_eval.kind,
            label=base_eval.label + " ?",
        )

    if node.kind == "LEAF":
        leaf: Leaf = node.value
        lab, _tag = leaf_truth.get(leaf.leaf_str, ("UNSAT", "MISSING_IN_REPORT"))
        lab_u = str(lab or "").strip().upper()
        if lab_u not in ("VALID", "UNSAT", "CONJECTURED-SAT"):
            lab_u = "UNSAT"

        # A non-empty root conjecture does not imply that every leaf for the
        # unresolved role is satisfiable. Use each leaf's local BDD state while
        # retaining root-level consistency for the complete policy.
        if (
            lab_u != "VALID"
            and isinstance(entity_root_effective_state, dict)
            and isinstance(entity_leaf_local_state, dict)
        ):
            src_role, dst_role = _extract_roles_from_leaf(leaf.leaf_str)
            for role in (src_role, dst_role):
                if not role:
                    continue
                root_state = str(entity_root_effective_state.get(role, "")).strip().lower()
                leaf_state = str(
                    (entity_leaf_local_state.get(role, {}) or {}).get(
                        leaf.leaf_str, ""
                    )
                ).strip().lower()
                if root_state == "set":
                    if leaf_state == "set":
                        lab_u = "CONJECTURED-SAT"
                        break
                    if leaf_state == "empty":
                        lab_u = "UNSAT"
                        break
                elif (under_optional_ctx or bool(node.optional)) and lab_u == "UNSAT":
                    if leaf_state == "set":
                        lab_u = "CONJECTURED-SAT"
                        break
                    if leaf_state == "empty":
                        lab_u = "UNSAT"
                        break

        if lab_u == "VALID":
            kind = "valid"
        elif lab_u == "UNSAT":
            kind = "unsat"
        elif lab_u == "CONJECTURED-SAT":
            kind = "conjectured"
        else:
            kind = "unsat"

        label = leaf.leaf_str if not lab_u else f"{leaf.leaf_str} [{lab_u}]"
        base = Eval(state=lab_u, effective_state=lab_u, kind=kind, label=label)
        return wrap_optional(base, node.optional), [(node, base)]

    if node.kind == "IDENT":
        name = str(node.value or "")
        if not name or name not in defs:
            base = Eval(state="UNSAT", effective_state="UNSAT", kind="unsat", label=f"{name} [UNRESOLVED_DEF]")
            return wrap_optional(base, node.optional), [(node, base)]
        if name in visiting:
            base = Eval(state="UNSAT", effective_state="UNSAT", kind="unsat", label=f"{name} [CYCLE]")
            return wrap_optional(base, node.optional), [(node, base)]
        visiting.add(name)
        ast = _parse_expr(_tokenize(defs[name]))
        child_eval, pairs = _eval_node(
            ast,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
            under_optional_ctx=under_optional_ctx or bool(node.optional),
            visiting=visiting,
        )
        visiting.remove(name)
        # IDENT intrinsic state mirrors the child's intrinsic state; effective mirrors child effective.
        kind = child_eval.kind
        base = Eval(
            state=child_eval.state,
            effective_state=child_eval.effective_state,
            kind=kind,
            label=f"{name}",
        )
        return wrap_optional(base, node.optional), [(node, base)] + pairs

    if node.kind in ("AND", "OR"):
        child_under_optional = under_optional_ctx or bool(node.optional)
        le, _ = _eval_node(
            node.left,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
            under_optional_ctx=child_under_optional,
            visiting=visiting,
        )
        re, _ = _eval_node(
            node.right,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
            under_optional_ctx=child_under_optional,
            visiting=visiting,
        )

        def and_label(a: str, b: str) -> str:
            if a == "UNSAT" or b == "UNSAT":
                return "UNSAT"
            if a == "CONJECTURED-SAT" or b == "CONJECTURED-SAT":
                return "CONJECTURED-SAT"
            return "VALID"

        def or_label(a: str, b: str) -> str:
            if a == "VALID" or b == "VALID":
                return "VALID"
            if a == "CONJECTURED-SAT" or b == "CONJECTURED-SAT":
                return "CONJECTURED-SAT"
            return "UNSAT"

        eff = and_label(le.effective_state, re.effective_state) if node.kind == "AND" else or_label(le.effective_state, re.effective_state)
        if eff == "VALID":
            kind = "valid"
        elif eff == "UNSAT":
            kind = "unsat"
        elif eff == "CONJECTURED-SAT":
            kind = "conjectured"
        else:
            kind = "unsat"
        base = Eval(state=eff, effective_state=eff, kind=kind, label=(node.kind if not eff else f"{node.kind} [{eff}]"))
        return wrap_optional(base, node.optional), [(node, base)]

    if node.kind == "GROUP":
        ce, _ = _eval_node(
            node.child,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
            under_optional_ctx=under_optional_ctx or bool(node.optional),
            visiting=visiting,
        )
        base = Eval(state=ce.state, effective_state=ce.effective_state, kind=ce.kind, label="(group)")
        return wrap_optional(base, node.optional), [(node, base)]

    base = Eval(state="UNSAT", effective_state="UNSAT", kind="unsat", label=f"{node.kind} [UNSUPPORTED_NODE]")
    return wrap_optional(base, node.optional), [(node, base)]


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_html_tree(
    title: str,
    root_name: str,
    root_node: Node,
    defs: Dict[str, str],
    leaf_truth: Dict[str, Tuple[str, str]],
    entity_root_effective_state: Optional[Dict[str, str]] = None,
    entity_leaf_local_state: Optional[Dict[str, Dict[str, str]]] = None,
    bdd_conjectures: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> str:
    def node_class(kind: str) -> str:
        return {
            "valid": "valid",
            "unsat": "unsat",
            "conjectured": "conjectured",
        }.get(kind, "unsat")

    def _flatten(op_kind: str, n: Optional[Node]) -> List[Node]:
        """
        Flatten left/right-associated chains of the same operator for nicer display.
        This keeps semantics identical, but avoids the deep nested AND/OR in the UI.
        """
        if n is None:
            return []
        if n.kind != op_kind or n.optional:
            return [n]
        out: List[Node] = []
        if n.left is not None:
            out.extend(_flatten(op_kind, n.left))
        if n.right is not None:
            out.extend(_flatten(op_kind, n.right))
        return out

    def render(n: Optional[Node], label_override: Optional[str] = None) -> str:
        if n is None:
            return '<li class="unsat">(empty)</li>'

        ev, _pairs = _eval_node(
            n,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
        )
        cls = node_class(ev.kind)
        label = label_override if label_override is not None else ev.label

        # Leaves: print as a single line.
        if n.kind == "LEAF":
            return f'<li class="{cls}"><code>{_html_escape(label)}</code></li>'

        # IDENT: show name, expand definition.
        if n.kind == "IDENT":
            name = str(n.value or "")
            # Expand def expression AST if possible (avoid cycles handled by eval).
            child_ast = _parse_expr(_tokenize(defs.get(name, ""))) if name in defs else None
            inner = render(child_ast) if child_ast else ""
            return (
                f'<li class="{cls}"><details open>'
                f'<summary><span class="{cls}">{_html_escape(label)}</span></summary>'
                f"<ul>{inner}</ul>"
                f"</details></li>"
            )

        # Operators / group
        if n.kind == "AND":
            kids = _flatten("AND", n)
            inner = "".join([render(k) for k in kids])
        elif n.kind == "OR":
            kids = _flatten("OR", n)
            inner = "".join([render(k) for k in kids])
        elif n.kind == "GROUP":
            inner = render(n.child)
        else:
            inner = ""

        return (
            f'<li class="{cls}"><details open>'
            f'<summary><span class="{cls}">{_html_escape(label)}</span></summary>'
            f"<ul>{inner}</ul>"
            f"</details></li>"
        )

    root_eval, _ = _eval_node(
        root_node,
        defs,
        leaf_truth,
        entity_root_effective_state=entity_root_effective_state,
        entity_leaf_local_state=entity_leaf_local_state,
    )
    root_cls = node_class(root_eval.kind)

    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
    table { border-collapse: collapse; margin: 8px 0 14px; }
    th, td { border: 1px solid #c7c7c7; padding: 5px 8px; text-align: left; }
    ul { list-style-type: none; margin: 0; padding-left: 18px; }
    li { margin: 2px 0; }
    .valid { color: #0a7d00; }
    .conjectured { color: #0a7d00; }
    .unsat { color: #b00020; }
    summary { cursor: pointer; }
    """
    root_word = root_eval.effective_state or ""
    bdd_html = ""
    if bdd_conjectures:
        bdd_rows: List[str] = []
        for role, ingresses in sorted(bdd_conjectures.items()):
            for ingress, prefixes in sorted(ingresses.items()):
                prefix_html = "<br>".join(
                    f"<code>{_html_escape(prefix)}</code>"
                    for prefix in prefixes
                    if str(prefix).strip()
                )
                if not prefix_html:
                    continue
                bdd_rows.append(
                    f"<tr><td>{_html_escape(role)}</td>"
                    f"<td><code>{_html_escape(ingress)}</code></td>"
                    f"<td>{prefix_html}</td></tr>"
                )
        if bdd_rows:
            bdd_html = (
                "<h4>Conjectures</h4>"
                "<table><thead><tr><th>Unresolved role</th><th>Ingress</th>"
                "<th>Candidate source prefixes</th></tr></thead>"
                f"<tbody>{''.join(bdd_rows)}</tbody></table>"
            )

    html = (
        "<!doctype html>"
        "<html><head><meta charset='utf-8'>"
        f"<title>{_html_escape(title)}</title>"
        f"<style>{css}</style>"
        "</head><body>"
        f"<h3>{_html_escape(title)}</h3>"
        f"<p><b>Root:</b> <span class='{root_cls}'>{_html_escape(root_name)}"
        + (f" = {root_word}" if root_word else "")
        + "</span></p>"
        "<p><b>Legend:</b> "
        "<span class='valid'>VALID</span> | "
        "<span class='conjectured'>CONJECTURED-SAT</span> | "
        "<span class='unsat'>UNSAT</span>"
        "</p>"
        + "<ul>"
        + render(
            Node(kind="IDENT", value=root_name),
            label_override=(f"{root_name} ({root_word})" if root_word else f"{root_name}"),
        )
        + "</ul>"
        + bdd_html
        + "</body></html>"
    )
    return html


def _render_text_tree(
    root_name: str,
    root_node: Node,
    defs: Dict[str, str],
    leaf_truth: Dict[str, Tuple[str, str]],
    entity_root_effective_state: Optional[Dict[str, str]] = None,
    entity_leaf_local_state: Optional[Dict[str, Dict[str, str]]] = None,
) -> str:
    """
    Simple text tree (no colors) with propagated labels.
    """

    def render(n: Optional[Node], indent: str) -> List[str]:
        if n is None:
            return [indent + "- (empty) => UNSAT"]
        ev, _ = _eval_node(
            n,
            defs,
            leaf_truth,
            entity_root_effective_state=entity_root_effective_state,
            entity_leaf_local_state=entity_leaf_local_state,
        )
        tag = str(ev.state or "").upper()
        if n.kind == "LEAF":
            return [indent + f"- {ev.label} => {tag}"]
        if n.kind == "IDENT":
            name = str(n.value or "")
            lines = [indent + (f"- {name} => {tag}" if tag else f"- {name} =>")]
            child = _parse_expr(_tokenize(defs.get(name, ""))) if name in defs else None
            return lines + render(child, indent + "  ")
        if n.kind == "AND":
            # Flatten for readability.
            def flat_and(x: Optional[Node]) -> List[Node]:
                if x is None:
                    return []
                if x.kind != "AND" or x.optional:
                    return [x]
                return flat_and(x.left) + flat_and(x.right)

            kids = flat_and(n)
            lines = [indent + f"- AND => {tag}"]
            out = lines
            for k in kids:
                out += render(k, indent + "  ")
            return out
        if n.kind == "OR":
            def flat_or(x: Optional[Node]) -> List[Node]:
                if x is None:
                    return []
                if x.kind != "OR" or x.optional:
                    return [x]
                return flat_or(x.left) + flat_or(x.right)

            kids = flat_or(n)
            lines = [indent + f"- OR => {tag}"]
            out = lines
            for k in kids:
                out += render(k, indent + "  ")
            return out
        if n.kind == "GROUP":
            return [indent + f"- (group) => {tag}"] + render(n.child, indent + "  ")
        return [indent + f"- {n.kind} => {tag}"]

    root_eval, _ = _eval_node(
        root_node,
        defs,
        leaf_truth,
        entity_root_effective_state=entity_root_effective_state,
        entity_leaf_local_state=entity_leaf_local_state,
    )
    root_word = root_eval.effective_state or ""
    header = f"{root_name}: {root_word}"
    return "\n".join([header] + render(Node(kind="IDENT", value=root_name), "")) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fsl", required=True, help="Path to vendor FSL file")
    ap.add_argument("--summary", required=True, help="Path to instance summary.txt")
    ap.add_argument("--out_html", required=True, help="Output HTML path")
    ap.add_argument("--out_txt", required=True, help="Output text path")
    ap.add_argument(
        "--root",
        default="",
        help="Root def name. If empty, uses the last def in the FSL file.",
    )
    ap.add_argument("--title", default="", help="Optional title for the compliance report")
    ap.add_argument(
        "--conjectures_detail",
        default="",
        help="Optional conjecture detail file generated by run_audit.py",
    )
    args = ap.parse_args()

    fsl_path = Path(args.fsl)
    summary_path = Path(args.summary)

    text = _strip_hash_comments(fsl_path.read_text())
    defs = _extract_defs(text)
    root = str(args.root).strip()
    if not root and defs:
        root = list(defs.keys())[-1]
    if root not in defs:
        raise SystemExit(f"Root def not found in FSL: {root} (available: {list(defs.keys())})")

    root_node = _parse_expr(_tokenize(defs[root]))
    if root_node is None:
        raise SystemExit(f"Failed to parse root expression for {root}")

    leaf_truth = _load_leaf_truth_from_summary(summary_path)
    detail_path = Path(str(args.conjectures_detail).strip()) if str(args.conjectures_detail or "").strip() else None
    if detail_path is None:
        stem = re.sub(r"\.summary\.txt$", "", summary_path.name)
        guess = summary_path.parent / "conjectures_detail" / f"{stem}.conjectures_detail.txt"
        detail_path = guess if guess.exists() else None
    entity_root_effective_state: Dict[str, str] = {}
    entity_leaf_local_state: Dict[str, Dict[str, str]] = {}
    bdd_conjectures: Dict[str, Dict[str, List[str]]] = {}
    if detail_path is not None and detail_path.exists():
        (
            entity_root_effective_state,
            entity_leaf_local_state,
            bdd_conjectures,
        ) = _load_entity_leaf_states_from_conjectures_detail(detail_path)

    title = args.title.strip() or f"{summary_path.name} vs {fsl_path.name}"
    html = _render_html_tree(
        title=title,
        root_name=root,
        root_node=root_node,
        defs=defs,
        leaf_truth=leaf_truth,
        entity_root_effective_state=entity_root_effective_state,
        entity_leaf_local_state=entity_leaf_local_state,
        bdd_conjectures=bdd_conjectures,
    )
    Path(args.out_html).write_text(html)

    txt = _render_text_tree(
        root_name=root,
        root_node=root_node,
        defs=defs,
        leaf_truth=leaf_truth,
        entity_root_effective_state=entity_root_effective_state,
        entity_leaf_local_state=entity_leaf_local_state,
    )
    Path(args.out_txt).write_text(txt)

    # Also emit a small machine-readable summary next to outputs.
    root_eval, _ = _eval_node(
        root_node,
        defs,
        leaf_truth,
        entity_root_effective_state=entity_root_effective_state,
        entity_leaf_local_state=entity_leaf_local_state,
    )
    meta = {
        "root": root,
        "root_label": str(root_eval.effective_state or ""),
        "root_is_valid": bool(root_eval.effective_state == "VALID"),
        "summary": str(summary_path),
        "fsl": str(fsl_path),
    }
    meta_path = Path(args.out_txt).with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print(f"[DONE] wrote {args.out_html}")
    print(f"[DONE] wrote {args.out_txt}")
    print(f"[DONE] wrote {meta_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
