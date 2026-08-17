"""
Audit an Elastispec DSL (FSL) specification against a Batfish snapshot.

This is the Partial Spec Verifier (Auditor) component of Elastispec.

Goal
----
Given:
- a Batfish snapshot directory built by `auditor/scripts/build_snapshot.py`
  (firewall config + inventory-derived role→IP mapping), and
- an FSL specification file (e.g. produced by the translator component)

This script:
1) Extracts every *leaf connection* of the form:
     ((SrcRole, *) -> (DstRole, <ports>) on <proto[, proto...]>)
   together with its AND/OR/optional ("?") context in the spec.
2) Converts each leaf connection into Batfish reachability queries using the
   snapshot's role→IP mapping (role_ip_mapping.json, which also carries the
   absent/web role markers), constraining flow origins via startLocation to
   avoid source-IP spoofing.
3) Classifies each leaf as VALID, UNSAT, or CONJECTURED-SAT. Unresolved sources
   use symbolic satisfying IP sets; unresolved destinations use a consistent
   concrete witness from the modeled interfaces. Composite source conjectures
   use BDD intersection (AND) or union (OR), excluding optional children from
   parent satisfiability.

Intermediate output
-------------------
These files are consumed by run_auditor.py and are not formal artifact output.

- <output_dir>/audit_<fsl_stem>.verification.json  full per-leaf details
- <output_dir>/audit_<fsl_stem>.summary.txt        one line per leaf (skim-first)
- <output_dir>/conjectures_detail/audit_<fsl_stem>.conjectures_detail.txt
                                                   per-entity conjectures by node
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints


@dataclass(frozen=True)
class LeafFlow:
    src_role: str
    dst_role: str
    ports_expr: str  # e.g. "443", "9163, 9164", "49152-65535", "*"
    protos: Tuple[str, ...]  # e.g. ("tcp",) or ("tcp","udp")
    # Context from FSL structure:
    # - under_optional: this leaf is gated by a trailing '?' somewhere on its path from the root spec
    # - under_or: this leaf is part of an OR-choice somewhere on its path from the root spec
    under_optional: bool = False
    under_or: bool = False


def _split_ports_expr(ports_expr: str) -> List[str]:
    """
    Split an FSL ports expression into per-port leaves.

    User requirement: treat "port1,port2,...,portN" as N separate rules.

    Notes:
    - "*" stays as ["*"] (unconstrained).
    - Ranges like "49152-65535" stay as ["49152-65535"] (single rule).
    - If there are commas, we split on "," and return the non-empty parts.
    """
    p = str(ports_expr or "").strip().replace(" ", "").rstrip("?")
    if not p:
        return ["*"]
    if p == "*":
        return ["*"]
    if "," not in p:
        return [p]
    parts = [x.strip() for x in p.split(",") if x.strip()]
    return parts or [p]


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(text or "").strip())
    return s[:80] or "audit"


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r") as f:
        return json.load(f)


def _load_role_ip_mapping(snapshot_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load the snapshot's role mapping produced by auditor/scripts/build_snapshot.py.

    One record per role, mirroring the inventory file format:
      {
        "Role":       {"host_ip": ["10.0.0.1", "..."]},
        "WebRole":    {"host_ip": ["203.0.113.10"], "kind": "web"},
        "AbsentRole": {"host_ip": []}
      }
    A role listed with an empty host_ip is known-absent; a role missing from
    the file entirely is unmapped (candidate for conjecture).
    """
    p = snapshot_dir / "role_ip_mapping.json"
    if not p.exists():
        return {}
    try:
        data = _load_json(p)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _role_ip_map_multi_from_mapping(mapping: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Extract role -> [host IPs] from the combined role mapping."""
    out: Dict[str, List[str]] = {}
    for role, rec in (mapping or {}).items():
        if not isinstance(rec, dict):
            continue
        ips = rec.get("host_ip")
        if isinstance(ips, str):
            ips = [ips]
        if not isinstance(ips, list):
            continue
        vals = [str(x).strip() for x in ips if str(x).strip()]
        if vals:
            out[str(role)] = vals
    return out


def _role_special_cases_from_mapping(mapping: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Extract role -> {kind} for special roles in the combined mapping:
    - an explicit kind marker (currently "web"), or
    - an empty host_ip list, which means the role is known-absent.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for role, rec in (mapping or {}).items():
        if not isinstance(rec, dict):
            continue
        kind = str(rec.get("kind") or "").strip().lower()
        if not kind:
            ips = rec.get("host_ip")
            if ips is None:
                ips = []
            if isinstance(ips, str):
                ips = [ips]
            vals = [str(x).strip() for x in ips if str(x).strip()] if isinstance(ips, list) else []
            if not vals:
                kind = "absent"
        if kind:
            out[str(role)] = {"kind": kind}
    return out


def _special_kind_for_role(role: str, special: Dict[str, Dict[str, Any]]) -> str | None:
    rec = special.get(str(role)) if isinstance(special, dict) else None
    if not isinstance(rec, dict):
        return None
    k = str(rec.get("kind") or "").strip().lower()
    return k or None


def _ipspec(values: Any) -> str:
    """
    Convert a list of IPs/CIDRs (or a single string) into a Batfish ipSpaceSpec.

    Batfish can represent large IP sets efficiently using BDDs, so we prefer
    passing the whole group rather than sampling a cross-product of (src,dst).
    """
    if isinstance(values, str) and values.strip():
        return values.strip()
    if isinstance(values, list):
        items = [str(v).strip() for v in values if str(v).strip()]
        # Dedup deterministically
        uniq: List[str] = []
        seen = set()
        for it in items:
            if it in seen:
                continue
            seen.add(it)
            uniq.append(it)
        return ",".join(uniq)
    return ""


def _truncate_ip_list(items: Sequence[str], limit: int = 10) -> List[str]:
    """Keep reports readable: include only the first few IPs and a suffix marker."""
    clean = [str(x).strip() for x in items if str(x).strip()]
    if len(clean) <= limit:
        return clean
    return clean[:limit] + [f"... (+{len(clean) - limit} more)"]


def _resolve_root_def(fsl_text: str, requested: str = "") -> str:
    """
    Resolve the root def name of an FSL spec.

    - If `requested` is given, it must exist in the file.
    - Otherwise use the last def in the file (specs list the aggregate def last).
    """
    names: List[str] = []
    for ln in (fsl_text or "").splitlines():
        t = ln.split("#", 1)[0].strip()
        m = re.match(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s+as\b", t, flags=re.IGNORECASE)
        if m:
            names.append(m.group(1))
    req = str(requested or "").strip()
    if req:
        if req not in names:
            raise SystemExit(f"--root def not found in FSL: {req} (available: {names})")
        return req
    if not names:
        raise SystemExit("No 'def <Name> as ...' blocks found in FSL file")
    return names[-1]


def _parse_leaf_flows_from_fsl_text(fsl_text: str, root: str = "") -> List[LeafFlow]:
    """
    Extract every leaf connection occurrence from an FSL file.

    We intentionally ignore spec logic (AND/OR/?, parentheses), and just find all
    occurrences of:
      ((Src, *) -> (Dst, ports) on proto[, proto...])
    """
    if not isinstance(fsl_text, str) or not fsl_text.strip():
        return []

    def _strip_comments(s: str) -> str:
        # Remove "# ..." comments.
        out_lines: List[str] = []
        for ln in s.splitlines():
            ln2 = ln.split("#", 1)[0]
            if ln2.strip():
                out_lines.append(ln2)
        return "\n".join(out_lines)

    def _extract_defs(s: str) -> Dict[str, str]:
        """
        Parse a very small subset of the vendor FSL format:
          def Name as <expr>
        where <expr> can span multiple lines until the next "def " or EOF.
        """
        lines = s.splitlines()
        defs: Dict[str, str] = {}
        cur_name: str | None = None
        cur_buf: List[str] = []
        for raw in lines:
            ln = raw.strip()
            if not ln:
                continue
            if ln.lower().startswith("def ") and " as" in ln.lower():
                # commit previous
                if cur_name is not None:
                    defs[cur_name] = " ".join(cur_buf).strip()
                # start new
                m = re.match(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s+as\s*(.*)$", ln, flags=re.IGNORECASE)
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
                cur_buf.append(ln)
        if cur_name is not None:
            defs[cur_name] = " ".join(cur_buf).strip()
        return defs

    # Leaf connection (allow 2+ leading parens like "(((Role,*) -> ... ))")
    # Backward compatible with both:
    #   ((Src, *) -> (Dst, 443) on tcp)
    LEAF_PAT = re.compile(
        # Non-greedy on the leading "(" run so we don't swallow the "(" that starts
        # the "(SrcRole, ...)" tuple, e.g. in "(((Src, *) -> (Dst, 443) on tcp) AND ...)".
        # NOTE: ports expression may contain commas (e.g., "9163, 9164"), so use
        # [^)]+? rather than stopping at the first comma.
        r"\(+?\s*\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)\s*on\s*([^)]+?)\s*\)",
        re.IGNORECASE,
    )

    def _parse_leaf_from_match(m: re.Match[str]) -> LeafFlow:
        src = (m.group(1) or "").strip().strip("()")
        dst = (m.group(2) or "").strip().strip("()")
        ports = (m.group(3) or "").strip()
        proto_raw = (m.group(4) or "").strip()

        ports = ports.replace(" ", "")
        ports = ports.rstrip("?")

        proto_raw = proto_raw.rstrip("?").strip()
        proto_parts = [p.strip().lower() for p in proto_raw.split(",") if p.strip()]
        proto_parts = [p for p in proto_parts if p != "any"]
        if not proto_parts:
            proto_parts = ["ip"]
        return LeafFlow(src_role=src, dst_role=dst, ports_expr=ports, protos=tuple(proto_parts))

    # ---- Parse defs and propagate (under_optional / under_or) context from the root spec ----
    text = _strip_comments(fsl_text or "")
    defs = _extract_defs(text)
    if not defs:
        # Fallback: just extract leaves from raw text.
        flat = text.replace("\n", " ")
        base = [_parse_leaf_from_match(m) for m in LEAF_PAT.finditer(flat)]
        expanded: List[LeafFlow] = []
        for f in base:
            for port in _split_ports_expr(f.ports_expr):
                expanded.append(
                    LeafFlow(
                        src_role=f.src_role,
                        dst_role=f.dst_role,
                        ports_expr=port,
                        protos=f.protos,
                        under_optional=bool(f.under_optional),
                        under_or=bool(f.under_or),
                    )
                )
        return expanded

    # Root: use the caller-provided root when valid, else fall back to the
    # last def in the file.
    if not root or root not in defs:
        root = list(defs.keys())[-1]

    # Tokenize def expressions into a minimal token stream:
    # - LEAF (stored inline)
    # - IDENT
    # - AND / OR
    # - ( / ) / ?
    def _tokenize(expr: str) -> List[Any]:
        tokens: List[Any] = []
        i = 0
        s = expr
        while i < len(s):
            ch = s[i]
            if ch.isspace():
                i += 1
                continue
            # Leaf connection must be detected BEFORE consuming '(' as punctuation.
            m = LEAF_PAT.match(s, i)
            if m:
                lf = _parse_leaf_from_match(m)
                tokens.append(("LEAF", lf))
                i = m.end()
                continue
            if ch in "()?":
                tokens.append(ch)
                i += 1
                continue
            # Operators
            if s[i : i + 3].upper() == "AND" and (i + 3 == len(s) or not s[i + 3].isalnum()):
                tokens.append("AND")
                i += 3
                continue
            if s[i : i + 2].upper() == "OR" and (i + 2 == len(s) or not s[i + 2].isalnum()):
                tokens.append("OR")
                i += 2
                continue
            # Identifier
            m2 = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i:])
            if m2:
                tokens.append(("IDENT", m2.group(0)))
                i += len(m2.group(0))
                continue
            # Unknown char: skip
            i += 1
        return tokens

    # Pratt-ish parser with AND higher precedence than OR.
    class _Node:
        __slots__ = ("kind", "value", "left", "right", "child", "optional")

        def __init__(
            self,
            kind: str,
            value: Any = None,
            left: "_Node | None" = None,
            right: "_Node | None" = None,
            child: "_Node | None" = None,
            optional: bool = False,
        ) -> None:
            self.kind = kind
            self.value = value
            self.left = left
            self.right = right
            self.child = child
            self.optional = optional

    def _parse_expr(tokens: List[Any]) -> _Node | None:
        pos = 0

        def peek() -> Any:
            return tokens[pos] if pos < len(tokens) else None

        def eat() -> Any:
            nonlocal pos
            t = tokens[pos] if pos < len(tokens) else None
            pos += 1
            return t

        def parse_primary() -> _Node | None:
            t = peek()
            if t is None:
                return None
            if t == "(":
                eat()
                inner = parse_or()
                if peek() == ")":
                    eat()
                node = inner
            elif isinstance(t, tuple) and t[0] == "LEAF":
                eat()
                node = _Node("LEAF", value=t[1])
            elif isinstance(t, tuple) and t[0] == "IDENT":
                eat()
                node = _Node("IDENT", value=t[1])
            else:
                eat()
                node = None

            # Optional marker applies to the preceding primary/group.
            if node is not None and peek() == "?":
                eat()
                node = _Node("OPT", child=node, optional=True)
            return node

        def parse_and() -> _Node | None:
            node = parse_primary()
            while True:
                t = peek()
                if t != "AND":
                    break
                eat()
                rhs = parse_primary()
                if node is None:
                    node = rhs
                elif rhs is None:
                    continue
                else:
                    node = _Node("AND", left=node, right=rhs)
            return node

        def parse_or() -> _Node | None:
            node = parse_and()
            while True:
                t = peek()
                if t != "OR":
                    break
                eat()
                rhs = parse_and()
                if node is None:
                    node = rhs
                elif rhs is None:
                    continue
                else:
                    node = _Node("OR", left=node, right=rhs)
            return node

        return parse_or()

    ast_cache: Dict[str, _Node | None] = {}

    def _ast_for_def(name: str) -> _Node | None:
        if name in ast_cache:
            return ast_cache[name]
        expr = defs.get(name)
        if not expr:
            ast_cache[name] = None
            return None
        tokens = _tokenize(expr)
        node = _parse_expr(tokens)
        ast_cache[name] = node
        return node

    # Traverse from root to collect leaf occurrences + context flags.
    flows: List[LeafFlow] = []
    # Important: the same def can be referenced under different contexts (e.g.
    # once directly and once under a trailing '?'), so we must NOT collapse
    # traversal by def name alone.
    seen_defs: set[Tuple[str, bool, bool]] = set()
    visiting_defs: set[str] = set()

    def _walk(node: _Node | None, under_optional: bool, under_or: bool) -> None:
        if node is None:
            return
        k = node.kind
        if k == "OPT":
            _walk(node.child, under_optional=True or under_optional, under_or=under_or)
            return
        if k == "OR":
            _walk(node.left, under_optional=under_optional, under_or=True or under_or)
            _walk(node.right, under_optional=under_optional, under_or=True or under_or)
            return
        if k == "AND":
            _walk(node.left, under_optional=under_optional, under_or=under_or)
            _walk(node.right, under_optional=under_optional, under_or=under_or)
            return
        if k == "IDENT":
            name = str(node.value or "")
            if not name:
                return
            key = (name, bool(under_optional), bool(under_or))
            if key in seen_defs:
                return
            # Prevent infinite recursion on cycles (shouldn't happen in vendor files,
            # but be defensive).
            if name in visiting_defs:
                return
            seen_defs.add(key)
            visiting_defs.add(name)
            try:
                _walk(_ast_for_def(name), under_optional=under_optional, under_or=under_or)
            finally:
                visiting_defs.discard(name)
            return
        if k == "LEAF":
            lf: LeafFlow = node.value
            flows.append(
                LeafFlow(
                    src_role=lf.src_role,
                    dst_role=lf.dst_role,
                    ports_expr=lf.ports_expr,
                    protos=lf.protos,
                    under_optional=bool(under_optional),
                    under_or=bool(under_or),
                )
            )
            return

    _walk(_ast_for_def(root), under_optional=False, under_or=False)

    # Always do a raw regex extraction as a safety net. Some vendor files have
    # unbalanced parentheses or other formatting that can cause the AST parser to
    # drop suffix subexpressions while still returning a non-empty partial set.
    #
    # The user expectation is: the final report must cover the same set of unique
    # 5-tuples present in the FSL text.
    flat = text.replace("\n", " ")
    raw_leaves = [_parse_leaf_from_match(m) for m in LEAF_PAT.finditer(flat)]

    if not flows:
        expanded0: List[LeafFlow] = []
        for f in raw_leaves:
            for port in _split_ports_expr(f.ports_expr):
                expanded0.append(
                    LeafFlow(
                        src_role=f.src_role,
                        dst_role=f.dst_role,
                        ports_expr=port,
                        protos=f.protos,
                        under_optional=bool(f.under_optional),
                        under_or=bool(f.under_or),
                    )
                )
        return expanded0

    # Merge any raw-extracted leaves that the AST walk missed.
    #
    # Context flags (under_optional / under_or) are best-effort and may be unknown
    # for these merged leaves; default them to False to avoid over-claiming.
    seen_5t: set[Tuple[str, str, str, Tuple[str, ...]]] = set(
        (f.src_role, f.dst_role, f.ports_expr, tuple(f.protos)) for f in flows
    )
    for rf in raw_leaves:
        k = (rf.src_role, rf.dst_role, rf.ports_expr, tuple(rf.protos))
        if k in seen_5t:
            continue
        seen_5t.add(k)
        flows.append(
            LeafFlow(
                src_role=rf.src_role,
                dst_role=rf.dst_role,
                ports_expr=rf.ports_expr,
                protos=rf.protos,
                under_optional=False,
                under_or=False,
            )
        )
    expanded2: List[LeafFlow] = []
    for f in flows:
        for port in _split_ports_expr(f.ports_expr):
            expanded2.append(
                LeafFlow(
                    src_role=f.src_role,
                    dst_role=f.dst_role,
                    ports_expr=port,
                    protos=f.protos,
                    under_optional=bool(f.under_optional),
                    under_or=bool(f.under_or),
                )
            )
    return expanded2


def _dedup_leaf_flows(flows: Sequence[LeafFlow]) -> List[LeafFlow]:
    """Deduplicate flows deterministically (stable-ish order)."""
    seen: set[Tuple[str, str, str, Tuple[str, ...], bool, bool]] = set()
    out: List[LeafFlow] = []
    for f in flows:
        # Keep context flags stable during dedup: two identical 5-tuples but with different
        # context should not collapse (it matters for "optional vs mandatory" triage).
        key = (f.src_role, f.dst_role, f.ports_expr, tuple(f.protos), bool(f.under_optional), bool(f.under_or))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _parse_fsl_to_ast(
    fsl_text: str,
    root: str,
) -> Tuple[Dict[str, str], Any, Any]:
    """
    Parse FSL and return (defs, root_node, ast_for_def).
    root_node is the AST for the root def; ast_for_def(name) returns AST for def `name`.
    Returns (defs, None, lambda: None) if parse fails.
    """
    def _strip_comments(s: str) -> str:
        return "\n".join([ln.split("#", 1)[0] for ln in (s or "").splitlines() if ln.split("#", 1)[0].strip()])

    def _extract_defs(s: str) -> Dict[str, str]:
        defs: Dict[str, str] = {}
        cur_name: Optional[str] = None
        cur_buf: List[str] = []
        for ln in (s or "").splitlines():
            t = ln.strip()
            if not t:
                continue
            if t.lower().startswith("def ") and " as" in t.lower():
                if cur_name is not None:
                    defs[cur_name] = " ".join(cur_buf).strip()
                m = re.match(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s+as\s*(.*)$", t, re.IGNORECASE)
                cur_name = m.group(1).strip() if m else None
                cur_buf = [m.group(2).strip()] if m and m.group(2) else []
            elif cur_name is not None:
                cur_buf.append(t)
        if cur_name is not None:
            defs[cur_name] = " ".join(cur_buf).strip()
        return defs

    LEAF_PAT = re.compile(
        r"\(+?\s*\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)\s*on\s*([^)]+?)\s*\)",
        re.IGNORECASE,
    )

    def _leaf_strs_from_match(m: re.Match[str]) -> List[str]:
        src = (m.group(1) or "").strip().strip("()")
        dst = (m.group(2) or "").strip().strip("()")
        ports_raw = (m.group(3) or "").strip().replace(" ", "").rstrip("?")
        proto_raw = (m.group(4) or "").strip().rstrip("?").strip()
        protos = [p.strip().lower() for p in proto_raw.split(",") if p.strip() and p.strip() != "any"]
        if not protos:
            protos = ["ip"]
        ports_list = _split_ports_expr(ports_raw)
        out: List[str] = []
        for port in ports_list:
            for proto in protos:
                out.append(f"(({src}, *) -> ({dst}, {port}) on {proto})")
        return out

    text = _strip_comments(fsl_text or "")
    defs = _extract_defs(text)
    if not defs or root not in defs:
        return ({}, None, lambda _: None)

    def _tokenize(expr: str) -> List[Any]:
        tokens: List[Any] = []
        s = expr or ""
        i = 0
        while i < len(s):
            if s[i].isspace():
                i += 1
                continue
            if s[i] == "(":
                j = i
                while j < len(s) and s[j] == "(":
                    j += 1
                if (j - i) >= 2:
                    m = LEAF_PAT.match(s, j - 2)
                    if m:
                        for _ in range(i, j - 2):
                            tokens.append("(")
                        for index, ls in enumerate(_leaf_strs_from_match(m)):
                            if index > 0:
                                tokens.append("AND")
                            tokens.append(("LEAF", ls))
                        i = m.end()
                        continue
            if s[i] in "()?":
                tokens.append(s[i])
                i += 1
                continue
            if s[i : i + 3].upper() == "AND" and (i + 3 >= len(s) or not s[i + 3].isalnum()):
                tokens.append("AND")
                i += 3
                continue
            if s[i : i + 2].upper() == "OR" and (i + 2 >= len(s) or not s[i + 2].isalnum()):
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

    class _Node:
        __slots__ = ("kind", "value", "left", "right", "child")

        def __init__(
            self,
            kind: str,
            value: Any = None,
            left: "_Node | None" = None,
            right: "_Node | None" = None,
            child: "_Node | None" = None,
        ) -> None:
            self.kind = kind
            self.value = value
            self.left = left
            self.right = right
            self.child = child

    def _parse_expr(tokens: List[Any]) -> _Node | None:
        def parse_primary(p: int) -> Tuple[_Node | None, int]:
            if p >= len(tokens):
                return None, p
            t = tokens[p]
            if t == "(":
                n, p2 = parse_or(p + 1)
                if p2 < len(tokens) and tokens[p2] == ")":
                    p2 += 1
                node = _Node("GROUP", child=n) if n else None
                if p2 < len(tokens) and tokens[p2] == "?":
                    p2 += 1
                    node = _Node("OPT", child=node) if node else None
                return node, p2
            if isinstance(t, tuple) and t and t[0] == "LEAF":
                p2 = p + 1
                node = _Node("LEAF", value=t[1])
                if p2 < len(tokens) and tokens[p2] == "?":
                    p2 += 1
                    node = _Node("OPT", child=node)
                return node, p2
            if isinstance(t, tuple) and t and t[0] == "IDENT":
                p2 = p + 1
                node = _Node("IDENT", value=t[1])
                if p2 < len(tokens) and tokens[p2] == "?":
                    p2 += 1
                    node = _Node("OPT", child=node)
                return node, p2
            return None, p + 1

        def parse_and(p: int) -> Tuple[_Node | None, int]:
            left, p = parse_primary(p)
            while p < len(tokens) and tokens[p] == "AND":
                right, p2 = parse_primary(p + 1)
                left = _Node("AND", left=left, right=right) if (left and right) else (left or right)
                p = p2
                if p < len(tokens) and tokens[p] == "?":
                    p += 1
                    left = _Node("OPT", child=left) if left else left
            return left, p

        def parse_or(p: int) -> Tuple[_Node | None, int]:
            left, p = parse_and(p)
            while p < len(tokens) and tokens[p] == "OR":
                right, p2 = parse_and(p + 1)
                left = _Node("OR", left=left, right=right) if (left and right) else (left or right)
                p = p2
                if p < len(tokens) and tokens[p] == "?":
                    p += 1
                    left = _Node("OPT", child=left) if left else left
            return left, p

        n, _ = parse_or(0)
        return n

    ast_cache: Dict[str, _Node | None] = {}

    def _ast_for_def(name: str) -> _Node | None:
        if name in ast_cache:
            return ast_cache[name]
        expr = defs.get(name)
        if not expr:
            ast_cache[name] = None
            return None
        toks = _tokenize(expr)
        ast_cache[name] = _parse_expr(toks)
        return ast_cache[name]

    root_node = _ast_for_def(root)
    return (defs, root_node, _ast_for_def)


def _compute_entity_conjecture_recursive(
    fsl_text: str,
    root: str,
    entity_conjectures: Dict[str, List[Tuple[str, Dict[str, Any]]]],
    bdd_to_pairs_fn: Any,
    pairs_to_all_ingresses_fn: Any,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """
    Compute entity conjectures with node-level outputs:
    - local: node-level conjecture including optional child content
    - effective: conjecture contributed upward (OPT children are removed/ignored)

    Combination over both layers uses AND=intersect, OR=union, with ABSENT semantics:
    - combine(ABSENT, A) = A
    - combine(ABSENT, ABSENT) = ABSENT

    Returns:
      (entity_effective_root, entity_node_details)
    """
    defs, root_node, _ast_for_def = _parse_fsl_to_ast(fsl_text, root)
    if not defs or root_node is None:
        return ({}, {})

    leaf_role_re = re.compile(r"^\(\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,")

    def _pairs_state_to_record(pairs: Optional[set[Tuple[str, str]]]) -> Dict[str, Any]:
        if pairs is None:
            return {"state": "absent", "all_ingresses": [], "prefixes": [], "prefixes_ranges": []}
        all_ing = pairs_to_all_ingresses_fn(pairs) if pairs else []
        all_prefixes: List[str] = []
        all_ranges: List[str] = []
        for rec in all_ing:
            rngs = rec.get("prefixes_ranges") or []
            all_prefixes.extend(rec.get("prefixes") or [])
            all_ranges.extend(rngs)
        return {
            "state": "set" if pairs else "empty",
            "all_ingresses": all_ing,
            "prefixes": all_prefixes,
            "prefixes_ranges": all_ranges,
        }

    def _combine_absent_aware(
        op: str,
        left: Optional[set[Tuple[str, str]]],
        right: Optional[set[Tuple[str, str]]],
    ) -> Optional[set[Tuple[str, str]]]:
        # ABSENT means "this node does not participate".
        if left is None and right is None:
            return None
        if left is None:
            return right
        if right is None:
            return left
        return (left & right) if op == "AND" else (left | right)

    entity_intersected: Dict[str, Dict[str, Any]] = {}
    entity_node_details: Dict[str, Dict[str, Any]] = {}
    for entity, leaf_bdd_list in entity_conjectures.items():
        leaf_to_pairs: Dict[str, set[Tuple[str, str]]] = {}
        for leaf_str, bdd in leaf_bdd_list or []:
            if isinstance(bdd, dict):
                leaf_to_pairs[leaf_str] = bdd_to_pairs_fn(bdd)

        def_conjectures: Dict[str, Dict[str, Any]] = {}
        leaf_conjectures: List[Dict[str, Any]] = []

        def _eval_node(
            node: Any,
            visiting: set[str],
            under_optional: bool = False,
        ) -> Tuple[Optional[set[Tuple[str, str]]], Optional[set[Tuple[str, str]]]]:
            # Returns (local_pairs, effective_pairs)
            if node is None:
                return (None, None)
            if node.kind == "LEAF":
                leaf_str = str(node.value or "")
                pairs = leaf_to_pairs.get(leaf_str)  # None = ABSENT (no constraint data)
                m = leaf_role_re.match(leaf_str)
                role_pos = "unknown"
                if m:
                    src_role = (m.group(1) or "").strip().strip("()")
                    dst_role = (m.group(2) or "").strip().strip("()")
                    if entity == src_role == dst_role:
                        role_pos = "both"
                    elif entity == src_role:
                        role_pos = "src"
                    elif entity == dst_role:
                        role_pos = "dst"
                if role_pos != "unknown":
                    leaf_conjectures.append(
                        {
                            "leaf": leaf_str,
                            "under_optional": bool(under_optional),
                            "role_position": role_pos,
                            "has_bdd": bool(pairs is not None),
                            "local": _pairs_state_to_record(pairs),
                            "effective": _pairs_state_to_record(pairs),
                        }
                    )
                return (pairs, pairs)
            if node.kind == "GROUP":
                return _eval_node(node.child, visiting, under_optional=under_optional)
            if node.kind == "OPT":
                child_local, _child_effective = _eval_node(node.child, visiting, under_optional=True)
                # Optional child is still visible locally, but removed from parent consistency.
                return (child_local, None)
            if node.kind == "IDENT":
                n = str(node.value or "")
                if not n or n in visiting or n not in defs:
                    return (None, None)
                visiting.add(n)
                try:
                    local_pairs, effective_pairs = _eval_node(_ast_for_def(n), visiting, under_optional=under_optional)
                finally:
                    visiting.discard(n)
                def_conjectures[n] = {
                    "local": _pairs_state_to_record(local_pairs),
                    "effective": _pairs_state_to_record(effective_pairs),
                }
                return (local_pairs, effective_pairs)
            if node.kind == "AND":
                l_local, l_eff = _eval_node(node.left, visiting, under_optional=under_optional)
                r_local, r_eff = _eval_node(node.right, visiting, under_optional=under_optional)
                return (
                    _combine_absent_aware("AND", l_local, r_local),
                    _combine_absent_aware("AND", l_eff, r_eff),
                )
            if node.kind == "OR":
                l_local, l_eff = _eval_node(node.left, visiting, under_optional=under_optional)
                r_local, r_eff = _eval_node(node.right, visiting, under_optional=under_optional)
                return (
                    _combine_absent_aware("OR", l_local, r_local),
                    _combine_absent_aware("OR", l_eff, r_eff),
                )
            return (None, None)

        root_local, root_effective = _eval_node(root_node, set(), under_optional=False)
        node_info = {
            "root": {
                "def": root,
                "local": _pairs_state_to_record(root_local),
                "effective": _pairs_state_to_record(root_effective),
            },
            "definitions": def_conjectures,
            "leaves": sorted(
                leaf_conjectures,
                key=lambda x: (
                    0 if not x.get("under_optional") else 1,
                    str(x.get("role_position") or ""),
                    str(x.get("leaf") or ""),
                ),
            ),
        }
        entity_node_details[entity] = node_info

        if root_effective:
            eff = _pairs_state_to_record(root_effective)
            entity_intersected[entity] = {
                "all_ingresses": eff["all_ingresses"],
                "prefixes": eff["prefixes"],
                "prefixes_ranges": eff["prefixes_ranges"],
            }
    return (entity_intersected, entity_node_details)


def _classify_unmapped_source_leaf(
    entity: str,
    leaf: str,
    entity_intersected: Dict[str, Dict[str, Any]],
    entity_node_conjectures: Dict[str, Dict[str, Any]],
) -> Tuple[str, str]:
    """Return the leaf verdict and source-BDD state used to derive it."""
    if entity not in entity_intersected:
        return ("UNSAT", "inconsistent")

    entity_details = entity_node_conjectures.get(entity) or {}
    for record in entity_details.get("leaves") or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("leaf") or "") != leaf:
            continue
        if str(record.get("role_position") or "") not in {"src", "both"}:
            continue
        local = record.get("local") or {}
        state = str(local.get("state") or "absent").strip().lower()
        if state == "set":
            return ("CONJECTURED-SAT", state)
        if state == "empty":
            return ("UNSAT", state)
        return ("UNSAT", "absent")

    return ("UNSAT", "absent")


def _map_role_to_ips(role: str, role_ip_map: Dict[str, List[str]]) -> List[str]:
    if not isinstance(role, str) or not role.strip():
        return []
    role = role.strip()
    if role == "*":
        return ["0.0.0.0/0"]
    return role_ip_map.get(role, [])


def _detect_fw_node(bf: Session, snapshot_name: str, config_filename: str) -> str:
    """
    Best-effort choose the firewall/config node name in Batfish.

    In this repo, we copy the config file into the snapshot under its filename
    (e.g. toy_firewall_config.txt). Batfish typically
    uses that filename as both Node and Hostname.
    """
    cfg = str(config_filename or "").strip()
    try:
        df = bf.q.nodeProperties().answer(snapshot=snapshot_name).frame()
        if df.empty:
            return cfg or "papercut_full_config.txt"
        if "Hostname" in df.columns and "Node" in df.columns:
            m = df[df["Hostname"].astype(str) == cfg]
            if not m.empty:
                return str(m.iloc[0]["Node"])
        if "Node" in df.columns:
            if (df["Node"].astype(str) == cfg).any():
                return cfg
            m2 = df[df["Node"].astype(str).str.contains(re.escape(cfg), na=False)]
            if not m2.empty:
                return str(m2.iloc[0]["Node"])
        if "Interfaces" in df.columns and "Node" in df.columns:
            df2 = df.copy()
            df2["iface_count"] = df2["Interfaces"].apply(lambda x: len(x) if isinstance(x, list) else 0)
            df2 = df2.sort_values("iface_count", ascending=False)
            return str(df2.iloc[0]["Node"])
    except Exception:
        pass
    return cfg or "papercut_full_config.txt"


def _fw_interface_table(bf: Session, fw_node: str, snapshot_name: str) -> List[Tuple[str, str]]:
    """Return [(ifaceName, primary_network)] for fw_node."""
    try:
        df = bf.q.interfaceProperties(nodes=fw_node).answer(snapshot=snapshot_name).frame()
        if df.empty or "Interface" not in df.columns or "Primary_Network" not in df.columns:
            return []
        out: List[Tuple[str, str]] = []
        for _, row in df.iterrows():
            iface_full = str(row.get("Interface") or "")
            pfx = str(row.get("Primary_Network") or "")
            if not iface_full or not pfx or pfx == "None":
                continue
            # iface_full is like "node[GigabitEthernet0/57]"
            iface = iface_full
            if "[" in iface_full and "]" in iface_full:
                iface = iface_full.split("[", 1)[1].split("]", 1)[0]
            out.append((iface, pfx))
        return out
    except Exception:
        return []


def _bucket_src_specs_by_fw_interface(
    fw_ifaces: Sequence[Tuple[str, str]],
    src_specs: Sequence[str],
) -> Dict[str, List[str]]:
    """
    Map source IP/CIDR sets to firewall interfaces by network overlap.

    If a mapped CIDR spans several modeled interface networks, each interface
    receives the portion of that CIDR that lies on its network.
    """
    import ipaddress

    nets: List[Tuple[str, ipaddress.IPv4Network]] = []
    for iface, pfx in fw_ifaces:
        try:
            net = ipaddress.ip_network(pfx, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets.append((iface, net))
        except Exception:
            continue

    buckets: Dict[str, List[str]] = {}
    for raw_spec in src_specs:
        spec = str(raw_spec or "").strip()
        if not spec:
            continue
        try:
            value = ipaddress.ip_network(spec, strict=False) if "/" in spec else ipaddress.ip_address(spec)
        except Exception:
            continue
        if isinstance(value, ipaddress.IPv4Address):
            for iface, net in nets:
                if value in net:
                    buckets.setdefault(iface, []).append(str(value))
                    break
            continue
        if not isinstance(value, ipaddress.IPv4Network):
            continue
        for iface, net in nets:
            if not value.overlaps(net):
                continue
            overlap = value if value.subnet_of(net) else net
            bucket = buckets.setdefault(iface, [])
            overlap_s = str(overlap)
            if overlap_s not in bucket:
                bucket.append(overlap_s)
    return buckets


def _bucket_src_ips_by_fw_interface(
    fw_ifaces: Sequence[Tuple[str, str]],
    src_ips: Sequence[str],
) -> Dict[str, List[str]]:
    """
    Map concrete src IPs to fw interfaces by Primary_Network containment.
    Returns: ifaceName -> [srcIp,...]
    """
    import ipaddress

    nets: List[Tuple[str, ipaddress.IPv4Network]] = []
    for iface, pfx in fw_ifaces:
        try:
            net = ipaddress.ip_network(pfx, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets.append((iface, net))
        except Exception:
            continue

    buckets: Dict[str, List[str]] = {}
    for ip_s in src_ips:
        s = str(ip_s or "").strip()
        if not s or "/" in s:
            continue
        try:
            ip = ipaddress.ip_address(s)
        except Exception:
            continue
        for iface, net in nets:
            if ip in net:
                buckets.setdefault(iface, []).append(s)
                break
    return buckets


def _search_filters_for_headers(
    bf: Session,
    headers: Dict[str, Any],
    snapshot_name: str,
) -> List[Dict[str, Any]]:
    hc = HeaderConstraints(
        srcIps=headers.get("srcIps"),
        dstIps=headers.get("dstIps"),
        dstPorts=headers.get("dstPorts"),
        ipProtocols=headers.get("ipProtocols"),
    )
    try:
        ans = bf.q.searchFilters(headers=hc).answer(snapshot=snapshot_name)
        df = ans.frame()
        if df.empty:
            return []
        cols = [c for c in ["Node", "Filter_Name", "Line_Content"] if c in df.columns]
        if cols:
            df = df[cols]
        return df.to_dict(orient="records")
    except Exception:
        return []


def _reachability_for_group_headers(
    bf: Session,
    headers: Dict[str, Any],
    snapshot_name: str,
    start_locations: Sequence[str] | None,
    actions: str,
    max_traces: int = 5,
) -> Tuple[bool, List[Any]]:
    """
    Run reachability for a group header space and return:
      (reachable_exists, witness_flows)
    where witness_flows is a small list of pybatfish Flow objects (examples).
    """
    hc = HeaderConstraints(
        srcIps=headers.get("srcIps"),
        dstIps=headers.get("dstIps"),
        dstPorts=headers.get("dstPorts"),
        ipProtocols=headers.get("ipProtocols"),
    )
    pc = None
    if start_locations:
        pc = PathConstraints(startLocation=",".join([str(x) for x in start_locations if str(x).strip()]))
    try:
        if pc is not None:
            ans = bf.q.reachability(headers=hc, pathConstraints=pc, maxTraces=max_traces, actions=actions).answer(
                snapshot=snapshot_name
            )
        else:
            ans = bf.q.reachability(headers=hc, maxTraces=max_traces, actions=actions).answer(snapshot=snapshot_name)
        df = ans.frame()
    except Exception as exc:
        raise RuntimeError(f"Batfish reachability query failed for actions={actions!r}") from exc
    if df.empty:
        return False, []
    flows: List[Any] = []
    if "Flow" in df.columns:
        for i in range(min(3, len(df))):
            flows.append(df.iloc[i].get("Flow"))
    return True, flows


def _parse_acl_any_sides(line_content: str) -> Tuple[bool, bool]:
    """
    Best-effort parse of a Batfish ACL line content and detect whether the
    *source* or *destination* is the wildcard "any".

    We only need a coarse signal to support "case 1" classification:
      - permit ip X any
      - permit ip any X
      - permit tcp X any eq 443
      - permit tcp any X eq 443

    Returns: (src_is_any, dst_is_any)
    """
    s = str(line_content or "").strip().lower()
    toks = [t for t in s.split() if t]
    if not toks:
        return False, False
    if "permit" not in toks:
        return False, False
    try:
        i = toks.index("permit")
    except ValueError:
        return False, False
    # Expect: permit <proto> <srcSpec...> <dstSpec...> ...
    if i + 2 >= len(toks):
        return False, False
    # proto token is toks[i+1], then src starts at i+2
    j = i + 2

    def is_any(tok: str) -> bool:
        return tok in ("any", "any4")

    def looks_like_ip(tok: str) -> bool:
        # very permissive; works for dotted-decimal and CIDR-ish tokens Batfish may emit
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", tok))

    def consume_endpoint(k: int) -> Tuple[bool, int]:
        if k >= len(toks):
            return False, k
        t = toks[k]
        if is_any(t):
            return True, k + 1
        # Common patterns: host <ip>, object-group <name>, object <name>
        if t == "host" and k + 1 < len(toks):
            return False, k + 2
        if t in ("object-group", "object") and k + 1 < len(toks):
            return False, k + 2
        # IP or prefix + optional wildcard/mask token
        if looks_like_ip(t):
            k2 = k + 1
            if k2 < len(toks) and looks_like_ip(toks[k2]):
                return False, k2 + 1
            return False, k2
        # Fallback: consume one token
        return False, k + 1

    src_any, j2 = consume_endpoint(j)
    dst_any, _j3 = consume_endpoint(j2)
    return src_any, dst_any


def _summarize_any_hit(filters: Sequence[Dict[str, Any]], side: str) -> bool:
    """
    Heuristic: did searchFilters match a permit that uses wildcard "any" on the
    requested side?

    - side="src": look for `permit ... any ...`
    - side="dst": look for `permit ... ... any ...`
    - side="either": any on either side

    This is useful when suggesting how an unmapped entity could be satisfied.
    """
    side = str(side or "").strip().lower()
    for r in filters or []:
        if not isinstance(r, dict):
            continue
        line = str(r.get("Line_Content") or "").lower()
        if "permit" not in line:
            continue
        src_any, dst_any = _parse_acl_any_sides(line)
        if side == "src" and src_any:
            return True
        if side == "dst" and dst_any:
            return True
        if side == "either" and (src_any or dst_any):
            return True
    return False


def _flow_to_simple_5tuple(flow_obj: Any) -> Dict[str, Any]:
    """Extract a small JSON-friendly subset from a pybatfish Flow object."""
    if flow_obj is None:
        return {}
    out: Dict[str, Any] = {}
    for k, attr in [
        ("srcIp", "srcIp"),
        ("dstIp", "dstIp"),
        ("dstPort", "dstPort"),
        ("ipProtocol", "ipProtocol"),
        ("ingressNode", "ingressNode"),
    ]:
        try:
            v = getattr(flow_obj, attr, None)
            if v is not None and str(v).strip():
                out[k] = str(v)
        except Exception:
            continue
    return out


def _pick_concrete_ip_in_prefix(pfx: str) -> str | None:
    """
    Pick a deterministic concrete host IP inside an interface Primary_Network prefix.

    We avoid using the network address (e.g., x.x.x.0) because it looks confusing in reports.
    Prefer +10, then +2, else the first usable host.
    """
    import ipaddress

    s = str(pfx or "").strip()
    if not s or "/" not in s:
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            return None
        base = int(net.network_address)
        for offset in (10, 2):
            cand = ipaddress.IPv4Address(base + offset)
            if cand in net and cand != net.network_address and cand != net.broadcast_address:
                return str(cand)
        for h in net.hosts():
            return str(h)
        return None
    except Exception:
        return None


def _modeled_dst_ipspec_from_fw_ifaces(
    fw_ifaces: Sequence[Tuple[str, str]],
    max_ips: int = 200,
) -> str:
    """
    Build an ipSpaceSpec for "dst is SOMEWHERE in the modeled snapshot".

    We use one concrete /32 per firewall interface subnet, so:
    - any OK/FAIL example is guaranteed to land in a subnet that exists in the snapshot
    - examples avoid confusing .0 network addresses
    """
    ips: List[str] = []
    seen: set[str] = set()
    for _iface, pfx in fw_ifaces or []:
        ip_s = _pick_concrete_ip_in_prefix(pfx)
        if not ip_s or ip_s in seen:
            continue
        seen.add(ip_s)
        ips.append(ip_s)
        if len(ips) >= int(max_ips):
            break
    # ipSpaceSpec accepts comma-separated literals.
    return ",".join(ips)


def _modeled_ip_list_from_fw_ifaces(
    fw_ifaces: Sequence[Tuple[str, str]],
    max_ips: int = 200,
) -> List[str]:
    """
    Return a list of concrete /32 IPs, one per firewall interface prefix.
    """
    ipspec = _modeled_dst_ipspec_from_fw_ifaces(fw_ifaces, max_ips=max_ips)
    return [s for s in (ipspec.split(",") if ipspec else []) if s.strip()]


def _suggest_for_unmapped_dst(
    bf: Session,
    snapshot_name: str,
    fw_node: str,
    fw_ifaces: Sequence[Tuple[str, str]],
    src_ip_list: Sequence[str],
    headers_group: Dict[str, Any],
    max_suggestions: int,
    probe_mode: str = "focused",
    fw_ifaces_detail: Sequence[Dict[str, str]] | None = None,
) -> Dict[str, Any]:
    """
    For leaf flows where dst role is unmapped but src role is mapped:
    - try to find *some* reachable witness flow (with concrete dstIp) in this snapshot
    - attach searchFilters rows for that witness

    NOTE: This does NOT "solve" the entity name. It's only: "there exists a dstIp
    that makes this 5-tuple reachable in the snapshot".
    """
    concrete_srcs = [str(x).strip() for x in src_ip_list if isinstance(x, str) and x.strip() and "/" not in x]
    if not concrete_srcs:
        return {"found": False, "reason": "no concrete src IPs to anchor startLocation"}

    suggestions: List[Dict[str, Any]] = []
    # For "treat unmapped dst as ANY" classification:
    exists_success_any = False
    exists_failure_any = False
    ok_example: Dict[str, Any] | None = None
    fail_example: Dict[str, Any] | None = None

    # IMPORTANT semantics for *_COVERED_BY_ANY (agreed with user):
    # - One endpoint role is unmapped (here: dst).
    # - We only treat it as "ANY" if the *matched permit rule* has dst=any.
    # - SOME vs TOTAL is determined by the RESOLVED side coverage (here: src IPs):
    #     - TOTAL_COVERED_BY_ANY: every concrete src IP can reach *some modeled dst IP* under a dst-any permit
    #     - SOME_COVERED_BY_ANY:  some (but not all) concrete src IPs can do so
    #
    # Therefore:
    # - We do NOT use "actions=failure" on a giant dst space to decide SOME vs TOTAL (that mixes in dst-side misses).
    # - We instead test each resolved src IP for existence of a successful witness to a modeled destination set.
    modeled_dst_list = _modeled_ip_list_from_fw_ifaces(fw_ifaces, max_ips=200)
    modeled_dst_ipspec = ",".join(modeled_dst_list) if modeled_dst_list else "0.0.0.0/0"
    representative_dst_for_fail = (
        modeled_dst_list[0] if modeled_dst_list else "1.1.1.1"
    )  # must be concrete for failure witness

    buckets = _bucket_src_ips_by_fw_interface(fw_ifaces, concrete_srcs)
    ip_to_iface: Dict[str, str] = {}
    for iface, ips_in_iface in buckets.items():
        for ip_s in ips_in_iface:
            ip_to_iface[ip_s] = iface

    covered_srcs: set[str] = set()
    for iface, ips_in_iface in sorted(buckets.items()):
        start_spec = f"@enter({fw_node}[{iface}])"
        # Check each src IP individually so SOME/TOTAL is decided by resolved-side coverage.
        for s_ip in ips_in_iface:
            h = dict(headers_group)
            h["srcIps"] = s_ip
            h["dstIps"] = modeled_dst_ipspec
            ok, ok_flows = _reachability_for_group_headers(
                bf,
                headers=h,
                snapshot_name=snapshot_name,
                start_locations=[start_spec],
                actions="success",
                max_traces=1,
            )
            if not ok or not ok_flows:
                continue
            wf = ok_flows[0]
            headers_w = {
                "srcIps": str(getattr(wf, "srcIp", "")),
                "dstIps": str(getattr(wf, "dstIp", "")),
                "dstPorts": str(getattr(wf, "dstPort", "")) if getattr(wf, "dstPort", None) is not None else None,
                "ipProtocols": [str(getattr(wf, "ipProtocol", "")).upper()] if getattr(wf, "ipProtocol", None) else None,
            }
            headers_w = {k: v for k, v in headers_w.items() if v not in (None, "", [])}
            filters = _search_filters_for_headers(bf, headers=headers_w, snapshot_name=snapshot_name)
            allowed_any = _summarize_any_hit(filters, side="dst")
            if not allowed_any:
                # Reachable, but not via a dst-any permit line; don't count toward *_COVERED_BY_ANY.
                continue

            covered_srcs.add(s_ip)
            exists_success_any = True
            if ok_example is None:
                ok_example = _flow_to_simple_5tuple(wf)

            if len(suggestions) < max_suggestions:
                suggestions.append(
                    {
                        "startLocation": start_spec,
                        "witness": _flow_to_simple_5tuple(wf),
                        "headers": headers_w,
                        "searchFilters": filters,
                        "allowed_by_any": True,
                    }
                )

    # Determine failures based on uncovered resolved-side IPs (not dst-side misses).
    uncovered = [ip for ip in concrete_srcs if ip not in covered_srcs]
    if uncovered:
        exists_failure_any = True
        if fail_example is None:
            s_fail = sorted(uncovered)[0]
            iface = ip_to_iface.get(s_fail)
            if iface:
                start_spec = f"@enter({fw_node}[{iface}])"
                dst_for_fail = (
                    (ok_example or {}).get("dstIp") or representative_dst_for_fail
                )
                h_fail = dict(headers_group)
                h_fail["srcIps"] = s_fail
                h_fail["dstIps"] = dst_for_fail
                bad, bad_flows = _reachability_for_group_headers(
                    bf,
                    headers=h_fail,
                    snapshot_name=snapshot_name,
                    start_locations=[start_spec],
                    actions="failure",
                    max_traces=1,
                )
                if bad and bad_flows:
                    fail_example = _flow_to_simple_5tuple(bad_flows[0])
                else:
                    # Best-effort fallback when Batfish can't produce a failure flow object.
                    fail_example = {
                        "srcIp": s_fail,
                        "dstIp": str(dst_for_fail),
                        "dstPort": str(headers_group.get("dstPorts") or ""),
                        "ipProtocol": str((headers_group.get("ipProtocols") or [""])[0] or ""),
                        "ingressNode": fw_node,
                    }

    return {
        "found": bool(suggestions),
        "suggestions": suggestions,
        "exists_success_any": bool(exists_success_any),
        "exists_failure_any": bool(exists_failure_any),
        "ok_example": ok_example,
        "fail_example": fail_example,
    }


def _load_bdd_debug_dump(path: Path) -> Dict[str, Any]:
    """Load and validate the custom Batfish BDD dump."""
    if not path.exists():
        raise RuntimeError(
            f"Batfish did not produce the BDD dump at {path}. "
            "Use the Elastispec custom Batfish image and mount its data directory."
        )
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        raise RuntimeError(f"Failed to read Batfish BDD dump: {path}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("ingressLocations"), dict):
        raise RuntimeError(f"Invalid Batfish BDD dump structure: {path}")
    return data


def _run_reachability_wildcard_start_for_bdd_dump(
    bf: Session,
    snapshot_name: str,
    headers_group: Dict[str, Any],
) -> None:
    """
    Run one reachability query with startLocation=@enter(/.*/) to populate the
    custom Batfish BDD debug dump with ALL ingress locations. The dump is
    overwritten by each query, so this must run before reading it.
    """
    hc = HeaderConstraints(
        srcIps=None,
        dstIps=headers_group.get("dstIps"),
        dstPorts=headers_group.get("dstPorts"),
        ipProtocols=headers_group.get("ipProtocols"),
    )
    pc = PathConstraints(startLocation="@enter(/.*/)")
    try:
        bf.q.reachability(headers=hc, pathConstraints=pc, maxTraces=1, actions="success").answer(
            snapshot=snapshot_name
        )
    except Exception as exc:
        raise RuntimeError("Batfish symbolic reachability query failed") from exc


def _bdd_reachable_src_subnets_all_ingresses(
    bdd_debug_json_path: Path | None,
) -> Dict[str, Any] | None:
    """
    Load BDD debug dump and return aggregated reachable source subnets from
    ALL ingress locations. Used when src is unmapped and we want the full
    set of possible source subnets across all interfaces.
    """
    if bdd_debug_json_path is None:
        return None
    dump = _load_bdd_debug_dump(bdd_debug_json_path)
    ingress_locations = dump.get("ingressLocations")
    if not isinstance(ingress_locations, dict):
        raise RuntimeError("Batfish BDD dump is missing ingressLocations")
    all_prefixes: List[str] = []
    all_ranges: List[str] = []
    per_ingress: List[Dict[str, Any]] = []
    for loc_key, rec in ingress_locations.items():
        if not isinstance(rec, dict):
            continue
        prefixes = [str(x).strip() for x in (rec.get("prefixes") or []) if str(x).strip()]
        ranges = [str(x).strip() for x in (rec.get("prefixes_ranges") or []) if str(x).strip()]
        if prefixes or ranges:
            per_ingress.append({"ingressLocation": loc_key, "prefixes": prefixes, "prefixes_ranges": ranges})
            all_prefixes.extend(prefixes)
            all_ranges.extend(ranges)
    if not per_ingress:
        return None
    header_space = dump.get("headerSpace")
    return {
        "all_ingresses": per_ingress,
        "prefixes": all_prefixes,
        "prefixes_ranges": all_ranges,
        "headerSpace": str(header_space).strip() if isinstance(header_space, str) else "",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "snapshot_dir",
        help="Batfish snapshot directory built by auditor/scripts/build_snapshot.py",
    )
    ap.add_argument(
        "fsl_path",
        help="Elastispec DSL (FSL) specification file to audit",
    )
    ap.add_argument(
        "--root",
        default="",
        help=(
            "Root def name of the FSL spec. If empty, uses the last def in the file."
        ),
    )
    ap.add_argument(
        "--network",
        default="elastispec_audit_net",
        help="Batfish network name (default: elastispec_audit_net)",
    )
    ap.add_argument(
        "--snapshot",
        default="elastispec_audit_ss",
        help="Batfish snapshot name (default: elastispec_audit_ss)",
    )
    ap.add_argument(
        "--output_dir",
        default="auditor/output",
        help="Directory to write auditor outputs (default: auditor/output)",
    )
    ap.add_argument(
        "--output_slug",
        default="",
        help=(
            "Optional suffix to disambiguate outputs (and, by default, network/snapshot) "
            "when running multiple instances. Example: --output_slug papercut_8"
        ),
    )
    ap.add_argument(
        "--bdd_debug_json_path",
        default="",
        help=(
            "Path to Batfish custom debug BDD JSON dump. "
            "If empty, defaults to $HOME/batfish-data/debug_bdd_reachability.json."
        ),
    )
    ap.add_argument(
        "--batfish_host",
        default="localhost",
        help="Batfish coordinator hostname (default: localhost)",
    )
    args = ap.parse_args()

    snapshot_dir = Path(args.snapshot_dir)
    fsl_path = Path(args.fsl_path)

    # IMPORTANT: when verifying multiple instances, default network/snapshot names and
    # default output stems collide. If output_slug is provided, scope network/snapshot
    # unless the user explicitly overrode them.
    output_slug = str(getattr(args, "output_slug", "") or "").strip()
    if output_slug:
        net_default = "elastispec_audit_net"
        ss_default = "elastispec_audit_ss"
        if str(getattr(args, "network", "")).strip() == net_default:
            args.network = f"{net_default}_{_slugify(output_slug)}"
        if str(getattr(args, "snapshot", "")).strip() == ss_default:
            args.snapshot = f"{ss_default}_{_slugify(output_slug)}"

    # The snapshot's role_ip_mapping.json carries both the role->IPs mapping and
    # the absent/web markers (kind/reason), mirroring the inventory file.
    role_mapping = _load_role_ip_mapping(snapshot_dir)
    role_ip_map_multi = _role_ip_map_multi_from_mapping(role_mapping)
    role_special = _role_special_cases_from_mapping(role_mapping)
    bdd_debug_json_arg = str(getattr(args, "bdd_debug_json_path", "") or "").strip()
    if bdd_debug_json_arg:
        bdd_debug_json_path: Path | None = Path(os.path.expanduser(bdd_debug_json_arg))
    else:
        bdd_debug_json_path = Path.home() / "batfish-data" / "debug_bdd_reachability.json"

    fsl_text = fsl_path.read_text()
    spec_root = _resolve_root_def(fsl_text, requested=str(getattr(args, "root", "") or ""))
    leaf_flows = _dedup_leaf_flows(_parse_leaf_flows_from_fsl_text(fsl_text, root=spec_root))

    # Sanity helper: count unique leaf 5-tuples (incl proto) present in the FSL text.
    # This is intentionally independent from the AST traversal so we can catch partial parses.
    def _expected_leaf_5tuples_from_fsl_text(text: str) -> set[str]:
        # Strip hash comments first.
        raw = text or ""
        raw = "\n".join([ln.split("#", 1)[0] for ln in raw.splitlines()])
        flat = raw.replace("\n", " ")

        # Keep a local copy of the leaf regex so this helper does not depend on the AST parser.
        leaf_pat = re.compile(
            r"\(+?\s*\(\s*([^,]+?)\s*,\s*\*\s*\)\s*->\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)\s*on\s*([^)]+?)\s*\)",
            re.IGNORECASE,
        )

        out: set[str] = set()
        for m in leaf_pat.finditer(flat):
            src = (m.group(1) or "").strip().strip("()")
            dst = (m.group(2) or "").strip().strip("()")
            ports_raw = (m.group(3) or "").strip().replace(" ", "").rstrip("?")
            proto_raw = (m.group(4) or "").strip().rstrip("?").strip()
            proto_parts = [p.strip().lower() for p in proto_raw.split(",") if p.strip()]
            proto_parts = [p for p in proto_parts if p != "any"]
            if not proto_parts:
                proto_parts = ["ip"]
            for port in _split_ports_expr(ports_raw):
                for p in proto_parts:
                    out.add(f"(({src}, *) -> ({dst}, {port}) on {p})")
        return out

    expected_leaf_set = _expected_leaf_5tuples_from_fsl_text(fsl_text)

    # Expand one LeafFlow into per-proto queries (tcp/udp/etc).
    expanded: List[Tuple[LeafFlow, str]] = []
    for lf in leaf_flows:
        for proto in lf.protos:
            expanded.append((lf, proto))

    bf = Session(host=str(args.batfish_host))
    bf.set_network(args.network)
    bf.init_snapshot(str(snapshot_dir), name=args.snapshot, overwrite=True)
    bf.set_snapshot(args.snapshot)

    # Auto-detect the firewall config filename from the snapshot (build_snapshot.py
    # copies the firewall config under configs/configs/).
    snapshot_configs_dir = snapshot_dir / "configs" / "configs"
    fw_cfg_candidates = sorted(p.name for p in snapshot_configs_dir.glob("*") if p.is_file())
    fw_cfg_filename = fw_cfg_candidates[0] if fw_cfg_candidates else ""
    fw_node = _detect_fw_node(bf, snapshot_name=args.snapshot, config_filename=fw_cfg_filename)
    # Flow origins are anchored at firewall interfaces ("@enter(<fw>[<iface>])"),
    # so the interface inventory is always needed.
    fw_ifaces: List[Tuple[str, str]] = _fw_interface_table(bf, fw_node=fw_node, snapshot_name=args.snapshot)

    def _proto_headers(proto_s: str) -> Dict[str, Any]:
        p = (proto_s or "").strip().lower()
        if not p or p == "ip":
            return {}
        return {"ipProtocols": [p.upper()]}

    use_consistent_conjectures = True
    conjecture_unknown_roles: set[str] = set()
    unmapped_dst_probe_cache: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}

    def _cached_suggest_for_unmapped_dst(
        *,
        src_role: str,
        src_ip_list: Sequence[str],
        ports_expr: str,
        proto_s: str,
    ) -> Dict[str, Any]:
        src_ipspec = _ipspec(list(src_ip_list) if isinstance(src_ip_list, (list, tuple)) else src_ip_list)
        key = (
            str(src_role or ""),
            str(src_ipspec or ""),
            str(ports_expr or ""),
            str(proto_s or "").strip().lower(),
            "focused",
        )
        if key in unmapped_dst_probe_cache:
            return unmapped_dst_probe_cache[key]
        headers_group_tmp: Dict[str, Any] = {"dstIps": "0.0.0.0/0"}
        if ports_expr and ports_expr != "*":
            headers_group_tmp["dstPorts"] = ports_expr
        headers_group_tmp.update(_proto_headers(proto_s))
        out = _suggest_for_unmapped_dst(
            bf,
            snapshot_name=args.snapshot,
            fw_node=fw_node,
            fw_ifaces=fw_ifaces,
            fw_ifaces_detail=None,
            src_ip_list=src_ip_list,
            headers_group=headers_group_tmp,
            max_suggestions=2,
            probe_mode="focused",
        )
        unmapped_dst_probe_cache[key] = out
        return out

    def _exists_success_from_src_role_to_dst_ip(
        src_ip_list: Sequence[str],
        dst_ip: str,
        ports_expr: str,
        proto_s: str,
    ) -> bool:
        """
        Best-effort existential check:
          ∃ srcIp in src_role, can it reach dst_ip for (proto, ports_expr)?

        This is used to validate a conjectured dstIp for an unmapped destination role.
        """
        dst_ip = str(dst_ip or "").strip()
        if not dst_ip or "/" in dst_ip or dst_ip == "0.0.0.0/0":
            return False
        concrete_srcs = [str(x).strip() for x in (src_ip_list or []) if isinstance(x, str) and x.strip() and "/" not in x and x.strip() != "0.0.0.0/0"]
        if not concrete_srcs:
            return False

        headers_base: Dict[str, Any] = {"dstIps": dst_ip}
        if ports_expr and ports_expr != "*":
            headers_base["dstPorts"] = ports_expr
        headers_base.update(_proto_headers(proto_s))

        buckets = _bucket_src_ips_by_fw_interface(fw_ifaces, concrete_srcs)
        for iface, ips_in_iface in sorted(buckets.items()):
            start_spec = f"@enter({fw_node}[{iface}])"
            for s_ip in ips_in_iface:
                h = dict(headers_base)
                h["srcIps"] = s_ip
                ok, _flows = _reachability_for_group_headers(
                    bf,
                    headers=h,
                    snapshot_name=args.snapshot,
                    start_locations=[start_spec],
                    actions="success",
                    max_traces=1,
                )
                if ok:
                    return True
        return False

    def _compute_consistent_dst_conjectures() -> Dict[str, Dict[str, str]]:
        """
        Returns mapping:
          unmapped_dst_role -> {"dstIp": "<ip>"}
        """
        if not use_consistent_conjectures:
            return {}
        max_iters = int(getattr(args, "conjecture_max_iters", 5) or 5)
        probe_mode = str(getattr(args, "unmapped_probe_mode", "focused"))

        # role -> list[(src_role, src_ip_list, ports_expr, proto)]
        constraints: Dict[str, List[Tuple[str, List[str], str, str]]] = {}
        for lf, proto in expanded:
            src_ips = _map_role_to_ips(lf.src_role, role_ip_map_multi)
            dst_ips = _map_role_to_ips(lf.dst_role, role_ip_map_multi)
            if dst_ips:
                continue
            if not src_ips:
                continue
            constraints.setdefault(lf.dst_role, []).append((lf.src_role, src_ips, lf.ports_expr, str(proto)))

        out: Dict[str, Dict[str, str]] = {}
        for role, reqs in sorted(constraints.items()):
            excluded: set[str] = set()
            for _attempt in range(max_iters):
                src_role0, src_ips0, ports0, proto0 = reqs[0]
                sug = _cached_suggest_for_unmapped_dst(src_role=src_role0, src_ip_list=src_ips0, ports_expr=ports0, proto_s=proto0)

                chosen_ip: str | None = None
                if isinstance(sug, dict):
                    for s0 in (sug.get("suggestions") or []):
                        if not isinstance(s0, dict):
                            continue
                        w = s0.get("witness") if isinstance(s0.get("witness"), dict) else None
                        if not w:
                            continue
                        d_ip = str(w.get("dstIp") or "").strip()
                        if not d_ip or "/" in d_ip:
                            continue
                        if d_ip in excluded:
                            continue
                        chosen_ip = d_ip
                        break

                if not chosen_ip:
                    break

                ok_all = True
                for _s_role, s_ips, ports_expr, proto_s in reqs:
                    if not _exists_success_from_src_role_to_dst_ip(
                        src_ip_list=s_ips,
                        dst_ip=chosen_ip,
                        ports_expr=ports_expr,
                        proto_s=proto_s,
                    ):
                        ok_all = False
                        break
                if ok_all:
                    out[role] = {"dstIp": chosen_ip}
                    break
                excluded.add(chosen_ip)
            if role not in out:
                conjecture_unknown_roles.add(role)
        return out

    dst_conjectures = _compute_consistent_dst_conjectures()
    if dst_conjectures:
        for role, c in dst_conjectures.items():
            ip = str(c.get("dstIp") or "").strip()
            if ip:
                role_ip_map_multi[role] = [ip]

    for role in list(dst_conjectures):
        if _special_kind_for_role(role, role_special) in {"absent", "web"}:
            dst_conjectures.pop(role, None)
            role_ip_map_multi.pop(role, None)

    unresolved_dst_requirements: List[str] = []
    for lf, proto in expanded:
        if _special_kind_for_role(lf.src_role, role_special) == "absent":
            continue
        if _special_kind_for_role(lf.dst_role, role_special) == "absent":
            continue
        src_ips = _map_role_to_ips(lf.src_role, role_ip_map_multi)
        dst_ips = _map_role_to_ips(lf.dst_role, role_ip_map_multi)
        if src_ips and not dst_ips:
            unresolved_dst_requirements.append(
                f"(({lf.src_role}, *) -> ({lf.dst_role}, {lf.ports_expr}) on {proto})"
            )
    if unresolved_dst_requirements:
        details = "\n".join(f"- {leaf}" for leaf in sorted(set(unresolved_dst_requirements)))
        raise RuntimeError(
            "Could not find a consistent concrete destination for every mapped-source, "
            f"unmapped-destination requirement:\n{details}"
        )

    results: List[Dict[str, Any]] = []
    total_valid = 0
    total_unsat = 0
    total_unmapped = 0

    for idx, (lf, proto) in enumerate(expanded):
        src_kind = _special_kind_for_role(lf.src_role, role_special)
        dst_kind = _special_kind_for_role(lf.dst_role, role_special)
        src_is_web = src_kind == "web"
        dst_is_web = dst_kind == "web"

        # Special cases:
        # - web: use the internal concrete endpoint assigned during snapshot preparation
        # - absent: entity does not exist in enterprise, so the leaf is unsatisfied
        if src_kind == "absent" or dst_kind == "absent":
            # We'll record and skip Batfish entirely.
            src_note = "src role marked absent/nonexistent" if src_kind == "absent" else ""
            dst_note = "dst role marked absent/nonexistent" if dst_kind == "absent" else ""
            rec: Dict[str, Any] = {
                "index": idx,
                "src_role": lf.src_role,
                "dst_role": lf.dst_role,
                "ports": lf.ports_expr,
                "proto": proto,
                "fsl_under_optional": bool(getattr(lf, "under_optional", False)),
                "fsl_under_or": bool(getattr(lf, "under_or", False)),
                "status": "unsat",
                "reason": "; ".join([x for x in [src_note, dst_note] if x]) or "endpoint marked absent/nonexistent",
            }
            results.append(rec)
            total_unsat += 1
            continue

        # "web" roles receive an internal concrete endpoint during snapshot
        # preparation and are evaluated as resolved roles here.
        src_ip_list = _map_role_to_ips(lf.src_role, role_ip_map_multi)
        dst_ip_list = _map_role_to_ips(lf.dst_role, role_ip_map_multi)

        rec: Dict[str, Any] = {
            "index": idx,
            "src_role": lf.src_role,
            "dst_role": lf.dst_role,
            "ports": lf.ports_expr,
            "proto": proto,
            "fsl_under_optional": bool(getattr(lf, "under_optional", False)),
            "fsl_under_or": bool(getattr(lf, "under_or", False)),
            "src_is_web": bool(src_is_web),
            "dst_is_web": bool(dst_is_web),
        }
        conjectured_roles = sorted(
            {role for role in (lf.src_role, lf.dst_role) if role in dst_conjectures}
        )
        if conjectured_roles:
            rec["destination_conjectures"] = {
                role: str(dst_conjectures[role].get("dstIp") or "")
                for role in conjectured_roles
            }

        if not src_ip_list:
            total_unmapped += 1
            ctx_bits: List[str] = []
            if rec.get("fsl_under_optional"):
                ctx_bits.append("optional")
            if rec.get("fsl_under_or"):
                ctx_bits.append("or-choice")
            ctx = f" (fsl: {', '.join(ctx_bits)})" if ctx_bits else " (fsl: mandatory)"
            reason = f"unmapped src role: {lf.src_role}{ctx}"
            if not dst_ip_list:
                reason += f"; unmapped dst role: {lf.dst_role}{ctx}"
            rec.update(
                {
                    "status": "unmapped",
                    "reason": reason,
                }
            )
            results.append(rec)
            continue
        if not dst_ip_list:
            total_unmapped += 1
            ctx_bits2: List[str] = []
            if rec.get("fsl_under_optional"):
                ctx_bits2.append("optional")
            if rec.get("fsl_under_or"):
                ctx_bits2.append("or-choice")
            ctx2 = f" (fsl: {', '.join(ctx_bits2)})" if ctx_bits2 else " (fsl: mandatory)"
            rec.update(
                {
                    "status": "unmapped",
                    "reason": f"unmapped dst role: {lf.dst_role}{ctx2}",
                }
            )
            results.append(rec)
            continue

        # NOTE: no sampling of src/dst IPs: we use Batfish ipSpaceSpec groups.
        #
        # IMPORTANT (spoofing): if we set both (startLocation = many nodes) AND (srcIps = large ipSpace),
        # Batfish can still legally produce flows where a node in startLocation sends a packet whose srcIp
        # is owned by a *different* node in the set (source-IP spoofing). Therefore each srcIp is anchored
        # at the firewall interface owning its subnet (see below).
        src_ipspec = _ipspec(src_ip_list)
        dst_ipspec = _ipspec(dst_ip_list)
        rec["srcIpCount"] = int(len([x for x in src_ip_list if str(x).strip() and "/" not in str(x)]))
        rec["dstIpCount"] = int(len([x for x in dst_ip_list if str(x).strip() and "/" not in str(x)]))
        rec["srcIps_preview"] = _truncate_ip_list(src_ip_list, limit=10)
        rec["dstIps_preview"] = _truncate_ip_list(dst_ip_list, limit=10)

        headers_group: Dict[str, Any] = {"dstIps": dst_ipspec}
        start_locs: List[str] = []
        rec["fw_node"] = fw_node
        if lf.ports_expr and lf.ports_expr != "*":
            headers_group["dstPorts"] = lf.ports_expr
        proto_l = (proto or "").strip().lower()
        if proto_l and proto_l != "ip":
            headers_group["ipProtocols"] = [proto_l.upper()]

        rec["startLocationsCount"] = int(len(start_locs))

        # IMPORTANT correctness: for ANY/TOTAL classification we must prevent spoofing,
        # so each srcIp is tied to the firewall interface that owns the src subnet.
        #
        # Then aggregate:
        # - exists_success: any srcIp has some SUCCESS to dst group
        # - exists_failure: any srcIp has some FAILURE to dst group (counterexample to ∀)
        exists_success = False
        exists_failure = False
        witness_flows: List[Any] = []
        counterexample_flows: List[Any] = []

        if lf.src_role == "*":
            # Wildcard sources are not tied to a specific owner. Fall back to the group query.
            headers_group["srcIps"] = src_ipspec
            exists_success, witness_flows = _reachability_for_group_headers(
                bf,
                headers=headers_group,
                snapshot_name=args.snapshot,
                start_locations=start_locs,
                actions="success",
                max_traces=5,
            )
            exists_failure, counterexample_flows = _reachability_for_group_headers(
                bf,
                headers=headers_group,
                snapshot_name=args.snapshot,
                start_locations=start_locs,
                actions="failure",
                max_traces=5,
            )
        else:
            src_specs = [str(x).strip() for x in src_ip_list if isinstance(x, str) and x.strip()]
            buckets = _bucket_src_specs_by_fw_interface(fw_ifaces, src_specs)
            rec["srcIfaceBucketCount"] = int(len(buckets))
            for iface, ips_in_iface in sorted(buckets.items()):
                start_spec = f"@enter({fw_node}[{iface}])"
                h = dict(headers_group)
                h["srcIps"] = ",".join(ips_in_iface)

                ok, ok_flows = _reachability_for_group_headers(
                    bf,
                    headers=h,
                    snapshot_name=args.snapshot,
                    start_locations=[start_spec],
                    actions="success",
                    max_traces=1,
                )
                if ok and not exists_success:
                    exists_success = True
                    witness_flows = ok_flows

                bad, bad_flows = _reachability_for_group_headers(
                    bf,
                    headers=h,
                    snapshot_name=args.snapshot,
                    start_locations=[start_spec],
                    actions="failure",
                    max_traces=1,
                )
                if bad and not exists_failure:
                    exists_failure = True
                    counterexample_flows = bad_flows

                if exists_success and exists_failure:
                    break

        witnesses: List[Dict[str, Any]] = []
        if exists_success:
            for wf in witness_flows:
                if wf is None:
                    continue
                try:
                    wh: Dict[str, Any] = {
                        "witness_flow": str(wf),
                        "ingressNode": getattr(wf, "ingressNode", None),
                    }
                    headers = {
                        "srcIps": str(getattr(wf, "srcIp")),
                        "dstIps": str(getattr(wf, "dstIp")),
                        "dstPorts": str(getattr(wf, "dstPort", "")) if getattr(wf, "dstPort", None) is not None else None,
                        "ipProtocols": [str(getattr(wf, "ipProtocol", "")).upper()] if getattr(wf, "ipProtocol", None) else None,
                    }
                    # Remove empty/null keys for cleaner JSON.
                    headers = {k: v for k, v in headers.items() if v not in (None, "", [])}
                    wh["headers"] = headers

                    filters = _search_filters_for_headers(bf, headers=headers, snapshot_name=args.snapshot)
                    wh["searchFilters"] = filters
                    wh["permitFilters"] = [
                        r
                        for r in filters
                        if "Line_Content" in r and "permit" in str(r["Line_Content"]).lower()
                    ]
                    witnesses.append(wh)
                except Exception:
                    continue

        counterexamples: List[Dict[str, Any]] = []
        if exists_failure:
            for cf in counterexample_flows:
                if cf is None:
                    continue
                try:
                    counterexamples.append(
                        {
                            "counterexample_flow": str(cf),
                            "ingressNode": getattr(cf, "ingressNode", None),
                            "srcIp": str(getattr(cf, "srcIp", "")),
                            "dstIp": str(getattr(cf, "dstIp", "")),
                        }
                    )
                except Exception:
                    continue

        rec["exists_success"] = bool(exists_success)
        rec["exists_failure_counterexample"] = bool(exists_failure)
        rec["witnesses"] = witnesses
        rec["counterexamples"] = counterexamples

        if exists_success and not exists_failure:
            rec["status"] = "valid"
            total_valid += 1
        else:
            rec["status"] = "unsat"
            total_unsat += 1

        results.append(rec)

    report = {
        "fsl_path": str(fsl_path),
        "snapshot_dir": str(snapshot_dir),
        "role_ip_mapping_loaded": bool(role_ip_map_multi),
        "destination_conjectures": {
            role: str(value.get("dstIp") or "")
            for role, value in sorted(dst_conjectures.items())
        },
        "total_leaf_occurrences": len(expanded),
        "total_valid": total_valid,
        "total_unsat": total_unsat,
        "total_unmapped": total_unmapped,
        "results": results,
    }

    out_dir = Path(getattr(args, "output_dir", "auditor/output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_stem = f"audit_{_slugify(fsl_path.stem)}"
    if output_slug:
        out_stem = f"{out_stem}.{_slugify(output_slug)}"
    out_path = out_dir / f"{out_stem}.verification.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[DONE] wrote {out_path}")

    # Also write a simplified TXT summary: one line per leaf flow (per proto)
    # with its VALID / UNSAT / CONJECTURED-SAT verdict.
    lines: List[str] = []
    lines.append(f"FSL: {fsl_path}")
    lines.append(f"Snapshot: {snapshot_dir}")
    lines.append("")
    lines.append("Legend: VALID | UNSAT | CONJECTURED-SAT")
    for role, value in sorted(dst_conjectures.items()):
        lines.append(f"CONJECTURED_MAPPING\t{role}\t{str(value.get('dstIp') or '')}")
    lines.append("")

    # Pre-pass: intersect BDD conjectures per entity across all leaves.
    # Entity X appearing in multiple leaves must have consistent conjecture (intersection).
    #
    # NOTE: the BDD dump provides the same source set in two representations:
    # `prefixes` (exact CIDR cover) and `prefixes_ranges` (contiguous intervals).
    # We keep only the CIDR cover to avoid duplicating the same set in reports;
    # ranges are used as a fallback when a dump record has no prefixes.
    def _bdd_to_ingress_subnet_pairs(bdd: Dict[str, Any]) -> set[Tuple[str, str]]:
        pairs: set[Tuple[str, str]] = set()
        all_ing = bdd.get("all_ingresses")
        if all_ing and isinstance(all_ing, list):
            for rec in all_ing:
                loc = str(rec.get("ingressLocation") or "").strip()
                if not loc:
                    continue
                prefs = [str(x).strip() for x in (rec.get("prefixes") or []) if str(x).strip()]
                rngs = [str(x).strip() for x in (rec.get("prefixes_ranges") or []) if str(x).strip()]
                for s in (prefs if prefs else rngs):
                    pairs.add((loc, s))
        else:
            loc = str(bdd.get("ingressLocation") or "").strip()
            prefs = [str(x).strip() for x in (bdd.get("prefixes") or []) if str(x).strip()]
            rngs = [str(x).strip() for x in (bdd.get("prefixes_ranges") or []) if str(x).strip()]
            for s in (prefs if prefs else rngs):
                pairs.add((loc, s))
        return pairs

    def _pairs_to_all_ingresses(pairs: set[Tuple[str, str]]) -> List[Dict[str, Any]]:
        by_loc: Dict[str, List[str]] = {}
        for loc, subnet in pairs:
            by_loc.setdefault(loc, []).append(subnet)
        return [{"ingressLocation": loc, "prefixes": [], "prefixes_ranges": sorted(set(subs))} for loc, subs in sorted(by_loc.items())]

    # Preprocess: check if port is opened for mapped dst (unmapped src case).
    # If port not opened, leaf does not participate in conjecture.
    port_not_opened_leaves: Dict[str, str] = {}  # leaf_str -> dst_role (mapped side)
    port_opened_cache: Dict[Tuple[str, str, str], bool] = {}
    for r in results:
        if not isinstance(r, dict) or "unmapped src role" not in str(r.get("reason") or ""):
            continue
        dst_role = r.get("dst_role")
        dst_ip_list = _map_role_to_ips(dst_role, role_ip_map_multi)
        if not dst_ip_list:
            continue
        dst_ipspec = _ipspec(dst_ip_list)
        ports_expr = str(r.get("ports") or "*")
        proto_s = str(r.get("proto") or "tcp").strip().lower()
        key = (dst_ipspec, ports_expr, proto_s)
        if key not in port_opened_cache:
            headers_chk: Dict[str, Any] = {"dstIps": dst_ipspec}
            if ports_expr and ports_expr != "*":
                headers_chk["dstPorts"] = ports_expr
            headers_chk.update(_proto_headers(proto_s))
            ok, _ = _reachability_for_group_headers(
                bf,
                headers=headers_chk,
                snapshot_name=args.snapshot,
                start_locations=["@enter(/.*/)"],
                actions="success",
                max_traces=1,
            )
            port_opened_cache[key] = ok
        if not port_opened_cache[key]:
            leaf_str = f"(({r.get('src_role')}, *) -> ({r.get('dst_role')}, {r.get('ports')}) on {r.get('proto')})"
            port_not_opened_leaves[leaf_str] = str(dst_role or "")

    entity_conjectures: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}  # entity -> [(leaf_str, bdd), ...]
    if bdd_debug_json_path:
        bdd_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for r in results:
            if not isinstance(r, dict) or "unmapped src role" not in str(r.get("reason") or ""):
                continue
            entity = str(r.get("src_role") or "").strip()
            dst_role = r.get("dst_role")
            dst_ip_list = _map_role_to_ips(dst_role, role_ip_map_multi)
            if not dst_ip_list:
                continue
            dst_ipspec = _ipspec(dst_ip_list)
            ports_expr = str(r.get("ports") or "*")
            proto_s = str(r.get("proto") or "tcp").strip().lower()
            key = (dst_ipspec, ports_expr, proto_s)
            if key not in bdd_cache:
                headers_group: Dict[str, Any] = {"dstIps": dst_ipspec}
                if ports_expr and ports_expr != "*":
                    headers_group["dstPorts"] = ports_expr
                headers_group.update(_proto_headers(proto_s))
                bdd_debug_json_path.unlink(missing_ok=True)
                _run_reachability_wildcard_start_for_bdd_dump(
                    bf, snapshot_name=args.snapshot, headers_group=headers_group
                )
                bdd = _bdd_reachable_src_subnets_all_ingresses(bdd_debug_json_path)
                bdd_cache[key] = bdd if isinstance(bdd, dict) else {}
            bdd = bdd_cache[key]
            if not bdd:
                continue
            leaf_str = f"(({r.get('src_role')}, *) -> ({r.get('dst_role')}, {r.get('ports')}) on {r.get('proto')})"
            if leaf_str in port_not_opened_leaves:
                continue
            entity_conjectures.setdefault(entity, []).append((leaf_str, bdd))

    # Ensure all unresolved entities appear in node-level conjecture output,
    # even when we do not have BDD constraints for them (e.g., unresolved dst).
    unresolved_entities: set[str] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        reason_s = str(r.get("reason") or "")
        if "unmapped src role" in reason_s:
            e = str(r.get("src_role") or "").strip()
            if e:
                unresolved_entities.add(e)
        if "unmapped dst role" in reason_s:
            e = str(r.get("dst_role") or "").strip()
            if e:
                unresolved_entities.add(e)
    for e in sorted(unresolved_entities):
        entity_conjectures.setdefault(e, [])

    # FSL-structure-aware conjecture:
    # local (diagnostic) + effective (consistency) with OPT removed on propagation.
    default_root = spec_root
    entity_intersected, entity_node_conjectures = _compute_entity_conjecture_recursive(
        fsl_text,
        default_root,
        entity_conjectures=entity_conjectures,
        bdd_to_pairs_fn=_bdd_to_ingress_subnet_pairs,
        pairs_to_all_ingresses_fn=_pairs_to_all_ingresses,
    )

    # Write detailed conjecture file under a dedicated folder.
    conjectures_detail_dir = out_dir / "conjectures_detail"
    conjectures_detail_dir.mkdir(parents=True, exist_ok=True)
    conjectures_detail_path = conjectures_detail_dir / f"{out_stem}.conjectures_detail.txt"
    try:
        conjectures_detail_ref = str(conjectures_detail_path.relative_to(out_dir))
    except Exception:
        conjectures_detail_ref = str(conjectures_detail_path)
    if entity_node_conjectures:
        detail_lines: List[str] = []
        detail_lines.append("Entity conjectures by node (local vs effective)")
        detail_lines.append("=" * 60)
        detail_lines.append("Semantics:")
        detail_lines.append("- local: includes optional child content (diagnostic view)")
        detail_lines.append("- effective: contributes upward for consistency (OPT child removed)")
        detail_lines.append("- state=absent: node does not participate for this entity")
        detail_lines.append("- state=empty: participates but no satisfying subnets")
        detail_lines.append("")
        for entity in sorted(entity_node_conjectures.keys()):
            data = entity_node_conjectures[entity]
            detail_lines.append(f"\n## {entity}")
            root_info = data.get("root") if isinstance(data, dict) else {}
            root_def = str((root_info or {}).get("def") or default_root)
            detail_lines.append(f"  Root def: {root_def}")

            def _append_state_block(title: str, rec: Dict[str, Any], indent: str = "  ") -> None:
                state = str(rec.get("state") or "absent")
                detail_lines.append(f"{indent}{title}: state={state}")
                if state == "set":
                    for ing in rec.get("all_ingresses") or []:
                        loc = str(ing.get("ingressLocation") or "").strip()
                        if not loc:
                            continue
                        prefs = ing.get("prefixes") or []
                        rngs = ing.get("prefixes_ranges") or []
                        subs = [s for s in (prefs + rngs) if str(s).strip()]
                        if not subs:
                            continue
                        detail_lines.append(f"{indent}  {loc}:")
                        for s in subs:
                            detail_lines.append(f"{indent}    - {s}")

            _append_state_block("Root local", (root_info or {}).get("local") or {}, indent="  ")
            _append_state_block("Root effective", (root_info or {}).get("effective") or {}, indent="  ")

            defs_rec = data.get("definitions") if isinstance(data, dict) else {}
            if isinstance(defs_rec, dict) and defs_rec:
                detail_lines.append("  Definitions:")
                for def_name in sorted(defs_rec.keys()):
                    d = defs_rec.get(def_name) or {}
                    detail_lines.append(f"    - {def_name}")
                    _append_state_block("local", d.get("local") or {}, indent="      ")
                    _append_state_block("effective", d.get("effective") or {}, indent="      ")

            leaves = data.get("leaves") if isinstance(data, dict) else []
            if isinstance(leaves, list) and leaves:
                detail_lines.append("  Leaves:")
                for lf in leaves:
                    if not isinstance(lf, dict):
                        continue
                    leaf = str(lf.get("leaf") or "")
                    role_pos = str(lf.get("role_position") or "unknown")
                    under_opt = bool(lf.get("under_optional"))
                    has_bdd = bool(lf.get("has_bdd"))
                    detail_lines.append(
                        f"    - {leaf} | role={role_pos} | optional={str(under_opt).lower()} | has_bdd={str(has_bdd).lower()}"
                    )
                    _append_state_block("local", lf.get("local") or {}, indent="      ")
                    _append_state_block("effective", lf.get("effective") or {}, indent="      ")
        conjectures_detail_path.write_text("\n".join(detail_lines) + "\n")
        print(f"[DONE] wrote {conjectures_detail_path}")

    for r in results:
        if not isinstance(r, dict):
            continue
        src = r.get("src_role")
        dst = r.get("dst_role")
        ports = r.get("ports")
        proto_s = r.get("proto")
        status = str(r.get("status") or "").upper()
        reason = r.get("reason") or ""
        reason_s = str(reason)
        leaf = f"(({src}, *) -> ({dst}, {ports}) on {proto_s})"

        # Paper status model: VALID | UNSAT | CONJECTURED-SAT
        has_unmapped_src = "unmapped src role" in reason_s
        has_unmapped_dst = "unmapped dst role" in reason_s

        if has_unmapped_src and has_unmapped_dst:
            tag = "UNSAT"
            comment = "both entities unmapped"
        elif has_unmapped_src:
            entity = str(src or "").strip()
            if leaf in port_not_opened_leaves:
                tag = "UNSAT"
                dst_role = port_not_opened_leaves.get(leaf, "")
                comment = f"port not opened for {dst_role} (mapped side entity)"
            else:
                tag, source_state = _classify_unmapped_source_leaf(
                    entity,
                    leaf,
                    entity_intersected,
                    entity_node_conjectures,
                )
                if source_state == "set":
                    comment = f"see {conjectures_detail_ref} for {entity}"
                elif source_state == "empty":
                    comment = (
                        "no modeled source can reach the mapped destination "
                        "on this protocol/port"
                    )
                elif source_state == "inconsistent":
                    comment = "no consistent source assignment satisfies the required policy"
                else:
                    comment = "unmapped entity"
        elif has_unmapped_dst:
            raise RuntimeError(f"Unresolved destination reached report generation: {leaf}")
        else:
            # Both ends resolved: reachability check result
            if status == "VALID":
                destination_mapping = r.get("destination_conjectures")
                if isinstance(destination_mapping, dict) and destination_mapping:
                    tag = "CONJECTURED-SAT"
                    mapped = ", ".join(
                        f"{role}={ip}" for role, ip in sorted(destination_mapping.items())
                    )
                    comment = f"destination conjecture: {mapped}"
                else:
                    tag = "VALID"
                    comment = ""
            else:
                tag = "UNSAT"
                comment = ""

        if comment:
            lines.append(f"{tag}\t{leaf}\t# {comment}")
        else:
            lines.append(f"{tag}\t{leaf}")

    # ---- Sanity check: report leaf tuple count matches FSL leaf tuple count ----
    reported_leaf_set: set[str] = set()
    for ln in lines:
        if not ln or "\t" not in ln:
            continue
        # Each result line is: "<STATUS>\t<LEAF>(\t...optional suffix...)"
        leaf_part = ln.split("\t", 2)[1].strip()
        if leaf_part.startswith("((") and ") on " in leaf_part:
            reported_leaf_set.add(leaf_part)

    print(f"[CHECK] FSL unique leaf 5-tuples (incl proto): {len(expected_leaf_set)}")
    print(f"[CHECK] Report unique leaf 5-tuples (incl proto): {len(reported_leaf_set)}")
    if expected_leaf_set != reported_leaf_set:
        missing = sorted(expected_leaf_set - reported_leaf_set)
        extra = sorted(reported_leaf_set - expected_leaf_set)
        if missing:
            print(f"[CHECK] Missing in report (first 20): {missing[:20]}")
        if extra:
            print(f"[CHECK] Extra in report (first 20): {extra[:20]}")

    txt_path = out_dir / f"{out_stem}.summary.txt"
    txt_path.write_text("\n".join(lines) + "\n")
    print(f"[DONE] wrote {txt_path}")


if __name__ == "__main__":
    main()
