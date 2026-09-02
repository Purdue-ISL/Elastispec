"""Attribute firewall permit lines to the policy leaves that justify them.

The audit already asks Batfish a reachability question for every leaf it resolves.
This module rides along with that pass rather than repeating it:

    build_inventory()   once per snapshot, before the leaf loop, to enumerate every
                        permit line that exists and where it is enforced
    Inventory.match()   beside each existing reachability query, reusing the header
                        space and ingress interface the loop already computed
    finalize()          once at the end, turning the collected justifications into
                        rule and port verdicts

A line's status falls out of that mapping:

    UNAPPLIED    the ACL is not attached to an active interface, so it permits nothing
    SHADOWED     earlier lines decide every packet this line could match
    MATCHED      at least one policy leaf justifies the line
    OUT_OF_SPEC  the line is live and effective, and no leaf justifies it

Matched lines are refined once more. Their destination ports are enumerated and split
into justified and unjustified, because a legacy port sharing a service object group
with documented ports is invisible at line granularity.

Justifications are keyed by rule, so several leaves - and, when one firewall serves
several applications, several specifications - can jointly justify one line.
Conjectured leaves justify rules like confirmed ones; each match carries the leaf
verdict so a reviewer can weigh the two differently.

This module is downstream of the compliance verdict and cannot change it.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

SCHEMA_VERSION = 2
QUALIFYING_VERDICTS = ["VALID", "CONJECTURED-SAT"]
SUPPORTED_FORMATS = {"CISCO_IOS", "CISCO_ASA"}
PERMIT_STATUSES = ("MATCHED", "OUT_OF_SPEC", "SHADOWED", "UNAPPLIED")
ALL_PORTS = (0, 65535)
# A line admitting one of these is a protocol-wide permit rather than an enumerated
# service object group; its port set is reported as unbounded instead of walked.
SENTINEL_PORTS = "0,1,65534,65535"
PORT_CAP = 64

RuleKey = Tuple[str, str, int]  # (node, acl, line index)
Location = Tuple[str, str]  # (interface, "IN" | "OUT")


class RuleMappingUnavailable(RuntimeError):
    """Batfish cannot supply a trustworthy rule inventory, so nothing is reported."""


@dataclass
class Rule:
    node: str
    acl: str
    index: int
    text: str
    action: str
    source_line: int | None = None
    applied_at: List[Location] = field(default_factory=list)
    status: str = ""
    matched_leaves: List[Dict[str, Any]] = field(default_factory=list)
    ports_matched: List[Tuple[str, int]] = field(default_factory=list)
    ports_out_of_spec: List[Tuple[str, int]] = field(default_factory=list)
    ports_unbounded: List[str] = field(default_factory=list)

    @property
    def key(self) -> RuleKey:
        return (self.node, self.acl, self.index)

    @property
    def rule_id(self) -> str:
        return f"{self.node}|{self.acl}|{self.index}"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "node": self.node,
            "filter": self.acl,
            "line_index": self.index,
            "source_line": self.source_line,
            "line": self.text,
            "action": self.action,
            "applied_at": [{"interface": i, "direction": d} for i, d in self.applied_at],
            "status": self.status,
            "matched_leaves": self.matched_leaves,
            "ports_matched": [{"protocol": p, "port": n} for p, n in self.ports_matched],
            "ports_out_of_spec": [{"protocol": p, "port": n} for p, n in self.ports_out_of_spec],
            "ports_unbounded": self.ports_unbounded,
        }


class Inventory:
    """Every permit line on the firewall, and where each one is enforced."""

    def __init__(
        self,
        node: str,
        config_format: str,
        rules: Sequence[Rule],
        acl_at: Dict[Location, str],
    ) -> None:
        self.node = node
        self.config_format = config_format
        self.rules = list(rules)
        self.acl_at = dict(acl_at)
        self.permits: Dict[RuleKey, Rule] = {r.key: r for r in self.rules if r.action == "PERMIT"}

    def match(
        self,
        bf: Session,
        snapshot_name: str,
        headers: Dict[str, Any],
        source_interface: str,
        destination_interfaces: Sequence[str],
    ) -> List[RuleKey]:
        """Permit lines carrying this traffic where it actually crosses the firewall.

        Only the ACL entering on the source interface and those leaving toward the
        destinations can decide the flow, so an unrelated allow-all elsewhere in the
        configuration cannot absorb the leaf. An empty source interface means the
        source was a wildcard and only the egress side is considered.
        """
        acls = {self.acl_at.get((_text(source_interface), "IN"))}
        for interface in destination_interfaces or ():
            acls.add(self.acl_at.get((_text(interface), "OUT")))

        found: List[RuleKey] = []
        for acl in sorted(acl for acl in acls if acl):
            for key in _candidates(bf, snapshot_name, self.node, acl, headers):
                rule = self.permits.get(key)
                if rule is None or key in found:
                    continue
                if _reachable(bf, snapshot_name, rule, headers):
                    found.append(key)
        return found


def build_inventory(
    bf: Session, snapshot_name: str, expected_node: str, snapshot_dir: Path
) -> Inventory:
    """Enumerate the permit lines and their attachments. Depends only on the snapshot.

    This is the denominator for the whole analysis: "no leaf justifies this line"
    cannot be stated without knowing every line that exists, and a query-driven view
    only ever reveals lines that matched something already asked about.
    """
    _require_clean_parse(bf, snapshot_name)
    node, config_format = _firewall(bf, snapshot_name, expected_node)
    rules = _rules(bf, snapshot_name, node)
    acl_at = _attachments(bf, snapshot_name, node, config_format, Path(snapshot_dir))

    known = {rule.acl for rule in rules}
    unknown = {acl for acl in acl_at.values() if acl not in known}
    if unknown:
        raise RuleMappingUnavailable(
            "An active interface references an ACL that cannot be inventoried: "
            + ", ".join(sorted(unknown))
        )

    attached: Dict[str, List[Location]] = {}
    for location, acl in acl_at.items():
        attached.setdefault(acl, []).append(location)
    for rule in rules:
        rule.applied_at = sorted(attached.get(rule.acl, []))
    return Inventory(node, config_format, rules, acl_at)


def finalize(
    bf: Session,
    snapshot_name: str,
    inventory: Inventory,
    justifications: Dict[RuleKey, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Turn collected justifications into rule statuses, port verdicts, and the report.

    Reachability is only probed for lines nothing justified. A matched line was already
    shown reachable for its leaf's traffic, so re-testing it would waste a query.
    """
    for key, rule in inventory.permits.items():
        leaves = _unique(justifications.get(key) or [])
        if leaves:
            rule.status = "MATCHED"
            rule.matched_leaves = leaves
            _split_ports(bf, snapshot_name, rule, leaves)
        elif not rule.applied_at:
            rule.status = "UNAPPLIED"
        elif not _reachable(bf, snapshot_name, rule):
            rule.status = "SHADOWED"
        else:
            rule.status = "OUT_OF_SPEC"
    return _report(inventory)


def _split_ports(
    bf: Session, snapshot_name: str, rule: Rule, leaves: Sequence[Dict[str, Any]]
) -> None:
    """Divide a matched line's destination ports into justified and unjustified.

    A leaf that names no protocol permits the line's whole port space, so the split is
    skipped rather than reported against the protocols other leaves happen to name.
    """
    if any(not (leaf.get("headers") or {}).get("ipProtocols") for leaf in leaves):
        return

    allowed: Dict[str, List[Tuple[int, int]]] = {}
    for leaf in leaves:
        headers = leaf.get("headers") or {}
        for protocol in headers.get("ipProtocols") or []:
            allowed.setdefault(str(protocol).upper(), []).extend(
                _intervals(headers.get("dstPorts"))
            )
    for protocol, intervals in sorted(allowed.items()):
        ports, unbounded = _ports_of(bf, snapshot_name, rule, protocol)
        if unbounded:
            rule.ports_unbounded.append(protocol)
            continue
        for port in sorted(ports):
            bucket = rule.ports_matched if _within(port, intervals) else rule.ports_out_of_spec
            bucket.append((protocol, port))


def _ports_of(
    bf: Session, snapshot_name: str, rule: Rule, protocol: str
) -> Tuple[Set[int], bool]:
    """Destination ports a line admits, and whether it is too broad to enumerate.

    Each round excludes the ports already seen, so a group of k ports costs k+1
    queries. The line's own match condition supplies the addresses.
    """
    if _witness_port(bf, snapshot_name, rule, protocol, SENTINEL_PORTS) is not None:
        return set(), True
    found: Set[int] = set()
    while len(found) < PORT_CAP:
        port = _witness_port(bf, snapshot_name, rule, protocol, _excluding(found))
        if port is None or port in found:
            return found, False
        found.add(port)
    return found, True


def _witness_port(
    bf: Session, snapshot_name: str, rule: Rule, protocol: str, ports: str | None
) -> int | None:
    frame = bf.q.searchFilters(
        nodes=rule.node,
        filters=rule.acl,
        headers=HeaderConstraints(ipProtocols=[protocol], dstPorts=ports),
        action=f"matchLine {rule.index}",
    ).answer(snapshot=snapshot_name).frame()
    if frame.empty:
        return None
    port = getattr(frame.iloc[0].get("Flow"), "dstPort", None)
    return None if port is None else int(port)


def _reachable(
    bf: Session, snapshot_name: str, rule: Rule, headers: Dict[str, Any] | None = None
) -> bool:
    """Whether any packet in `headers` reaches this line rather than an earlier one."""
    frame = bf.q.searchFilters(
        nodes=rule.node,
        filters=rule.acl,
        headers=_constraints(headers or {}),
        action=f"matchLine {rule.index}",
    ).answer(snapshot=snapshot_name).frame()
    return not frame.empty


def _candidates(
    bf: Session, snapshot_name: str, node: str, acl: str, headers: Dict[str, Any]
) -> List[RuleKey]:
    frame = bf.q.findMatchingFilterLines(
        nodes=node,
        filters=acl,
        headers=_constraints(headers),
        action="permit",
        ignoreComposites=True,
    ).answer(snapshot=snapshot_name).frame()
    return sorted(
        (_text(row.get("Node")), _text(row.get("Filter")), int(row.get("Line_Index")))
        for row in _rows(frame)
        if _text(row.get("Action")).upper() == "PERMIT"
    )


def _rules(bf: Session, snapshot_name: str, node: str) -> List[Rule]:
    """Every user-authored ACL line, with the config line number where it is written."""
    frame = bf.q.namedStructures(
        nodes=node, structureTypes="IP_ACCESS_LIST", ignoreGenerated=True
    ).answer(snapshot=snapshot_name).frame()
    source_lines = _source_lines(bf, snapshot_name)
    rules: List[Rule] = []
    for row in _rows(frame):
        acl = _text(row.get("Structure_Name"))
        definition = _as_dict(row.get("Structure_Definition"))
        if _text(row.get("Node")) != node or not acl:
            continue
        lines = definition.get("lines")
        if not isinstance(lines, list):
            raise RuleMappingUnavailable(f"Batfish returned an invalid definition for ACL {acl}.")
        for index, line in enumerate(lines):
            if not isinstance(line, dict):
                raise RuleMappingUnavailable(f"Batfish returned an invalid line in ACL {acl}.")
            action = _text(line.get("action")).upper()
            if action not in {"PERMIT", "DENY"}:
                continue
            vendor = line.get("vendorStructureId")
            vendor = vendor if isinstance(vendor, dict) else {}
            name = _text(vendor.get("structureName"))
            rules.append(
                Rule(
                    node=node,
                    acl=acl,
                    index=index,
                    text=_text(line.get("name")) or name,
                    action=action,
                    source_line=source_lines.get(name),
                )
            )
    return sorted(rules, key=lambda r: (r.acl, r.index))


def _source_lines(bf: Session, snapshot_name: str) -> Dict[str, int]:
    frame = bf.q.definedStructures().answer(snapshot=snapshot_name).frame()
    out: Dict[str, int] = {}
    for row in _rows(frame):
        if "access-list line" not in _text(row.get("Structure_Type")).lower():
            continue
        name = _text(row.get("Structure_Name"))
        found = re.search(r"\[\s*(\d+)", _text(row.get("Source_Lines")))
        if name and found:
            out[name] = int(found.group(1))
    return out


def _attachments(
    bf: Session, snapshot_name: str, node: str, config_format: str, snapshot_dir: Path
) -> Dict[Location, str]:
    """Map each active (interface, direction) to the user ACL enforced there.

    IOS exposes the binding directly, except where Batfish substitutes a filter of its
    own; those carry a leading tilde and no operator wrote them. On ASA that
    substitution is the rule rather than the exception, since Batfish attaches a
    synthesized combined ACL and nests the user ACL inside it, so the `access-group`
    lines are read from the configuration instead.
    """
    frame = bf.q.interfaceProperties(
        nodes=node, properties="Active,Incoming_Filter_Name,Outgoing_Filter_Name"
    ).answer(snapshot=snapshot_name).frame()
    active = {_iface(row.get("Interface")) for row in _rows(frame) if bool(row.get("Active"))}
    out: Dict[Location, str] = {}

    if config_format == "CISCO_ASA":
        configs = snapshot_dir / "configs" / "configs"
        files = sorted(p for p in configs.iterdir() if p.is_file()) if configs.is_dir() else []
        if len(files) != 1:
            raise RuleMappingUnavailable("ASA analysis requires exactly one configuration file.")
        pattern = re.compile(
            r"^\s*access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)\s*$", re.IGNORECASE
        )
        for raw in files[0].read_text(errors="replace").splitlines():
            found = pattern.match(raw)
            if found and found.group(3) in active:
                _bind(out, (found.group(3), found.group(2).upper()), found.group(1))
        return out

    for row in _rows(frame):
        interface = _iface(row.get("Interface"))
        if not bool(row.get("Active")) or not interface:
            continue
        for direction, column in (("IN", "Incoming_Filter_Name"), ("OUT", "Outgoing_Filter_Name")):
            acl = _text(row.get(column))
            if acl and not acl.startswith("~"):
                _bind(out, (interface, direction), acl)
    return out


def _bind(out: Dict[Location, str], location: Location, acl: str) -> None:
    if out.get(location, acl) != acl:
        raise RuleMappingUnavailable(
            f"More than one user ACL is attached at {location[0]} {location[1]}."
        )
    out[location] = acl


def _firewall(bf: Session, snapshot_name: str, expected_node: str) -> Tuple[str, str]:
    frame = bf.q.nodeProperties().answer(snapshot=snapshot_name).frame()
    rows = _rows(frame)
    if len(rows) != 1:
        raise RuleMappingUnavailable("Rule analysis currently requires exactly one firewall node.")
    node = _text(rows[0].get("Node"))
    if not node or (expected_node and node != expected_node):
        raise RuleMappingUnavailable("Batfish firewall node selection was inconsistent.")
    config_format = _text(rows[0].get("Configuration_Format")).upper()
    if config_format not in SUPPORTED_FORMATS:
        raise RuleMappingUnavailable("Rule analysis currently supports Cisco IOS and ASA only.")
    return node, config_format


def _require_clean_parse(bf: Session, snapshot_name: str) -> None:
    frame = bf.q.fileParseStatus().answer(snapshot=snapshot_name).frame()
    rows = _rows(frame)
    if not rows:
        raise RuleMappingUnavailable("Batfish returned no configuration parse status.")
    failed = sorted(
        _text(row.get("File_Name")) or "unknown file"
        for row in rows
        if _text(row.get("Status")).upper() != "PASSED"
    )
    if failed:
        raise RuleMappingUnavailable(
            "Batfish did not fully parse the firewall configuration: " + ", ".join(failed)
        )


def _report(inventory: Inventory) -> Dict[str, Any]:
    """Serialize the classified inventory.

    `rules` carries the full detail. The four lists beside it are views for callers
    that want one answer directly, so they identify a rule rather than restating it.
    """
    permits = list(inventory.permits.values())
    counts = {status: 0 for status in PERMIT_STATUSES}
    for rule in permits:
        counts[rule.status] += 1

    def rule_ref(rule: Rule) -> Dict[str, Any]:
        return {
            "rule_id": rule.rule_id,
            "filter": rule.acl,
            "line_index": rule.index,
            "source_line": rule.source_line,
            "line": rule.text,
        }

    def port_refs(rule: Rule, ports: Sequence[Tuple[str, int]]) -> List[Dict[str, Any]]:
        return [dict(rule_ref(rule), protocol=protocol, port=port) for protocol, port in ports]

    matched_ports = [ref for r in permits for ref in port_refs(r, r.ports_matched)]
    out_of_spec_ports = [ref for r in permits for ref in port_refs(r, r.ports_out_of_spec)]
    counts.update(
        {
            "permit_total": len(permits),
            "deny_catalogued": sum(1 for r in inventory.rules if r.action == "DENY"),
            "ports_matched": len(matched_ports),
            "ports_out_of_spec": len(out_of_spec_ports),
        }
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_status": "complete",
        "message": "",
        "scope": {
            "network_model": "single-node Cisco IOS/ASA ACLs",
            "qualifying_policy_verdicts": QUALIFYING_VERDICTS,
            "classified_rule_action": "PERMIT",
            "match_semantics": "packet-space overlap per line, then per destination port",
            "specifications": sorted(
                {
                    _text(leaf.get("spec"))
                    for r in permits
                    for leaf in r.matched_leaves
                    if leaf.get("spec")
                }
            ),
        },
        "firewall": {"node": inventory.node, "configuration_format": inventory.config_format},
        "counts": counts,
        "matched_rules": [rule_ref(r) for r in permits if r.status == "MATCHED"],
        "out_of_spec_rules": [rule_ref(r) for r in permits if r.status == "OUT_OF_SPEC"],
        "matched_ports": matched_ports,
        "out_of_spec_ports": out_of_spec_ports,
        "rules": [rule.as_dict() for rule in inventory.rules],
    }


def unavailable_rule_mapping(message: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_status": "unavailable",
        "message": str(message or "Rule analysis was unavailable."),
        "scope": {"qualifying_policy_verdicts": QUALIFYING_VERDICTS},
        "counts": {},
        "matched_rules": [],
        "out_of_spec_rules": [],
        "matched_ports": [],
        "out_of_spec_ports": [],
        "rules": [],
    }


def _unique(leaves: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for leaf in leaves:
        marker = json.dumps(leaf, sort_keys=True, separators=(",", ":"), default=str)
        if marker not in seen:
            seen.add(marker)
            out.append(leaf)
    return out


def _constraints(headers: Dict[str, Any]) -> HeaderConstraints:
    return HeaderConstraints(
        srcIps=headers.get("srcIps"),
        dstIps=headers.get("dstIps"),
        dstPorts=headers.get("dstPorts"),
        ipProtocols=headers.get("ipProtocols"),
    )


def _intervals(expr: Any) -> List[Tuple[int, int]]:
    text = _text(expr)
    if not text or text == "*":
        return [ALL_PORTS]
    out: List[Tuple[int, int]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            low, high = part.split("-", 1) if "-" in part else (part, part)
            out.append((int(low), int(high)))
        except ValueError:
            continue
    return out or [ALL_PORTS]


def _within(port: int, intervals: Sequence[Tuple[int, int]]) -> bool:
    return any(low <= port <= high for low, high in intervals)


def _excluding(ports: Set[int]) -> str | None:
    """A dstPorts specifier covering every port except `ports`."""
    if not ports:
        return None
    spans: List[str] = []
    cursor = ALL_PORTS[0]
    for port in sorted(ports):
        if port > cursor:
            spans.append(f"{cursor}-{port - 1}" if port - 1 > cursor else str(cursor))
        cursor = port + 1
    if cursor <= ALL_PORTS[1]:
        spans.append(f"{cursor}-{ALL_PORTS[1]}" if ALL_PORTS[1] > cursor else str(cursor))
    return ",".join(spans)


def _rows(frame: Any) -> List[Dict[str, Any]]:
    return [] if frame is None or frame.empty else frame.to_dict(orient="records")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "none", "nan"} else text


def _iface(value: Any) -> str:
    text = _text(value)
    return text.split("[", 1)[1][:-1] if "[" in text and text.endswith("]") else text


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value) if isinstance(value, str) else None
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}
