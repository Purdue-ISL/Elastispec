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

    UNAPPLIED    the filter is not attached to an active interface, so it permits nothing
    SHADOWED     earlier lines decide every packet this line could match
    MATCHED      at least one policy leaf justifies the line
    OUT_OF_SPEC  the line is live and effective, and no leaf justifies it

Matched lines are refined once more. Their destination ports are enumerated and split
into justified and unjustified, because a legacy port grouped together with documented
ports in one line is invisible at line granularity.

Justifications are keyed by rule, so several leaves - and, when one firewall serves
several applications, several specifications - can jointly justify one line.
Conjectured leaves justify rules like confirmed ones; each match carries the leaf
verdict so a reviewer can weigh the two differently.

This module is downstream of the compliance verdict and cannot change it.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

SCHEMA_VERSION = 3
QUALIFYING_VERDICTS = ["VALID", "CONJECTURED-SAT"]
PERMIT_STATUSES = ("MATCHED", "OUT_OF_SPEC", "SHADOWED", "UNAPPLIED")
# Batfish labels every filter it evaluates in a trace with the point in the pipeline
# where it applies. The direction is what matters here, not the transformation stage.
INGRESS_FILTER_TYPES = ("INGRESS_FILTER",)
EGRESS_FILTER_TYPES = ("EGRESS_FILTER",)
# Batfish names the referring construct first when it records why a structure is
# referenced, so a reference from an interface begins this way whatever the vendor calls
# the filter itself. The bare context "interface" is a reference to an interface rather
# than from one, so the trailing space matters.
ATTACHMENT_CONTEXT_PREFIX = "interface "
ALL_PORTS = (0, 65535)
# A line admitting one of these is a protocol-wide permit rather than an enumerated set
# of services; its port set is reported as unbounded instead of walked.
SENTINEL_PORTS = "0,1,65534,65535"
PORT_CAP = 64

RuleKey = Tuple[str, str, int]  # (node, filter, line index)
Location = Tuple[str, str]  # (interface, "IN" | "OUT")


class RuleMappingUnavailable(RuntimeError):
    """Batfish cannot supply a trustworthy rule inventory, so nothing is reported."""


@dataclass
class Rule:
    node: str
    filter_name: str
    index: int
    text: str
    action: str
    source_line: int | None = None
    # First and last configuration line of the whole filter, for vendors whose parser
    # does not record a line number per rule.
    filter_lines: Tuple[int, int] | None = None
    applied_at: List[Location] = field(default_factory=list)
    status: str = ""
    matched_leaves: List[Dict[str, Any]] = field(default_factory=list)
    ports_matched: List[Tuple[str, int]] = field(default_factory=list)
    ports_out_of_spec: List[Tuple[str, int]] = field(default_factory=list)
    ports_unbounded: List[str] = field(default_factory=list)

    @property
    def key(self) -> RuleKey:
        return (self.node, self.filter_name, self.index)

    @property
    def rule_id(self) -> str:
        return f"{self.node}|{self.filter_name}|{self.index}"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "node": self.node,
            "filter": self.filter_name,
            "line_index": self.index,
            "source_line": self.source_line,
            "filter_source_lines": list(self.filter_lines) if self.filter_lines else None,
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
        filter_at: Dict[Location, str],
    ) -> None:
        self.node = node
        self.config_format = config_format
        self.rules = list(rules)
        self.filter_at = dict(filter_at)
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

        Only the filter entering on the source interface and those leaving toward the
        destinations can decide the flow, so an unrelated allow-all elsewhere in the
        configuration cannot absorb the leaf. An empty source interface means the
        source was a wildcard and only the egress side is considered.
        """
        filters = {self.filter_at.get((_text(source_interface), "IN"))}
        for interface in destination_interfaces or ():
            filters.add(self.filter_at.get((_text(interface), "OUT")))

        found: List[RuleKey] = []
        for filter_name in sorted(name for name in filters if name):
            for key in _candidates(bf, snapshot_name, self.node, filter_name, headers):
                rule = self.permits.get(key)
                if rule is None or key in found:
                    continue
                if _reachable(bf, snapshot_name, rule, headers):
                    found.append(key)
        return found


def build_inventory(bf: Session, snapshot_name: str, expected_node: str) -> Inventory:
    """Enumerate the permit lines and their attachments. Depends only on the snapshot.

    This is the denominator for the whole analysis: "no leaf justifies this line"
    cannot be stated without knowing every line that exists, and a query-driven view
    only ever reveals lines that matched something already asked about.
    """
    _require_clean_parse(bf, snapshot_name)
    node, config_format = _firewall(bf, snapshot_name, expected_node)
    rules = _rules(bf, snapshot_name, node)
    known = {rule.filter_name for rule in rules}
    filter_at = _attachments(bf, snapshot_name, node, known)

    unknown = {name for name in filter_at.values() if name not in known}
    if unknown:
        raise RuleMappingUnavailable(
            "An active interface references a filter that cannot be inventoried: "
            + ", ".join(sorted(unknown))
        )

    attached: Dict[str, List[Location]] = {}
    for location, filter_name in filter_at.items():
        attached.setdefault(filter_name, []).append(location)
    for rule in rules:
        rule.applied_at = sorted(attached.get(rule.filter_name, []))
    return Inventory(node, config_format, rules, filter_at)


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
        filters=rule.filter_name,
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
        filters=rule.filter_name,
        headers=_constraints(headers or {}),
        action=f"matchLine {rule.index}",
    ).answer(snapshot=snapshot_name).frame()
    return not frame.empty


def _candidates(
    bf: Session, snapshot_name: str, node: str, filter_name: str, headers: Dict[str, Any]
) -> List[RuleKey]:
    frame = bf.q.findMatchingFilterLines(
        nodes=node,
        filters=filter_name,
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
    """Every user-authored filter line, with the config line number where it is written."""
    frame = bf.q.namedStructures(
        nodes=node, structureTypes="IP_ACCESS_LIST", ignoreGenerated=True
    ).answer(snapshot=snapshot_name).frame()
    origins: List[Tuple[Rule, str]] = []
    for row in _rows(frame):
        filter_name = _text(row.get("Structure_Name"))
        definition = _as_dict(row.get("Structure_Definition"))
        if _text(row.get("Node")) != node or not filter_name:
            continue
        if not definition:
            raise RuleMappingUnavailable(f"Batfish returned an unreadable definition for filter {filter_name}.")
        # Batfish omits this key entirely for a filter with no lines, which is valid
        # configuration that simply contributes no rules.
        lines = definition.get("lines") if "lines" in definition else []
        if not isinstance(lines, list):
            raise RuleMappingUnavailable(f"Batfish returned an invalid definition for filter {filter_name}.")
        for index, line in enumerate(lines):
            if not isinstance(line, dict):
                raise RuleMappingUnavailable(f"Batfish returned an invalid line in filter {filter_name}.")
            action = _text(line.get("action")).upper()
            if action not in {"PERMIT", "DENY"}:
                continue
            vendor = line.get("vendorStructureId")
            vendor = vendor if isinstance(vendor, dict) else {}
            name = _text(vendor.get("structureName"))
            origins.append(
                (
                    Rule(
                        node=node,
                        filter_name=filter_name,
                        index=index,
                        text=_text(line.get("name")) or name,
                        action=action,
                    ),
                    name,
                )
            )

    per_rule, spans = _definition_lines(
        bf,
        snapshot_name,
        {name for _rule, name in origins if name},
        {rule.filter_name for rule, _name in origins},
    )
    for rule, name in origins:
        rule.source_line = per_rule.get(name)
        rule.filter_lines = spans.get(rule.filter_name)
    return sorted((rule for rule, _name in origins), key=lambda r: (r.filter_name, r.index))


def _definition_lines(
    bf: Session, snapshot_name: str, rule_names: Set[str], filter_names: Set[str]
) -> Tuple[Dict[str, int], Dict[str, Tuple[int, int]]]:
    """Where rules and whole filters are written, as (line per rule, span per filter).

    Looked up by the exact names already collected from the filters themselves, so no
    structure-type label has to be recognised and nothing is assumed about how a vendor
    names its rules. Not every vendor parser records a line for each rule, and the
    filter span is the fallback context for those.
    """
    if not rule_names and not filter_names:
        return {}, {}
    frame = bf.q.definedStructures().answer(snapshot=snapshot_name).frame()
    per_rule: Dict[str, int] = {}
    spans: Dict[str, List[Tuple[int, int]]] = {}
    for row in _rows(frame):
        name = _text(row.get("Structure_Name"))
        numbers = _line_numbers(row.get("Source_Lines"))
        if not numbers:
            continue
        if name in rule_names:
            per_rule[name] = numbers[0]
        if name in filter_names:
            spans.setdefault(name, []).append((min(numbers), max(numbers)))
    # A name shared by several structures would make its span a guess, so it is dropped.
    return per_rule, {name: found[0] for name, found in spans.items() if len(found) == 1}


def _line_numbers(raw: Any) -> List[int]:
    """Configuration line numbers listed in a Batfish `Source_Lines` value."""
    bracketed = re.search(r"\[([^\]]*)\]", _text(raw))
    return [int(found) for found in re.findall(r"\d+", bracketed.group(1))] if bracketed else []


def _attachments(
    bf: Session, snapshot_name: str, node: str, user_filters: Set[str]
) -> Dict[Location, str]:
    """Map each active (interface, direction) to the operator-authored filter enforced there.

    Recovered from Batfish's device model rather than from configuration text, so it
    does not depend on any vendor's grammar. Most vendors expose the binding through
    `interfaceProperties`. Some, Cisco ASA among them, report no filter names there at
    all, so the bindings are read instead off traces, where Batfish states both the
    filter it evaluated and whether it applied on ingress or egress.

    Either way Batfish may interpose a filter of its own making, which it names with a
    leading tilde and which no operator wrote. Those are resolved to the authored
    filter nested inside them.
    """
    interfaces = _interfaces(bf, snapshot_name, node)
    nested = _nested_authored(bf, snapshot_name, node, user_filters)

    out: Dict[Location, str] = {}
    for name, (active, incoming, outgoing, _prefix) in interfaces.items():
        if not active:
            continue
        for direction, raw in (("IN", incoming), ("OUT", outgoing)):
            authored = _authored_filter(raw, user_filters, nested)
            if authored:
                _bind(out, (name, direction), authored)

    expected = _expected_attachments(bf, snapshot_name, user_filters)
    if not out or _unrecovered(out, expected):
        out.update(_traced_attachments(bf, snapshot_name, node, interfaces, user_filters, nested))

    missing = _unrecovered(out, expected)
    if missing:
        raise RuleMappingUnavailable(
            "Batfish reports these filters as attached to an interface but their "
            "binding could not be recovered, so rules cannot be classified: "
            + ", ".join(sorted(missing))
        )
    if not out:
        raise RuleMappingUnavailable(
            "No filter on this device could be tied to an interface, so rules cannot be "
            "told apart from ones that were never applied."
        )
    return out


def _interfaces(
    bf: Session, snapshot_name: str, node: str
) -> Dict[str, Tuple[bool, str, str, str]]:
    frame = bf.q.interfaceProperties(
        nodes=node,
        properties="Active,Incoming_Filter_Name,Outgoing_Filter_Name,All_Prefixes",
    ).answer(snapshot=snapshot_name).frame()
    out: Dict[str, Tuple[bool, str, str, str]] = {}
    for row in _rows(frame):
        name = _iface(row.get("Interface"))
        if not name:
            continue
        prefixes = row.get("All_Prefixes")
        prefix = _text(prefixes[0]) if isinstance(prefixes, (list, tuple)) and prefixes else ""
        out[name] = (
            bool(row.get("Active")),
            _text(row.get("Incoming_Filter_Name")),
            _text(row.get("Outgoing_Filter_Name")),
            prefix,
        )
    return out


def _nested_authored(
    bf: Session, snapshot_name: str, node: str, user_filters: Set[str]
) -> Dict[str, str]:
    """For each filter Batfish synthesized, the single authored filter it defers to."""
    frame = bf.q.namedStructures(
        nodes=node, structureTypes="IP_ACCESS_LIST", ignoreGenerated=False
    ).answer(snapshot=snapshot_name).frame()
    out: Dict[str, str] = {}
    for row in _rows(frame):
        name = _text(row.get("Structure_Name"))
        if not name.startswith("~"):
            continue
        referenced = sorted(_referenced_filters(_as_dict(row.get("Structure_Definition"))) & user_filters)
        if len(referenced) == 1:
            out[name] = referenced[0]
        elif len(referenced) > 1:
            raise RuleMappingUnavailable(
                f"Batfish filter {name} defers to more than one authored filter "
                f"({', '.join(referenced)}), so its binding is ambiguous."
            )
    return out


def _referenced_filters(definition: Any) -> Set[str]:
    found: Set[str] = set()
    stack = [definition]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            name = current.get("aclName")
            if isinstance(name, str):
                found.add(name)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return found


def _authored_filter(raw: str, user_filters: Set[str], nested: Dict[str, str]) -> str:
    name = _text(raw)
    if name in user_filters:
        return name
    return nested.get(name, "")


def _expected_attachments(
    bf: Session, snapshot_name: str, user_filters: Set[str]
) -> Set[str]:
    """Every filter Batfish records as referenced from an interface.

    This guards the UNAPPLIED verdict: if Batfish says a filter is attached to an
    interface, reporting its rules as never applied would be wrong, so the analysis
    refuses to run instead. Only the word for the referring construct is matched, never
    a vendor's term for the filter itself, so the guard travels across vendors. The
    direction is deliberately not read from here, since only Batfish's own interface and
    trace data state it in vendor-neutral terms.
    """
    frame = bf.q.referencedStructures().answer(snapshot=snapshot_name).frame()
    out: Set[str] = set()
    for row in _rows(frame):
        name = _text(row.get("Structure_Name"))
        context = _text(row.get("Context")).lower()
        if name in user_filters and context.startswith(ATTACHMENT_CONTEXT_PREFIX):
            out.add(name)
    return out


def _unrecovered(found: Dict[Location, str], expected: Set[str]) -> Set[str]:
    return expected - set(found.values())


def _traced_attachments(
    bf: Session,
    snapshot_name: str,
    node: str,
    interfaces: Dict[str, Tuple[bool, str, str, str]],
    user_filters: Set[str],
    nested: Dict[str, str],
) -> Dict[Location, str]:
    """Read filter bindings off traces, for devices whose model omits them.

    One trace per active interface, each aimed at the next interface's subnet, so a
    ring of N traces covers every interface on ingress and on egress. A filter that
    denies the probe still names itself in the trace, so the binding is recovered
    whether or not the probe would be permitted.
    """
    usable: List[Tuple[str, str]] = []
    for name, (active, _in, _out, prefix) in sorted(interfaces.items()):
        probe = _probe_ip(prefix) if active else ""
        if probe:
            usable.append((name, probe))

    out: Dict[Location, str] = {}
    if len(usable) < 2:
        return out

    for index, (source, _source_ip) in enumerate(usable):
        target, target_ip = usable[(index + 1) % len(usable)]
        if target == source:
            continue
        for interface, direction, filter_name in _trace_filters(
            bf, snapshot_name, node, source, target_ip
        ):
            authored = _authored_filter(filter_name, user_filters, nested)
            if authored and interface in interfaces:
                _bind(out, (interface, direction), authored)
    return out


def _trace_filters(
    bf: Session, snapshot_name: str, node: str, ingress: str, destination: str
) -> List[Tuple[str, str, str]]:
    """(interface, direction, filter) for every filter one probe packet crosses."""
    try:
        frame = bf.q.traceroute(
            startLocation=f"@enter({node}[{ingress}])",
            headers=HeaderConstraints(dstIps=destination),
        ).answer(snapshot=snapshot_name).frame()
    except Exception:  # noqa: BLE001 - a device that cannot be traced is handled by the caller
        return []

    found: List[Tuple[str, str, str]] = []
    for row in _rows(frame):
        for trace in row.get("Traces") or []:
            for hop in getattr(trace, "hops", None) or []:
                if _text(getattr(hop, "node", "")) != node:
                    continue
                # Steps arrive in pipeline order, so the interface a packet was routed
                # out of is known by the time its egress filter is evaluated.
                egress = ""
                for step in getattr(hop, "steps", None) or []:
                    detail = getattr(step, "detail", None)
                    if detail is None:
                        continue
                    egress = _text(getattr(detail, "outputInterface", "")) or egress
                    filter_name = _text(getattr(detail, "filter", ""))
                    if not filter_name:
                        continue
                    kind = _text(getattr(detail, "filterType", "")).upper()
                    if kind.endswith(INGRESS_FILTER_TYPES):
                        found.append(
                            (_text(getattr(detail, "inputInterface", "")), "IN", filter_name)
                        )
                    elif kind.endswith(EGRESS_FILTER_TYPES) and egress:
                        found.append((egress, "OUT", filter_name))
    return found


def _probe_ip(prefix: str) -> str:
    """A host address inside `prefix` other than the interface's own address."""
    text = _text(prefix)
    if "/" not in text:
        return ""
    try:
        network = ipaddress.ip_network(text, strict=False)
        own = ipaddress.ip_interface(text).ip
        for candidate in network.hosts():
            if candidate != own:
                return str(candidate)
    except Exception:  # noqa: BLE001 - an unusable prefix simply yields no probe
        return ""
    return ""


def _bind(out: Dict[Location, str], location: Location, filter_name: str) -> None:
    if out.get(location, filter_name) != filter_name:
        raise RuleMappingUnavailable(
            f"More than one filter is attached at {location[0]} {location[1]}."
        )
    out[location] = filter_name


def _firewall(bf: Session, snapshot_name: str, expected_node: str) -> Tuple[str, str]:
    """The firewall node and the format Batfish parsed it as.

    The format is recorded for the report but is not gated on. Whether a device can be
    analysed depends on whether its filter bindings can be recovered, which
    `_attachments` establishes directly, not on recognising its vendor.
    """
    frame = bf.q.nodeProperties().answer(snapshot=snapshot_name).frame()
    rows = _rows(frame)
    if len(rows) != 1:
        raise RuleMappingUnavailable("Rule analysis currently requires exactly one firewall node.")
    node = _text(rows[0].get("Node"))
    if not node or (expected_node and node != expected_node):
        raise RuleMappingUnavailable("Batfish firewall node selection was inconsistent.")
    return node, _text(rows[0].get("Configuration_Format")).upper()


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
            "filter": rule.filter_name,
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
            "network_model": "single-node interface-attached filters",
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
