"""Build a Batfish snapshot from a firewall config and server inventory."""

import argparse
import ipaddress
import json
import re
from pathlib import Path


# Internal concrete endpoint used for inventory roles marked as external.
WEB_SUBNET_HOST = "203.0.113.10"


def _config_defines_interfaces(base_text: str) -> bool:
  """Return whether a complete device config defines interface stanzas."""
  for raw in (base_text or "").splitlines():
    if re.match(r"^interface\s+\S+", raw.strip(), flags=re.IGNORECASE):
      return True
  return False


def _inventory_to_mapping_and_special_cases(inventory: dict) -> tuple[dict, dict]:
  """Normalize server inventory records into mapped and special-case roles."""
  mapping: dict = {}
  special: dict = {}

  for raw_role, record in sorted((inventory or {}).items(), key=lambda item: str(item[0])):
    if not isinstance(raw_role, str) or not raw_role.strip():
      raise SystemExit("Inventory contains an invalid role name")
    role = raw_role.strip()
    if any(char in role for char in "\t\r\n"):
      raise SystemExit(f"Inventory role names cannot contain tabs or newlines: {role!r}")
    if not isinstance(record, dict):
      raise SystemExit(f"Inventory role {role!r} must map to a JSON object")

    unknown_fields = sorted(set(record) - {"host_ip"})
    if unknown_fields:
      raise SystemExit(
        f"Inventory role {role!r} has unsupported field(s): {unknown_fields}. "
        "Use only host_ip; nested inventory fields are not supported."
      )
    if "host_ip" not in record:
      continue

    raw_ips = record.get("host_ip")
    if raw_ips is None:
      raise SystemExit(
        f"Role {role} has host_ip: null. Omit host_ip to leave the role "
        "unresolved; use ['N/A'] to mark it absent."
      )
    ips = raw_ips if isinstance(raw_ips, list) else [raw_ips]
    cleaned = [str(value).strip() for value in ips if str(value).strip()]
    if not cleaned:
      special[role] = {"kind": "absent"}
      continue

    lowered = [value.casefold() for value in cleaned]
    if "n/a" in lowered:
      if lowered != ["n/a"]:
        raise SystemExit(
          f"Role {role} has an invalid 'N/A' host_ip value: {cleaned}. "
          "Use exactly ['N/A'] for a role that is not deployed."
        )
      special[role] = {"kind": "absent"}
      continue

    if "web" in lowered:
      if lowered != ["web"]:
        raise SystemExit(
          f"Role {role} has an invalid 'web' host_ip value: {cleaned}. "
          "Use exactly ['web'] for an external service."
        )
      mapping[role] = {"host_ip": [WEB_SUBNET_HOST]}
      special[role] = {"kind": "web"}
      continue

    for value in cleaned:
      try:
        if "/" in value:
          network = ipaddress.ip_network(value, strict=False)
          if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError
        elif not isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address):
          raise ValueError
      except ValueError:
        raise SystemExit(f"Role {role} has an unrecognized IPv4 host_ip entry: {value!r}")
    mapping[role] = {"host_ip": cleaned}

  return mapping, special


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument(
    "--config",
    required=True,
    help="Complete firewall config with interfaces and ACL bindings.",
  )
  parser.add_argument(
    "--inventory",
    required=True,
    help="Elastispec server inventory JSON.",
  )
  parser.add_argument(
    "--output_dir",
    required=True,
    help="Snapshot output directory.",
  )
  args = parser.parse_args()

  config_path = Path(args.config)
  inventory_path = Path(args.inventory)
  output_dir = Path(args.output_dir)
  configs_dir = output_dir / "configs" / "configs"
  configs_dir.mkdir(parents=True, exist_ok=True)

  with inventory_path.open(encoding="utf-8") as handle:
    inventory = json.load(handle)
  if not isinstance(inventory, dict):
    raise SystemExit(f"Inventory must be a JSON object mapping role to record: {inventory_path}")
  mapping, special_cases = _inventory_to_mapping_and_special_cases(inventory)

  base_text = config_path.read_text(encoding="utf-8")
  if not _config_defines_interfaces(base_text):
    raise SystemExit(
      f"Config {config_path} defines no interfaces. The Auditor requires a "
      "complete, self-contained configuration and does not synthesize one."
    )
  config_target = configs_dir / config_path.name
  config_target.write_text(base_text, encoding="utf-8")

  combined: dict[str, dict] = {
    role: {"host_ip": list(record.get("host_ip") or [])}
    for role, record in sorted(mapping.items())
  }
  for role, record in sorted(special_cases.items()):
    entry = combined.setdefault(role, {"host_ip": []})
    if record.get("kind") == "web":
      entry["kind"] = "web"

  role_mapping_out = output_dir / "role_ip_mapping.json"
  role_mapping_out.write_text(
    json.dumps(combined, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
  )

  print(f"Snapshot written under: {output_dir}")
  print(f"- Firewall config copy: {config_target}")
  print(f"- Role mapping: {role_mapping_out}")


if __name__ == "__main__":
  main()
