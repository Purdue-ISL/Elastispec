# PaperCut Specification

This directory contains:

- [`papercut.fsl`](papercut.fsl), the full PaperCut Elastispec specification.
- [`inventory.template.json`](inventory.template.json), a server inventory
  template with every role referenced by the specification.

## Archived Sources Used

- <https://web.archive.org/web/20250327175449/https://www.papercut.com/kb/Main/FirewallPorts/>
- <https://web.archive.org/web/20250402104727/https://www.papercut.com/help/manuals/mobility-print/set-up/system-requirements/#firewall-rules>
- <https://web.archive.org/web/20250403052600/https://www.papercut.com/help/manuals/print-deploy/set-up/system-requirements/#firewall-rules>

## Prepare The Inventory

Each top-level key is a role used by the specification. Fill each role using
the [Auditor inventory format](../../README.md#creating-an-inventory-file):

- Add `host_ip` with one or more IPv4 addresses or CIDRs for a known mapping.
- Use `["N/A"]` when the role is not deployed.
- Keep `["web"]` for an external server; the Auditor skips external server
  policies.
- Leave `{}` when a role is unresolved.

Run the Auditor after filling the template:

```bash
./auditor/scripts/run_auditor_docker.sh \
  --config /path/to/firewall.cfg \
  --inventory /path/to/papercut_inventory.json \
  --spec auditor/specifications/papercut/papercut.fsl \
  --output /path/to/papercut_audit.html
```
