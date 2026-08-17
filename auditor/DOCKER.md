# Elastispec Auditor Run Modes

The Auditor uses two public Linux x86_64 / amd64 container images:

- [`qing0/elastispec-auditor:sigcomm2026`](https://hub.docker.com/r/qing0/elastispec-auditor)
- [`qing0/elastispec-batfish:sigcomm2026`](https://hub.docker.com/r/qing0/elastispec-batfish)

They run with Docker Engine on Linux x86_64 / amd64 and with Docker Desktop
using Linux containers on Windows x64. Neither mode requires an API key.

| Mode | Auditor | Batfish |
| --- | --- | --- |
| Docker Compose (recommended) | Docker Hub image | Docker Hub image |
| Python source | Host Python environment | Docker Hub image |

## Prerequisites

- Linux: [Docker Engine](https://docs.docker.com/engine/install/) with Docker
  Compose on x86_64 / amd64.
- Windows: [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)
  on x64, configured to use Linux containers.
- This repository checkout.

Run all commands from the repository root.

## Mode 1: Docker Compose

The Docker runner pulls both images when needed, starts both containers, mounts
the three inputs read-only, writes the compliance report to the host, and
removes the stopped containers and temporary Batfish volume after the run.

### Linux

```bash
./auditor/scripts/run_auditor_docker.sh \
  --config auditor/examples/papercut_toy/toy_firewall_config.txt \
  --inventory auditor/examples/papercut_toy/inventory.json \
  --spec auditor/examples/papercut_toy/papercut_toy.fsl \
  --output auditor/output/papercut_toy.html \
  --title "PaperCut firewall audit"
```

### Windows PowerShell

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\auditor\scripts\run_auditor_docker.ps1 `
  -Config auditor\examples\papercut_toy\toy_firewall_config.txt `
  -Inventory auditor\examples\papercut_toy\inventory.json `
  -Spec auditor\examples\papercut_toy\papercut_toy.fsl `
  -Output auditor\output\papercut_toy.html `
  -Title "PaperCut firewall audit"
```

For enterprise inputs, keep the command and replace the config, inventory,
specification, and output paths. The runners create the output directory when
needed.

## Mode 2: Python Source With Batfish Container

Start only Batfish:

```bash
BATFISH_DATA_DIR="$(mktemp -d)"
docker run -d --rm \
  --name elastispec-batfish \
  -v "$BATFISH_DATA_DIR:/data" \
  -p 9996:9996 -p 9997:9997 \
  qing0/elastispec-batfish:sigcomm2026
```

Install and run the Python source as described in
[README.md](README.md#python-source-mode). Stop Batfish after the run:

```bash
docker stop elastispec-batfish
rm -rf "$BATFISH_DATA_DIR"
```

Run one Auditor process at a time for each Batfish data directory.
