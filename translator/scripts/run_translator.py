#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    repo_root = root.parent
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(root))
    from translator_runtime.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
