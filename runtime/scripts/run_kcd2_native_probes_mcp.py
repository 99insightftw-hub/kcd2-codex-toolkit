#!/usr/bin/env python3
"""Run the bounded native-probes analysis MCP over STDIO."""

from __future__ import annotations

import argparse
from pathlib import Path

from kcd2_native_probes.mcp_server import main


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    main(parser.parse_args().repository_root)
