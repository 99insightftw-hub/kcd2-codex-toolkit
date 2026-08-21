#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from kcd2_mod_build_deploy.mcp_server import main


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    main(parser.parse_args().repository_root)
