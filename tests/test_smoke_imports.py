from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "src"))


class SmokeImportTests(unittest.TestCase):
    def test_public_runtime_packages_import(self) -> None:
        import kcd2_index_adapter  # noqa: F401
        import kcd2_mod_build_deploy  # noqa: F401
        import kcd2_native_probes  # noqa: F401
        import kcd2_toolchain_core  # noqa: F401


if __name__ == "__main__":
    unittest.main()
