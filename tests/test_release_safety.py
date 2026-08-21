from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".dll", ".exe", ".pdb", ".i64", ".idb", ".id0", ".id1", ".id2",
    ".nam", ".til", ".gpr", ".db", ".sqlite", ".pyc", ".log", ".dmp",
    ".pak", ".dds", ".tif", ".tiff", ".cgf", ".skin", ".chr",
}
FORBIDDEN_TEXT = re.compile(
    r"C:\\Users\\[^\\\s]+|OneDrive|WHGame\.dll\.i64|"
    r"(?:api[_-]?key|client_secret|private_key)\s*[:=]",
    re.IGNORECASE,
)


class ReleaseSafetyTests(unittest.TestCase):
    def test_no_proprietary_or_generated_payloads(self) -> None:
        offenders = []
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT)
            if "__pycache__" in relative.parts or path.suffix.lower() in FORBIDDEN_SUFFIXES:
                offenders.append(str(relative))
        self.assertEqual([], offenders)

    def test_no_private_machine_paths_or_secret_assignments(self) -> None:
        offenders = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".py", ".md", ".json", ".toml", ".yaml", ".yml", ".ps1"}:
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if FORBIDDEN_TEXT.search(text):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
