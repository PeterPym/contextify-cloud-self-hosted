#!/usr/bin/env python3
"""Fail if raw SQL reintroduces risky UUID/text cast patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SCAN_ROOT = Path("contextify_cloud")
PYTHON_SUFFIX = ".py"


@dataclass(frozen=True)
class Violation:
    """A risky SQL cast pattern found in a file."""

    path: Path
    line_number: int
    rule_id: str
    line: str


RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("postgres-cast-to-text", re.compile(r"::\s*text\b", re.IGNORECASE)),
    ("postgres-cast-to-uuid", re.compile(r"::\s*uuid\b", re.IGNORECASE)),
    (
        "sql-cast-as-text",
        re.compile(r"\bCAST\s*\([^)]*\bAS\s+TEXT\b", re.IGNORECASE),
    ),
    (
        "sql-cast-as-uuid",
        re.compile(r"\bCAST\s*\([^)]*\bAS\s+UUID\b", re.IGNORECASE),
    ),
)


def iter_scan_files(root: Path = SCAN_ROOT) -> list[Path]:
    """Return the Python files that should be scanned."""
    if not root.exists():
        return []
    return sorted(path for path in root.rglob(f"*{PYTHON_SUFFIX}") if path.is_file())


def check_text(text: str, *, path: Path) -> list[Violation]:
    """Return any cast violations found in the supplied source text."""
    violations: list[Violation] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule_id, pattern in RULES:
            if pattern.search(line):
                violations.append(
                    Violation(
                        path=path,
                        line_number=line_number,
                        rule_id=rule_id,
                        line=line.strip(),
                    )
                )
    return violations


def check_paths(paths: list[Path]) -> list[Violation]:
    """Scan a list of files and return all violations."""
    violations: list[Violation] = []
    for path in paths:
        violations.extend(check_text(path.read_text(), path=path))
    return violations


def main() -> int:
    violations = check_paths(iter_scan_files())
    if not violations:
        print("No risky SQL cast patterns found.")
        return 0

    print("Risky SQL cast patterns found:")
    for violation in violations:
        print(
            f"{violation.path}:{violation.line_number}: "
            f"{violation.rule_id}: {violation.line}"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
