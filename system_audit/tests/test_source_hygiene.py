"""Guards against stray content in the shipped sources (a no-op literal slipped into daemon.py)."""
import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "credwatch"
SOURCES = sorted(SRC.rglob("*.py"))


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(SRC)))
def test_no_bare_literal_statements(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    stray = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and not isinstance(node.value.value, str)  # docstrings are fine
        and node.value.value is not Ellipsis  # Protocol stubs
    ]
    assert stray == []


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(SRC)))
def test_ends_with_single_newline(path):
    text = path.read_text(encoding="utf-8")
    assert text == "" or (text.endswith("\n") and not text.endswith("\n\n"))
