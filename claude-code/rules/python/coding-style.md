---
paths:
  - "**/*.py"
  - "**/*.pyi"
---
# Python Coding Style

> This file extends [common/coding-style.md](../common/coding-style.md) with Python specific content.

## Standards

- Target **Python 3.12+**; use built-in generics (`list[str]`, `dict[str, int]`) instead of `typing` equivalents
- Follow **PEP 8** conventions
- Use **type annotations** on all function signatures

## Immutability

Prefer immutable data structures:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class User:
    name: str
    email: str

from typing import NamedTuple

class Point(NamedTuple):
    x: float
    y: float
```

## Formatting

- **black** for code formatting
- **isort** for import sorting
- **ruff** for linting

## Type Checking

- **pyright** (preferred) or **mypy** for static type analysis
- Run in CI: `pyright .` or `mypy --strict .`

## Reference

See skill: `python-patterns` for comprehensive Python idioms and patterns.
