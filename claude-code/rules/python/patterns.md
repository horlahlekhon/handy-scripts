---
paths:
  - "**/*.py"
  - "**/*.pyi"
---
# Python Patterns

> This file extends [common/patterns.md](../common/patterns.md) with Python specific content.

## Protocol (Duck Typing)

```python
from typing import Protocol

class Repository(Protocol):
    def find_by_id(self, id: str) -> dict | None: ...
    def save(self, entity: dict) -> dict: ...
```

## Dataclasses or Pydantic (if available) as DTOs

> **Pydantic note**: The examples below use Pydantic v2 syntax. If your project uses Pydantic v1, `BaseModel` fields and validators differ — check the installed version with `pip show pydantic`.

```python
from dataclasses import dataclass
from pydantic import BaseModel

@dataclass
class CreateUserRequest:
    name: str
    email: str
    age: int | None = None  # Python 3.10+ union syntax; use Optional[int] for 3.9

# Pydantic v2 — model_config replaces class Config from v1
class CreateUserRequest(BaseModel):
    name: str
    email: str
    age: int | None = None
```

Prefer `X | None` over `Optional[X]` for Python 3.10+.

## Context Managers & Generators

- Use context managers (`with` statement) for resource management
- Use generators for lazy evaluation and memory-efficient iteration

## Reference

See skill: `python-patterns` for comprehensive patterns including decorators, concurrency, and package organization.
