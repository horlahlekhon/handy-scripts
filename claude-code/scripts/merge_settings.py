#!/usr/bin/env python3
"""Merge a repo-managed Claude Code settings.json into the user's settings.json.

Dicts merge recursively, lists are unioned (order kept, duplicates dropped),
and scalars from the overlay win. Keys only in the existing file are kept, so
machine-local settings (theme, plugins, extra permissions) survive re-installs.
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]


def _union(base: list[Any], overlay: list[Any]) -> list[Any]:
    return base + [item for item in overlay if item not in base]


def deep_merge(base: JsonObject, overlay: JsonObject) -> JsonObject:
    merged: JsonObject = dict(base)
    for key, value in overlay.items():
        current = base.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = deep_merge(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            merged[key] = _union(current, value)
        else:
            merged[key] = value
    return merged


def _load_object(path: Path) -> JsonObject:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def merge_files(source: Path, target: Path) -> None:
    overlay = _load_object(source)
    base: JsonObject = {}
    if target.exists():
        base = _load_object(target)
        shutil.copy2(target, target.with_name(target.name + ".bak"))
    merged = deep_merge(base, overlay)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(merged, indent=2) + "\n")
    tmp.replace(target)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: merge_settings.py <source.json> <target.json>", file=sys.stderr)
        return 2
    try:
        merge_files(Path(argv[0]), Path(argv[1]))
    except (OSError, ValueError) as exc:
        print(f"merge_settings: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
