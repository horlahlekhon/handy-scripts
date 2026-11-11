import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from merge_settings import deep_merge, merge_files  # noqa: E402

SCRIPT = SCRIPTS_DIR / "merge_settings.py"


def test_union_lists_preserves_order_and_dedupes():
    base = {"permissions": {"deny": ["Read(~/.ssh/**)", "Read(~/.kube/**)"]}}
    overlay = {"permissions": {"deny": ["Read(~/.ssh/**)", "Read(~/.aws/**)"]}}

    result = deep_merge(base, overlay)

    assert result["permissions"]["deny"] == [
        "Read(~/.ssh/**)",
        "Read(~/.kube/**)",
        "Read(~/.aws/**)",
    ]


def test_existing_keys_not_in_overlay_are_kept():
    base = {"theme": "dark", "permissions": {"allow": ["Bash(ls:*)"]}}
    overlay = {"permissions": {"deny": ["Read(~/.ssh/**)"]}}

    result = deep_merge(base, overlay)

    assert result["theme"] == "dark"
    assert result["permissions"]["allow"] == ["Bash(ls:*)"]
    assert result["permissions"]["deny"] == ["Read(~/.ssh/**)"]


def test_overlay_scalar_wins():
    result = deep_merge({"a": 1, "b": {"c": "old"}}, {"b": {"c": "new"}})

    assert result == {"a": 1, "b": {"c": "new"}}


def test_inputs_are_not_mutated():
    base = {"permissions": {"deny": ["x"]}}
    overlay = {"permissions": {"deny": ["y"]}}

    deep_merge(base, overlay)

    assert base == {"permissions": {"deny": ["x"]}}
    assert overlay == {"permissions": {"deny": ["y"]}}


def test_merge_files_creates_target_when_missing(tmp_path):
    source = tmp_path / "src.json"
    target = tmp_path / "nested" / "settings.json"
    source.write_text(json.dumps({"permissions": {"deny": ["Read(~/.ssh/**)"]}}))

    merge_files(source, target)

    assert json.loads(target.read_text()) == {"permissions": {"deny": ["Read(~/.ssh/**)"]}}
    assert not target.with_suffix(".json.bak").exists()


def test_merge_files_backs_up_existing_target(tmp_path):
    source = tmp_path / "src.json"
    target = tmp_path / "settings.json"
    source.write_text(json.dumps({"permissions": {"deny": ["b"]}}))
    target.write_text(json.dumps({"theme": "dark", "permissions": {"deny": ["a"]}}))

    merge_files(source, target)

    assert json.loads(target.read_text()) == {"theme": "dark", "permissions": {"deny": ["a", "b"]}}
    assert json.loads((tmp_path / "settings.json.bak").read_text())["permissions"]["deny"] == ["a"]


def test_merge_files_rejects_invalid_target_json(tmp_path):
    source = tmp_path / "src.json"
    target = tmp_path / "settings.json"
    source.write_text("{}")
    target.write_text("{not json")

    with pytest.raises(ValueError, match="settings.json"):
        merge_files(source, target)

    assert target.read_text() == "{not json"


def test_merge_files_rejects_non_object_json(tmp_path):
    source = tmp_path / "src.json"
    target = tmp_path / "settings.json"
    source.write_text("[]")

    with pytest.raises(ValueError, match="JSON object"):
        merge_files(source, target)


def test_cli_exits_nonzero_on_bad_input(tmp_path):
    target = tmp_path / "settings.json"
    target.write_text("{bad")
    source = tmp_path / "src.json"
    source.write_text("{}")

    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(source), str(target)],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1
    assert "settings.json" in proc.stderr


def test_repo_settings_denies_credential_dirs():
    repo_settings = json.loads((SCRIPTS_DIR.parent / "settings.json").read_text())
    deny = repo_settings["permissions"]["deny"]

    for directory in (".ssh", ".gnupg", ".aws"):
        assert f"Read(~/{directory}/**)" in deny
        assert f"Edit(~/{directory}/**)" in deny
        assert f"Bash(*/{directory}*)" in deny
