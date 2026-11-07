from __future__ import annotations

import logging

from credwatch.proc import SubprocessRunner


def test_subprocess_runner_captures_text_and_logs_debug(caplog):
    with caplog.at_level(logging.DEBUG, logger="credwatch.proc"):
        result = SubprocessRunner().run(["echo", "hi"])
    assert (result.returncode, result.stdout) == (0, "hi\n")
    assert "rc=0" in caplog.text
