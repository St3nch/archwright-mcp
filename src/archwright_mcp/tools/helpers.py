from __future__ import annotations

import json
import shlex
from typing import Any

from ..core import Controller
from ..errors import ArchwrightError


def q(value: object) -> str:
    return shlex.quote(str(value))


def result_ok(result: dict[str, Any]) -> dict[str, Any]:
    result["ok"] = result.get("exit_code", 1) == 0
    return result


def command(controller: Controller, tool: str, cmd: str, *, root: bool = False, mutation: bool = False, timeout: int | None = None, request: dict[str, Any] | None = None) -> dict[str, Any]:
    return result_ok(controller.simple(tool=tool, command=cmd, root=root, mutation=mutation, timeout=timeout, request=request))


def json_stdout(result: dict[str, Any]) -> Any:
    if result.get("exit_code") != 0:
        return result
    try:
        return json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError as exc:
        raise ArchwrightError("VALIDATION_FAILED", "Expected JSON output from target", {"stdout": result.get("stdout")}) from exc
