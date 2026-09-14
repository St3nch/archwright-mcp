from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ArchwrightError(Exception):
    code: str
    message: str
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details or {},
            },
        }
