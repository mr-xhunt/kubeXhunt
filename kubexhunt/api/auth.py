"""Authentication helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BearerTokenAuth:
    """Simple bearer-token authentication helper."""

    token: str = ""

    def apply(self, headers: dict[str, str]) -> dict[str, str]:
        """Return headers with Authorization applied when a token exists."""

        result = dict(headers)
        if self.token:
            result["Authorization"] = f"Bearer {self.token}"
        return result
