"""Base API models and interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ApiError:
    """Structured API error details."""

    kind: str
    message: str
    retriable: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApiResponse:
    """Normalized API response container."""

    status_code: int
    data: dict[str, Any] | list[Any] | None
    raw_text: str | None = None
    error: ApiError | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Return whether the response was successful."""

        return 200 <= self.status_code < 300 and self.error is None


class SyncApiClient(Protocol):
    """Protocol for synchronous API clients."""

    def get(self, path: str, **kwargs) -> ApiResponse: ...
    def post(self, path: str, data: Any = None, **kwargs) -> ApiResponse: ...
    def patch(self, path: str, data: Any = None, **kwargs) -> ApiResponse: ...
    def delete(self, path: str, **kwargs) -> ApiResponse: ...


class KubeApiClient(SyncApiClient, Protocol):
    """Protocol for Kubernetes API clients with async-ready methods."""

    async def aget(self, path: str, **kwargs) -> ApiResponse: ...
    async def apost(self, path: str, data: Any = None, **kwargs) -> ApiResponse: ...
    async def apatch(self, path: str, data: Any = None, **kwargs) -> ApiResponse: ...
    async def adelete(self, path: str, **kwargs) -> ApiResponse: ...
