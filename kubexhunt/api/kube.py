"""Kubernetes API and HTTP helpers extracted from the legacy script."""

from __future__ import annotations

import asyncio
from typing import Any, Callable

try:
    import aiohttp
except ImportError:
    aiohttp = None

from kubexhunt.api.auth import BearerTokenAuth
from kubexhunt.api.base import ApiResponse, KubeApiClient
from kubexhunt.api.transport import HttpTransport, TransportConfig, build_ssl_context
from kubexhunt.core.context import Context
from kubexhunt.core.logging import StructuredLogger, log_exception
from kubexhunt.core.utils import safe_json_loads


def get_user_agent(context: Context) -> str:
    """Return the current user agent string based on stealth mode."""

    if context.get("stealth", 0) >= 1:
        return "kubectl/v1.29.0 (linux/amd64) kubernetes/v1.29.0"
    return "KubeXHunt/1.2.0"


class KubernetesApiClient(KubeApiClient):
    """Reusable synchronous Kubernetes/HTTP client with async-ready methods."""

    def __init__(
        self,
        *,
        context: Context,
        logger: StructuredLogger,
        jitter: Callable[[], None] | None = None,
        timeout: int = 8,
        retries: int = 0,
        backoff_seconds: float = 0.25,
        verify_tls: bool = False,
        rate_limit_per_second: float = 0.0,
    ) -> None:
        self.context = context
        self.logger = logger
        self.transport = HttpTransport(
            context=context,
            logger=logger,
            config=TransportConfig(
                timeout=timeout,
                retries=retries,
                backoff_seconds=backoff_seconds,
                verify_tls=verify_tls,
                proxy=context.proxy or "",
                rate_limit_per_second=rate_limit_per_second,
            ),
            jitter=jitter,
        )

    def _api_url(self, path: str) -> str:
        return f"{self.context.api_server}{path}"

    def request_text(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: Any = None,
        timeout: int | None = None,
        auth: BearerTokenAuth | None = None,
    ) -> ApiResponse:
        """Execute a generic text-oriented HTTP request."""

        request_headers = {"User-Agent": get_user_agent(self.context)}
        if headers:
            request_headers.update(headers)
        if auth is not None:
            request_headers = auth.apply(request_headers)
        return self.transport.request(
            url, method=method, headers=request_headers, data=data, timeout=timeout, parse_json=False
        )

    def request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: Any = None,
        timeout: int | None = None,
        auth: BearerTokenAuth | None = None,
    ) -> ApiResponse:
        """Execute a generic JSON-oriented HTTP request."""

        request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(self.context),
        }
        if headers:
            request_headers.update(headers)
        if auth is not None:
            request_headers = auth.apply(request_headers)
        return self.transport.request(
            url, method=method, headers=request_headers, data=data, timeout=timeout, parse_json=True
        )

    def request_k8s(
        self,
        path: str,
        *,
        method: str = "GET",
        data: Any = None,
        token: str | None = None,
        timeout: int | None = None,
        anonymous: bool = False,
    ) -> ApiResponse:
        """Execute a Kubernetes API request."""

        auth = None if anonymous else BearerTokenAuth(token or self.context.token)
        return self.request_json(self._api_url(path), method=method, data=data, timeout=timeout, auth=auth)

    def get(self, path: str, **kwargs) -> ApiResponse:
        return self.request_k8s(path, method="GET", **kwargs)

    def post(self, path: str, data: Any = None, **kwargs) -> ApiResponse:
        return self.request_k8s(path, method="POST", data=data, **kwargs)

    def patch(self, path: str, data: Any = None, **kwargs) -> ApiResponse:
        return self.request_k8s(path, method="PATCH", data=data, **kwargs)

    def delete(self, path: str, **kwargs) -> ApiResponse:
        return self.request_k8s(path, method="DELETE", **kwargs)

    async def aget(self, path: str, **kwargs) -> ApiResponse:
        return await self._async_request_k8s(path, method="GET", **kwargs)

    async def apost(self, path: str, data: Any = None, **kwargs) -> ApiResponse:
        return await self._async_request_k8s(path, method="POST", data=data, **kwargs)

    async def apatch(self, path: str, data: Any = None, **kwargs) -> ApiResponse:
        return await self._async_request_k8s(path, method="PATCH", data=data, **kwargs)

    async def adelete(self, path: str, **kwargs) -> ApiResponse:
        return await self._async_request_k8s(path, method="DELETE", **kwargs)

    async def _async_request_k8s(
        self,
        path: str,
        *,
        method: str = "GET",
        data: Any = None,
        token: str | None = None,
        timeout: int | None = None,
        anonymous: bool = False,
    ) -> ApiResponse:
        """Async-ready request path with sync fallback when aiohttp is unavailable."""

        if aiohttp is None:
            return self.request_k8s(path, method=method, data=data, token=token, timeout=timeout, anonymous=anonymous)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(self.context),
        }
        if not anonymous:
            headers = BearerTokenAuth(token or self.context.token).apply(headers)
        url = self._api_url(path)
        try:
            async with (
                aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout or self.transport.config.timeout)
                ) as session,
                session.request(
                    method,
                    url,
                    json=data,
                    headers=headers,
                    ssl=build_ssl_context(self.transport.config.verify_tls),
                    proxy=self.context.proxy or None,
                ) as response,
            ):
                raw_text = await response.text()
                status_code, parsed = safe_json_loads(raw_text, response.status, self.context, self.logger)
                return ApiResponse(
                    status_code=status_code, data=parsed, raw_text=raw_text, headers=dict(response.headers)
                )
        except Exception as exc:
            log_exception(self.logger, f"Async API request failed for {path}", exc, self.context)
            return ApiResponse(status_code=0, data=None, error=None, raw_text=None)


def _build_client(
    *,
    context: Context,
    logger: StructuredLogger,
    jitter: Callable[[], None] | None = None,
    timeout: int = 8,
) -> KubernetesApiClient:
    """Create a client that preserves legacy transport semantics."""

    return KubernetesApiClient(
        context=context,
        logger=logger,
        jitter=jitter,
        timeout=timeout,
        retries=getattr(context, "retries", 0) or context.get("retries", 0),
        verify_tls=bool(context.get("verify_tls", False)),
        rate_limit_per_second=float(context.get("rate_limit_per_second", 0.0) or 0.0),
    )


def k8s_api_call(
    path: str,
    *,
    context: Context,
    logger: StructuredLogger,
    method: str = "GET",
    data: Any = None,
    token: str | None = None,
    timeout: int = 8,
    jitter: Callable[[], None] | None = None,
) -> tuple[int, Any | None]:
    """Call the Kubernetes API while preserving the legacy return shape."""

    client = _build_client(context=context, logger=logger, jitter=jitter, timeout=timeout)
    response = client.request_k8s(path, method=method, data=data, token=token, timeout=timeout)
    return response.status_code, response.data


def http_get_call(
    url: str,
    *,
    context: Context,
    logger: StructuredLogger,
    headers: dict[str, str] | None = None,
    timeout: int = 5,
    jitter: Callable[[], None] | None = None,
) -> tuple[int, str]:
    """Execute a plain HTTP GET while preserving the legacy return shape."""

    client = _build_client(context=context, logger=logger, jitter=jitter, timeout=timeout)
    response = client.request_text(url, headers=headers, timeout=timeout)
    return response.status_code, response.raw_text or ""


def http_get_noauth_call(
    path: str,
    *,
    context: Context,
    logger: StructuredLogger,
    timeout: int = 5,
    jitter: Callable[[], None] | None = None,
) -> tuple[int, Any | None]:
    """Call the Kubernetes API without auth while preserving the legacy return shape."""

    client = _build_client(context=context, logger=logger, jitter=jitter, timeout=timeout)
    response = client.request_k8s(path, timeout=timeout, anonymous=True)
    return response.status_code, response.data


async def async_k8s_api_batch(
    requests: list[dict[str, Any]],
    *,
    context: Context,
    logger: StructuredLogger,
    concurrency: int = 8,
) -> list[tuple[int, Any | None]]:
    """Asynchronously execute Kubernetes API requests when aiohttp is available."""

    client = KubernetesApiClient(
        context=context,
        logger=logger,
        timeout=max([request.get("timeout", 8) for request in requests] + [8]),
        retries=getattr(context, "retries", 0) or context.get("retries", 0),
        verify_tls=bool(context.get("verify_tls", False)),
        rate_limit_per_second=float(context.get("rate_limit_per_second", 0.0) or 0.0),
    )

    if aiohttp is None:
        results = []
        for request in requests:
            response = client.request_k8s(
                request["path"],
                method=request.get("method", "GET"),
                data=request.get("data"),
                token=request.get("token"),
                timeout=request.get("timeout", 8),
            )
            results.append((response.status_code, response.data))
        return results

    semaphore = asyncio.Semaphore(concurrency)

    async def _one(request: dict[str, Any]) -> tuple[int, Any | None]:
        async with semaphore:
            response = await client._async_request_k8s(
                request["path"],
                method=request.get("method", "GET"),
                data=request.get("data"),
                token=request.get("token"),
                timeout=request.get("timeout", 8),
            )
            return response.status_code, response.data

    return await asyncio.gather(*[_one(request) for request in requests])
