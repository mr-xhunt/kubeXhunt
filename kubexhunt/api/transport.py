"""HTTP transport helpers."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from kubexhunt.api.base import ApiError, ApiResponse
from kubexhunt.api.rate_limit import RateLimiter
from kubexhunt.core.context import Context
from kubexhunt.core.logging import StructuredLogger, log_exception
from kubexhunt.core.utils import safe_json_loads


@dataclass(frozen=True)
class TransportConfig:
    """Sync HTTP transport configuration."""

    timeout: int = 8
    retries: int = 0
    backoff_seconds: float = 0.25
    verify_tls: bool = False
    proxy: str = ""
    rate_limit_per_second: float = 0.0


def build_ssl_context(verify_tls: bool = False) -> ssl.SSLContext:
    """Create the TLS context used by HTTP requests."""

    if verify_tls:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class HttpTransport:
    """Reusable synchronous HTTP transport with retries and safe parsing."""

    def __init__(
        self,
        *,
        context: Context,
        logger: StructuredLogger,
        config: TransportConfig | None = None,
        jitter: Callable[[], None] | None = None,
    ) -> None:
        self.context = context
        self.logger = logger
        self.config = config or TransportConfig(proxy=context.proxy or "")
        self.jitter = jitter
        self.rate_limiter = RateLimiter(self.config.rate_limit_per_second)

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[Any] = []
        proxy = self.config.proxy or self.context.proxy
        if proxy:
            parsed = urllib.parse.urlparse(proxy)
            scheme = parsed.scheme or "http"
            handlers.append(urllib.request.ProxyHandler({scheme: proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=build_ssl_context(self.config.verify_tls)))
        return urllib.request.build_opener(*handlers)

    def _make_error(self, kind: str, exc: Exception, *, retriable: bool, **details: Any) -> ApiError:
        return ApiError(kind=kind, message=str(exc), retriable=retriable, details=details)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: Any = None,
        timeout: int | None = None,
        parse_json: bool = True,
    ) -> ApiResponse:
        """Execute a single HTTP request with normalized behavior."""

        attempts = max(1, self.config.retries + 1)
        effective_timeout = timeout or self.config.timeout
        serialized_body = json.dumps(data).encode() if data is not None else None
        request_headers = dict(headers or {})
        last_error: ApiError | None = None

        for attempt in range(1, attempts + 1):
            if self.jitter is not None:
                self.jitter()
            self.rate_limiter.acquire()
            opener = self._build_opener()
            request = urllib.request.Request(url, data=serialized_body, headers=request_headers, method=method)
            try:
                with opener.open(request, timeout=effective_timeout) as response:
                    raw_bytes = response.read()
                    raw_text = raw_bytes.decode(errors="replace")
                    if parse_json:
                        status_code, parsed = safe_json_loads(raw_text, response.status, self.context, self.logger)
                        return ApiResponse(
                            status_code=status_code,
                            data=parsed,
                            raw_text=raw_text,
                            headers=dict(response.headers.items()),
                        )
                    return ApiResponse(
                        status_code=response.status,
                        data=None,
                        raw_text=raw_text,
                        headers=dict(response.headers.items()),
                    )
            except urllib.error.HTTPError as exc:
                raw_text = exc.read().decode(errors="replace")
                if parse_json:
                    status_code, parsed = safe_json_loads(raw_text, exc.code, self.context, self.logger)
                else:
                    status_code, parsed = exc.code, None
                return ApiResponse(
                    status_code=status_code,
                    data=parsed,
                    raw_text=raw_text,
                    error=ApiError(
                        kind="http_error", message=str(exc), retriable=False, details={"status_code": exc.code}
                    ),
                    headers=dict(exc.headers.items()) if exc.headers else {},
                )
            except TimeoutError as exc:
                last_error = self._make_error("timeout", exc, retriable=attempt < attempts, attempt=attempt)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", exc)
                retriable = attempt < attempts
                last_error = self._make_error(
                    "url_error", reason if isinstance(reason, Exception) else exc, retriable=retriable, attempt=attempt
                )
            except (ssl.SSLError, ValueError, OSError) as exc:
                last_error = self._make_error("transport_error", exc, retriable=attempt < attempts, attempt=attempt)

            if last_error is not None:
                log_exception(
                    self.logger, f"HTTP transport request failed for {url}", Exception(last_error.message), self.context
                )
            if attempt < attempts:
                time.sleep(self.config.backoff_seconds * attempt)

        return ApiResponse(status_code=0, data=None, raw_text=None, error=last_error)
