"""Unit tests for the API client layer."""

from __future__ import annotations

import io
import urllib.error

from kubexhunt.api.base import ApiError
from kubexhunt.api.kube import KubernetesApiClient, http_get_call, http_get_noauth_call, k8s_api_call
from kubexhunt.core.context import Context
from kubexhunt.core.logging import StructuredLogger


class FakeHeaders(dict):
    """Minimal headers object with dict-style iteration."""

    def items(self):
        return super().items()


class FakeResponse:
    """Minimal context-manager response object."""

    def __init__(self, status: int, body: str, headers: dict[str, str] | None = None):
        self.status = status
        self._body = body.encode()
        self.headers = FakeHeaders(headers or {})

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeOpener:
    """Fake opener that returns a fixed response or raises a fixed error."""

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.requests = []

    def open(self, request, timeout=0):
        self.requests.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _context() -> Context:
    ctx = Context(token="token-123", api_server="https://cluster.local", proxy="")
    ctx["retries"] = 1
    return ctx


def _logger() -> StructuredLogger:
    return StructuredLogger(debug=True)


def test_api_client_success_parses_json(monkeypatch):
    opener = FakeOpener(response=FakeResponse(200, '{"kind":"Pod","metadata":{"name":"demo"}}'))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)
    client = KubernetesApiClient(context=_context(), logger=_logger())

    response = client.request_k8s("/api/v1/pods/demo")

    assert response.status_code == 200
    assert response.data == {"kind": "Pod", "metadata": {"name": "demo"}}
    request = opener.requests[0][0]
    assert request.get_header("Authorization") == "Bearer token-123"


def test_api_client_timeout_returns_structured_error(monkeypatch):
    opener = FakeOpener(error=TimeoutError("timed out"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)
    client = KubernetesApiClient(context=_context(), logger=_logger(), retries=1)

    response = client.request_k8s("/api/v1/pods")

    assert response.status_code == 0
    assert isinstance(response.error, ApiError)
    assert response.error.kind == "timeout"
    assert response.error.retriable is False


def test_api_client_invalid_json_returns_none_data(monkeypatch):
    opener = FakeOpener(response=FakeResponse(200, "not-json"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)

    status_code, parsed = k8s_api_call("/api/v1/pods", context=_context(), logger=_logger())

    assert status_code == 200
    assert parsed is None


def test_api_client_auth_failure_keeps_status_and_error(monkeypatch):
    error = urllib.error.HTTPError(
        url="https://cluster.local/api/v1/pods",
        code=401,
        msg="Unauthorized",
        hdrs=FakeHeaders({"Content-Type": "application/json"}),
        fp=io.BytesIO(b'{"message":"Unauthorized"}'),
    )
    opener = FakeOpener(error=error)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)
    client = KubernetesApiClient(context=_context(), logger=_logger())

    response = client.request_k8s("/api/v1/pods")

    assert response.status_code == 401
    assert response.data == {"message": "Unauthorized"}
    assert response.error is not None
    assert response.error.kind == "http_error"


def test_api_client_empty_response_returns_none(monkeypatch):
    opener = FakeOpener(response=FakeResponse(200, ""))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)

    status_code, parsed = http_get_noauth_call("/api/v1/namespaces", context=_context(), logger=_logger())

    assert status_code == 200
    assert parsed is None


def test_http_get_call_preserves_text(monkeypatch):
    opener = FakeOpener(response=FakeResponse(200, "plain-text"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: opener)

    status_code, body = http_get_call(
        "http://example.local", context=_context(), logger=_logger(), headers={"X-Test": "1"}
    )

    assert status_code == 200
    assert body == "plain-text"
