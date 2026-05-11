"""Shared logging helpers."""

from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any

from kubexhunt.core.context import Context


class StructuredLogger:
    """Minimal structured logger with optional JSON output."""

    LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

    def __init__(self, verbose: bool = False, debug: bool = False, json_logs: bool = False):
        self.verbose = verbose
        self.debug = debug
        self.json_logs = json_logs

    def _should_log(self, level: str) -> bool:
        threshold = "DEBUG" if self.debug else "INFO" if self.verbose else "WARN"
        return self.LEVELS[level] >= self.LEVELS[threshold]

    def log(self, level: str, message: str, **fields: Any) -> None:
        if not self._should_log(level):
            return
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
        if fields:
            payload["fields"] = fields
        if self.json_logs:
            print(json.dumps(payload, sort_keys=True))
        else:
            suffix = f" | {fields}" if fields else ""
            print(f"[{level}] {message}{suffix}")

    def debug_log(self, message: str, **fields: Any) -> None:
        self.log("DEBUG", message, **fields)

    def info(self, message: str, **fields: Any) -> None:
        self.log("INFO", message, **fields)

    def warn(self, message: str, **fields: Any) -> None:
        self.log("WARN", message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self.log("ERROR", message, **fields)


def get_logger(name: str) -> logging.Logger:
    """Return a package logger."""

    return logging.getLogger(name)


def log_exception(logger: StructuredLogger, message: str, exc: Exception, context: Context | None = None) -> None:
    """Safely log exceptions with optional stack traces in debug mode."""

    if context and context.debug:
        logger.error(message, error=str(exc), traceback=traceback.format_exc())
    else:
        logger.debug_log(message, error=str(exc))
