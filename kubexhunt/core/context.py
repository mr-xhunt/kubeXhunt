"""Runtime context model."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Context:
    """Mutable runtime context shared across phases."""

    token: str = ""
    namespace: str = "default"
    api_server: str = "https://kubernetes.default"
    cloud: str = "Unknown"
    runtime: str = "unknown"
    debug: bool = False
    verbose: bool = False
    proxy: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-style compatibility getter."""

        if key == "api":
            return self.api_server or default
        if hasattr(self, key):
            return getattr(self, key)
        return self.extras.get(key, default)

    def __getitem__(self, key: str) -> Any:
        value = self.get(key, None)
        if value is None and key not in self.extras and not hasattr(self, key):
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        """Dictionary-style compatibility setter."""

        if key == "api":
            self.api_server = value
            self.extras[key] = value
            return
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            self.extras[key] = value

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable view of the runtime context."""

        data = {
            "token": self.token,
            "namespace": self.namespace,
            "api_server": self.api_server,
            "cloud": self.cloud,
            "runtime": self.runtime,
            "debug": self.debug,
            "verbose": self.verbose,
            "proxy": self.proxy,
        }
        data.update(self.extras)
        return data
