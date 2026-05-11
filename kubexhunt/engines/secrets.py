"""Secrets and sensitive data engine."""

from __future__ import annotations

import os
import re

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_secrets(legacy) -> None:
    """Execute the extracted secrets phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "13"
    legacy.phase_header(
        "13",
        "Secrets & Sensitive Data",
        "Env var credentials, mounted secrets, config file scanning",
    )

    legacy.section("Environment Variable Secret Scan")
    cred_kw = [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "auth_token",
        "access_token",
        "credential",
        "database_url",
    ]
    skip_kw = [
        "kubernetes",
        "service_port",
        "service_host",
        "_path",
        "_home",
        "_dir",
        "_url",
        "shell",
        "term",
        "lang",
        "pwd",
        "oldpwd",
    ]
    found_envs = []
    for key, value in os.environ.items():
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in cred_kw) and not any(keyword in key_lower for keyword in skip_kw):
            found_envs.append((key, value[:80]))
    if found_envs:
        legacy.finding(
            "HIGH",
            f"Potential credentials in env vars: {len(found_envs)}",
            "\n".join([f"{key}={value}" for key, value in found_envs[:8]]),
            "Use Kubernetes Secrets mounted as files — not env vars",
        )
    else:
        legacy.finding("PASS", "No obvious credentials in env vars", "")

    legacy.section("Mounted Secret File Scan")
    secret_paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/ssl/private",
        "/root/.docker/config.json",
        "/root/.aws/credentials",
        "/root/.kube/config",
        "/etc/git-credentials",
        "/run/secrets",
        "/etc/kubernetes/azure.json",
        "/etc/kubernetes/cloud.conf",
    ]
    found_secrets = []
    for path in secret_paths:
        if os.path.isfile(path):
            found_secrets.append((path, (legacy.file_read(path, lines=2) or "")[:100]))
        elif os.path.isdir(path):
            try:
                files = os.listdir(path)
                if files:
                    found_secrets.append((f"{path}/", f"Contains: {', '.join(files[:5])}"))
            except (OSError, UnicodeDecodeError, ValueError):
                pass
    _, key_files, _ = legacy.run_cmd(
        r"find /app /config /etc/app /srv /opt /home 2>/dev/null "
        r"-name '*.pem' -o -name '*.key' -o -name '*.p12' 2>/dev/null | head -10"
    )
    for key_file in key_files.split("\n"):
        if key_file.strip():
            found_secrets.append((key_file.strip(), "PKI key/cert file"))
    if found_secrets:
        legacy.finding(
            "MEDIUM",
            f"Mounted secret files: {len(found_secrets)}",
            "\n".join([f"{path}: {legacy.truncate(value, 80)}" for path, value in found_secrets[:8]]),
            "Audit mounted files | Rotate exposed credentials",
        )
    else:
        legacy.finding("PASS", "No unexpected secret files at common paths", "")

    legacy.section("Config File Credential Scan")
    cred_pattern = re.compile(
        r"""(?:password|passwd|secret|api_key|apikey|token|credential)\s*[:=]\s*["']?([^\s"'<>]{6,})""",
        re.IGNORECASE,
    )
    found_configs = []
    for directory in ["/app", "/config", "/etc/app", "/srv", "/opt", "/home"]:
        if not os.path.isdir(directory):
            continue
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    if any(
                        filename.endswith(ext)
                        for ext in [".conf", ".yaml", ".yml", ".json", ".env", ".ini", ".properties", ".xml"]
                    ):
                        file_path = os.path.join(root, filename)
                        try:
                            content = legacy.file_read(file_path) or ""
                            matches = cred_pattern.findall(content)
                            if matches:
                                found_configs.append((file_path, matches[:3]))
                        except (OSError, UnicodeDecodeError, ValueError):
                            pass
        except (OSError, UnicodeDecodeError, ValueError):
            pass
    if found_configs:
        for file_path, matches in found_configs[:5]:
            legacy.finding(
                "HIGH",
                f"Hardcoded credentials in: {file_path}",
                f"Values: {', '.join([legacy.truncate(match, 40) for match in matches[:3]])}",
                "Move to Kubernetes Secrets | Rotate exposed values",
            )
    else:
        legacy.finding("PASS", "No hardcoded credentials in common config locations", "")


class SecretsEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 13 secrets logic."""

    def __init__(self) -> None:
        super().__init__(name="secrets", phase="13", function_name="phase_secrets")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted secrets engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_secrets(legacy)
        return legacy.FINDINGS[before:]
