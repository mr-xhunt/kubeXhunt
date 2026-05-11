"""Helm and application secret extraction engine."""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import os
import re

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_helm(legacy) -> None:
    """Execute the extracted Helm phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "18"
    legacy.phase_header(
        "18",
        "Helm & Application Secret Extraction",
        "Helm release secrets, imagePullSecrets, application credential files",
    )

    legacy.section("Helm Release Secrets")
    code, resp = legacy.k8s_api("/api/v1/secrets")
    if code == 200 and resp:
        helm_secrets = [item for item in resp.get("items", []) if item.get("type", "") == "helm.sh/release.v1"]
        if helm_secrets:
            legacy.finding(
                "HIGH",
                f"Found {len(helm_secrets)} Helm release secret(s)",
                f"Releases: {', '.join([secret['metadata']['name'] for secret in helm_secrets[:6]])}",
                "Restrict secret read permissions | Use Helm secrets plugin with encryption",
            )
            for helm_secret in helm_secrets[:3]:
                data = helm_secret.get("data", {})
                raw_b64 = data.get("release", "")
                if raw_b64:
                    try:
                        raw = legacy.decode_b64(raw_b64)
                        try:
                            raw2 = base64.b64decode(raw)
                            decompressed = gzip.decompress(raw2).decode(errors="replace")
                        except (OSError, ValueError, TypeError):
                            decompressed = raw
                        cred_pattern = re.compile(
                            r"""(?:password|secret|apikey|token|credential)\s*[:=]\s*["']?([^\s"'<>{}]{6,})""",
                            re.IGNORECASE,
                        )
                        matches = cred_pattern.findall(decompressed)
                        if matches:
                            legacy.finding(
                                "CRITICAL",
                                f"Credentials in Helm release: {helm_secret['metadata']['name']}",
                                f"Found: {', '.join([match[:50] for match in matches[:4]])}",
                                "Rotate exposed credentials | Use external-secrets operator",
                            )
                    except (binascii.Error, ValueError, TypeError, OSError, NameError) as exc:
                        legacy.finding(
                            "INFO",
                            f"Helm release {helm_secret['metadata']['name']} — parse error: {str(exc)[:60]}",
                            "",
                        )
        else:
            legacy.finding("PASS", "No Helm release secrets found or accessible", "")

    legacy.section("Cluster-Wide imagePullSecrets")
    registry_creds = set()
    for pod in legacy.CTX.get("all_pods") or []:
        for image_pull_secret in pod.get("spec", {}).get("imagePullSecrets", []):
            secret_name = image_pull_secret.get("name", "")
            namespace = pod["metadata"]["namespace"]
            if secret_name:
                code_s, resp_s = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/secrets/{secret_name}")
                if code_s == 200 and resp_s:
                    cfg = resp_s.get("data", {}).get(".dockerconfigjson", "")
                    if cfg:
                        try:
                            parsed = json.loads(legacy.decode_b64(cfg))
                            for registry in parsed.get("auths", {}):
                                registry_creds.add(f"{namespace}/{secret_name} → {registry}")
                        except json.JSONDecodeError:
                            pass
    if registry_creds:
        legacy.finding(
            "HIGH",
            f"Registry credentials from imagePullSecrets: {len(registry_creds)}",
            "\n".join(list(registry_creds)[:6]),
            "Restrict secret read | Rotate registry credentials",
        )

    legacy.section("Application Secret File Scanning")
    cred_pattern = re.compile(
        r"""(?:password|passwd|secret|api_key|token|credential)\s*[:=]\s*["']?([^\s"'<>]{6,})""",
        re.IGNORECASE,
    )
    scan_dirs = ["/app", "/config", "/etc/app", "/srv", "/opt", "/home"]
    cred_files = []
    known_files = [
        ".env",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
        ".netrc",
        "secrets.yaml",
        "secrets.yml",
        "vault-token",
        "token",
    ]
    for directory in scan_dirs:
        if not os.path.isdir(directory):
            continue
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    if filename in known_files:
                        content = (legacy.file_read(file_path, lines=3) or "")[:200]
                        if content:
                            cred_files.append((file_path, legacy.truncate(content, 100)))
                    elif any(filename.endswith(ext) for ext in [".env", ".conf", ".yaml", ".yml", ".json"]):
                        content = legacy.file_read(file_path) or ""
                        matches = cred_pattern.findall(content)
                        if matches:
                            cred_files.append(
                                (file_path, f"Matches: {', '.join([match[:40] for match in matches[:3]])}")
                            )
        except OSError:
            pass
    if cred_files:
        legacy.finding(
            "HIGH",
            f"Credential files found: {len(cred_files)}",
            "\n".join([f"{path}: {value}" for path, value in cred_files[:6]]),
            "Move to Kubernetes Secrets | Remove credential files from images",
        )
    else:
        legacy.finding("PASS", "No credential files found in application directories", "")


class HelmEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 18 Helm logic."""

    def __init__(self) -> None:
        super().__init__(name="helm", phase="18", function_name="phase_helm")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted Helm engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_helm(legacy)
        return legacy.FINDINGS[before:]
