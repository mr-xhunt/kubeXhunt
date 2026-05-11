"""EKS-specific engine."""

from __future__ import annotations

import os

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_eks(legacy) -> None:
    """Execute the extracted EKS phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "10"
    legacy.phase_header("10", "EKS-Specific Tests", "aws-auth ConfigMap, IRSA, node IAM role, access entries")
    if legacy.CTX.get("cloud") != "AWS":
        legacy.finding("INFO", "Not AWS — EKS checks skipped", f"Detected: {legacy.CTX.get('cloud', 'Unknown')}")
        return
    legacy.section("aws-auth ConfigMap")
    code, resp = legacy.k8s_api("/api/v1/namespaces/kube-system/configmaps/aws-auth")
    if code == 200 and resp:
        data = resp.get("data", {})
        map_roles = data.get("mapRoles", "")
        map_users = data.get("mapUsers", "")
        legacy.finding(
            "INFO",
            "aws-auth ConfigMap readable",
            f"mapRoles entries: {map_roles.count('rolearn:')}\nmapUsers entries: {map_users.count('userarn:')}",
        )
        if "system:masters" in map_roles or "system:masters" in map_users:
            legacy.finding(
                "HIGH",
                "system:masters in aws-auth",
                "IAM roles/users mapped to cluster-admin equivalent",
                "Replace system:masters with specific ClusterRole bindings",
            )
            legacy.add_attack_edge("AWS IAM Role", "Cluster Admin", "aws-auth system:masters mapping", "HIGH")
        if not legacy.CTX.get("no_mutate"):
            code_p, _ = legacy.k8s_api(
                "/api/v1/namespaces/kube-system/configmaps/aws-auth",
                method="PATCH",
                data={"metadata": {"labels": {"kubexhunt-test": "probe"}}},
            )
            if code_p == 200:
                legacy.finding(
                    "CRITICAL",
                    "aws-auth ConfigMap is WRITABLE",
                    "Add any IAM role as cluster-admin — permanent backdoor\nAny AWS IAM identity → kubectl cluster-admin access",
                    "Restrict configmap patch/update in kube-system to cluster-admin only\nConsider migrating to EKS Access Entries",
                )
                legacy.k8s_api(
                    "/api/v1/namespaces/kube-system/configmaps/aws-auth",
                    method="PATCH",
                    data={"metadata": {"labels": {"kubexhunt-test": None}}},
                )
                legacy.add_attack_edge(
                    "AWS IAM Role", "Cluster Admin", "Write aws-auth → add system:masters IAM role", "CRITICAL"
                )
            else:
                legacy.finding("PASS", "aws-auth read-only for this SA", f"HTTP {code_p}")
    else:
        legacy.finding("PASS", "aws-auth not accessible", f"HTTP {code}")
    legacy.section("IRSA Detection")
    role_arn = os.environ.get("AWS_ROLE_ARN", "")
    if role_arn:
        legacy.finding(
            "INFO",
            "IRSA configured on this pod",
            f"Role ARN: {role_arn}\nToken: {os.environ.get('AWS_WEB_IDENTITY_TOKEN_FILE', '')}",
            "Scope IRSA role policy to minimum required permissions",
        )
    else:
        legacy.finding("PASS", "No IRSA token", "AWS_ROLE_ARN not set")
    legacy.section("EKS Cluster Info from IMDS")
    if legacy.CTX.get("aws_account"):
        region = legacy.CTX.get("aws_region", "")
        account = legacy.CTX.get("aws_account", "")
        legacy.finding(
            "INFO",
            "AWS account enumerated",
            f"Account: {account} | Region: {region}\naws eks list-clusters --region {region}",
            "Block IMDS to prevent account enumeration",
        )


class EKSEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="eks", phase="10", function_name="phase_eks")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_eks(legacy)
        return legacy.FINDINGS[before:]
