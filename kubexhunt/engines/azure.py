"""Azure AKS-specific engine."""

from __future__ import annotations

import json
import os
import urllib.parse

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_azure(legacy) -> None:
    """Execute the extracted Azure phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "20"
    legacy.phase_header(
        "20", "Azure AKS-Specific Tests", "IMDS, Managed Identity, Workload Identity, azure.json, AAD Pod Identity"
    )
    if legacy.CTX.get("cloud") != "Azure":
        legacy.finding("INFO", "Not Azure — AKS checks skipped", f"Detected: {legacy.CTX.get('cloud', 'Unknown')}")
        return
    legacy.section("Azure IMDS Instance Info")
    code, body = legacy.http_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers={"Metadata": "true"}, timeout=3
    )
    if code == 200:
        try:
            meta = json.loads(body)
            comp = meta.get("compute", {})
            legacy.finding(
                "INFO",
                "Azure IMDS accessible",
                f"VM: {comp.get('name', '')} | ResourceGroup: {comp.get('resourceGroupName', '')}\nLocation: {comp.get('location', '')} | SubID: {comp.get('subscriptionId', '')[:8]}...",
                "Block IMDS from pods via NetworkPolicy egress deny 169.254.169.254/32",
            )
            legacy.CTX["azure_sub"] = comp.get("subscriptionId", "")
            legacy.CTX["azure_rg"] = comp.get("resourceGroupName", "")
        except json.JSONDecodeError:
            legacy.finding("HIGH", "Azure IMDS accessible but parse failed", legacy.truncate(body, 200))
    legacy.section("Managed Identity Token Theft")
    for resource in [
        "https://management.azure.com/",
        "https://storage.azure.com/",
        "https://graph.microsoft.com/",
        "https://vault.azure.net/",
    ]:
        encoded = urllib.parse.quote(resource, safe="")
        code, body = legacy.http_get(
            f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={encoded}",
            headers={"Metadata": "true"},
            timeout=3,
        )
        if code == 200:
            try:
                tok_data = json.loads(body)
                legacy.finding(
                    "CRITICAL",
                    f"Managed Identity OAuth2 token for {resource}",
                    f"Token type: {tok_data.get('token_type')} | Expires: {tok_data.get('expires_in')}s\nToken preview: {tok_data.get('access_token', '')[:20]}...",
                    "Restrict IMDS | Use Workload Identity Federation instead of Managed Identity",
                )
                legacy.add_attack_edge("Compromised Pod", "Azure Account", f"Managed Identity → {resource}", "CRITICAL")
            except json.JSONDecodeError:
                pass
        elif code == 400:
            legacy.finding(
                "MEDIUM",
                "Managed Identity endpoint reachable but no identity assigned",
                "",
                "Still block IMDS access as defense-in-depth",
            )
    legacy.section("Azure Workload Identity")
    az_client = os.environ.get("AZURE_CLIENT_ID", "")
    az_tenant = os.environ.get("AZURE_TENANT_ID", "")
    az_tok_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "")
    if az_client and az_tenant:
        legacy.file_read(az_tok_file) if az_tok_file else ""
        legacy.finding(
            "HIGH",
            "Azure Workload Identity configured on this pod",
            f"Client ID: {az_client}\nTenant: {az_tenant}\nToken file: {az_tok_file}\nCan exchange K8s SA token for Azure AD token",
            "Scope AKS Workload Identity to minimum required Azure permissions",
        )
        legacy.add_attack_edge("Compromised Pod", "Azure AD", "Workload Identity token exchange", "HIGH")
    else:
        legacy.finding("PASS", "No Azure Workload Identity env vars", "")
    legacy.section("azure.json Service Principal Credentials")
    for az_path in ["/etc/kubernetes/azure.json", "/etc/kubernetes/cloud.conf"]:
        content = legacy.file_read(az_path)
        if content:
            try:
                az_cfg = json.loads(content)
                client_id = az_cfg.get("aadClientId", "") or az_cfg.get("clientId", "")
                client_secret = az_cfg.get("aadClientSecret", "") or az_cfg.get("clientSecret", "")
                tenant = az_cfg.get("tenantId", "")
                sub = az_cfg.get("subscriptionId", "")
                if client_secret:
                    legacy.finding(
                        "CRITICAL",
                        f"Service Principal credentials in {az_path}",
                        f"ClientID: {client_id} | Secret: {client_secret[:8]}...\nTenantID: {tenant} | SubID: {sub[:8]}...\naz login --service-principal -u {{clientId}} -p {{secret}} --tenant {{tenant}}",
                        "Rotate SP credentials immediately | Migrate to Managed Identity",
                    )
                    legacy.add_attack_edge(
                        "Compromised Pod", "Azure Subscription", f"SP credentials in {az_path} → az login", "CRITICAL"
                    )
                else:
                    legacy.finding(
                        "HIGH",
                        f"azure.json accessible at {az_path}",
                        f"Contains: {', '.join(az_cfg.keys())}\nMay use MSI — check for Managed Identity escalation",
                        "Restrict read access to azure.json",
                    )
            except json.JSONDecodeError:
                legacy.finding(
                    "HIGH",
                    f"{az_path} readable but not JSON",
                    legacy.truncate(content, 200),
                    "Review content for credentials | Restrict file access",
                )
    legacy.section("AAD Pod Identity (Legacy)")
    code_nmi, resp_nmi = legacy.k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_nmi == 200 and resp_nmi:
        nmi_pods = [
            pod
            for pod in resp_nmi.get("items", [])
            if "nmi" in pod["metadata"]["name"].lower() or "aad-pod-identity" in pod["metadata"]["name"].lower()
        ]
        if nmi_pods:
            legacy.finding(
                "HIGH",
                "AAD Pod Identity (legacy) NMI DaemonSet detected",
                f"NMI pods: {', '.join([pod['metadata']['name'] for pod in nmi_pods])}\nPods can request tokens without Kubernetes-level auth check via NMI",
                "Migrate to Workload Identity | Restrict AzureIdentity CRD access",
            )
            code_nmi_tok, _ = legacy.http_get(
                "http://127.0.0.1:2579/metadata/identity/oauth2/token?resource=https://management.azure.com/",
                headers={"podname": "test", "podns": "default"},
                timeout=2,
            )
            if code_nmi_tok == 200:
                legacy.finding(
                    "CRITICAL",
                    "AAD Pod Identity NMI token endpoint accessible — unauthenticated",
                    "Port 2579 responds to token requests without pod validation",
                    "Upgrade to Workload Identity immediately",
                )
                legacy.add_attack_edge("Compromised Pod", "Azure AD", "NMI unauthenticated token → Azure", "CRITICAL")
    legacy.section("AKS SP Secret in kube-system")
    code_sp, resp_sp = legacy.k8s_api("/api/v1/namespaces/kube-system/secrets")
    if code_sp == 200 and resp_sp:
        sp_secrets = [
            secret
            for secret in resp_sp.get("items", [])
            if "service-principal" in secret["metadata"]["name"].lower()
            or "azurespn" in secret["metadata"]["name"].lower()
            or "azure" in secret["metadata"]["name"].lower()
        ]
        if sp_secrets:
            for secret in sp_secrets[:3]:
                client_secret = secret.get("data", {}).get("clientSecret", "") or secret.get("data", {}).get(
                    "secret", ""
                )
                if client_secret:
                    legacy.finding(
                        "CRITICAL",
                        f"AKS SP secret in kube-system: {secret['metadata']['name']}",
                        f"clientSecret: {legacy.decode_b64(client_secret)[:20]}...",
                        "Rotate SP credentials | Migrate to Managed Identity",
                    )


class AzureEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="azure", phase="20", function_name="phase_azure")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_azure(legacy)
        return legacy.FINDINGS[before:]
