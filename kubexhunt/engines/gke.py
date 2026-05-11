"""GKE-specific engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_gke(legacy) -> None:
    """Execute the extracted GKE phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "11"
    legacy.phase_header("11", "GKE-Specific Tests", "Workload Identity, metadata scopes, legacy endpoints, dashboard")
    if legacy.CTX.get("cloud") != "GKE":
        legacy.finding("INFO", "Not GKE — GKE checks skipped", f"Detected: {legacy.CTX.get('cloud', 'Unknown')}")
        return
    legacy.section("Workload Identity Annotations")
    code, resp = legacy.k8s_api(f"/api/v1/namespaces/{legacy.CTX.get('namespace', 'default')}/serviceaccounts")
    if code == 200 and resp:
        for sa in resp.get("items", []):
            wi = sa.get("metadata", {}).get("annotations", {}).get("iam.gke.io/gcp-service-account", "")
            if wi:
                legacy.finding(
                    "INFO",
                    f"Workload Identity on {sa['metadata']['name']}",
                    f"Bound to GCP SA: {wi}\nCheck GCP SA IAM bindings for least privilege",
                    "Audit GCP SA permissions",
                )
    legacy.section("GKE Node SA Scopes")
    code, body = legacy.http_get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
        headers={"Metadata-Flavor": "Google"},
        timeout=3,
    )
    if code == 200:
        scopes = body.strip().split("\n")
        dangerous = [scope for scope in scopes if "cloud-platform" in scope or "devstorage.read_write" in scope]
        if dangerous:
            legacy.finding(
                "CRITICAL",
                "Node SA has cloud-platform scope — full GCP API access",
                f"Scopes:\n{chr(10).join(dangerous)}",
                "Use Workload Identity | Remove node SA scopes",
            )
            legacy.add_attack_edge("GCP OAuth Token", "Full GCP Account", "cloud-platform scope", "CRITICAL")
        else:
            legacy.finding(
                "MEDIUM", "Node has limited GCP scopes", f"Scopes: {', '.join(scopes[:4])}", "Move to Workload Identity"
            )
    legacy.section("Kubernetes Dashboard")
    code_dash, resp_dash = legacy.k8s_api("/api/v1/namespaces/kubernetes-dashboard/services")
    if code_dash == 200 and resp_dash and resp_dash.get("items"):
        legacy.finding(
            "MEDIUM",
            "Kubernetes Dashboard deployed",
            "Check SA permissions: kubectl get clusterrolebindings | grep dashboard",
            "Restrict dashboard SA | Disable if unused",
        )
    else:
        legacy.finding("PASS", "Kubernetes Dashboard not found", "")


class GKEEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="gke", phase="11", function_name="phase_gke")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_gke(legacy)
        return legacy.FINDINGS[before:]
