"""Advanced attack techniques engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_advanced(legacy) -> None:
    """Execute the extracted advanced techniques phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "22"
    legacy.phase_header(
        "22",
        "Advanced Red Team Techniques",
        "/proc harvest, DNS poisoning risk, service account token projection, scheduler abuse",
    )

    namespace = legacy.CTX.get("namespace", "default")

    legacy.section("SA Token Audience Abuse")
    token = legacy.CTX.get("token", "")
    if token:
        jwt = legacy.decode_jwt(token)
        audience = jwt.get("aud", [])
        issuer = jwt.get("iss", "")
        if not audience:
            legacy.finding(
                "HIGH",
                "SA token has no audience — potential token replay",
                f"iss: {issuer}\nNo aud claim → token may be accepted by other services",
                "Use bound tokens with explicit audience | Upgrade K8s >= 1.21",
            )
        elif isinstance(audience, list) and len(audience) == 1 and "kubernetes.default.svc" in audience[0]:
            legacy.finding("PASS", "SA token audience correctly scoped", f"aud: {audience}")
        else:
            legacy.finding(
                "MEDIUM",
                "Broad SA token audience",
                f"aud: {audience}\nToken may be accepted beyond the API server",
                "Configure TokenRequest with specific audience per workload",
            )

    legacy.section("DNS Cache Poisoning Risk")
    cap_data = legacy.file_read("/proc/self/status") or ""
    cap_eff = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"):
            cap_eff = line.split()[1]
            break
    if cap_eff:
        cap_int = int(cap_eff, 16)
        net_admin = 1 << 12
        net_raw = 1 << 13
        if cap_int & net_admin:
            legacy.finding(
                "HIGH",
                "NET_ADMIN capability — DNS poisoning possible",
                "Pod can modify routing tables, run DHCP server, intercept DNS\n"
                "Can respond to DNS queries faster than CoreDNS → redirect traffic",
                "Drop NET_ADMIN capability | Enable Istio mTLS",
            )
            legacy.add_attack_edge("Compromised Pod", "Other Pods", "DNS poisoning via NET_ADMIN", "HIGH")
        if cap_int & net_raw:
            legacy.finding(
                "HIGH",
                "NET_RAW capability — raw packet injection possible",
                "Can forge ARP responses, inject raw packets, sniff traffic",
                "Drop NET_RAW capability | Apply NetworkPolicy + mTLS",
            )

    legacy.section("Kubernetes Controller Hijacking Check")
    controller_paths = [
        (f"/apis/apps/v1/namespaces/{namespace}/deployments", "Deployments"),
        (f"/apis/apps/v1/namespaces/{namespace}/statefulsets", "StatefulSets"),
        (f"/apis/apps/v1/namespaces/{namespace}/daemonsets", "DaemonSets"),
        (f"/apis/batch/v1/namespaces/{namespace}/cronjobs", "CronJobs"),
    ]
    hijackable = []
    for list_path, controller_type in controller_paths:
        code_l, resp_l = legacy.k8s_api(list_path)
        if code_l == 200 and resp_l:
            items = resp_l.get("items", [])
            if items:
                first = items[0]["metadata"]["name"]
                code_p, _ = legacy.k8s_api(
                    f"{list_path}/{first}",
                    method="PATCH",
                    data=[{"op": "test", "path": "/metadata/name", "value": first}],
                )
                if code_p in (200, 204):
                    hijackable.append(f"{controller_type}: {first}")
    if hijackable:
        legacy.finding(
            "HIGH",
            "Controller hijacking possible — can inject malicious sidecars",
            f"Patchable: {', '.join(hijackable)}\n"
            "Inject: image: attacker/backdoor:latest or malicious command override\n"
            "App continues to run normally — stealth persistence",
            "Remove patch/update verbs from SA RBAC | Use Kyverno to block image changes",
        )
        legacy.add_attack_edge(
            "SA Token", "Stealth Persistence", "Controller patch → malicious sidecar injection", "HIGH"
        )

    legacy.section("Token Privilege Comparison (Namespace vs Cluster)")
    code_all, _ = legacy.k8s_api("/api/v1/secrets")
    code_ns, _ = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/secrets")
    if code_all == 200:
        legacy.finding(
            "CRITICAL",
            "Token has CLUSTER-WIDE secret access",
            "Highest privilege level for secret access",
            "Restrict to namespace-scoped roles only",
        )
    elif code_ns == 200:
        legacy.finding(
            "HIGH",
            "Token has namespace-scoped secret access",
            f"Limited to: {namespace}",
            "Remove secret read from SA RBAC if not required",
        )


class AdvancedEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 22 logic."""

    def __init__(self) -> None:
        super().__init__(name="advanced", phase="22", function_name="phase_advanced")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted advanced engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_advanced(legacy)
        return legacy.FINDINGS[before:]
