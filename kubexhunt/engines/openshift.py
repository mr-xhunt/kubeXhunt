"""OpenShift-specific engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_openshift(legacy) -> None:
    """Execute the extracted OpenShift phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "21"
    legacy.phase_header(
        "21", "OpenShift / OKD Tests", "SCC enumeration, OAuth, internal registry, routes, OpenShift RBAC"
    )
    code_oc, resp_oc = legacy.k8s_api("/apis/security.openshift.io/v1/securitycontextconstraints")
    is_openshift = code_oc in (200, 403)
    if not is_openshift:
        legacy.finding("INFO", "Not OpenShift — SCC API not present", "")
        return
    legacy.section("SecurityContextConstraints Enumeration")
    if code_oc == 200 and resp_oc:
        sccs = resp_oc.get("items", [])
        dangerous_sccs = [
            scc["metadata"]["name"]
            for scc in sccs
            if scc["metadata"]["name"] in ("anyuid", "privileged", "hostmount-anyuid", "hostaccess", "hostnetwork")
        ]
        if dangerous_sccs:
            legacy.finding(
                "HIGH",
                f"Dangerous SCCs exist: {', '.join(dangerous_sccs)}",
                "anyuid = run as any UID | privileged = full node access",
                "Audit SCC assignments | Remove anyuid/privileged from non-admin SAs",
            )
        legacy.finding(
            "INFO", f"SCCs enumerated: {len(sccs)}", f"SCCs: {', '.join([scc['metadata']['name'] for scc in sccs[:8]])}"
        )
    legacy.section("Current Pod SCC Detection")
    _, scc_out, _ = legacy.run_cmd("cat /proc/self/attr/current 2>/dev/null")
    if scc_out:
        if "privileged" in scc_out.lower() or "anyuid" in scc_out.lower():
            legacy.finding(
                "CRITICAL",
                f"Pod running under dangerous SCC: {scc_out}",
                "privileged or anyuid SCC = equivalent to PSS Privileged",
                "Assign restricted SCC | Remove anyuid from SA",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", "anyuid/privileged SCC → host escape", "CRITICAL")
        else:
            legacy.finding("INFO", f"Current SCC: {scc_out}", "")
    legacy.section("SA SCC Permission Check")
    sa = legacy.CTX.get("sa_name", "default")
    namespace = legacy.CTX.get("namespace", "default")
    code_sa_scc, resp_sa_scc = legacy.k8s_api(
        "/apis/authorization.openshift.io/v1/subjectaccessreviews",
        method="POST",
        data={
            "apiVersion": "authorization.openshift.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": f"system:serviceaccount:{namespace}:{sa}",
                "groups": [],
                "resource": {"resource": "securitycontextconstraints", "verb": "use", "group": "security.openshift.io"},
            },
        },
    )
    if code_sa_scc == 201 and resp_sa_scc and resp_sa_scc.get("status", {}).get("allowed", False):
        legacy.finding(
            "HIGH",
            f"SA {namespace}/{sa} can use SCCs",
            "Can escalate privileges by requesting higher SCC",
            "Audit SCC use permissions | Apply OPA/Kyverno restrictions",
        )
    legacy.section("OpenShift Route Enumeration")
    code_rt, resp_rt = legacy.k8s_api("/apis/route.openshift.io/v1/routes")
    if code_rt == 200 and resp_rt:
        routes = resp_rt.get("items", [])
        internal_routes = [
            route
            for route in routes
            if "internal" in route.get("spec", {}).get("host", "").lower()
            or "admin" in route.get("spec", {}).get("host", "").lower()
        ]
        legacy.finding(
            "INFO",
            f"OpenShift Routes enumerated: {len(routes)}",
            f"Routes: {', '.join([route['spec']['host'] for route in routes[:6]])}\nInternal/admin routes: {len(internal_routes)}",
            "Review exposed routes | Apply OpenShift NetworkPolicy",
        )
        if internal_routes:
            legacy.finding(
                "MEDIUM",
                "Admin/internal routes exposed via OpenShift Router",
                "\n".join([route["spec"]["host"] for route in internal_routes[:5]]),
                "Restrict route access | Apply authentication on internal routes",
            )
    legacy.section("OpenShift Internal Registry")
    code_reg, resp_reg = legacy.k8s_api("/api/v1/namespaces/openshift-image-registry/services")
    if code_reg == 200 and resp_reg and resp_reg.get("items"):
        legacy.finding(
            "INFO",
            "OpenShift internal registry detected",
            "Accessible at: image-registry.openshift-image-registry.svc:5000\nimage-puller SA may have pull secrets worth stealing",
            "Audit image-puller SA token permissions",
        )
        code_ip, resp_ip = legacy.k8s_api("/api/v1/namespaces/openshift-image-registry/secrets")
        if code_ip == 200 and resp_ip:
            pull_secrets = [
                secret
                for secret in resp_ip.get("items", [])
                if "puller" in secret["metadata"]["name"].lower() or "push" in secret["metadata"]["name"].lower()
            ]
            if pull_secrets:
                legacy.finding(
                    "HIGH",
                    "OpenShift image registry pull/push secrets accessible",
                    f"Secrets: {', '.join([secret['metadata']['name'] for secret in pull_secrets[:5]])}",
                    "Restrict registry secret access | Rotate registry credentials",
                )
    legacy.section("OpenShift OAuth Token Probe")
    code_oauth, _ = legacy.http_get(legacy.CTX["api"] + "/oauth/token/request", timeout=3)
    if code_oauth in (200, 302):
        legacy.finding(
            "INFO",
            "OpenShift OAuth endpoint reachable",
            "Browser-based token request endpoint accessible",
            "Restrict OAuth token request endpoint if not needed",
        )
    legacy.section("OpenShift Namespace Enumeration")
    code_ons, resp_ons = legacy.k8s_api("/apis/project.openshift.io/v1/projects")
    if code_ons == 200 and resp_ons:
        projects = resp_ons.get("items", [])
        sensitive = [
            project["metadata"]["name"]
            for project in projects
            if any(
                keyword in project["metadata"]["name"]
                for keyword in ["openshift", "kube-system", "production", "prod", "finance", "payment"]
            )
        ]
        legacy.finding(
            "INFO",
            f"OpenShift Projects enumerated: {len(projects)}",
            f"Sensitive: {', '.join(sensitive[:6])}",
            "Restrict project list to required namespaces only",
        )


class OpenShiftEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="openshift", phase="21", function_name="phase_openshift")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_openshift(legacy)
        return legacy.FINDINGS[before:]
