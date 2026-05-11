"""RBAC engine."""

from __future__ import annotations

import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_rbac(legacy) -> None:
    """Execute the RBAC phase using the extracted engine module."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "3"
    legacy.phase_header(
        "3",
        "Kubernetes API Enumeration via RBAC",
        "SA permissions, secret theft, impersonation, TokenRequest, bind/escalate verbs",
    )

    ns = legacy.CTX.get("namespace", "default")
    if not legacy.CTX.get("token"):
        legacy.finding("INFO", "No SA token — RBAC checks skipped", "")
        return

    legacy.section("Anonymous API Access")
    code, resp = legacy.http_get_noauth("/api/v1/namespaces")
    if code == 200:
        legacy.finding(
            "CRITICAL",
            "Anonymous API access enabled — no authentication required",
            "Any network-reachable entity can query the Kubernetes API",
            "Set --anonymous-auth=false on API server",
        )
        legacy.add_attack_edge("Network Access", "Kubernetes API", "Anonymous auth → direct API access", "CRITICAL")
    elif code == 403:
        legacy.finding("PASS", "Anonymous access denied (403 Forbidden)", "API reachable but auth enforced")
    else:
        legacy.finding("INFO", f"Anonymous API test: HTTP {code}", "")

    legacy.section("Self-Subject Rules Review (All Namespaces)")
    wildcard = False
    all_rules = []
    nss_to_check = legacy.CTX.get("namespaces", [ns])
    if not nss_to_check:
        nss_to_check = [ns]

    code, resp = legacy.k8s_api(
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        method="POST",
        data={"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": ns}},
    )
    if code == 200 and resp:
        rules = resp.get("status", {}).get("resourceRules", [])
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            groups = rule.get("apiGroups", [])
            if "*" in verbs and "*" in resources and "*" in groups:
                wildcard = True
                legacy.finding(
                    "CRITICAL",
                    "Wildcard RBAC — full cluster access via SA token",
                    "apiGroups:[*] resources:[*] verbs:[*]",
                    "Apply least-privilege RBAC",
                )
                legacy.add_attack_edge("SA Token", "Cluster Admin", "Wildcard RBAC binding", "CRITICAL")
        if not wildcard:
            legacy.finding("INFO", f"SA has {len(rules)} RBAC rule(s)", "Checking specific dangerous verbs...")
        all_rules = rules

    legacy.section("Dangerous Verb Detection")
    for rule in all_rules:
        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])
        if "bind" in verbs:
            legacy.finding(
                "CRITICAL",
                "SA has 'bind' verb — can grant any role to any subject",
                f"Resources: {resources}\nCan bind cluster-admin to attacker SA",
                "Remove bind verb from all non-cluster-admin roles",
            )
            legacy.add_attack_edge("SA Token", "Cluster Admin", "bind verb → grant cluster-admin", "CRITICAL")
        if "escalate" in verbs:
            legacy.finding(
                "CRITICAL",
                "SA has 'escalate' verb — can update roles to add new permissions",
                f"Resources: {resources}",
                "Remove escalate verb",
            )
            legacy.add_attack_edge("SA Token", "Cluster Admin", "escalate verb → self-grant permissions", "CRITICAL")
        if "impersonate" in verbs:
            legacy.finding(
                "CRITICAL",
                "SA has 'impersonate' verb — can act as any user or group",
                f"Resources: {resources}\nTest: --as=system:admin --as-group=system:masters",
                "Remove impersonate verb from SA",
            )
            legacy.add_attack_edge("SA Token", "Cluster Admin", "impersonate → system:masters", "CRITICAL")

    legacy.section("Impersonation Attack Test")
    token = legacy.CTX.get("token", "")
    api = legacy.CTX.get("api", "https://kubernetes.default")
    try:
        req = urllib.request.Request(
            api + "/api/v1/namespaces",
            headers={
                "Authorization": f"Bearer {token}",
                "Impersonate-User": "system:admin",
                "Impersonate-Group": "system:masters",
                "Accept": "application/json",
                "User-Agent": legacy._get_ua(),
            },
        )
        with urllib.request.urlopen(req, context=legacy._ssl_ctx(), timeout=6) as response:
            if response.status == 200:
                legacy.finding(
                    "CRITICAL",
                    "Impersonation as system:admin ACCEPTED",
                    "Impersonate-User: system:admin | Impersonate-Group: system:masters\n"
                    "Full cluster-admin access via impersonation",
                    "Remove impersonate verb from SA RBAC role",
                )
                legacy.add_attack_edge("SA Token", "Cluster Admin", "Impersonation accepted by API", "CRITICAL")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            legacy.finding("PASS", "Impersonation rejected (403)", "SA cannot impersonate system:admin")
    except Exception:
        pass

    legacy.section("TokenRequest API Abuse")
    sa_name = legacy.CTX.get("sa_name", "default")
    code, resp = legacy.k8s_api(
        f"/api/v1/namespaces/{ns}/serviceaccounts/{sa_name}/token",
        method="POST",
        data={
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {"audiences": ["https://kubernetes.default.svc"], "expirationSeconds": 3600},
        },
    )
    if code == 201 and resp:
        legacy.finding(
            "HIGH",
            "TokenRequest API allowed — can generate fresh SA tokens indefinitely",
            f"Generated new token for {ns}/{sa_name} (expires in 1h)\n"
            "Even if original token is rotated, attacker can keep minting new ones",
            "Restrict 'create' verb on serviceaccounts/token",
        )
        legacy.add_attack_edge("SA Token", "Persistent Access", "TokenRequest → infinite token generation", "HIGH")
    else:
        legacy.finding("PASS", "TokenRequest not permitted", f"HTTP {code}")

    legacy.section("Secret Access")
    checks = [
        ("ns_secrets", f"/api/v1/namespaces/{ns}/secrets"),
        ("all_secrets", "/api/v1/secrets"),
        ("namespaces", "/api/v1/namespaces"),
        ("pods", "/api/v1/pods"),
        ("configmaps", f"/api/v1/namespaces/{ns}/configmaps"),
        ("services", "/api/v1/services"),
        ("deployments", f"/apis/apps/v1/namespaces/{ns}/deployments"),
        ("crbs", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"),
        ("events", f"/api/v1/namespaces/{ns}/events"),
        ("nodes", "/api/v1/nodes"),
    ]
    results = {}

    def _check(name, path):
        code, response = legacy.k8s_api(path, timeout=6)
        return name, code, response

    with ThreadPoolExecutor(max_workers=8) as executor:
        for name, code, response in executor.map(lambda item: _check(*item), checks):
            results[name] = (code, response)

    code_ns, resp_ns = results.get("ns_secrets", (0, None))
    code_all, resp_all = results.get("all_secrets", (0, None))

    if code_ns == 200 and resp_ns:
        items = resp_ns.get("items", [])
        names = [item["metadata"]["name"] for item in items]
        legacy.finding(
            "CRITICAL",
            f"Can list secrets in '{ns}' ({len(items)} secrets)",
            f"Secrets: {', '.join(names[:8])}{'...' if len(names) > 8 else ''}",
            "Set automountServiceAccountToken: false | Restrict SA permissions",
        )
        legacy.add_attack_edge("SA Token", "Namespace Secrets", f"list secrets in {ns}", "CRITICAL")
        for item in items:
            secret_name = item["metadata"]["name"]
            if "default-token" not in secret_name:
                code_secret, resp_secret = legacy.k8s_api(f"/api/v1/namespaces/{ns}/secrets/{secret_name}")
                if code_secret == 200 and resp_secret:
                    data = resp_secret.get("data", {})
                    decoded = {key: legacy.decode_b64(value)[:60] for key, value in list(data.items())[:4]}
                    legacy.finding(
                        "CRITICAL",
                        f"Secret readable: {secret_name}",
                        "\n".join([f"{key}: {value}" for key, value in decoded.items()]),
                        "Restrict RBAC — remove get/list on secrets",
                    )
                break

    if code_all == 200 and resp_all:
        total = len(resp_all.get("items", []))
        legacy.finding(
            "CRITICAL",
            f"Cluster-wide secret access ({total} secrets across all namespaces)",
            "Can read every secret in every namespace",
            "Remove cluster-wide secret list/get from RBAC",
        )
        legacy.add_attack_edge("SA Token", "All Cluster Secrets", "cluster-wide secret list", "CRITICAL")

    legacy.section("Cluster Enumeration")
    code_namespaces, resp_namespaces = results.get("namespaces", (0, None))
    if code_namespaces == 200 and resp_namespaces:
        namespaces = [item["metadata"]["name"] for item in resp_namespaces.get("items", [])]
        legacy.finding(
            "HIGH",
            f"Can list all namespaces ({len(namespaces)})",
            f"Namespaces: {', '.join(namespaces)}",
            "Restrict cluster-level namespace list",
        )
        legacy.CTX["namespaces"] = namespaces

    code_pods, resp_pods = results.get("pods", (0, None))
    if code_pods == 200 and resp_pods:
        pods = resp_pods.get("items", [])
        legacy.finding(
            "HIGH",
            f"Can list all pods cluster-wide ({len(pods)})",
            f"Sample: {', '.join([pod['metadata']['name'] for pod in pods[:4]])}",
            "Restrict pod list to own namespace",
        )
        legacy.CTX["all_pods"] = pods

    code_nodes, resp_nodes = results.get("nodes", (0, None))
    if code_nodes == 200 and resp_nodes:
        nodes = resp_nodes.get("items", [])
        node_info = []
        for node in nodes:
            meta = node.get("metadata", {})
            status = node.get("status", {})
            info = status.get("nodeInfo", {})
            addresses = {address["type"]: address["address"] for address in status.get("addresses", [])}
            node_info.append(
                {
                    "name": meta.get("name", ""),
                    "ip": addresses.get("InternalIP", ""),
                    "external_ip": addresses.get("ExternalIP", ""),
                    "hostname": addresses.get("Hostname", ""),
                    "os": info.get("operatingSystem", ""),
                    "runtime": info.get("containerRuntimeVersion", ""),
                    "kubelet": info.get("kubeletVersion", ""),
                    "kernel": info.get("kernelVersion", ""),
                }
            )
        legacy.finding(
            "HIGH",
            f"Can enumerate all nodes ({len(nodes)})",
            "\n".join(
                [
                    f"{item['name']} | {item['ip']} | {item['runtime']} | kubelet {item['kubelet']}"
                    for item in node_info[:6]
                ]
            ),
            "Restrict node list permission",
        )
        legacy.CTX["nodes"] = node_info
    else:
        legacy.finding("PASS", "Cannot list nodes", "")

    code_events, resp_events = results.get("events", (0, None))
    if code_events == 200 and resp_events:
        events = resp_events.get("items", [])
        credential_events = [
            event
            for event in events
            if any(
                keyword in str(event.get("message", "")).lower()
                for keyword in ["password", "secret", "token", "credential", "failed mount", "failedmount"]
            )
        ]
        if credential_events:
            legacy.finding(
                "HIGH",
                f"Event logs leak sensitive info ({len(credential_events)} events with keywords)",
                "\n".join([legacy.truncate(event.get("message", ""), 100) for event in credential_events[:4]]),
                "Restrict event read permissions | Sanitize application log messages",
            )
        else:
            legacy.finding(
                "INFO", f"Can read events ({len(events)} total)", "No immediate credential leakage in events"
            )

    legacy.section("Pod Exec & Log Permissions")
    for verb_resource, label in [
        ("pods/exec", "Exec into pods (lateral movement)"),
        ("pods/log", "Read pod logs (credential leakage)"),
    ]:
        code_auth, resp_auth = legacy.k8s_api(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            method="POST",
            data={
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectAccessReview",
                "spec": {"resourceAttributes": {"namespace": ns, "verb": "create", "resource": verb_resource}},
            },
        )
        if code_auth == 201 and resp_auth:
            allowed = resp_auth.get("status", {}).get("allowed", False)
            if allowed:
                legacy.finding(
                    "HIGH",
                    f"SA can: {label}",
                    f"verb: create | resource: {verb_resource} | namespace: {ns}",
                    f"Remove {verb_resource} create from SA RBAC",
                )
                legacy.add_attack_edge("SA Token", "Other Pods", f"{verb_resource} → lateral movement", "HIGH")

    legacy.section("cluster-admin Bindings")
    code_crbs, resp_crbs = results.get("crbs", (0, None))
    if code_crbs == 200 and resp_crbs:
        admin_subjects = []
        for crb in resp_crbs.get("items", []):
            if crb.get("roleRef", {}).get("name") == "cluster-admin":
                for subject in crb.get("subjects", []):
                    admin_subjects.append(
                        f"{subject.get('kind')}: {subject.get('namespace', 'cluster')}/{subject.get('name')}"
                    )
        if admin_subjects:
            legacy.finding(
                "HIGH",
                f"cluster-admin bound to {len(admin_subjects)} subject(s)",
                "\n".join(admin_subjects[:6]),
                "Audit and reduce cluster-admin bindings",
            )

    legacy.section("ConfigMap Sensitive Data")
    code_cm, resp_cm = legacy.k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    if code_cm == 200 and resp_cm:
        for configmap in resp_cm.get("items", []):
            for key, value in (configmap.get("data") or {}).items():
                if any(keyword in key.lower() for keyword in ["password", "secret", "key", "token", "credential"]):
                    legacy.finding(
                        "MEDIUM",
                        f"Sensitive key in ConfigMap {configmap['metadata']['name']}.{key}",
                        f"Value: {str(value)[:80]}",
                        "Use Kubernetes Secrets not ConfigMaps for credentials",
                    )


class RBACEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 3 RBAC logic."""

    def __init__(self) -> None:
        super().__init__(name="rbac", phase="3", function_name="phase_rbac")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted RBAC engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_rbac(legacy)
        return legacy.FINDINGS[before:]
