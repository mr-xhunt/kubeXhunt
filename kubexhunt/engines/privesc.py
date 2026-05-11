"""Cluster privilege-escalation engine."""

from __future__ import annotations

import time

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_privesc(legacy) -> None:
    """Execute the extracted privilege-escalation phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "7"
    legacy.phase_header(
        "7",
        "Cluster-Wide Privilege Escalation",
        "Privileged pod creation, RBAC escalation, controller hijacking, scheduler abuse",
    )

    namespace = legacy.CTX.get("namespace", "default")
    if not legacy.CTX.get("token"):
        legacy.finding("INFO", "No SA token — escalation checks skipped", "")
        return

    no_mutate = legacy.CTX.get("no_mutate", False)

    legacy.section("Privileged Pod Creation")
    if no_mutate:
        legacy.finding("INFO", "--no-mutate: skipping pod creation test", "Inferring from RBAC only")
    else:
        test_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": f"kubexhunt-probe-{int(time.time())}"},
            "spec": {"containers": [{"name": "probe", "image": "busybox", "command": ["sleep", "10"]}]},
        }
        code, resp = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/pods", method="POST", data=test_pod)
        if code == 201:
            pod_name = resp.get("metadata", {}).get("name", "")
            legacy.finding(
                "HIGH",
                f"Can create pods in '{namespace}'",
                f"Created: {pod_name}",
                "Remove pod create from SA | Apply PSS Restricted",
            )
            legacy.k8s_api(f"/api/v1/namespaces/{namespace}/pods/{pod_name}", method="DELETE")

            priv_pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": f"kubexhunt-priv-{int(time.time())}"},
                "spec": {
                    "hostPID": True,
                    "hostNetwork": True,
                    "containers": [
                        {
                            "name": "escape",
                            "image": "busybox",
                            "command": ["sleep", "10"],
                            "securityContext": {"privileged": True},
                            "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                        }
                    ],
                    "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                },
            }
            code2, resp2 = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/pods", method="POST", data=priv_pod)
            if code2 == 201:
                priv_name = resp2.get("metadata", {}).get("name", "")
                legacy.finding(
                    "CRITICAL",
                    "Privileged pod creation SUCCESS — full node escape achievable",
                    f"Created: {priv_name} with hostPID+hostNetwork+hostPath+privileged\nRoot access to every node this pod is scheduled on",
                    "Apply PSS Restricted | Deny pod create from SA | Use Kyverno",
                )
                legacy.k8s_api(f"/api/v1/namespaces/{namespace}/pods/{priv_name}", method="DELETE")
                legacy.add_attack_edge("SA Token", "Node Root", "Privileged pod creation → node escape", "CRITICAL")
            else:
                legacy.finding("PASS", "Privileged pod creation blocked", f"HTTP {code2}")
        else:
            legacy.finding("PASS", f"Cannot create pods in '{namespace}'", f"HTTP {code}")

    legacy.section("Scheduler Abuse — Targeted Node Scheduling")
    code_auth, resp_auth = legacy.k8s_api(
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        method="POST",
        data={
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": {"namespace": namespace, "verb": "create", "resource": "pods"}},
        },
    )
    can_create_pods = code_auth == 201 and resp_auth and resp_auth.get("status", {}).get("allowed", False)
    if can_create_pods and legacy.CTX.get("nodes"):
        node_names = [node["name"] for node in legacy.CTX["nodes"]]
        legacy.finding(
            "HIGH",
            "Can schedule pods on specific nodes via nodeName field",
            f"Nodes: {', '.join(node_names[:4])}\nForce pod onto control-plane or sensitive-workload nodes",
            "Remove pod create | Apply NodeSelector restrictions via Kyverno",
        )
        legacy.add_attack_edge("SA Token", "Control Plane Node", "nodeName scheduling → targeted node", "HIGH")

    legacy.section("ClusterRoleBinding Creation")
    if not no_mutate:
        test_crb = f"kubexhunt-test-{int(time.time())}"
        code, _ = legacy.k8s_api(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            method="POST",
            data={
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": test_crb},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
                "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": namespace}],
            },
        )
        if code == 201:
            legacy.finding(
                "CRITICAL",
                "Can create ClusterRoleBindings — permanent RBAC escalation",
                f"Created: {test_crb}\nBind cluster-admin to any SA → full takeover",
                "Remove ClusterRoleBinding create from SA",
            )
            legacy.k8s_api(f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{test_crb}", method="DELETE")
            legacy.add_attack_edge("SA Token", "Cluster Admin", "Create ClusterRoleBinding → cluster-admin", "CRITICAL")
        else:
            legacy.finding("PASS", "Cannot create ClusterRoleBindings", f"HTTP {code}")

    legacy.section("Full Controller Patch Test")
    controllers = [
        (f"/apis/apps/v1/namespaces/{namespace}/deployments", "Deployment"),
        (f"/apis/apps/v1/namespaces/{namespace}/statefulsets", "StatefulSet"),
        (f"/apis/apps/v1/namespaces/{namespace}/daemonsets", "DaemonSet"),
        (f"/apis/batch/v1/namespaces/{namespace}/cronjobs", "CronJob"),
    ]
    for list_path, ctrl_type in controllers:
        code_l, resp_l = legacy.k8s_api(list_path)
        if code_l == 200 and resp_l:
            items = resp_l.get("items", [])
            if items:
                name = items[0]["metadata"]["name"]
                patch = [{"op": "test", "path": "/metadata/name", "value": name}]
                code_p, _ = legacy.k8s_api(f"{list_path}/{name}", method="PATCH", data=patch)
                if code_p in (200, 204):
                    legacy.finding(
                        "HIGH",
                        f"Can patch {ctrl_type} '{name}'",
                        "Inject malicious sidecar containers into existing workloads\nAttacker container runs alongside legitimate app — stealth persistence",
                        f"Remove {ctrl_type.lower()} patch permission from SA",
                    )
                    legacy.add_attack_edge(
                        "SA Token", "Stealth Persistence", f"Patch {ctrl_type} → sidecar injection", "HIGH"
                    )

    legacy.section("Admission Webhook Security")
    code_wh, resp_wh = legacy.k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    if code_wh == 200 and resp_wh:
        ignore_whs = []
        for webhook in resp_wh.get("items", []):
            for hook in webhook.get("webhooks", []):
                if hook.get("failurePolicy") == "Ignore":
                    ignore_whs.append(webhook["metadata"]["name"])
                    svc_ref = hook.get("clientConfig", {}).get("service", {})
                    if svc_ref:
                        wh_ns = svc_ref.get("namespace", "")
                        wh_svc = svc_ref.get("name", "")
                        wh_ip = legacy.dns_resolve(f"{wh_svc}.{wh_ns}.svc.cluster.local")
                        svc_reachable = bool(wh_ip) or legacy.tcp_open(f"{wh_svc}.{wh_ns}.svc.cluster.local", 443, 2)
                        if not svc_reachable:
                            legacy.finding(
                                "CRITICAL",
                                f"Webhook '{webhook['metadata']['name']}' failurePolicy=Ignore AND service unreachable",
                                f"Service: {wh_svc}.{wh_ns} — cannot be resolved\nALL admission policies bypassed silently when webhook is down",
                                "Set failurePolicy: Fail | Fix webhook service",
                            )
                            legacy.add_attack_edge(
                                "SA Token",
                                "Policy Bypass",
                                "Webhook unreachable + Ignore → privileged pod creation",
                                "CRITICAL",
                            )
        if ignore_whs:
            legacy.finding(
                "HIGH",
                f"Webhooks with failurePolicy=Ignore: {len(ignore_whs)}",
                f"Webhooks: {', '.join(ignore_whs)}\nPolicies silently bypassed if webhook down",
                "Set failurePolicy: Fail on all security-relevant webhooks",
            )
        else:
            legacy.finding("PASS", "All admission webhooks use failurePolicy=Fail", "")

    legacy.section("etcd Encryption at Rest")
    code_ap, resp_ap = legacy.k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items", []):
            if "kube-apiserver" in pod.get("metadata", {}).get("name", ""):
                for container in pod.get("spec", {}).get("containers", []):
                    cmd_str = " ".join(container.get("command", []))
                    if "encryption-provider-config" in cmd_str:
                        legacy.finding(
                            "PASS", "etcd encryption-at-rest configured", "--encryption-provider-config flag set"
                        )
                    else:
                        legacy.finding(
                            "HIGH",
                            "etcd encryption-at-rest NOT detected",
                            "Secrets stored in plaintext in etcd",
                            "Configure --encryption-provider-config on API server",
                        )
    elif code_ap in (401, 403):
        legacy.finding(
            "INFO",
            f"Cannot inspect kube-apiserver pod (HTTP {code_ap}) — etcd encryption status unknown",
            "On EKS: aws eks describe-cluster --name <cluster> --query cluster.encryptionConfig",
        )


class PrivEscEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="privesc", phase="7", function_name="phase_privesc")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_privesc(legacy)
        return legacy.FINDINGS[before:]
