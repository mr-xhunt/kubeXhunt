"""Persistence engine."""

from __future__ import annotations

import json
import time

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_persistence(legacy) -> None:
    """Execute the extracted persistence phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "8"
    legacy.phase_header(
        "8",
        "Persistence Techniques",
        "Backdoor SA, DaemonSet, sidecar injection, CronJob persistence",
    )

    namespace = legacy.CTX.get("namespace", "default")
    no_mutate = legacy.CTX.get("no_mutate", False)
    if not legacy.CTX.get("token"):
        legacy.finding("INFO", "No SA token — persistence checks skipped", "")
        return

    if no_mutate:
        legacy.finding(
            "INFO",
            "Persistence options available (output only)",
            json.dumps(legacy.build_persistence_options(), indent=2)[:1200],
        )
        return

    legacy.section("ServiceAccount Creation in kube-system")
    sa_name = f"kubexhunt-sa-{int(time.time())}"
    code, _ = legacy.k8s_api(
        "/api/v1/namespaces/kube-system/serviceaccounts",
        method="POST",
        data={"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa_name}},
    )
    if code == 201:
        legacy.finding(
            "CRITICAL",
            "Can create SAs in kube-system — backdoor SA possible",
            f"Created: {sa_name}\nBind cluster-admin to backdoor SA → permanent access",
            "Restrict SA create in kube-system",
        )
        legacy.k8s_api(f"/api/v1/namespaces/kube-system/serviceaccounts/{sa_name}", method="DELETE")
        legacy.add_attack_edge("SA Token", "Persistent Cluster Admin", "Backdoor SA in kube-system", "CRITICAL")
    else:
        legacy.finding("PASS", "Cannot create SAs in kube-system", f"HTTP {code}")

    legacy.section("DaemonSet Creation in kube-system")
    daemonset_name = f"kubexhunt-ds-{int(time.time())}"
    daemonset_spec = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": daemonset_name, "namespace": "kube-system"},
        "spec": {
            "selector": {"matchLabels": {"app": "kxh-test"}},
            "template": {
                "metadata": {"labels": {"app": "kxh-test"}},
                "spec": {
                    "tolerations": [{"operator": "Exists"}],
                    "containers": [{"name": "probe", "image": "busybox", "command": ["sleep", "10"]}],
                },
            },
        },
    }
    code, _ = legacy.k8s_api("/apis/apps/v1/namespaces/kube-system/daemonsets", method="POST", data=daemonset_spec)
    if code == 201:
        legacy.finding(
            "CRITICAL",
            "Can create DaemonSets in kube-system — runs on EVERY node",
            f"Created: {daemonset_name}\nCluster-wide persistence on all nodes",
            "Remove DaemonSet create | Restrict kube-system write access",
        )
        legacy.k8s_api(f"/apis/apps/v1/namespaces/kube-system/daemonsets/{daemonset_name}", method="DELETE")
        legacy.add_attack_edge("SA Token", "All Nodes", "DaemonSet in kube-system → every node", "CRITICAL")
    else:
        legacy.finding("PASS", "Cannot create DaemonSets in kube-system", f"HTTP {code}")

    legacy.section("CronJob Persistence")
    cronjob_name = f"kubexhunt-cj-{int(time.time())}"
    cronjob_spec = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": cronjob_name, "namespace": namespace},
        "spec": {
            "schedule": "*/5 * * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "probe", "image": "busybox", "command": ["sleep", "5"]}],
                            "restartPolicy": "OnFailure",
                        }
                    }
                }
            },
        },
    }
    code, _ = legacy.k8s_api(f"/apis/batch/v1/namespaces/{namespace}/cronjobs", method="POST", data=cronjob_spec)
    if code == 201:
        legacy.finding(
            "HIGH",
            f"Can create CronJobs in '{namespace}' — scheduled persistence",
            f"Created: {cronjob_name} (every 5min)\nReliable attacker foothold",
            "Remove CronJob create permission from SA",
        )
        legacy.k8s_api(f"/apis/batch/v1/namespaces/{namespace}/cronjobs/{cronjob_name}", method="DELETE")
    else:
        legacy.finding("PASS", f"Cannot create CronJobs in '{namespace}'", f"HTTP {code}")

    legacy.section("Deployment Sidecar Injection")
    code_deployments, resp_deployments = legacy.k8s_api(f"/apis/apps/v1/namespaces/{namespace}/deployments")
    if code_deployments == 200 and resp_deployments:
        deployments = resp_deployments.get("items", [])
        if deployments:
            deployment_name = deployments[0]["metadata"]["name"]
            patch = [{"op": "test", "path": "/metadata/name", "value": deployment_name}]
            code_patch, _ = legacy.k8s_api(
                f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment_name}",
                method="PATCH",
                data=patch,
            )
            if code_patch in (200, 204):
                legacy.finding(
                    "HIGH",
                    f"Can patch deployment '{deployment_name}' — sidecar injection possible",
                    "Inject malicious container alongside legitimate app",
                    "Remove deployment patch permission",
                )


class PersistenceEngine(LegacyFunctionEngine):
    """Persistence engine."""

    def __init__(self) -> None:
        super().__init__(name="persistence", phase="8", function_name="phase_persistence")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted persistence phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_persistence(legacy)
