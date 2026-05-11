"""Kubelet engine."""

from __future__ import annotations

import json

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine
from kubexhunt.engines.cluster_intel import get_node_ips


def harvest_kubelet_pods(legacy, pods_data, node_ip, port) -> None:
    """Parse kubelet /pods response for credentials."""

    items = pods_data.get("items", []) if isinstance(pods_data, dict) else []
    creds_found = []
    cred_keywords = ["password", "passwd", "secret", "token", "key", "credential", "api_key"]
    for pod in items[:20]:
        for container in pod.get("spec", {}).get("containers", []):
            for env in container.get("env", []):
                if any(keyword in env.get("name", "").lower() for keyword in cred_keywords):
                    value = env.get("value", "") or str(env.get("valueFrom", ""))
                    creds_found.append(f"{pod['metadata']['name']}/{container['name']}: {env['name']}={value[:60]}")
    if creds_found:
        legacy.finding(
            "CRITICAL",
            f"Credentials harvested from kubelet /pods at {node_ip}:{port}",
            "\n".join(creds_found[:8]),
            "Disable anonymous kubelet | Remove plain-text env var credentials",
        )
        legacy.add_attack_edge(
            f"Kubelet {node_ip}",
            "Cluster Credentials",
            "Env var harvest from /pods endpoint",
            "CRITICAL",
        )


def run_phase_kubelet(legacy) -> None:
    """Execute the extracted kubelet exploitation phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "16"
    legacy.phase_header(
        "16",
        "Kubelet Exploitation",
        "Anonymous access, /pods credential harvest, exec endpoint, weak TLS",
    )

    node_ips = get_node_ips(legacy)
    legacy.info_line(f"Probing kubelet on: {', '.join(node_ips[:5])}")

    for node_ip in node_ips[:5]:
        legacy.section(f"Kubelet @ {node_ip}")

        if legacy.tcp_open(node_ip, 10255, 2):
            code, body = legacy.http_get(f"http://{node_ip}:10255/pods", timeout=5)
            if code == 200:
                legacy.finding(
                    "CRITICAL",
                    f"Kubelet port 10255 OPEN with NO AUTH at {node_ip}",
                    "Anonymous read access to pod metadata, env vars, mounted secrets",
                    "Disable --read-only-port=0 on kubelet | Apply firewall rules",
                )
                legacy.add_attack_edge(
                    "Network Access",
                    "All Pod Credentials",
                    "Kubelet 10255 anonymous → /pods harvest",
                    "CRITICAL",
                )
                try:
                    pods_data = json.loads(body)
                    harvest_kubelet_pods(legacy, pods_data, node_ip, 10255)
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            else:
                legacy.finding("INFO", f"Port 10255 open at {node_ip} but /pods returned HTTP {code}", "")
        else:
            legacy.finding("PASS", f"Kubelet port 10255 not reachable at {node_ip}", "")

        if legacy.tcp_open(node_ip, 10250, 2):
            code_anonymous, body_anonymous = legacy.http_get(f"https://{node_ip}:10250/pods", timeout=5)
            if code_anonymous == 200:
                legacy.finding(
                    "CRITICAL",
                    f"Kubelet 10250 accessible ANONYMOUSLY at {node_ip}",
                    "Full pod list, exec capability without credentials",
                    "Set --anonymous-auth=false on kubelet | Apply RBAC --authorization-mode=Webhook",
                )
                legacy.add_attack_edge(
                    "Network Access",
                    "Node RCE",
                    f"Kubelet 10250 anonymous exec → {node_ip}",
                    "CRITICAL",
                )
                try:
                    pods_data = json.loads(body_anonymous)
                    harvest_kubelet_pods(legacy, pods_data, node_ip, 10250)
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            elif code_anonymous == 401:
                legacy.finding("PASS", f"Kubelet 10250 requires auth at {node_ip}", "Auth enforced (401)")
            else:
                legacy.finding("INFO", f"Kubelet 10250 at {node_ip}: HTTP {code_anonymous}", "")

            code_running_pods, _ = legacy.http_get(f"https://{node_ip}:10250/runningpods/", timeout=3)
            if code_running_pods == 200:
                legacy.finding(
                    "HIGH",
                    f"Kubelet /runningpods accessible at {node_ip}",
                    "Lists all running pods with container IDs and spec",
                    "Restrict kubelet API access | Enable webhook authorization",
                )
        else:
            legacy.finding("INFO", f"Kubelet 10250 not reachable at {node_ip}", "Not in hostNetwork or filtered")


class KubeletEngine(LegacyFunctionEngine):
    """Kubelet engine."""

    def __init__(self) -> None:
        super().__init__(name="kubelet", phase="16", function_name="phase_kubelet")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted kubelet phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_kubelet(legacy)
