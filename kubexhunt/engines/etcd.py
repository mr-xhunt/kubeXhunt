"""etcd engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine
from kubexhunt.engines.cluster_intel import get_node_ips


def run_phase_etcd(legacy) -> None:
    """Execute the extracted etcd exposure phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "17"
    legacy.phase_header(
        "17",
        "etcd Exposure",
        "Unauthenticated etcd access, secret dump, TLS bypass",
    )

    node_ips = get_node_ips(legacy)
    legacy.info_line(f"Probing etcd on: {', '.join(node_ips[:5])}")

    for node_ip in node_ips[:5]:
        legacy.section(f"etcd @ {node_ip}")

        if not legacy.tcp_open(node_ip, 2379, 2):
            legacy.finding("PASS", f"etcd port 2379 not reachable at {node_ip}", "Filtered or not exposed")
            continue

        code, body = legacy.http_get(f"http://{node_ip}:2379/version", timeout=4)
        if code == 200:
            legacy.finding(
                "CRITICAL",
                f"etcd at {node_ip}:2379 accessible WITHOUT TLS",
                f"Version info: {legacy.truncate(body, 120)}\n"
                "Entire Kubernetes state — all secrets — readable without credentials",
                "Enable --client-cert-auth=true on etcd | Restrict port 2379 to API server only",
            )
            legacy.add_attack_edge(
                "Network Access",
                "All Cluster Secrets",
                f"etcd {node_ip}:2379 no-auth → /registry/secrets dump",
                "CRITICAL",
            )

            code_keys, _ = legacy.http_get(f"http://{node_ip}:2379/v3/keys/registry/secrets", timeout=4)
            if code_keys == 200:
                legacy.finding(
                    "CRITICAL",
                    "etcd v3 keys accessible — full cluster secret dump possible",
                    f"Endpoint: http://{node_ip}:2379/v3/keys/registry/secrets\n"
                    "Use etcdctl to extract all Kubernetes secrets",
                    "Immediately restrict etcd access to API server only",
                )
            continue

        code_tls, body_tls = legacy.http_get(f"https://{node_ip}:2379/version", timeout=4)
        if code_tls == 200:
            legacy.finding(
                "CRITICAL",
                f"etcd at {node_ip}:2379 accessible via HTTPS without client cert",
                f"TLS present but no mutual TLS enforced\n{legacy.truncate(body_tls, 120)}",
                "Enable --client-cert-auth=true | Require etcd client certificates",
            )
            legacy.add_attack_edge(
                "Network Access",
                "All Cluster Secrets",
                f"etcd {node_ip}:2379 TLS no client cert",
                "CRITICAL",
            )
        else:
            legacy.finding("PASS", f"etcd at {node_ip}:2379 properly protected", f"HTTP {code_tls}")

        if legacy.tcp_open(node_ip, 2380, 2):
            code_peer, _ = legacy.http_get(f"http://{node_ip}:2380/version", timeout=3)
            if code_peer == 200:
                legacy.finding(
                    "HIGH",
                    f"etcd peer port 2380 open and accessible at {node_ip}",
                    "Peer port should be internal only",
                    "Restrict etcd peer port 2380 to etcd cluster members only",
                )


class EtcdEngine(LegacyFunctionEngine):
    """etcd engine."""

    def __init__(self) -> None:
        super().__init__(name="etcd", phase="17", function_name="phase_etcd")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted etcd phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_etcd(legacy)
