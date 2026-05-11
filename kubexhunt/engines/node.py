"""Node compromise engine."""

from __future__ import annotations

import os

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_node(legacy) -> None:
    """Execute the extracted node compromise phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "6"
    legacy.phase_header(
        "6",
        "Node-Level Compromise",
        "Kubelet certs, other pods' SA tokens, host files, CA cert abuse",
    )

    legacy.section("Kubelet PKI Theft")
    for pki in ["/host/var/lib/kubelet/pki", "/var/lib/kubelet/pki"]:
        if os.path.isdir(pki):
            try:
                pems = [name for name in os.listdir(pki) if name.endswith(".pem")]
                if pems:
                    legacy.finding(
                        "CRITICAL",
                        f"Kubelet PKI accessible: {pki}",
                        f"Files: {', '.join(pems[:5])}\nsystem:node:<name> role → impersonate kubelet to API server",
                        "Remove hostPath mounts | PSS Restricted",
                    )
                    legacy.add_attack_edge(
                        "Node Access",
                        "API Server",
                        "Kubelet cert → system:node impersonation",
                        "CRITICAL",
                    )
                    break
            except OSError:
                pass
    else:
        legacy.finding("PASS", "Kubelet PKI not accessible", "")

    legacy.section("Other Pods' SA Tokens")
    stolen = []
    seen_tokens = set()
    for base in ["/host/var/lib/kubelet/pods", "/var/lib/kubelet/pods"]:
        if not os.path.isdir(base):
            continue
        _, find_out, _ = legacy.run_cmd(f"find {base} -name 'token' -not -path '*..data*' 2>/dev/null")
        for token_path in find_out.split("\n"):
            token_path = token_path.strip()
            if not token_path:
                continue
            token = (legacy.file_read(token_path) or "").strip()
            if not token or token in seen_tokens:
                continue
            seen_tokens.add(token)

            jwt = legacy.decode_jwt(token)
            sa_name = jwt.get("kubernetes.io/serviceaccount/service-account.name", "")
            namespace = jwt.get("kubernetes.io/serviceaccount/namespace", "")
            if not sa_name or not namespace:
                sub = jwt.get("sub", "")
                if sub.startswith("system:serviceaccount:"):
                    parts = sub.split(":")
                    if len(parts) == 4:
                        namespace = parts[2]
                        sa_name = parts[3]
            if not sa_name or not namespace:
                path_parts = token_path.split("/")
                try:
                    volume_index = path_parts.index("volumes")
                    vol_name = path_parts[volume_index + 2] if len(path_parts) > volume_index + 2 else ""
                    sa_name = sa_name or vol_name or "unknown"
                    namespace = namespace or "unknown"
                except (ValueError, IndexError):
                    pass

            sa_name = sa_name or "unknown"
            namespace = namespace or "unknown"
            stolen.append((sa_name, namespace, token_path, token))

    if stolen:
        legacy.finding(
            "CRITICAL",
            f"Found {len(stolen)} SA token(s) from other pods",
            "\n".join([f"{ns}/{sa} — {path}" for sa, ns, path, _ in stolen[:8]]),
            "Remove hostPath mounts | PSS Restricted blocks hostPath: /",
        )
        legacy.add_attack_edge(
            "Node Access",
            "Other Namespaces",
            "Stolen SA tokens from /var/lib/kubelet/pods",
            "CRITICAL",
        )
        high_value = []
        for sa_name, namespace, token_path, token in stolen:
            legacy.score_token(token, f"{namespace}/{sa_name} (stolen)")
            checks = {
                "secrets": legacy.k8s_api("/api/v1/secrets", token=token)[0],
                "nodes": legacy.k8s_api("/api/v1/nodes", token=token)[0],
                "namespaces": legacy.k8s_api("/api/v1/namespaces", token=token)[0],
                "crbs": legacy.k8s_api("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", token=token)[0],
            }
            allowed = [name for name, status in checks.items() if status == 200]
            if allowed:
                high_value.append((namespace, sa_name, token_path, allowed))
                legacy.finding(
                    "CRITICAL",
                    f"Stolen token {namespace}/{sa_name} has elevated permissions",
                    f"Token: {token_path}\nAllowed: {', '.join(allowed)}",
                    "PSS Restricted + no hostPath",
                )
                legacy.add_attack_edge(
                    f"Stolen Token {namespace}/{sa_name}",
                    "Elevated Access",
                    f"Permissions: {', '.join(allowed)}",
                    "CRITICAL",
                )
        if not high_value:
            legacy.finding(
                "INFO",
                "Stolen tokens found but all have limited permissions",
                f"{len(stolen)} tokens tested — none had secrets/nodes/namespaces/crbs access",
            )
    else:
        legacy.finding("PASS", "No other pods' tokens accessible", "")

    legacy.section("Sensitive Host Files")
    sensitive = [
        ("/host/etc/kubernetes/admin.conf", "CRITICAL", "K8s admin kubeconfig"),
        ("/host/etc/kubernetes/kubelet.conf", "HIGH", "Kubelet kubeconfig"),
        ("/host/var/lib/kubelet/kubeconfig", "HIGH", "Kubelet kubeconfig (alt)"),
        ("/host/home/kubernetes/kube-env", "HIGH", "GKE node kube-env"),
        ("/host/etc/shadow", "HIGH", "Node /etc/shadow"),
        ("/host/root/.ssh/id_rsa", "CRITICAL", "Root SSH private key"),
        ("/host/root/.ssh/authorized_keys", "HIGH", "Root SSH authorized keys"),
        ("/host/etc/kubernetes/pki/ca.key", "CRITICAL", "Cluster CA private key"),
    ]
    any_found = False
    for path, severity, desc in sensitive:
        if os.path.exists(path):
            preview = legacy.truncate((legacy.file_read(path, lines=2) or ""), 80)
            legacy.finding(
                severity,
                f"Sensitive file: {desc}",
                f"Path: {path}\nPreview: {preview}",
                "Remove hostPath mounts | Apply PSS Restricted",
            )
            any_found = True
            if severity == "CRITICAL":
                legacy.add_attack_edge("Node Access", "Cluster Admin", f"{desc} → full cluster access", "CRITICAL")
    if not any_found:
        legacy.finding("PASS", "No sensitive host files accessible", "")

    legacy.section("Cluster CA Certificate")
    ca = legacy.file_read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if ca:
        for path in ["/etc/kubernetes/pki/ca.crt", "/host/etc/kubernetes/pki/ca.crt"]:
            if os.path.exists(path):
                legacy.finding(
                    "HIGH",
                    f"Additional CA cert accessible: {path}",
                    "Combined with node PKI → possible API server MITM",
                    "Remove hostPath CA cert mounts",
                )
        legacy.finding(
            "INFO",
            "Standard SA CA cert present",
            "Normal — used for TLS verification | Not exploitable alone",
        )

    legacy.print_token_ranking()


class NodeEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 6 node logic."""

    def __init__(self) -> None:
        super().__init__(name="node", phase="6", function_name="phase_node")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted node engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_node(legacy)
        return legacy.FINDINGS[before:]
