"""Miscellaneous network/plugin checks engine."""

from __future__ import annotations

import os

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_misc(legacy) -> None:
    """Execute the extracted misc phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "25"
    legacy.phase_header(
        "25",
        "Network Plugin & Miscellaneous Checks",
        "CNI detection, kube-proxy, CA reuse, service account settings cluster-wide",
    )
    legacy.section("CNI / Network Plugin Detection")
    cni_hints = {
        "calico": ["/etc/cni/net.d/10-calico.conflist", "/etc/calico"],
        "cilium": ["/etc/cni/net.d/05-cilium.conf", "/sys/fs/bpf/tc"],
        "weave": ["/etc/cni/net.d/10-weave.conf"],
        "flannel": ["/etc/cni/net.d/10-flannel.conf", "/run/flannel"],
        "canal": ["/etc/cni/net.d/10-canal.conf"],
    }
    detected_cni = []
    for cni, paths in cni_hints.items():
        if any(os.path.exists(path) for path in paths):
            detected_cni.append(cni)
    for pod in legacy.CTX.get("all_pods") or []:
        for container in pod.get("spec", {}).get("containers", []):
            image = container.get("image", "").lower()
            for cni in ["calico", "cilium", "weave", "flannel"]:
                if cni in image and cni not in detected_cni:
                    detected_cni.append(cni)
    if detected_cni:
        legacy.finding(
            "INFO",
            f"CNI detected: {', '.join(detected_cni)}",
            "Network plugin determines available attack paths:\nCalico: GlobalNetworkPolicy available for IMDS blocking\nCilium: eBPF enforcement | Weave: limited isolation",
        )
    else:
        legacy.finding("INFO", "CNI not detected from pod", "Filesystem not exposing CNI config")
    legacy.section("kube-proxy Mode")
    code_kp, resp_kp = legacy.k8s_api("/api/v1/namespaces/kube-system/configmaps/kube-proxy")
    if code_kp == 200 and resp_kp:
        cfg = resp_kp.get("data", {}).get("config.conf", "") or resp_kp.get("data", {}).get("kubeconfig.conf", "")
        if "iptables" in cfg:
            legacy.finding("INFO", "kube-proxy mode: iptables", "Standard mode")
        elif "ipvs" in cfg:
            legacy.finding("INFO", "kube-proxy mode: ipvs", "IPVS mode — different lateral movement patterns")
        elif "ebpf" in cfg.lower():
            legacy.finding("INFO", "kube-proxy replacement: eBPF (Cilium)", "")
    legacy.section("Cluster-Wide automountServiceAccountToken")
    over_mounted = []
    for pod in legacy.CTX.get("all_pods") or []:
        spec = pod.get("spec", {})
        meta = pod.get("metadata", {})
        if spec.get("automountServiceAccountToken") is not False:
            over_mounted.append(f"{meta.get('namespace', '')}/{meta.get('name', '')}")
    if over_mounted:
        legacy.finding(
            "MEDIUM",
            f"{len(over_mounted)} pods auto-mount SA tokens (potential default)",
            f"Sample: {', '.join(over_mounted[:6])}\nEvery compromised pod becomes a K8s API auth point",
            "Set automountServiceAccountToken: false on all pods that don't need K8s API access",
        )
    elif legacy.CTX.get("all_pods"):
        legacy.finding("PASS", "All pods explicitly disable SA token auto-mount", "")
    legacy.section("Service Account Default Tokens")
    code_sa, resp_sa = legacy.k8s_api(f"/api/v1/namespaces/{legacy.CTX.get('namespace', 'default')}/serviceaccounts")
    if code_sa == 200 and resp_sa:
        default_sas = [sa for sa in resp_sa.get("items", []) if sa["metadata"]["name"] == "default"]
        if default_sas:
            sa_spec = default_sas[0]
            if sa_spec.get("automountServiceAccountToken") is not False:
                legacy.finding(
                    "MEDIUM",
                    "'default' SA has automountServiceAccountToken not explicitly false",
                    "Pods using default SA inherit token mounting",
                    "kubectl patch sa default -p '{\"automountServiceAccountToken\":false}'",
                )
            else:
                legacy.finding("PASS", "'default' SA has automountServiceAccountToken: false", "")


class MiscEngine(LegacyFunctionEngine):
    def __init__(self) -> None:
        super().__init__(name="misc", phase="25", function_name="phase_misc")

    async def run(self, _context, _config, _state, _api_client):
        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_misc(legacy)
        return legacy.FINDINGS[before:]
