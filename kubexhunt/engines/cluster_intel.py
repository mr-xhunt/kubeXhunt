"""Cluster intelligence engine."""

from __future__ import annotations

import re

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def get_node_ips(legacy):
    """Get node IPs via every available method, in priority order."""

    ips = list(legacy.CTX.get("node_ips", []))
    if ips:
        return ips

    if legacy.CTX.get("kubectl"):
        _, out, _ = legacy.run_cmd(
            "kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type==InternalIP)].address}'",
            timeout=10,
        )
        if out:
            for ip in out.strip().strip("'").split():
                if ip and ip not in ips:
                    ips.append(ip)
            if ips:
                legacy.info_line(f"Node IPs via kubectl: {', '.join(ips)}")
                legacy.CTX["node_ips"] = ips
                return ips

    for config_path in [
        "/host/var/lib/kubelet/config.yaml",
        "/host/var/lib/kubelet/kubeconfig",
        "/host/etc/kubernetes/kubelet.conf",
    ]:
        content = legacy.file_read(config_path) or ""
        if content:
            match = re.search(r"server:\s*https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", content)
            if match and match.group(1) not in ips:
                ips.append(match.group(1))
                legacy.info_line(f"Node IP from kubelet config ({config_path}): {match.group(1)}")

    _, hostname_out, _ = legacy.run_cmd("hostname -I", timeout=3)
    if hostname_out:
        for ip in hostname_out.strip().split():
            if (
                ip
                and not ip.startswith("127.")
                and not ip.startswith("169.254.")
                and not ip.startswith("::")
                and ip not in ips
            ):
                ips.append(ip)
                legacy.info_line(f"Node IP from hostname -I: {ip}")

    for fib_path in ["/host/proc/net/fib_trie", "/proc/net/fib_trie"]:
        fib = legacy.file_read(fib_path) or ""
        if fib:
            local_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)\n.*?LOCAL", fib)
            for ip in local_ips:
                if (
                    not ip.startswith("127.")
                    and not ip.startswith("169.254.")
                    and not ip.endswith(".0")
                    and not ip.endswith(".255")
                    and ip not in ips
                ):
                    ips.append(ip)
                    legacy.info_line(f"Node IP from fib_trie: {ip}")
                    break
            if ips:
                break

    for downward_path in ["/etc/podinfo", "/etc/pod-info", "/etc/pod_info"]:
        node_name = (legacy.file_read(f"{downward_path}/nodeName") or "").strip()
        if node_name:
            resolved = legacy.dns_resolve(node_name)
            if resolved and resolved not in ips:
                ips.append(resolved)
                legacy.info_line(f"Node IP via Downward API DNS: {node_name} → {resolved}")

    if not ips:
        ips = ["127.0.0.1"]

    legacy.CTX["node_ips"] = ips
    return ips


def run_phase_cluster_intel(legacy) -> None:
    """Execute the extracted cluster intelligence and CVE detection phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "15"
    legacy.phase_header(
        "15",
        "Cluster Intelligence & CVE Detection",
        "K8s version, CVE mapping, node enum, events, leases, CRDs, cluster-wide pod audit",
    )

    legacy.section("Kubernetes Version Fingerprinting")
    code, resp = legacy.k8s_api("/version")
    if code == 200 and resp:
        git_version = resp.get("gitVersion", "")
        major = resp.get("major", "0")
        minor = resp.get("minor", "0").replace("+", "")
        legacy.CTX["k8s_version"] = git_version
        legacy.CTX["k8s_major"] = major
        legacy.CTX["k8s_minor"] = minor
        legacy.finding("INFO", f"Kubernetes version: {git_version}", "Checking against known CVEs...")

        k8s_minor = legacy._parse_k8s_minor(git_version)
        cve_hits = 0
        for cve in legacy.K8S_CVES:
            if cve.get("runc_check"):
                legacy._check_runc_cve(cve, git_version)
                continue
            if cve.get("affected_all"):
                legacy.finding(
                    cve["severity"],
                    f"{cve['id']}: {cve['desc']}",
                    f"Affected: {cve['affected']}\nCluster: {git_version}",
                    f"Apply mitigation for {cve['id']} — no K8s version fix exists",
                )
                cve_hits += 1
                continue
            fixed_minor = cve.get("fixed_minor")
            if fixed_minor is not None and k8s_minor < fixed_minor:
                legacy.finding(
                    cve["severity"],
                    f"{cve['id']}: {cve['desc']}",
                    f"Affected: {cve['affected']}\nCluster: {git_version} (minor={k8s_minor}, fixed in minor={fixed_minor})",
                    f"Upgrade Kubernetes — {cve['id']} fixed in minor version {fixed_minor}+",
                )
                cve_hits += 1
        if cve_hits == 0:
            legacy.finding(
                "PASS",
                f"No known K8s CVEs apply to {git_version}",
                f"All version-specific CVEs in database are fixed in minor >= {k8s_minor}",
            )
    else:
        legacy.finding("INFO", f"Cannot read /version (HTTP {code})", "")

    legacy.section("Kernel Version & Exploit Detection")
    _, uname_release, _ = legacy.run_cmd("uname -r")
    _, uname_system, _ = legacy.run_cmd("uname -s")
    if uname_release:
        is_linux = uname_system.strip().lower() == "linux"
        legacy.finding(
            "INFO",
            f"Kernel version: {uname_release}",
            f"OS: {uname_system.strip()} | Linux CVE checks: {'enabled' if is_linux else 'skipped (non-Linux)'}",
        )
        if is_linux:
            running_version = legacy._parse_kernel_ver(uname_release)
            is_ubuntu = "ubuntu" in uname_release.lower() or "generic" in uname_release.lower()
            kernel_hits = 0
            for kernel_cve in legacy.KERNEL_CVES:
                if kernel_cve.get("ubuntu_only") and not is_ubuntu:
                    continue
                cve_min = kernel_cve.get("min", (0, 0, 0))
                cve_max = kernel_cve.get("max", (0, 0, 0))
                if legacy._kernel_ver_in_range(running_version, cve_min, cve_max):
                    legacy.finding(
                        kernel_cve["severity"],
                        f"{kernel_cve['id']}: {kernel_cve['desc']}",
                        f"Affected: {kernel_cve['affected']}\nRunning: {uname_release} → parsed {running_version}\n"
                        "This kernel IS in the affected range",
                        f"Upgrade kernel immediately | Review {kernel_cve['id']}",
                    )
                    kernel_hits += 1
            if kernel_hits == 0:
                legacy.finding(
                    "PASS",
                    f"No kernel CVEs apply to {uname_release}",
                    f"Parsed version {running_version} — above all affected ranges in database",
                )
        else:
            legacy.finding(
                "INFO",
                "Non-Linux OS detected — kernel CVE checks skipped",
                "Darwin/macOS kernel version numbers are unrelated to Linux CVE ranges",
            )

    legacy.section("Node Enumeration")
    if legacy.CTX.get("nodes"):
        node_ips = [node["ip"] for node in legacy.CTX["nodes"] if node.get("ip")]
        legacy.CTX["node_ips"] = node_ips
        legacy.info_line(f"Node IPs from API: {', '.join(node_ips[:6])}")
        for node in legacy.CTX["nodes"]:
            runtime = node.get("runtime", "")
            if "runc" in runtime.lower():
                legacy.finding(
                    "HIGH",
                    f"Node {node['name']} uses runc — verify CVE-2024-21626",
                    f"Runtime: {runtime}\nLeaky Vessels: runc < 1.1.12 → /proc/self/fd container escape",
                    "Upgrade container runtime to latest version",
                )
    else:
        legacy.info_line("Node list not available via SA token — trying kubectl + host filesystem...")
        node_ips = get_node_ips(legacy)
        if node_ips and node_ips != ["127.0.0.1"]:
            legacy.finding(
                "INFO",
                f"Node IPs discovered via fallback: {len(node_ips)}",
                f"IPs: {', '.join(node_ips)}\n"
                "Source: kubectl get nodes / kubelet config / /proc/net/fib_trie / hostname -I",
            )

    legacy.section("API Server Public Exposure")
    legacy._check_api_server_public()

    legacy.section("Worker Node Public IP Check")
    legacy._check_node_public_ips()

    legacy.section("Kubernetes Event Intelligence")
    code_events, resp_events = legacy.k8s_api("/api/v1/events")
    if code_events == 200 and resp_events:
        events = resp_events.get("items", [])
        findings_in_events = []
        for event in events:
            message = event.get("message", "")
            if any(
                keyword in message.lower()
                for keyword in ["password", "secret", "token", "credential", "failed to mount", "failed mount"]
            ):
                findings_in_events.append(message)
        if findings_in_events:
            legacy.finding(
                "HIGH",
                "Event logs leak sensitive information cluster-wide",
                "\n".join([legacy.truncate(message, 120) for message in findings_in_events[:5]]),
                "Sanitize application messages | Restrict event read permissions",
            )
        else:
            legacy.finding(
                "INFO",
                f"Cluster-wide events readable ({len(events)} events)",
                "No immediate credential leakage detected",
            )
    else:
        legacy.finding("PASS", "Cannot read cluster-wide events", f"HTTP {code_events}")

    legacy.section("Lease Object Enumeration")
    code_leases, resp_leases = legacy.k8s_api("/apis/coordination.k8s.io/v1/leases")
    if code_leases == 200 and resp_leases:
        leases = resp_leases.get("items", [])
        controllers = [lease["metadata"]["name"] for lease in leases if "kube" in lease["metadata"]["name"].lower()]
        legacy.finding(
            "INFO",
            f"Lease objects readable ({len(leases)} total)",
            f"Controllers: {', '.join(controllers[:6])}\n"
            "Reveals leader election holders, node names, controller identities",
            "Restrict coordination.k8s.io/leases list permission",
        )

    legacy.section("CRD Enumeration")
    code_crd, resp_crd = legacy.k8s_api("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
    if code_crd == 200 and resp_crd:
        crds = resp_crd.get("items", [])
        sensitive_crds = [
            crd["metadata"]["name"]
            for crd in crds
            if any(
                keyword in crd["metadata"]["name"].lower()
                for keyword in ["argocd", "vault", "gitops", "crossplane", "external-secrets", "sealed"]
            )
        ]
        legacy.finding(
            "INFO",
            f"CRDs enumerated: {len(crds)} total",
            f"Sensitive CRDs: {', '.join(sensitive_crds[:6]) if sensitive_crds else 'none'}\n"
            "ArgoCD/Vault CRDs often contain credentials in CR objects",
            "Restrict CRD list | Audit CR objects for embedded secrets",
        )
        argocd_detected = any("argocd" in name for name in sensitive_crds)
        if argocd_detected:
            legacy.CTX["argocd_detected"] = True
            legacy._enumerate_argocd()

    if legacy.CTX.get("argocd_detected") and not any("ArgoCD" in finding["check"] for finding in legacy.FINDINGS):
        legacy.info_line("ArgoCD detected via process scan — running deep enumeration...")
        legacy._enumerate_argocd()

    legacy.section("Cluster-Wide Privileged Pod Audit")
    all_pods = legacy.CTX.get("all_pods", [])
    if not all_pods:
        code_pods, resp_pods = legacy.k8s_api("/api/v1/pods")
        if code_pods == 200 and resp_pods:
            all_pods = resp_pods.get("items", [])
    privileged_pods = []
    for pod in all_pods:
        spec = pod.get("spec", {})
        meta = pod.get("metadata", {})
        issues = []
        if spec.get("hostPID"):
            issues.append("hostPID")
        if spec.get("hostNetwork"):
            issues.append("hostNetwork")
        if spec.get("hostIPC"):
            issues.append("hostIPC")
        for container in spec.get("containers", []):
            security_context = container.get("securityContext", {})
            if security_context.get("privileged"):
                issues.append(f"privileged({container['name']})")
            if security_context.get("runAsUser") == 0:
                issues.append(f"runAsRoot({container['name']})")
            if security_context.get("allowPrivilegeEscalation"):
                issues.append(f"privEsc({container['name']})")
        if issues:
            privileged_pods.append(f"{meta.get('namespace', '')}/{meta.get('name', '')} [{', '.join(issues)}]")
    if privileged_pods:
        legacy.finding(
            "HIGH",
            f"Privileged/over-permissioned pods running cluster-wide: {len(privileged_pods)}",
            "\n".join(privileged_pods[:8]),
            "Apply PSS Restricted | Audit security contexts | Remove unnecessary privileges",
        )
    elif all_pods:
        legacy.finding("PASS", "No obviously privileged pods found cluster-wide", "")


class ClusterIntelEngine(LegacyFunctionEngine):
    """Cluster intelligence engine."""

    def __init__(self) -> None:
        super().__init__(name="cluster_intel", phase="15", function_name="phase_cluster_intel")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted cluster intel phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_cluster_intel(legacy)
