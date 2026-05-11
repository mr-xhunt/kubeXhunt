"""Pod and container recon engine."""

from __future__ import annotations

import os
import stat
import time

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_pod_recon(legacy) -> None:
    """Execute the extracted pod and container recon phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "1"
    legacy.phase_header(
        "1",
        "Pod & Container Recon",
        "Capabilities, seccomp, AppArmor, filesystem, hostPID/Net, runtime socket",
    )

    legacy.section("Linux Capabilities")
    cap_data = legacy.file_read("/proc/self/status") or ""
    cap_eff = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"):
            cap_eff = line.split()[1]
            break

    if cap_eff:
        cap_int = int(cap_eff, 16)
        all_caps = 0x1FFFFFFFFF
        if cap_int == all_caps or cap_eff == "ffffffffffffffff":
            legacy.finding(
                "CRITICAL",
                "ALL Linux capabilities granted (privileged container)",
                f"CapEff: {cap_eff} — equivalent to root on the node",
                "Set privileged: false and capabilities.drop: [ALL]",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", "Privileged container → nsenter", "CRITICAL")
        elif cap_int > 0x00000000A80425FB:
            legacy.finding(
                "HIGH",
                "Elevated capabilities detected",
                f"CapEff: {cap_eff} — check for NET_RAW, SYS_ADMIN, SYS_PTRACE",
                "Drop all caps; add back only required ones",
            )
        else:
            legacy.finding("PASS", "Capabilities within normal bounds", f"CapEff: {cap_eff}")

    legacy.section("Seccomp")
    seccomp = ""
    for line in cap_data.split("\n"):
        if line.startswith("Seccomp:"):
            seccomp = line.split()[1]
            break
    if seccomp == "0":
        legacy.finding(
            "HIGH",
            "Seccomp disabled — all ~400 syscalls available",
            "Seccomp: 0",
            "Set seccompProfile.type: RuntimeDefault",
        )
    elif seccomp in ("1", "2"):
        legacy.finding("PASS", f"Seccomp mode {seccomp} active", "Syscall filtering active")

    legacy.section("AppArmor")
    aa = legacy.file_read("/proc/self/attr/current")
    if aa:
        aa = aa.strip().rstrip("\x00")
        if "unconfined" in aa:
            legacy.finding(
                "MEDIUM",
                "AppArmor unconfined",
                f"Profile: {aa}",
                "Apply AppArmor RuntimeDefault or custom profile",
            )
        else:
            legacy.finding("PASS", f"AppArmor profile: {aa}", "AppArmor restricting syscalls")

    legacy.section("Filesystem")
    test_path = f"/ro-test-{int(time.time())}"
    try:
        with open(test_path, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.remove(test_path)
        legacy.finding("MEDIUM", "Root filesystem is writable", "", "Set readOnlyRootFilesystem: true")
    except (PermissionError, OSError):
        legacy.finding("PASS", "Root filesystem is read-only", "")

    core_pattern = legacy.file_read("/proc/sys/kernel/core_pattern")
    if core_pattern and os.access("/proc/sys/kernel/core_pattern", os.W_OK):
        legacy.finding(
            "CRITICAL",
            "core_pattern is writable — privileged escape possible",
            f"Current: {core_pattern.strip()}\nWrite pipe handler → code executes on host",
            "Remove SYS_ADMIN / privileged flag",
        )
        legacy.add_attack_edge("Compromised Pod", "Node Root", "core_pattern write → host code exec", "CRITICAL")
    else:
        legacy.finding("PASS", "core_pattern not writable", "")

    dev_block = []
    if os.path.isdir("/dev"):
        for entry in os.listdir("/dev"):
            full = f"/dev/{entry}"
            try:
                if stat.S_ISBLK(os.stat(full).st_mode):
                    dev_block.append(full)
            except Exception:
                pass
    if dev_block:
        legacy.finding(
            "HIGH",
            "Block devices accessible in /dev",
            f"Devices: {', '.join(dev_block[:5])}\nRaw disk read → exfiltrate host data",
            "Remove hostPath /dev mount | Drop SYS_RAWIO",
        )
    else:
        legacy.finding("PASS", "No block devices in /dev", "")

    legacy.section("hostPath Mounts")
    for mount_point in ["/host", "/hostfs", "/rootfs", "/node", "/mnt/host"]:
        if os.path.isdir(mount_point) and os.path.exists(f"{mount_point}/etc/shadow"):
            legacy.finding(
                "CRITICAL",
                f"Host filesystem at {mount_point}",
                "Read /etc/shadow, kubelet certs, SSH keys, pod tokens",
                "Remove hostPath volumes",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", f"chroot {mount_point} /bin/bash", "CRITICAL")
            break
    else:
        legacy.finding("PASS", "No host filesystem mount", "")

    legacy.section("hostPID")
    pid1 = (legacy.file_read("/proc/1/comm") or "").strip()
    mount_ns_self = os.readlink("/proc/self/ns/mnt") if os.path.exists("/proc/self/ns/mnt") else ""
    mount_ns_pid1 = os.readlink("/proc/1/ns/mnt") if os.path.exists("/proc/1/ns/mnt") else ""
    host_namespace_visible = pid1 in ("systemd", "init", "bash", "sh") or (
        mount_ns_self
        and mount_ns_pid1
        and mount_ns_self == mount_ns_pid1
        and pid1 not in ("python", "python3", "sleep")
    )
    if host_namespace_visible:
        legacy.finding(
            "CRITICAL",
            "hostPID: true — host PID namespace visible",
            f"PID 1: {pid1} | mount-ns-self={mount_ns_self} | mount-ns-pid1={mount_ns_pid1}",
            "Remove hostPID: true",
        )
        legacy.add_attack_edge("Compromised Pod", "Host Processes", "hostPID → /proc/<pid>/environ read", "HIGH")
    else:
        legacy.finding("PASS", "Isolated PID namespace", f"PID 1: {pid1}")

    legacy.section("hostNetwork")
    kubelet_10255 = legacy.tcp_open("127.0.0.1", 10255, 1.5)
    kubelet_10250 = legacy.tcp_open("127.0.0.1", 10250, 1.5)
    if kubelet_10255 or kubelet_10250:
        ports = []
        if kubelet_10255:
            ports.append("10255")
        if kubelet_10250:
            ports.append("10250")
        legacy.finding(
            "CRITICAL",
            "hostNetwork: true — kubelet reachable on localhost",
            f"Ports: {', '.join(ports)}",
            "Remove hostNetwork: true",
        )
        legacy.add_attack_edge("Compromised Pod", "Kubelet API", "hostNetwork → localhost:10250", "CRITICAL")
    else:
        legacy.finding("PASS", "Kubelet not reachable on localhost", "")

    legacy.section("Container Runtime Socket")
    for sock in [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/host/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
    ]:
        if os.path.exists(sock):
            legacy.finding(
                "CRITICAL",
                f"Runtime socket exposed: {sock}",
                "Create privileged containers, exec into any pod, list all workloads",
                "Never mount runtime sockets into application pods",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", f"Docker/containerd via {sock}", "CRITICAL")
            break
    else:
        legacy.finding("PASS", "No runtime socket exposed", "")

    legacy.section("Container Runtime Type")
    runtime = "unknown"
    if os.path.exists("/host/run/containerd/containerd.sock") or os.path.exists("/run/containerd/containerd.sock"):
        runtime = "containerd"
    elif os.path.exists("/var/run/docker.sock"):
        runtime = "docker"
    elif os.path.exists("/run/crio/crio.sock"):
        runtime = "cri-o"
    else:
        cgroup = legacy.file_read("/proc/1/cgroup") or ""
        if "docker" in cgroup:
            runtime = "docker"
        elif "containerd" in cgroup:
            runtime = "containerd"
        elif "crio" in cgroup:
            runtime = "cri-o"
        if runtime == "unknown":
            cgroup2 = legacy.file_read("/proc/self/cgroup") or ""
            if "containerd" in cgroup2:
                runtime = "containerd"
            elif "docker" in cgroup2:
                runtime = "docker"
        if runtime == "unknown":
            kube_cfg = legacy.file_read("/host/var/lib/kubelet/config.yaml") or ""
            if "containerd" in kube_cfg:
                runtime = "containerd"
            elif "docker" in kube_cfg:
                runtime = "docker"
            elif "crio" in kube_cfg:
                runtime = "cri-o"
        if runtime == "unknown":
            mounts = legacy.file_read("/proc/1/mountinfo") or ""
            if "containerd" in mounts:
                runtime = "containerd"
            elif "docker" in mounts:
                runtime = "docker"
            elif "crio" in mounts:
                runtime = "cri-o"
        if runtime == "unknown" and legacy.CTX.get("kubectl"):
            _, rt_out, _ = legacy.run_cmd(
                "kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'",
                timeout=5,
            )
            if rt_out:
                runtime = rt_out.strip().strip("'").split("://")[0]

    _, uname_out, _ = legacy.run_cmd("uname -r")
    if "gvisor" in uname_out.lower() or "runsc" in uname_out.lower():
        runtime = "gVisor (sandbox — escape harder)"
        legacy.finding("PASS", "gVisor/Kata sandbox detected — container escape significantly harder", "")
    else:
        legacy.finding("INFO", f"Container runtime: {runtime}", "Escape feasibility depends on runtime")
    legacy.CTX["runtime"] = runtime


class PodReconEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 1 pod/container recon."""

    def __init__(self) -> None:
        super().__init__(name="pod", phase="1", function_name="phase_pod_recon")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted pod recon engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_pod_recon(legacy)
        return legacy.FINDINGS[before:]
