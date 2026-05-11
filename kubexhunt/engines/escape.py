"""Container escape engine."""

from __future__ import annotations

import os

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_escape(legacy) -> None:
    """Execute the extracted container escape phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "5"
    legacy.phase_header(
        "5",
        "Container Escape Vectors",
        "nsenter, chroot, cgroup v1, core_pattern, user namespaces, runtime socket",
    )

    cap_data = legacy.file_read("/proc/self/status") or ""
    cap_eff = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"):
            cap_eff = line.split()[1]
            break
    has_all = int(cap_eff, 16) >= 0x1FFFFFFFFF if cap_eff else False
    pid1 = (legacy.file_read("/proc/1/comm") or "").strip()
    has_hpid = pid1 in ("systemd", "init")

    legacy.section("nsenter Escape")
    if has_hpid and has_all:
        legacy.finding(
            "CRITICAL",
            "nsenter escape possible: hostPID=true + privileged=true",
            "nsenter -t 1 -m -u -i -n -p -- /bin/bash\n→ Full root shell on node",
            "Remove hostPID: true | Set privileged: false | Drop all caps",
        )
        legacy.add_attack_edge("Compromised Pod", "Node Root", "nsenter -t 1 → host bash", "CRITICAL")
    elif has_hpid:
        legacy.finding(
            "HIGH",
            "hostPID=true but not fully privileged",
            "Read /proc/<pid>/environ from host processes → credential leak",
            "Remove hostPID: true",
        )
    else:
        legacy.finding("PASS", "nsenter escape not possible", "hostPID not enabled")

    legacy.section("chroot Escape")
    for mount_point in ["/host", "/hostfs", "/rootfs", "/node", "/mnt/host"]:
        if os.path.exists(f"{mount_point}/etc/shadow"):
            legacy.finding(
                "CRITICAL",
                f"chroot escape via hostPath at {mount_point}",
                f"chroot {mount_point} /bin/bash → node root",
                "Remove hostPath volumes | Enable PSS Restricted",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", f"chroot {mount_point}", "CRITICAL")
            break
    else:
        legacy.finding("PASS", "chroot escape not possible", "No host filesystem mount")

    legacy.section("cgroup v1 release_agent")
    release_agents = []
    try:
        for subsys in os.listdir("/sys/fs/cgroup"):
            release_agent = f"/sys/fs/cgroup/{subsys}/release_agent"
            if os.path.exists(release_agent):
                release_agents.append(release_agent)
    except OSError:
        pass
    writable_release_agents = [path for path in release_agents[:3] if os.access(path, os.W_OK)]
    if writable_release_agents:
        legacy.finding(
            "CRITICAL",
            "cgroup v1 release_agent writable — host escape possible",
            f"Paths: {', '.join(writable_release_agents)}\n"
            "Write payload to release_agent → executes on host when cgroup released",
            "Disable cgroup v1 | Use cgroup v2 | Drop all capabilities",
        )
        legacy.add_attack_edge("Compromised Pod", "Node Root", "cgroup v1 release_agent write", "CRITICAL")
    elif release_agents:
        legacy.finding("LOW", "cgroup v1 release_agent present but not writable", "")
    else:
        legacy.finding("PASS", "cgroup v1 release_agent not accessible", "")

    legacy.section("User Namespace Escape")
    rc, out, _ = legacy.run_cmd("unshare --user --map-root-user id 2>&1", timeout=5)
    if rc == 0 and "uid=0" in out:
        legacy.finding(
            "HIGH",
            "User namespace unshare allowed — potential privilege escalation",
            f"unshare --user --map-root-user id → {out.strip()}",
            "Disable user namespace creation: kernel.unprivileged_userns_clone=0",
        )
        legacy.add_attack_edge("Compromised Pod", "Elevated Privileges", "unshare user namespace", "HIGH")
    else:
        legacy.finding("PASS", "User namespace unshare blocked", "")

    legacy.section("Runtime Socket Escape")
    runtime_sockets = {
        "/var/run/docker.sock": "Docker",
        "/run/containerd/containerd.sock": "containerd",
        "/host/run/containerd/containerd.sock": "containerd (hostPath)",
        "/run/crio/crio.sock": "CRI-O",
    }
    found = False
    for path, runtime_name in runtime_sockets.items():
        if os.path.exists(path):
            legacy.finding(
                "CRITICAL",
                f"{runtime_name} socket at {path}",
                "Create privileged containers, exec into any container, snapshot filesystems",
                "Never mount runtime sockets into application pods",
            )
            legacy.add_attack_edge("Compromised Pod", "Node Root", f"{runtime_name} socket escape", "CRITICAL")
            found = True
    if not found:
        legacy.finding("PASS", "No runtime socket exposed", "")


class EscapeEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 5 escape logic."""

    def __init__(self) -> None:
        super().__init__(name="escape", phase="5", function_name="phase_escape")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted escape engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_escape(legacy)
        return legacy.FINDINGS[before:]
