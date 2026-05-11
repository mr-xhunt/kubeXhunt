"""DoS and resource exhaustion engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_dos(legacy) -> None:
    """Execute the extracted DoS phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "14"
    legacy.phase_header(
        "14",
        "DoS & Resource Exhaustion",
        "Resource limits, ResourceQuota, LimitRange, audit logging",
    )

    namespace = legacy.CTX.get("namespace", "default")

    legacy.section("Container Memory Limit")
    mem_found = False
    for mem_path in [
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.soft_limit_in_bytes",
    ]:
        mem = (legacy.file_read(mem_path) or "").strip()
        if mem:
            if mem in ("9223372036854771712", "9223372036854775807", "max", ""):
                legacy.finding(
                    "MEDIUM",
                    "No memory limit on this container",
                    f"Path: {mem_path} = {mem} | Can OOM the node",
                    "Set resources.limits.memory",
                )
            else:
                try:
                    legacy.finding("PASS", f"Memory limit: {int(mem) // 1024 // 1024} MB", f"Path: {mem_path}")
                except (ValueError, TypeError):
                    legacy.finding("PASS", f"Memory limit: {mem}", f"Path: {mem_path}")
            mem_found = True
            break
    if not mem_found:
        _, cg_out, _ = legacy.run_cmd(
            "cat /sys/fs/cgroup/$(cat /proc/self/cgroup | head -1 | cut -d: -f3)/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.max 2>/dev/null",
            timeout=3,
        )
        cg_out = cg_out.strip()
        if cg_out:
            if cg_out == "max":
                legacy.finding(
                    "MEDIUM",
                    "No memory limit (cgroup v2)",
                    "memory.max = max — unlimited",
                    "Set resources.limits.memory",
                )
            else:
                try:
                    legacy.finding("PASS", f"Memory limit (cgroup v2): {int(cg_out) // 1024 // 1024} MB", "")
                except (ValueError, TypeError):
                    legacy.finding("PASS", f"Memory limit (cgroup v2): {cg_out}", "")
        else:
            legacy.finding("INFO", "Memory limit not readable", "cgroup path not accessible from container")

    legacy.section("Container CPU Limit")
    cpu_found = False
    for cpu_path in ["/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "/sys/fs/cgroup/cpu.max"]:
        cpu_parts = (legacy.file_read(cpu_path) or "").strip().split()
        cpu = cpu_parts[0] if cpu_parts else ""
        if cpu:
            if cpu in ("-1", "max"):
                legacy.finding(
                    "MEDIUM",
                    "No CPU limit",
                    f"Path: {cpu_path} = {cpu} | Can starve other pods of CPU",
                    "Set resources.limits.cpu",
                )
            else:
                legacy.finding("PASS", f"CPU limit: {cpu}µs/period", f"Path: {cpu_path}")
            cpu_found = True
            break
    if not cpu_found:
        _, cpu_out, _ = legacy.run_cmd(
            "cat /sys/fs/cgroup/$(cat /proc/self/cgroup | head -1 | cut -d: -f3)/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu.max 2>/dev/null",
            timeout=3,
        )
        cpu_out = cpu_out.strip().split()[0] if cpu_out.strip() else ""
        if cpu_out:
            if cpu_out == "max":
                legacy.finding(
                    "MEDIUM",
                    "No CPU limit (cgroup v2)",
                    "cpu.max = max — unlimited",
                    "Set resources.limits.cpu",
                )
            else:
                legacy.finding("PASS", f"CPU limit (cgroup v2): {cpu_out}µs/period", "")
        else:
            legacy.finding("INFO", "CPU limit not readable", "cgroup path not accessible from container")

    legacy.section("Namespace ResourceQuota")
    code_rq, resp_rq = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/resourcequotas")
    if code_rq == 200 and resp_rq:
        items = resp_rq.get("items", [])
        if not items:
            legacy.finding(
                "MEDIUM",
                f"No ResourceQuota in '{namespace}'",
                "Unlimited pod/CPU/memory creation — DoS via resource exhaustion",
                "Apply ResourceQuota to all workload namespaces",
            )
        else:
            for quota in items:
                hard = quota.get("status", {}).get("hard", {})
                used = quota.get("status", {}).get("used", {})
                legacy.finding(
                    "PASS",
                    f"ResourceQuota: {quota['metadata']['name']}",
                    " | ".join([f"{key}: {used.get(key, '?')}/{value}" for key, value in list(hard.items())[:4]]),
                )

    legacy.section("Namespace LimitRange")
    code_lr, resp_lr = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/limitranges")
    if code_lr == 200 and resp_lr:
        if not resp_lr.get("items"):
            legacy.finding(
                "LOW",
                f"No LimitRange in '{namespace}'",
                "Pods without explicit limits get unlimited resources",
                "Apply LimitRange with default CPU/memory requests and limits",
            )
        else:
            legacy.finding("PASS", f"LimitRange active in '{namespace}'", "Default resource limits provided")

    legacy.section("Audit Logging")
    audit_found = False
    code_ap, resp_ap = legacy.k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items", []):
            if "kube-apiserver" in pod.get("metadata", {}).get("name", ""):
                for container in pod.get("spec", {}).get("containers", []):
                    cmd = " ".join(container.get("command", []))
                    if "--audit-log-path" in cmd:
                        legacy.finding(
                            "PASS",
                            "Audit logging configured (--audit-log-path)",
                            "--audit-log-path flag set on kube-apiserver",
                        )
                        audit_found = True
                        if "--audit-policy-file" not in cmd:
                            legacy.finding(
                                "LOW",
                                "Audit policy file not set",
                                "Default policy may miss important events",
                                "Set --audit-policy-file with RequestResponse level",
                            )
                break
    if not audit_found and legacy.CTX.get("cloud") == "AWS":
        account = legacy.CTX.get("aws_account", "")
        region = legacy.CTX.get("aws_region", "")
        if account and region:
            api = legacy.CTX.get("api", "")
            if "eks.amazonaws.com" in api:
                legacy.finding(
                    "INFO",
                    "EKS managed cluster detected — audit logs via CloudWatch",
                    f"Check: AWS Console → CloudWatch → Log Groups → /aws/eks/<cluster>/cluster\n"
                    f"Or: aws logs describe-log-groups --region {region} --log-group-name-prefix /aws/eks\n"
                    f'Enable via: aws eks update-cluster-config --name <cluster> --logging \'{{"clusterLogging":[{{"types":["audit"],"enabled":true}}]}}\'',
                    "Enable EKS audit logging in CloudWatch",
                )
                audit_found = True
            else:
                legacy.finding(
                    "LOW",
                    "AWS cluster but non-EKS API endpoint — audit logging status unknown",
                    "Check CloudWatch or cluster configuration for audit log settings",
                    "Enable audit logging for forensic trail",
                )
        else:
            legacy.finding(
                "LOW",
                "AWS cluster — cannot determine if CloudWatch audit logging enabled",
                "No AWS account info available\nCheck: aws eks describe-cluster --name <n> --query cluster.logging",
                "Enable EKS audit logging: types: [audit, authenticator]",
            )
            audit_found = True
    if not audit_found and code_ap in (401, 403):
        if legacy.CTX.get("cloud") == "AWS":
            legacy.finding(
                "LOW",
                "EKS audit logging status unknown (cannot inspect API server)",
                "Cannot list kube-system pods — managed EKS hides API server\n"
                "Verify CloudWatch audit logs are enabled:\n"
                "aws eks describe-cluster --name <cluster> --query cluster.logging\n"
                "aws logs describe-log-groups --log-group-name-prefix /aws/eks",
                "Enable via: eksctl utils update-cluster-logging --enable-types audit",
            )
        else:
            legacy.finding(
                "LOW",
                "Kubernetes audit logging not detected",
                "Cannot inspect API server — audit log status unknown",
                "Enable --audit-log-path on API server | Check cloud provider audit settings",
            )
        audit_found = True
    if not audit_found:
        legacy.finding(
            "LOW",
            "Kubernetes audit logging not detected",
            "Attacker activity leaves no forensic trail",
            "Enable --audit-log-path on API server | For EKS: enable CloudWatch audit logs",
        )


class DoSEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 14 DoS logic."""

    def __init__(self) -> None:
        super().__init__(name="dos", phase="14", function_name="phase_dos")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted DoS engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_dos(legacy)
        return legacy.FINDINGS[before:]
