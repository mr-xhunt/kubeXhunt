"""Stealth and evasion analysis engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_stealth_analysis(legacy) -> None:
    """Execute the extracted stealth-analysis phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "24"
    legacy.phase_header(
        "24",
        "Stealth & Evasion Analysis",
        "Detection surface, audit log events, SIEM gaps, evasion recommendations",
    )

    legacy.section("Audit Log Event Classification")
    print(f"  {legacy.c(legacy.C.GRAY, 'This scan generated the following API calls by audit impact:')}\n")

    silent_checks = [
        "File reads (/proc, /sys, /var/run/secrets)",
        "Environment variable inspection",
        "Local port probing (socket.connect)",
        "DNS resolution",
        "Container capability checks",
        "Filesystem write test",
    ]
    logged_checks = [
        "GET /api/v1/* — all list/get operations",
        "POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        "POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "GET /version, /api, /apis",
    ]
    mutating_checks = [
        "POST /api/v1/namespaces/{ns}/pods — test pod creation",
        "POST /apis/rbac.../clusterrolebindings — test CRB creation",
        "DELETE — cleanup of created resources",
        "POST /api/v1/namespaces/{ns}/serviceaccounts — in kube-system",
    ]

    legacy.finding("INFO", "Silent checks (no audit log entry)", "\n".join(silent_checks))
    legacy.finding(
        "MEDIUM",
        "Logged API calls (appear in audit logs — LOW risk detection)",
        "\n".join(logged_checks),
        "Use --stealth 1 to add jitter and kubectl User-Agent",
    )
    if legacy.CTX.get("no_mutate"):
        legacy.finding(
            "PASS",
            "Mutating API calls skipped (--no-mutate active)",
            "No POST/PATCH/DELETE calls made\nZero write operations in audit log",
        )
    else:
        legacy.finding(
            "HIGH",
            "Mutating API calls were made during this scan",
            "\n".join(mutating_checks) + "\nThese appear in K8s audit logs as create/delete by this SA",
            "Re-run with --no-mutate flag for zero write-operation scans",
        )

    legacy.section("Detection Tools Present")
    runtime_tools = legacy.CTX.get("runtime_tools", None)
    if runtime_tools is None:
        has_no_runtime = any("No runtime security tooling" in finding["check"] for finding in legacy.FINDINGS)
        has_runtime = any(
            "Runtime security:" in finding["check"]
            or "Tetragon TracingPolicies active" in finding["check"]
            or "Kyverno" in finding["check"]
            for finding in legacy.FINDINGS
        )
        runtime_tools = [] if has_no_runtime else (["unknown"] if has_runtime else [])
    if not runtime_tools:
        legacy.finding(
            "INFO",
            "No runtime detection tools found — scan was NOT detected",
            "Tetragon, Falco, Kyverno, Istio not detected\nAll API calls, file reads, and probes went undetected",
            "Install Tetragon (eBPF enforcement) + Falco (alerting)",
        )
    else:
        tools_str = ", ".join(tool for tool in runtime_tools if tool != "unknown")
        legacy.finding(
            "INFO",
            f"Runtime tools present: {tools_str or 'detected'} — scan may have been logged",
            f"Review Falco/Tetragon alerts for scan activity\nTools active: {tools_str}",
            "Correlate scan timestamps with runtime alerts and audit logs",
        )

    legacy.section("Stealth Recommendations")
    stealth_level = legacy.CTX.get("stealth", 0)
    if stealth_level == 0:
        legacy.finding(
            "INFO",
            "Running in stealth level 0 (default)",
            "All checks run at full speed | Python urllib User-Agent | No jitter\n"
            "Re-run with --stealth 1 or --stealth 2 for lower detection profile",
            "Use --stealth 2 --no-mutate for production cluster assessments",
        )
    elif stealth_level == 1:
        legacy.finding(
            "PASS",
            "Stealth level 1 active",
            "kubectl User-Agent spoofing | Timing jitter (0.3–2s) | Non-mutating mode",
        )
    elif stealth_level >= 2:
        legacy.finding(
            "PASS",
            "Stealth level 2 active",
            "Full evasion mode | Read-only inference | Batched API calls | Maximum jitter",
        )


class StealthEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 24 stealth logic."""

    def __init__(self) -> None:
        super().__init__(name="stealth", phase="24", function_name="phase_stealth_analysis")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted stealth engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_stealth_analysis(legacy)
        return legacy.FINDINGS[before:]
