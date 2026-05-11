"""Runtime engine."""

from __future__ import annotations

import os
import shutil
import stat
import time

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_runtime(legacy) -> None:
    """Execute the extracted runtime security phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "12"
    legacy.phase_header(
        "12",
        "Runtime Security Gaps",
        "Tetragon, Falco, TracingPolicies, exec-from-tmp enforcement",
    )

    legacy.section("Runtime Tool Detection")
    tools_found = {}
    tool_map = {
        "tetragon": "Tetragon eBPF enforcement",
        "falco": "Falco detection (alerts only)",
        "sysdig": "Sysdig monitoring",
        "aqua": "Aqua Security",
        "twistlock": "Twistlock/Prisma Cloud",
        "datadog": "Datadog agent",
    }

    code, resp = legacy.k8s_api("/api/v1/namespaces/kube-system/pods")
    if code == 200 and resp:
        for pod in resp.get("items", []):
            name = pod["metadata"]["name"].lower()
            for tool, description in tool_map.items():
                if tool in name and tool not in tools_found:
                    tools_found[tool] = description

    api_group_map = {
        "cilium.io": ("tetragon", "Tetragon eBPF enforcement"),
        "isovalent.com": ("tetragon", "Tetragon eBPF enforcement"),
        "hubble.enterprise": ("tetragon", "Tetragon eBPF enforcement"),
        "falco.org": ("falco", "Falco detection (alerts only)"),
        "kyverno.io": ("kyverno", "Kyverno policy engine"),
        "networking.istio.io": ("istio", "Istio service mesh (mTLS)"),
        "security.istio.io": ("istio", "Istio AuthorizationPolicy"),
        "install.istio.io": ("istio", "Istio service mesh (mTLS)"),
        "extensions.istio.io": ("istio", "Istio service mesh (mTLS)"),
    }
    code_apis, resp_apis = legacy.k8s_api("/apis", timeout=6)
    if code_apis == 200 and resp_apis:
        for group in resp_apis.get("groups", []):
            group_name = group.get("name", "")
            for api_group, (tool, description) in api_group_map.items():
                if api_group in group_name and tool not in tools_found:
                    tools_found[tool] = description
                    legacy.info_line(f"Detected via API groups: {group_name} → {description}")

    crd_checks = [
        ("/apis/cilium.io/v1alpha1/tracingpolicies", "tetragon", "Tetragon eBPF enforcement"),
        ("/apis/cilium.io/v1alpha1/tracingpoliciesnamespaced", "tetragon", "Tetragon eBPF enforcement"),
        ("/apis/falco.org/v1alpha1/falcoconfigs", "falco", "Falco detection (alerts only)"),
        ("/apis/kyverno.io/v1/clusterpolicies", "kyverno", "Kyverno policy engine"),
        ("/apis/kyverno.io/v2beta1/clusterpolicies", "kyverno", "Kyverno policy engine"),
        ("/apis/networking.istio.io/v1alpha3/peerauthentications", "istio", "Istio service mesh (mTLS)"),
        ("/apis/security.istio.io/v1/authorizationpolicies", "istio", "Istio AuthorizationPolicy"),
        ("/apis/networking.istio.io/v1beta1/peerauthentications", "istio", "Istio service mesh (mTLS)"),
    ]
    for path, tool, description in crd_checks:
        if tool not in tools_found:
            code_crd, _ = legacy.k8s_api(path, timeout=4)
            if code_crd == 403:
                tools_found[tool] = description

    for filesystem_path, tool, description in [
        ("/etc/tetragon", "tetragon", "Tetragon eBPF enforcement"),
        ("/etc/falco/falco.yaml", "falco", "Falco detection (alerts only)"),
        ("/etc/falco", "falco", "Falco detection (alerts only)"),
    ]:
        if tool not in tools_found and os.path.exists(filesystem_path):
            tools_found[tool] = description

    if tools_found:
        for _tool, description in tools_found.items():
            legacy.finding("INFO", f"Runtime security: {description}", "")
        legacy.CTX["runtime_tools"] = list(tools_found.keys())
    else:
        legacy.finding(
            "HIGH",
            "No runtime security tooling detected",
            "No Tetragon, Falco, Kyverno, or Istio found via pods, CRDs, or filesystem."
            " Post-exploitation activity goes undetected",
            "Install Tetragon (eBPF enforcement) + Falco (alerting)",
        )
        legacy.CTX["runtime_tools"] = []

    legacy.section("Tetragon TracingPolicies")
    tracing_policy_code, tracing_policy_resp = 0, None
    for tracing_policy_path in [
        "/apis/cilium.io/v1alpha1/tracingpolicies",
        "/apis/cilium.io/v1alpha1/tracingpolicy",
    ]:
        tracing_policy_code, tracing_policy_resp = legacy.k8s_api(tracing_policy_path, timeout=5)
        if tracing_policy_code in (200, 403):
            break

    if tracing_policy_code == 200 and tracing_policy_resp:
        policies = tracing_policy_resp.get("items", [])
        if policies:
            legacy.finding(
                "PASS",
                f"Tetragon TracingPolicies active: {len(policies)}",
                f"Policies: {', '.join([policy['metadata']['name'] for policy in policies])}",
            )
        else:
            legacy.finding(
                "HIGH",
                "Tetragon installed but NO TracingPolicies active",
                "Observing only — no enforcement rules",
                "Apply block-reverse-shell and block-exec-from-tmp TracingPolicies",
            )
    elif tracing_policy_code == 403:
        legacy.finding(
            "INFO",
            "Tetragon TracingPolicies not readable (HTTP 403)",
            "Tetragon installed — SA lacks tracingpolicies list permission. Check manually: kubectl get tracingpolicy",
            "",
        )
    elif "tetragon" in tools_found:
        legacy.finding(
            "INFO",
            "Tetragon detected via API groups — TracingPolicy list not permitted",
            "cilium.io API group present in cluster."
            " SA lacks tracingpolicies list permission."
            " Check manually: kubectl get tracingpolicy",
            "",
        )
    else:
        legacy.finding("INFO", "Tetragon CRD not detected", "")

    legacy.section("Exec from /tmp Test")
    try:
        test_bin = f"/tmp/kubexhunt-exec-{int(time.time())}"
        shutil.copy("/bin/true", test_bin)
        os.chmod(test_bin, stat.S_IRWXU)
        rc, out, err = legacy.run_cmd(test_bin, timeout=3)
        os.remove(test_bin)
        if "Killed" in err or rc == 137:
            legacy.finding("PASS", "Exec from /tmp BLOCKED", "Tetragon block-exec-from-tmp policy active")
        else:
            legacy.finding(
                "HIGH",
                "Exec from /tmp ALLOWED",
                f"Ran binary from /tmp (rc={rc}) — crypto miners/malware can execute",
                "Apply Tetragon TracingPolicy: block-exec-from-tmp",
            )
    except (OSError, shutil.Error) as exc:
        legacy.finding("INFO", "Exec from /tmp test inconclusive", str(exc)[:80])


class RuntimeSecurityEngine(LegacyFunctionEngine):
    """Runtime security engine."""

    def __init__(self) -> None:
        super().__init__(name="runtime", phase="12", function_name="phase_runtime")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted runtime phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_runtime(legacy)
