"""Attack chain simulation engine."""

from __future__ import annotations

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_attack_chains(legacy) -> None:
    """Execute the extracted attack-chain phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "23"
    legacy.phase_header(
        "23",
        "Real-World Attack Chain Simulation",
        "Tesla-style IMDS breach, RBAC→Node, SA token privilege ranking, webhook bypass",
    )

    legacy.section("Chain 1: Pod RCE → Cloud Credentials → Cloud Account")
    cloud = legacy.CTX.get("cloud", "Unknown")
    step1 = legacy.CTX.get("token", "") != ""
    step2 = (cloud == "AWS" and legacy.CTX.get("aws_creds")) or cloud in ("GKE", "Azure")
    if step1:
        legacy.info_line("✓ Step 1: SA token present (Pod RCE → token access)")
    else:
        legacy.info_line("✗ Step 1: No SA token")
    if step2:
        legacy.info_line(f"✓ Step 2: Cloud credentials accessible via IMDS ({cloud})")
        legacy.info_line("✓ Step 3: Full cloud account compromise possible")
        legacy.finding(
            "CRITICAL",
            "Attack Chain COMPLETE: Pod RCE → Cloud Account Compromise",
            f"Path: Pod RCE → SA Token → {cloud} IMDS → IAM Credentials → Full Cloud Access\n"
            "Similar to Tesla Kubernetes breach (2018) — cryptomining on cloud account\n"
            "Mitigations needed at every step of this chain",
            "Block IMDS | Remove cloud-platform scope | Restrict SA token",
        )
        legacy.add_attack_edge(
            "Pod RCE", "Cloud Account Compromise", f"SA Token → {cloud} IMDS → IAM creds", "CRITICAL"
        )
    else:
        legacy.info_line(f"✗ Step 2: Cloud credentials NOT accessible ({cloud})")
        legacy.finding("PASS", "Chain 1: Cloud credential path blocked", "IMDS not reachable or no token")

    legacy.section("Chain 2: RBAC Misconfiguration → Privileged Pod → Node Root")
    can_list_secrets = any(
        finding["severity"] == "CRITICAL" and "secrets" in finding["check"].lower() for finding in legacy.FINDINGS
    )
    can_create_pods = any(
        "create pods" in finding["check"].lower() or "privileged pod" in finding["check"].lower()
        for finding in legacy.FINDINGS
        if finding["severity"] in ("CRITICAL", "HIGH")
    )
    if can_list_secrets:
        legacy.info_line("✓ Step 1: Can list/read secrets (RBAC misconfiguration)")
    if can_create_pods:
        legacy.info_line("✓ Step 2: Can create privileged pods")
        legacy.info_line("✓ Step 3: Privileged pod → hostPath: / → node root")
        legacy.finding(
            "CRITICAL",
            "Attack Chain COMPLETE: RBAC → Privileged Pod → Node Root",
            "Path: Over-permissive RBAC → Create privileged pod with hostPath: / → chroot node\n"
            "→ Read /host/var/lib/kubelet/pods/*/token → pivot to other namespaces\n"
            "Most common Kubernetes privilege escalation pattern",
            "Apply PSS Restricted | Restrict pod create from SA | Deploy Kyverno",
        )
        legacy.add_attack_edge("RBAC Misconfiguration", "Node Root", "Pod create → hostPath: / → chroot", "CRITICAL")
    else:
        legacy.finding("PASS", "Chain 2: Privileged pod creation blocked", "PSS or RBAC restricting pod create")

    legacy.section("Chain 3: SA Token Theft → Cluster Admin Takeover")
    stolen_tokens = [
        finding
        for finding in legacy.FINDINGS
        if "stolen token" in finding["check"].lower() and finding["severity"] == "CRITICAL"
    ]
    high_priv_stolen = [
        score for score in legacy.TOKEN_SCORES if "stolen" in score["label"].lower() and score["score"] >= 60
    ]
    stolen_secrets_access = any(
        ("stolen token" in finding["check"].lower() or "stolen" in finding["check"].lower())
        and ("secret" in finding["detail"].lower() or "elevated" in finding["check"].lower())
        and finding["severity"] == "CRITICAL"
        for finding in legacy.FINDINGS
    )
    wildcard_rbac = any(
        "wildcard" in finding["check"].lower()
        or "cluster-admin" in finding["detail"].lower()
        or "wildcard rbac" in finding["check"].lower()
        for finding in legacy.FINDINGS
        if finding["severity"] == "CRITICAL"
    )
    if stolen_tokens:
        legacy.info_line(f"✓ Step 1: {len(stolen_tokens)} SA token(s) stolen from /var/lib/kubelet/pods")
    if high_priv_stolen:
        legacy.info_line(
            f"✓ Step 2: High-privilege stolen token found: {high_priv_stolen[0]['label']} (score {high_priv_stolen[0]['score']}/100)"
        )
    if stolen_tokens and (wildcard_rbac or high_priv_stolen or stolen_secrets_access):
        best = high_priv_stolen[0]["label"] if high_priv_stolen else "stolen token"
        legacy.info_line("✓ Step 3: Token has sufficient privileges for cluster-admin escalation")
        legacy.finding(
            "CRITICAL",
            "Attack Chain COMPLETE: Token Theft → Cluster Admin",
            f"Path: hostPath mount → steal SA tokens → {best} has elevated RBAC\n"
            "→ List/read all secrets cluster-wide → steal credentials → create backdoor CRB\n"
            "Similar to real-world K8s cluster takeovers",
            "Remove hostPath | PSS Restricted | Audit all SA token permissions",
        )
        legacy.add_attack_edge(
            "Node Access",
            "Permanent Cluster Admin",
            f"Token theft ({best}) → elevated RBAC → cluster takeover",
            "CRITICAL",
        )
    else:
        legacy.finding("PASS", "Chain 3: Token theft chain blocked", "No stolen tokens with elevated RBAC found")

    legacy.section("Chain 4: Webhook Bypass → Policy Bypass → Node Escape")
    webhook_bypass = any(
        "ignore" in finding["check"].lower() and "unreachable" in finding["detail"].lower()
        for finding in legacy.FINDINGS
        if finding["severity"] == "CRITICAL"
    )
    if webhook_bypass:
        legacy.finding(
            "CRITICAL",
            "Attack Chain COMPLETE: Webhook Bypass → Unconstrained Pod Creation",
            "Path: Webhook failurePolicy=Ignore + service unreachable → policies bypass\n"
            "→ Create privileged pod → node root\n"
            "Kyverno/OPA policies provide zero protection when webhook is down",
            "Set failurePolicy: Fail | Ensure webhook HA | Test webhook failure scenarios",
        )
        legacy.add_attack_edge("Webhook Failure", "Node Root", "Policy bypass → privileged pod", "CRITICAL")
    else:
        legacy.finding("PASS", "Chain 4: No webhook bypass path identified", "")


class AttackChainsEngine(LegacyFunctionEngine):
    """Compatibility wrapper around the extracted phase 23 attack-chain logic."""

    def __init__(self) -> None:
        super().__init__(name="attack_chains", phase="23", function_name="phase_attack_chains")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted attack-chain engine."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        run_phase_attack_chains(legacy)
        return legacy.FINDINGS[before:]
