"""Risk correlation module."""

from __future__ import annotations

from typing import Any, cast

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.core.runtime import get_active_runtime


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def enrich_findings_with_mitre(legacy) -> None:
    """Add MITRE ATT&CK techniques to findings based on severity and keywords."""

    print("[DEBUG] Running MITRE enrichment")
    enriched = 0
    for finding in legacy.FINDINGS:
        techniques = set()
        text = (finding.get("check", "") + " " + finding.get("detail", "")).lower()
        severity = finding.get("severity", "")
        if severity == "CRITICAL":
            techniques.update(["T1611", "T1552.007"])
        elif severity == "HIGH":
            techniques.update(["T1613", "T1078.004"])
        elif severity == "MEDIUM":
            techniques.add("T1526")
        for technique, keywords in legacy._MITRE_KEYWORD_MAP.items():
            if any(keyword in text for keyword in keywords):
                techniques.add(technique)
        if techniques:
            finding["mitre_techniques"] = sorted(techniques)
            enriched += 1
        else:
            finding.setdefault("mitre_techniques", [])
    print(f"[DEBUG] MITRE enrichment complete: {enriched}/{len(legacy.FINDINGS)} findings enriched")


def generate_detection_rules(legacy) -> dict[str, list]:
    """Generate Falco and Tetragon rules from the active findings set."""

    print("[DEBUG] Generating detection rules")
    falco_rules = []
    tetragon_rules = []

    for finding in legacy.FINDINGS:
        if finding.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM"):
            continue
        check = finding.get("check", "")
        text = (check + " " + finding.get("detail", "")).lower()

        if any(keyword in text for keyword in ("privileged", "escape", "breakout", "hostpid", "hostipc")):
            falco_rules.append(
                {
                    "rule": "Privileged Container Spawn Detected",
                    "desc": f"Triggered by finding: {check[:80]}",
                    "condition": "spawned_process and container.privileged=true",
                    "output": "Privileged container spawned (user=%user.name container=%container.id image=%container.image.repository)",
                    "priority": "CRITICAL",
                }
            )
            tetragon_rules.append(
                {
                    "name": "block-privileged-exec",
                    "desc": "Block execution inside privileged containers",
                    "match_binary": ["/bin/sh", "/bin/bash", "python3", "python"],
                    "action": "Sigkill",
                }
            )

        if any(keyword in text for keyword in ("secret", "credential", "token", "password")):
            falco_rules.append(
                {
                    "rule": "K8s Secret Read from Non-Approved Process",
                    "desc": f"Triggered by finding: {check[:80]}",
                    "condition": "ka.verb=get and ka.target.resource=secrets and not ka.user.name in (system:kube-controller-manager)",
                    "output": "K8s secret accessed (user=%ka.user.name ns=%ka.target.namespace secret=%ka.target.name)",
                    "priority": "WARNING",
                }
            )

        if any(keyword in text for keyword in ("imds", "169.254.169.254", "metadata", "aws", "gke", "azure")):
            falco_rules.append(
                {
                    "rule": "IMDS Endpoint Access Detected",
                    "desc": f"Triggered by finding: {check[:80]}",
                    "condition": "outbound and fd.sip=169.254.169.254",
                    "output": "Process accessing IMDS (proc=%proc.name container=%container.id)",
                    "priority": "ERROR",
                }
            )
            tetragon_rules.append(
                {
                    "name": "block-imds-access",
                    "desc": "Block direct IMDS endpoint access",
                    "match_binary": ["curl", "wget", "python3", "python", "nc"],
                    "match_args": ["169.254.169.254"],
                    "action": "Sigkill",
                }
            )

        if any(keyword in text for keyword in ("rbac", "clusterrole", "wildcard", "cluster-admin")):
            falco_rules.append(
                {
                    "rule": "Suspicious RBAC Escalation Attempt",
                    "desc": f"Triggered by finding: {check[:80]}",
                    "condition": "ka.verb in (create,update,patch) and ka.target.resource=clusterrolebindings",
                    "output": "RBAC escalation attempt (user=%ka.user.name subject=%ka.req.binding.subject.name)",
                    "priority": "CRITICAL",
                }
            )

    seen_falco = set()
    seen_tetragon = set()
    falco_dedup = []
    tetragon_dedup = []
    for rule in falco_rules:
        if rule["rule"] not in seen_falco:
            seen_falco.add(rule["rule"])
            falco_dedup.append(rule)
    for rule in tetragon_rules:
        if rule["name"] not in seen_tetragon:
            seen_tetragon.add(rule["name"])
            tetragon_dedup.append(rule)

    legacy.CTX["detection_rules"] = cast(Any, {"falco": falco_dedup, "tetragon": tetragon_dedup})
    print(f"[DEBUG] Detection rules generated: {len(falco_dedup)} Falco, {len(tetragon_dedup)} Tetragon")
    return legacy.CTX["detection_rules"]


def enrich_findings() -> None:
    """Apply MITRE enrichment using the modular implementation."""

    enrich_findings_with_mitre(_runtime())


def detection_rules() -> dict[str, list]:
    """Generate or return detection rules using the modular implementation."""

    return generate_detection_rules(_runtime())
