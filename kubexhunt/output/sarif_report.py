"""SARIF report renderer."""

from __future__ import annotations

import json
import re

from kubexhunt.core.runtime import get_active_runtime
from kubexhunt.core.legacy import load_legacy_module


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def build_report(runtime) -> dict:
    """Build a SARIF report from the current runtime."""

    rules = []
    results = []
    seen_rules = set()

    for index, finding in enumerate(runtime.FINDINGS):
        if finding["severity"] in ("PASS", "INFO"):
            continue
        rule_id = re.sub(r"[^a-zA-Z0-9]", "", finding["check"])[:32] or f"RULE{index}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            mitre = runtime.MITRE_MAP.get(finding["severity"], [])
            rules.append(
                {
                    "id": rule_id,
                    "name": finding["check"][:60],
                    "shortDescription": {"text": finding["check"][:80]},
                    "fullDescription": {"text": finding["detail"][:300]},
                    "helpUri": "https://github.com/mayank-choubey/kubexhunt",
                    "properties": {
                        "tags": mitre + [finding["severity"], f"Phase-{finding['phase']}"],
                        "security-severity": {
                            "CRITICAL": "9.8",
                            "HIGH": "7.5",
                            "MEDIUM": "5.0",
                            "LOW": "2.0",
                        }.get(finding["severity"], "0.0"),
                    },
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": {
                    "CRITICAL": "error",
                    "HIGH": "error",
                    "MEDIUM": "warning",
                    "LOW": "note",
                }.get(finding["severity"], "note"),
                "message": {"text": f"{finding['check']}\n{finding['detail'][:200]}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "kubernetes-cluster"}}}],
                "properties": {
                    "severity": finding["severity"],
                    "phase": finding["phase"],
                    "remediation": finding["remediation"][:200],
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KubeXHunt",
                        "version": "1.2.0",
                        "informationUri": "https://github.com/mayank-choubey/kubexhunt",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "cluster": runtime.CTX.get("api", ""),
                    "namespace": runtime.CTX.get("namespace", ""),
                    "k8s_version": runtime.CTX.get("k8s_version", ""),
                },
            }
        ],
    }


def save(filepath: str) -> None:
    """Write the SARIF report using the modular implementation."""

    runtime = _runtime()
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(build_report(runtime), handle, indent=2)
