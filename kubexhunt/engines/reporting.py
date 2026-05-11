"""Diff/reporting finalization phase."""

from __future__ import annotations

import json


def run_phase_reporting(runtime, diff_file: str | None = None) -> None:
    """Execute phase 26 diff analysis and CI gate finalization."""

    runtime.CURRENT_PHASE = "26"
    runtime.STATE.current_phase = "26"
    runtime.phase_header(
        "26", "Diff Analysis & Report Finalization", "Compare with previous scan, new/fixed/changed findings"
    )

    if not diff_file:
        runtime.finding("INFO", "No previous scan provided for diff", "Use --diff previous.json to compare")
        return

    runtime.section("Diff vs Previous Scan")
    try:
        with open(diff_file, encoding="utf-8") as handle:
            prev = json.load(handle)
        prev_findings = {finding["check"]: finding for finding in prev.get("findings", [])}
        curr_findings = {finding["check"]: finding for finding in runtime.FINDINGS}

        new_findings = [
            finding
            for check, finding in curr_findings.items()
            if check not in prev_findings and finding["severity"] not in ("PASS", "INFO")
        ]
        fixed_findings = [
            finding
            for check, finding in prev_findings.items()
            if check not in curr_findings and finding["severity"] not in ("PASS", "INFO")
        ]
        changed_findings = []
        for check in curr_findings:
            if check in prev_findings and curr_findings[check]["severity"] != prev_findings[check]["severity"]:
                changed_findings.append((prev_findings[check], curr_findings[check]))

        print(f"\n  {runtime.c(runtime.C.BOLD, 'Diff Summary:')}")
        print(f"  {runtime.c(runtime.C.RED, f'[NEW    ] +{len(new_findings):3} findings')} — regressions")
        print(f"  {runtime.c(runtime.C.GREEN, f'[FIXED  ] -{len(fixed_findings):3} findings')} — improvements")
        print(f"  {runtime.c(runtime.C.YELLOW, f'[CHANGED]  {len(changed_findings):3} findings')} — severity changes")

        if new_findings:
            runtime.finding(
                "HIGH",
                f"NEW findings since last scan: {len(new_findings)}",
                "\n".join([f"[{finding['severity']}] {finding['check']}" for finding in new_findings[:8]]),
                "Investigate regressions — these are new vulnerabilities",
            )
        if fixed_findings:
            runtime.finding(
                "PASS",
                f"FIXED since last scan: {len(fixed_findings)}",
                "\n".join([f"[{finding['severity']}] {finding['check']}" for finding in fixed_findings[:8]]),
            )
        for prev_finding, curr_finding in changed_findings[:5]:
            runtime.finding(
                "MEDIUM",
                f"Severity CHANGED: {curr_finding['check']}",
                f"{prev_finding['severity']} → {curr_finding['severity']}",
                "Review why severity changed",
            )

        critical_new = [finding for finding in new_findings if finding["severity"] == "CRITICAL"]
        high_new = [finding for finding in new_findings if finding["severity"] == "HIGH"]
        if critical_new or high_new:
            runtime.finding(
                "CRITICAL",
                f"CI/CD GATE FAILURE: {len(critical_new)} new CRITICAL, {len(high_new)} new HIGH",
                "New CRITICAL/HIGH findings since last scan — pipeline should fail",
                "Fix new findings before merging | Use --no-mutate in CI pipeline",
            )
            runtime.CTX["ci_fail"] = True
        else:
            runtime.finding("PASS", "CI/CD gate: No new CRITICAL/HIGH findings", "")
    except FileNotFoundError:
        runtime.finding("INFO", f"Diff file not found: {diff_file}", "")
    except Exception as exc:
        runtime.finding("INFO", f"Diff error: {exc}", "")
