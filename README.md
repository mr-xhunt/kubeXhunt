# KubeXHunt: Kubernetes Post-Compromise Security Assessment

[![PyPI](https://github.com/mr-xhunt/kubeX/actions/workflows/release.yml/badge.svg)](https://pypi.org/project/kubexhunt/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Author](https://img.shields.io/badge/Author-Mayank%20Choubey-orange.svg)](https://www.python.org/downloads/)

---

## What Is KubeXHunt?

**KubeXHunt** is an automated Kubernetes post-compromise assessment framework. Drop it onto a compromised pod and get:

- **27 continuous enumeration phases** — from pod basics to cluster compromise, node escape, cloud pivoting, and supply chain attacks
- **Automated attack chain generation** — finds paths from your current pod to cluster-admin, complete with exploitation steps
- **Zero external dependencies** — runs on Python 3.9+ stdlib only; works on any Kubernetes cluster
- **Multi-cloud support** — detects and pivots through EKS IRSA, GKE Workload Identity, Azure Pod Identity
- **Structured findings** — MITRE ATT&CK for Containers, CWE, CIS Benchmark, and CVSS 3.1 severity mapping
- **Multiple output formats** — JSON, HTML, SARIF (for CI/CD), Markdown, and GraphViz attack graphs

---

> Credits to **[Chandrapal Badshah](https://github.com/0xbadshah)** for providing exceptional training on Kubernetes Security, which significantly contributed to the development of this tool and deepened my understanding of Kubernetes security practices.

> Special thanks to **[Payatu](https://github.com/payatu)** for sponsoring and providing access to this training, enabling the research and development behind KubeXHunt.

---

## Why Does KubeXHunt Exist?

Kubernetes security tools fall into two camps:

1. **Posture scanners** (kube-bench, kubescape, Trivy) — find misconfiguration *before* deployment
2. **Network/RBAC analyzers** (KubeHound) — map the entire cluster's attack surface from the API

But there's a gap: **What happens when you already have code execution inside a pod?**

Existing post-compromise frameworks (Peirates, kube-hunter, BOtB) are 3–5 years old and archived. KubeXHunt fills that void by:

- **Automating real-world attack chains** — not just finding individual vulnerabilities, but chaining them into exploitable path
- **Providing in-cluster execution** — no kubectl, no API access required; works from a compromised pod
- **Generating actionable exploitation code** — see the exact shell commands/YAML to move laterally and escalate
- **Integrating cloud pivoting** — because Kubernetes on EKS/GKE/AKS means compromising the cloud account is the endgame

---

## Quick Start

### Installation

```bash
# Install via pip (Python 3.9+)
pip install kubexhunt

# Verify installation
kubexhunt --help

# Retrieve the report
kubectl logs kubexhunt-scan > report.json
```

### As a Python Script

```bash
# Clone and install
git clone https://github.com/mr-xhunt/kubeX.git
cd kubexhunt
pip install -e ".[dev]"

# Run a full assessment
python3 -m kubexhunt --output report.html

# Run specific phases (read-only)
python3 -m kubexhunt --phase 1 2 3 --no-mutate

# Run in stealth mode
python3 -m kubexhunt --stealth 2 --fast --no-mutate
```

### As a One-Liner

```bash
python3 kubexhunt.py --output report.json --diff previous.json
```

---

## Example: Pod → Cloud Account Compromise

```bash
# 1. Run KubeXHunt
kubexhunt --output report.json

# 2. Review findings
# - Finding: ServiceAccount has get/create pod permissions
# - Finding: IMDS endpoint reachable (EC2 metadata)
# - Finding: Workload Identity binding detected (IRSA)

# 3. See the attack chain
# Pod (default/app) 
#   → Can create pods (RBAC)
#   → Create privileged pod with hostPath:/ (node escape)
#   → Access /var/lib/kubelet/kubeconfig (steal higher-priv token)
#   → Use stolen token to query all secrets (including IRSA token)
#   → IRSA token → AWS STS credentials
#   → AWS CLI: aws s3 ls → s3://prod-database-backups/
#   → Exfil production database

# 4. Generated PoC (from KubeXHunt output):
# kubectl create pod privileged-escape --image=alpine ... hostPath:/ ...
# export TOKEN=$(curl http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# curl http://169.254.169.254/latest/meta-data/iam/security-credentials -H "X-aws-ec2-metadata-token: $TOKEN"
```

---

## Phases Overview

| Phase | Name | What It Does | Opsec |
|-------|------|--------------|-------|
| 0 | Setup | Bootstrap (install kubectl, detect runtime) | 🟢 QUIET |
| 1 | Pod Recon | Enumerate SA, mounts, capabilities, env | ⚪ SILENT |
| 2 | Cloud Metadata | Check IMDS, GCP, Azure endpoints | 🟢 QUIET |
| 3 | RBAC | Enumerate roles, bindings, escalation paths | 🟡 MEDIUM |
| 4 | Network | Port scanning, DNS brute, reachability | 🔴 LOUD |
| 5 | Escape | Kernel CVE detection, seccomp bypass | 🔴 LOUD |
| 6 | Admission | Check webhook policies, bypass techniques | 🟡 MEDIUM |
| 7 | Kubelet | Enumerate 10250, 10255, pod credential harvesting | 🟡 MEDIUM |
| 8 | Privilege Escalation | Pod/role creation, RBAC binding chains | 🔴 LOUD |
| 9 | Supply Chain | Image pull secrets, registry probing | 🟡 MEDIUM |
| 10–12 | Cloud Platforms | EKS, GKE, Azure detection & enumeration | 🟢 QUIET |
| 13 | Secrets | Enumerate all Kubernetes secrets | 🔴 LOUD |
| 14 | DoS | Resource exhaustion, CrashLoopBackOff attacks | 🔴 LOUD |
| 15+ | Advanced | Cluster intelligence, stealth analysis, etc. | 🟡 MEDIUM |

**Use `--stealth` to skip LOUD phases in production:**
```bash
python3 kubexhunt.py --stealth 2 --no-mutate  # Skip LOUD & MEDIUM, read-only
```

---

## Key Features

### 1. Structured Findings

Every finding includes:
- **MITRE ATT&CK for Containers** technique IDs (e.g., `T1078.001` Valid Accounts)
- **CWE** and **CVSS 3.1** scores
- **CIS Kubernetes Benchmark** control mappings
- **Remediation steps** with effort estimates
- **Attack paths** showing how this finding chains to compromise

Example finding (JSON):
```json
{
  "id": "RBAC-WILDCARD-001",
  "title": "ClusterRole with overly permissive wildcard verbs",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "mitre": ["T1078.001", "T1087.002"],
  "cwe": ["CWE-276"],
  "attack_paths": [
    {
      "path_id": "PATH-001",
      "nodes": ["sa:default:app", "clusterrole:viewer", "secret:kube-system:admin-token", "CLUSTER_ADMIN"],
      "steps": ["Use SA to list ClusterRoles", "Find wildcard verbs", "Read all secrets", "Extract admin token"]
    }
  ],
  "remediation": {
    "summary": "Restrict ClusterRole permissions to only required verbs",
    "steps": [
      {"step": "kubectl patch clusterrole viewer ...", "effort": "LOW"}
    ]
  }
}
```

### 2. Attack Path Graphs

Visualize your route to cluster compromise:
```
[Compromised Pod]
  ↓ CAN_CREATE_POD (RBAC)
[Malicious Pod with hostPath:/]
  ↓ CAN_ESCAPE_TO_NODE
[Node Root Shell]
  ↓ MOUNTS_ALL_SA_TOKENS
[Stolen Cluster-Admin Token]
  ↓ CAN_IMPERSONATE
[Cluster Admin]
```

Export as:
- **D3.js interactive HTML** (click to zoom/filter)
- **Graphviz DOT** (render with `dot -Tpng`)
- **Neo4j Cypher queries** (for further analysis)

### 3. Opsec Ratings

Each check is rated for detectability:
- ⚪ **SILENT** — Indistinguishable from normal behavior
- 🟢 **QUIET** — Hard to detect without dedicated monitoring
- 🟡 **MEDIUM** — Visible in standard audit logs
- 🔴 **LOUD** — Obvious anomalies, immediate detection

Use stealth levels to balance coverage vs. noise:
```bash
--stealth 0   # Run all phases (maximum noise)
--stealth 1   # Skip LOUD phases (good balance)
--stealth 2   # Skip LOUD + MEDIUM (minimal noise, limited coverage)
```

### 4. Multi-Output Formats

```bash
python3 kubexhunt.py --output report.json      # Machine-readable
python3 kubexhunt.py --output report.html      # Interactive UI
python3 kubexhunt.py --output report.sarif     # CI/CD integration
python3 kubexhunt.py --output report.txt       # Console-friendly
python3 kubexhunt.py --output report.graphviz  # Attack graphs
```

### 5. Diff and Trending

```bash
# Compare against a previous scan
python3 kubexhunt.py --diff previous.json

# Shows: new findings, resolved findings, regressions
```

---

## Installation

### Via PyPI (coming soon)
```bash
pip install kubexhunt
```

### Via Homebrew (coming soon)
```bash
brew install kubexhunt
```

### Via Krew (kubectl plugin)
```bash
kubectl krew install kubexhunt
kubexhunt scan --output report.json
```

### From Source
```bash
git clone https://github.com/mr-xhunt/kubeX.git
cd kubexhunt
pip install -e .
python3 -m kubexhunt --help
```

---

## Use Cases

### Red Teams
- Simulate post-breach K8s cluster compromise
- Generate realistic attack scenarios
- Test incident response workflows

### Security Engineering
- Continuous cluster monitoring (run nightly)
- Regression detection (compare scans over time)
- CISO reporting (HTML/SARIF for dashboards)

### DevOps / Platform Teams
- Pre-prod cluster hardening validation
- Compliance audits (CIS Benchmark mapping)
- Incident investigation ("was this cluster already compromised?")

### Security Researchers
- Graph-based cluster analysis
- Novel privilege escalation paths
- CVE-to-K8s-exploitation chains

---

## Comparison to Alternatives

| Feature | KubeXHunt | KubeHound | kube-hunter | Peirates |
|---------|-----------|-----------|-------------|----------|
| **Attack-path chaining** | ✅ Automated | ✅ Graph DB | ❌ No | ❌ Manual |
| **In-cluster execution** | ✅ Agent | ❌ Agentless | ✅ Agent | ✅ Agent |
| **Cloud pivoting** | ✅ K8s→AWS/GCP/Azure | ❌ K8s only | ❌ No | ❌ No |
| **Zero external dependencies** | ✅ Yes | ❌ Neo4j | ✅ Yes | ✅ Yes |
| **Exploitation automation** | ✅ Shell scripts | ❌ No | ❌ No | ❌ No |
| **MITRE ATT&CK mapping** | ✅ Per-finding | ❌ No | ❌ No | ❌ No |
| **Opsec ratings** | ✅ SILENT/QUIET/MEDIUM/LOUD | ❌ No | ❌ No | ❌ No |
| **Maintained** | ✅ Active | ✅ Active | ❌ Archived | ❌ Archived |
| **GitHub stars** | TBD | 2.8k | 4.2k | 2.0k |

---

## Documentation

- **[Getting Started Guide](docs/getting-started.md)** — Installation and first scan
- **[Phase Reference](docs/phases.md)** — Detailed description of each phase
- **[Architecture](docs/architecture.md)** — System design and module overview
- **[Contributing](CONTRIBUTING.md)** — How to add new features and fixes
- **[Security Policy](SECURITY.md)** — Responsible vulnerability disclosure
- **[Roadmap](docs/roadmap.md)** — Future directions and priorities

---

## Examples

### Scan Your Test Cluster (read-only)
```bash
export KUBECONFIG=/path/to/kubeconfig
python3 kubexhunt.py --no-mutate --output test-cluster-report.json
```

### Simulate Post-Breach Attack Chain
```bash
python3 kubexhunt.py --mutate --exploit daemonset-root --output attacker-poc.json
```

### CI/CD Integration (SARIF for GitHub Security)
```bash
python3 kubexhunt.py --output sarif-report.sarif --phase 1 2 3
# Upload to GitHub via:
# gh api repos/OWNER/REPO/code-scanning/sarifs --input sarif-report.sarif
```

### Compare Scan Results
```bash
python3 kubexhunt.py --output today.json --diff yesterday.json
# Shows: NEW findings, FIXED findings, REGRESSIONS
```

---

## Community & Support

- **GitHub Issues** — [Report bugs](https://github.com/mr-xhunt/kubeX/issues)
- **Discussions** — [Ask questions](https://github.com/mr-xhunt/kubeX/discussions)
- **Contributing** — [Add features](CONTRIBUTING.md)
- **Security** — [Report vulnerabilities](SECURITY.md)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

KubeXHunt was inspired by:
- **Peirates** (InGuardians) — post-compromise K8s exploitation
- **kube-hunter** (Aqua) — K8s vulnerability discovery
- **BloodHound** (SpecterOps) — AD attack graph model
- **KubeHound** (Datadog) — Kubernetes attack graph

Special thanks to the Kubernetes security community for research and feedback.

---

## Disclaimer

**KubeXHunt is a security assessment tool designed for authorized testing only.**

- Only run against clusters you own or have explicit written authorization to test
- Unauthorized access to computer systems is illegal
- Authors assume no liability for misuse

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

---

**Ready to assess your cluster?**

```bash
python3 kubexhunt.py --output report.html
open report.html
```
