#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║   KubeXHunt — Kubernetes Security Assessment Tool            ║
║   Automated cluster security testing from a compromised pod  ║
║   Usage: python3 kubexhunt.py [--phase N] [--fast]           ║
║          [--output FILE] [--no-color] [--kubectl-only]       ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os, sys, json, base64, socket, subprocess, threading, time, re, argparse
import urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ══════════════════════════════════════════════════════════════════
# COLORS & UI
# ══════════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    BG_RED = "\033[41m"

NO_COLOR = False

def c(color, text):
    if NO_COLOR: return text
    return f"{color}{text}{C.RESET}"

def sev(level):
    """Return colored severity badge."""
    badges = {
        "CRITICAL": c(C.RED,    "🔴 CRITICAL"),
        "HIGH":     c(C.ORANGE, "🟠 HIGH    "),
        "MEDIUM":   c(C.YELLOW, "🟡 MEDIUM  "),
        "LOW":      c(C.BLUE,   "🔵 LOW     "),
        "INFO":     c(C.CYAN,   "ℹ  INFO    "),
        "PASS":     c(C.GREEN,  "✅ PASS    "),
    }
    return badges.get(level, level)

def banner():
    print(c(C.RED, """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║"""))
    print(c(C.RED,"║") + c(C.BOLD+C.WHITE,"   ██╗  ██╗██╗   ██╗██████╗ ███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗   ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,"   ██║ ██╔╝██║   ██║██╔══██╗██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝   ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.CYAN, "   █████╔╝ ██║   ██║██████╔╝█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║      ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,"   ██╔═██╗ ██║   ██║██╔══██╗██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║      ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.CYAN, "   ██║  ██╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║      ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,"   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ") + c(C.RED,"║"))
    print(c(C.RED, """║                                                                   ║
║         Kubernetes Security Assessment Tool  v1.0.0              ║
║         Starting from a Compromised Pod → Full Cluster Audit     ║
╚═══════════════════════════════════════════════════════════════════╝
"""))

def phase_header(num, name, desc):
    line = "─" * 62
    print(f"\n{c(C.CYAN, line)}")
    print(f"{c(C.BOLD+C.WHITE, f'  PHASE {num}')} {c(C.CYAN, '│')} {c(C.BOLD+C.YELLOW, name)}")
    print(f"  {c(C.GRAY, desc)}")
    print(f"{c(C.CYAN, line)}")

def finding(sev_level, check, detail, remediation=None):
    """Print and record a finding."""
    icon_map = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "INFO":     "ℹ️ ",
        "PASS":     "✅",
    }
    icon = icon_map.get(sev_level, "  ")
    color_map = {
        "CRITICAL": C.RED,
        "HIGH":     C.ORANGE,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.BLUE,
        "INFO":     C.CYAN,
        "PASS":     C.GREEN,
    }
    col = color_map.get(sev_level, C.WHITE)
    print(f"  {icon} {c(col, f'[{sev_level:8}]')} {c(C.BOLD, check)}")
    if detail:
        for line in detail.split('\n'):
            if line.strip():
                print(f"  {c(C.GRAY, '│')}          {c(C.DIM, line.strip())}")
    if remediation and sev_level not in ("PASS", "INFO"):
        print(f"  {c(C.GRAY, '│')} {c(C.GREEN, '⚑ Fix:')} {c(C.DIM+C.GREEN, remediation)}")

    # Record for summary
    FINDINGS.append({
        "severity": sev_level,
        "check": check,
        "detail": detail,
        "remediation": remediation or "",
        "phase": CURRENT_PHASE,
    })

def subcheck(label, status, detail=""):
    ok = status in (True, "ok", "pass", "yes")
    icon = c(C.GREEN, "  ✓") if ok else c(C.RED, "  ✗")
    stat = c(C.GREEN, "PASS") if ok else c(C.RED, "FAIL")
    print(f"{icon} {c(C.DIM, label):50} [{stat}]")
    if detail:
        print(f"    {c(C.GRAY, detail[:100])}")

def info_line(msg):
    print(f"  {c(C.CYAN, '→')} {c(C.DIM, msg)}")

def section(title):
    print(f"\n  {c(C.BOLD+C.MAGENTA, '▸ ' + title)}")

# ══════════════════════════════════════════════════════════════════
# GLOBALS
# ══════════════════════════════════════════════════════════════════
FINDINGS = []
CURRENT_PHASE = "0"
CTX = {}  # Shared context — token, namespace, api, cloud type, etc.

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def k8s_api(path, method="GET", data=None, token=None, timeout=8):
    """Call Kubernetes API. Returns (status_code, dict_or_None)."""
    t = token or CTX.get("token", "")
    api = CTX.get("api", "https://kubernetes.default")
    url = api + path
    headers = {
        "Authorization": f"Bearer {t}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        # Disable SSL verification (self-signed cluster cert)
        import ssl
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx_ssl, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except:
            return e.code, None
    except Exception:
        return 0, None

def http_get(url, headers=None, timeout=5):
    """Simple HTTP GET. Returns (status, body_str)."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""

def tcp_open(host, port, timeout=1.5):
    """Check if TCP port is open."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return True
    except:
        return False

def dns_resolve(name):
    """Resolve hostname. Returns IP or None."""
    try:
        return socket.gethostbyname(name)
    except:
        return None

def run_cmd(cmd, timeout=10):
    """Run shell command. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def file_read(path, lines=None):
    """Read file safely. Returns content or None."""
    try:
        with open(path) as f:
            if lines:
                return "".join([f.readline() for _ in range(lines)])
            return f.read()
    except:
        return None

def decode_b64(s):
    try:
        return base64.b64decode(s).decode(errors="replace")
    except:
        return s

def decode_jwt(token):
    """Decode JWT payload (no verification)."""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=="
            return json.loads(base64.urlsafe_b64decode(padded))
    except:
        pass
    return {}

def truncate(s, n=120):
    s = str(s).replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s

# ══════════════════════════════════════════════════════════════════
# PHASE 0: SETUP & KUBECTL INSTALL
# ══════════════════════════════════════════════════════════════════
def install_kubectl():
    """Install kubectl on the pod if not present."""
    global CURRENT_PHASE
    CURRENT_PHASE = "0"
    phase_header("0", "Setup & kubectl Installation", "Detecting environment, installing kubectl, gathering credentials")

    section("kubectl Detection")
    rc, out, _ = run_cmd("kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null")
    if rc == 0 and "Client" in out:
        info_line(f"kubectl already present: {out.split(chr(10))[0]}")
        CTX["kubectl"] = True
    else:
        info_line("kubectl not found — installing...")
        arch_rc, arch, _ = run_cmd("uname -m")
        arch = arch.strip()
        goarch = "arm64" if "aarch64" in arch or "arm64" in arch else "amd64"

        # Get latest stable version
        ver_rc, ver, _ = run_cmd(
            "curl -sL https://dl.k8s.io/release/stable.txt 2>/dev/null || echo v1.29.0"
        )
        version = ver.strip() or "v1.29.0"

        url = f"https://dl.k8s.io/release/{version}/bin/linux/{goarch}/kubectl"
        install_cmds = [
            f"curl -sLO {url} 2>/dev/null || wget -q -O kubectl {url} 2>/dev/null",
            "chmod +x kubectl",
            "mv kubectl /usr/local/bin/kubectl 2>/dev/null || mv kubectl /tmp/kubectl",
            "export PATH=$PATH:/tmp",
        ]
        for cmd in install_cmds:
            run_cmd(cmd)

        rc2, out2, _ = run_cmd("kubectl version --client 2>/dev/null")
        if rc2 == 0:
            finding("PASS", "kubectl installed", f"Version: {out2.split(chr(10))[0]}")
            CTX["kubectl"] = True
        else:
            finding("INFO", "kubectl install failed", "Will use direct API calls instead")
            CTX["kubectl"] = False

    section("Credential Gathering")
    # SA token
    token = file_read("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if token:
        token = token.strip()
        CTX["token"] = token
        jwt = decode_jwt(token)
        ns = jwt.get("kubernetes.io/serviceaccount/namespace", "")
        sa = jwt.get("kubernetes.io/serviceaccount/service-account.name", "")
        exp = jwt.get("exp", 0)
        finding("INFO", "SA token present",
            f"Namespace: {ns} | SA: {sa} | Expires: {datetime.fromtimestamp(exp) if exp else 'never (long-lived)'}")
        CTX["namespace"] = ns
        CTX["sa_name"] = sa
    else:
        finding("LOW", "No SA token mounted", "automountServiceAccountToken: false")
        CTX["token"] = ""
        CTX["namespace"] = os.environ.get("POD_NAMESPACE", "default")

    # Namespace fallback
    if not CTX.get("namespace"):
        ns_file = file_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        CTX["namespace"] = (ns_file or "default").strip()

    # API server
    api_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    CTX["api"] = f"https://{api_host}:{api_port}"
    info_line(f"API server: {CTX['api']}")

    # Test API connectivity
    section("API Connectivity")
    code, resp = k8s_api("/api/v1/namespaces/" + CTX["namespace"])
    if code == 200:
        finding("PASS", "Kubernetes API reachable", f"Connected to {CTX['api']}")
        CTX["api_ok"] = True
    elif code == 403:
        finding("INFO", "API reachable but SA has limited permissions", f"HTTP {code}")
        CTX["api_ok"] = True
    else:
        finding("INFO", "API connection issue", f"HTTP {code}")
        CTX["api_ok"] = False

    # Detect cloud provider
    section("Cloud Provider Detection")
    cloud = detect_cloud()
    CTX["cloud"] = cloud
    finding("INFO", f"Cloud provider detected: {cloud}", "Activating provider-specific checks")

    info_line(f"Namespace: {CTX['namespace']} | SA: {CTX.get('sa_name','unknown')} | Cloud: {cloud}")

def detect_cloud():
    # AWS
    code, _ = http_get("http://169.254.169.254/latest/meta-data/", timeout=2)
    if code == 200:
        return "AWS"
    # GKE
    code, _ = http_get("http://metadata.google.internal/",
                        headers={"Metadata-Flavor": "Google"}, timeout=2)
    if code in (200, 403):
        return "GKE"
    # Azure
    code, _ = http_get("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        headers={"Metadata": "true"}, timeout=2)
    if code == 200:
        return "Azure"
    return "Unknown"

# ══════════════════════════════════════════════════════════════════
# PHASE 1: POD & CONTAINER RECON
# ══════════════════════════════════════════════════════════════════
def phase_pod_recon():
    global CURRENT_PHASE
    CURRENT_PHASE = "1"
    phase_header("1", "Pod & Container Recon",
                 "Capabilities, privileged mode, filesystem, hostPID, hostNetwork")

    section("Linux Capabilities")
    cap_data = file_read("/proc/self/status")
    cap_eff = ""
    if cap_data:
        for line in cap_data.split("\n"):
            if line.startswith("CapEff:"):
                cap_eff = line.split()[1]
                break

    if cap_eff:
        cap_int = int(cap_eff, 16)
        ALL_CAPS = 0x1FFFFFFFFF
        if cap_int == ALL_CAPS or cap_eff == "ffffffffffffffff":
            finding("CRITICAL", "ALL Linux capabilities granted (privileged container)",
                f"CapEff: {cap_eff} — equivalent to root on the node",
                "Set privileged: false and capabilities.drop: [ALL] in securityContext")
        elif cap_int > 0x00000000a80425fb:  # above default
            finding("HIGH", "Non-default elevated capabilities detected",
                f"CapEff: {cap_eff} — check for NET_RAW, SYS_ADMIN, SYS_PTRACE",
                "Drop all capabilities and add back only what is needed")
        else:
            finding("PASS", "Capabilities within normal bounds", f"CapEff: {cap_eff}")

    section("Seccomp & Privileged Mode")
    seccomp = ""
    if cap_data:
        for line in cap_data.split("\n"):
            if line.startswith("Seccomp:"):
                seccomp = line.split()[1]
                break
    if seccomp == "0":
        finding("HIGH", "Seccomp disabled",
            "Seccomp: 0 — all ~400 Linux syscalls available",
            "Set seccompProfile.type: RuntimeDefault in securityContext")
    elif seccomp in ("1", "2"):
        finding("PASS", f"Seccomp enabled (mode {seccomp})", "Syscall filtering active")

    section("Filesystem")
    # Read-only root filesystem test
    test_path = f"/ro-test-{int(time.time())}"
    try:
        with open(test_path, "w") as f:
            f.write("x")
        os.remove(test_path)
        finding("MEDIUM", "Root filesystem is writable",
            "Container can write to / — attacker can modify app files",
            "Set readOnlyRootFilesystem: true in securityContext")
    except (PermissionError, OSError):
        finding("PASS", "Root filesystem is read-only", "readOnlyRootFilesystem: true enforced")

    # hostPath mounts
    mounts_raw = file_read("/proc/mounts") or ""
    host_mounts = []
    for line in mounts_raw.split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            mp = parts[1]
            if mp in ("/host", "/hostfs", "/rootfs", "/node", "/mnt/host"):
                host_mounts.append(mp)
            elif mp == "/" and "overlay" not in line and "tmpfs" not in line:
                pass  # normal container root
    # Check suspicious host dirs
    for mp in ["/host", "/hostfs", "/rootfs", "/node"]:
        if os.path.isdir(mp) and os.path.exists(f"{mp}/etc/shadow"):
            host_mounts.append(mp)
            finding("CRITICAL", f"Host filesystem mounted at {mp}",
                "Can read /etc/shadow, kubelet certs, SSH keys, other pod tokens",
                "Remove hostPath volumes from deployment spec")
            break
    if not host_mounts:
        finding("PASS", "No host filesystem mount detected", "hostPath: / not present")

    section("hostPID Check")
    pid1_comm = file_read("/proc/1/comm")
    if pid1_comm and pid1_comm.strip() in ("systemd", "init", "bash"):
        finding("CRITICAL", "hostPID: true — host process namespace visible",
            f"PID 1 is '{pid1_comm.strip()}' (node init system — not container init)",
            "Remove hostPID: true from pod spec")
    else:
        finding("PASS", "Isolated PID namespace",
            f"PID 1 is '{(pid1_comm or 'unknown').strip()}'")

    section("hostNetwork Check")
    # Get our IP and see if it's a node-range IP
    _, ip_out, _ = run_cmd("hostname -I 2>/dev/null || ip addr show | grep 'inet ' | awk '{print $2}'")
    # Check kubelet port reachability (only accessible from host network)
    kubelet_10255 = tcp_open("127.0.0.1", 10255, timeout=1.5)
    kubelet_10250 = tcp_open("127.0.0.1", 10250, timeout=1.5)
    if kubelet_10255 or kubelet_10250:
        ports = []
        if kubelet_10255: ports.append("10255 (read-only, no auth)")
        if kubelet_10250: ports.append("10250 (authenticated)")
        finding("CRITICAL", "hostNetwork: true — kubelet API reachable on localhost",
            f"Ports accessible: {', '.join(ports)}",
            "Remove hostNetwork: true from pod spec")
    else:
        finding("PASS", "Node-local kubelet ports not reachable", "hostNetwork not enabled or ports filtered")

    section("Container Runtime Socket")
    sockets = [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/host/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
    ]
    for sock in sockets:
        if os.path.exists(sock):
            finding("CRITICAL", f"Container runtime socket exposed: {sock}",
                "Can create privileged containers, list/stop all workloads",
                "Never mount container runtime sockets into application pods")
            break
    else:
        finding("PASS", "No container runtime socket exposed", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 2: CLOUD METADATA
# ══════════════════════════════════════════════════════════════════
def phase_cloud_metadata():
    global CURRENT_PHASE
    CURRENT_PHASE = "2"
    phase_header("2", "Cloud Metadata & IAM Credentials",
                 "IMDS credential theft, GKE metadata, OAuth token exfiltration")

    cloud = CTX.get("cloud", "Unknown")

    if cloud == "AWS":
        section("AWS IMDSv1 (No Auth)")
        code, body = http_get("http://169.254.169.254/latest/meta-data/", timeout=3)
        if code == 200:
            finding("CRITICAL", "IMDSv1 accessible — zero authentication required",
                "Any process can steal IAM credentials without a session token",
                "Set HttpTokens=required on all EC2 instances (IMDSv2 only)")
        else:
            finding("PASS", "IMDSv1 blocked", "IMDSv2 required or IMDS not reachable")

        section("AWS IMDSv2 Credential Theft")
        code, body = http_get(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=3
        )
        # Actually need PUT for IMDSv2 token
        try:
            import ssl
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                data=b"",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                method="PUT"
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                imds_token = r.read().decode().strip()
        except:
            imds_token = ""

        if imds_token:
            # Get IAM role
            code, role_body = http_get(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3
            )
            role_name = role_body.strip() if code == 200 else ""

            if role_name:
                # Get credentials
                code2, creds_body = http_get(
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                    headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3
                )
                try:
                    creds = json.loads(creds_body)
                    key_id = creds.get("AccessKeyId", "")[:16] + "..."
                    expiry = creds.get("Expiration", "unknown")
                    finding("CRITICAL", "AWS IAM credentials stolen via IMDS",
                        f"Role: {role_name} | KeyId: {key_id} | Expires: {expiry}\n"
                        f"Use: export AWS_ACCESS_KEY_ID={creds.get('AccessKeyId','')} "
                        f"AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...",
                        "Block 169.254.169.254/32 via Calico GlobalNetworkPolicy")
                except:
                    finding("HIGH", "IMDS reachable, role found but creds parsing failed",
                        f"Role: {role_name}",
                        "Block 169.254.169.254/32 via NetworkPolicy")

                # Get instance identity
                code3, iid_body = http_get(
                    "http://169.254.169.254/latest/dynamic/instance-identity/document",
                    headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3
                )
                try:
                    iid = json.loads(iid_body)
                    info_line(f"Account: {iid.get('accountId')} | Region: {iid.get('region')} | Instance: {iid.get('instanceId')}")
                    CTX["aws_account"] = iid.get("accountId", "")
                    CTX["aws_region"] = iid.get("region", "")
                except:
                    pass
            else:
                finding("MEDIUM", "IMDS reachable but no IAM role attached",
                    "Instance may not have an instance profile",
                    "Still block IMDS access as defense-in-depth")
        else:
            finding("PASS", "IMDS not reachable or blocked", "Calico NetworkPolicy blocking 169.254.169.254")

        # Check IRSA
        section("AWS IRSA (IAM Role for Service Account)")
        role_arn = os.environ.get("AWS_ROLE_ARN", "")
        token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "")
        if role_arn and token_file:
            token_content = file_read(token_file)
            if token_content:
                jwt = decode_jwt(token_content.strip())
                finding("HIGH", "IRSA token present — pod-level AWS IAM access",
                    f"Role ARN: {role_arn}\n"
                    f"SA: {jwt.get('kubernetes.io/serviceaccount/service-account.name', '?')}\n"
                    "Run: aws sts assume-role-with-web-identity --role-arn ... --web-identity-token ...",
                    "Scope IRSA role policy to minimum required AWS permissions")
        else:
            finding("PASS", "No IRSA token found", "Pod not annotated with IAM role ARN")

    elif cloud == "GKE":
        section("GKE Metadata Server")
        code, body = http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"}, timeout=3
        )
        if code == 200:
            try:
                tok = json.loads(body)
                token_preview = tok.get("access_token", "")[:20] + "..."
                finding("CRITICAL", "GKE OAuth2 token accessible via metadata server",
                    f"Token type: {tok.get('token_type')} | Expires: {tok.get('expires_in')}s\n"
                    f"Preview: {token_preview}",
                    "Enable Workload Identity and disable node SA for pods")
            except:
                finding("HIGH", "GKE metadata accessible, token parse failed", truncate(body))
        else:
            finding("PASS", "GKE metadata token not accessible", f"HTTP {code}")

        section("GKE Node SA Scopes")
        code, scopes_body = http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
            headers={"Metadata-Flavor": "Google"}, timeout=3
        )
        if code == 200:
            scopes = scopes_body.strip().split("\n")
            dangerous = [s for s in scopes if "cloud-platform" in s or "devstorage.read_write" in s]
            if dangerous:
                finding("CRITICAL", "Dangerous GCP scopes on node SA",
                    f"Scopes: {', '.join(dangerous[:3])}\ncloud-platform = full GCP API access",
                    "Use Workload Identity instead of node SA scopes")
            else:
                finding("MEDIUM", "GKE node has GCP scopes (limited)",
                    f"Scopes: {', '.join(scopes[:3])}",
                    "Consider removing all scopes and using Workload Identity")

        section("GKE Legacy Metadata (No Header Required)")
        code, body = http_get(
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
            timeout=3
        )
        if code == 200:
            finding("CRITICAL", "GKE legacy metadata accessible WITHOUT Metadata-Flavor header",
                "Old GKE clusters (< 1.21) expose tokens without authentication header",
                "Upgrade GKE cluster or enable metadata concealment")
        else:
            finding("PASS", "Legacy GKE metadata endpoint blocked", f"HTTP {code}")

    else:
        finding("INFO", f"Cloud: {cloud} — IMDS checks skipped", "AWS and GKE specific checks not applicable")

# ══════════════════════════════════════════════════════════════════
# PHASE 3: RBAC & K8S API ENUMERATION
# ══════════════════════════════════════════════════════════════════
def phase_rbac():
    global CURRENT_PHASE
    CURRENT_PHASE = "3"
    phase_header("3", "Kubernetes API Enumeration via RBAC",
                 "Service account permissions, secret theft, cluster enumeration")

    ns = CTX.get("namespace", "default")

    if not CTX.get("token"):
        finding("INFO", "No SA token — RBAC checks skipped", "automountServiceAccountToken: false")
        return

    section("Self-Subject Rules Review")
    code, resp = k8s_api(
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        method="POST",
        data={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":ns}}
    )
    wildcard = False
    if code == 200 and resp:
        rules = resp.get("status", {}).get("resourceRules", [])
        for rule in rules:
            vbs = rule.get("verbs", [])
            res = rule.get("resources", [])
            grps = rule.get("apiGroups", [])
            if "*" in vbs and "*" in res and "*" in grps:
                wildcard = True
                finding("CRITICAL", "Wildcard RBAC — full cluster access via SA token",
                    f"Rules include apiGroups:[*] resources:[*] verbs:[*]\n"
                    "Attacker can read all secrets, create privileged pods, modify RBAC",
                    "Apply least-privilege RBAC — scope to specific resources and verbs only")
        if not wildcard:
            finding("INFO", f"SA has {len(rules)} RBAC rule(s)", "Review rules below for over-permission")

    section("Secret Access Check")
    results_parallel = {}
    checks = [
        ("list_ns_secrets",  f"/api/v1/namespaces/{ns}/secrets"),
        ("list_all_secrets", "/api/v1/secrets"),
        ("list_namespaces",  "/api/v1/namespaces"),
        ("list_pods",        "/api/v1/pods"),
        ("list_cms",         f"/api/v1/namespaces/{ns}/configmaps"),
        ("list_services",    "/api/v1/services"),
        ("list_deployments", f"/apis/apps/v1/namespaces/{ns}/deployments"),
        ("list_crbs",        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"),
    ]

    def _check(name, path):
        code, resp = k8s_api(path, timeout=6)
        return name, code, resp

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_check, n, p): n for n, p in checks}
        for fut in as_completed(futures):
            name, code, resp = fut.result()
            results_parallel[name] = (code, resp)

    code_ns, resp_ns = results_parallel.get("list_ns_secrets", (0, None))
    code_all, resp_all = results_parallel.get("list_all_secrets", (0, None))

    if code_ns == 200 and resp_ns:
        items = resp_ns.get("items", [])
        names = [i["metadata"]["name"] for i in items]
        finding("CRITICAL", f"Can list secrets in namespace '{ns}' ({len(items)} found)",
            f"Secrets: {', '.join(names[:8])}{'...' if len(names) > 8 else ''}",
            "Set automountServiceAccountToken: false or restrict SA to zero permissions")
        # Try to read first non-default secret
        for item in items:
            sname = item["metadata"]["name"]
            if "default-token" not in sname and "harbor" not in sname.lower():
                code_s, resp_s = k8s_api(f"/api/v1/namespaces/{ns}/secrets/{sname}")
                if code_s == 200 and resp_s:
                    data = resp_s.get("data", {})
                    decoded = {k: decode_b64(v)[:60] for k, v in list(data.items())[:4]}
                    finding("CRITICAL", f"Secret contents readable: {sname}",
                        "\n".join([f"{k}: {v}" for k, v in decoded.items()]),
                        "Restrict RBAC — remove get/list on secrets")
                break
    else:
        finding("PASS", f"Cannot list secrets in '{ns}'", f"HTTP {code_ns}")

    if code_all == 200 and resp_all:
        total = len(resp_all.get("items", []))
        finding("CRITICAL", f"Can list ALL secrets cluster-wide ({total} total)",
            "Has cluster-wide secret read access — can read every secret in every namespace",
            "Remove cluster-wide secret list/get from RBAC roles")
    elif code_ns != 200:
        finding("PASS", "No cluster-wide secret access", f"HTTP {code_all}")

    section("Cluster Enumeration")
    code_nss, resp_nss = results_parallel.get("list_namespaces", (0, None))
    if code_nss == 200 and resp_nss:
        nss = [i["metadata"]["name"] for i in resp_nss.get("items", [])]
        finding("HIGH", f"Can list all namespaces ({len(nss)} found)",
            f"Namespaces: {', '.join(nss)}",
            "Restrict cluster-level namespace list permission")
        CTX["namespaces"] = nss
    else:
        finding("PASS", "Cannot list namespaces cluster-wide", f"HTTP {code_nss}")

    code_pods, resp_pods = results_parallel.get("list_pods", (0, None))
    if code_pods == 200 and resp_pods:
        pods = resp_pods.get("items", [])
        finding("HIGH", f"Can list all pods cluster-wide ({len(pods)} found)",
            f"Sample: {', '.join([p['metadata']['name'] for p in pods[:4]])}",
            "Restrict pod list to specific namespace only")

    # Cluster-admin binding check
    code_crbs, resp_crbs = results_parallel.get("list_crbs", (0, None))
    if code_crbs == 200 and resp_crbs:
        admin_bindings = []
        for crb in resp_crbs.get("items", []):
            if crb.get("roleRef", {}).get("name") == "cluster-admin":
                for s in crb.get("subjects", []):
                    admin_bindings.append(
                        f"{s.get('kind')}: {s.get('namespace','cluster')}/{s.get('name')}"
                    )
        if admin_bindings:
            finding("HIGH", f"cluster-admin role bound to {len(admin_bindings)} subject(s)",
                "\n".join(admin_bindings[:6]),
                "Audit cluster-admin bindings — remove any non-essential subjects")

    section("ConfigMap Sensitive Data")
    code_cm, resp_cm = results_parallel.get("list_cms", (0, None))
    if code_cm == 200 and resp_cm:
        for cm in resp_cm.get("items", []):
            data = cm.get("data", {})
            for k, v in data.items():
                if any(kw in k.lower() for kw in ["password","secret","key","token","credential"]):
                    finding("MEDIUM", f"Sensitive key in ConfigMap: {cm['metadata']['name']}.{k}",
                        f"Value: {str(v)[:80]}",
                        "Use Secrets instead of ConfigMaps for sensitive values")

# ══════════════════════════════════════════════════════════════════
# PHASE 4: NETWORK RECON & LATERAL MOVEMENT
# ══════════════════════════════════════════════════════════════════
def phase_network(fast=False):
    global CURRENT_PHASE
    CURRENT_PHASE = "4"
    phase_header("4", "Network Recon & Lateral Movement",
                 "Service discovery, port scanning, internal API access, traffic sniffing")

    section("Service Discovery via Environment Variables")
    svc_env = {}
    for k, v in os.environ.items():
        if k.endswith("_SERVICE_HOST"):
            svc_name = k[:-len("_SERVICE_HOST")].lower().replace("_", "-")
            port_key = k[:-len("_SERVICE_HOST")] + "_SERVICE_PORT"
            port = os.environ.get(port_key, "?")
            svc_env[svc_name] = (v, port)

    if svc_env:
        finding("INFO", f"K8s auto-injected {len(svc_env)} service endpoint(s)",
            "\n".join([f"{n}: {v}:{p}" for n, (v, p) in list(svc_env.items())[:8]]))
        CTX["known_services"] = svc_env
    else:
        finding("INFO", "No service env vars found", "K8s service discovery env vars absent")

    section("DNS Enumeration")
    dns_targets = [
        "payment-api", "payment-api.payments", "payment-api.payments.svc.cluster.local",
        "payments", "billing", "auth", "api", "backend", "database", "db",
        "redis", "postgres", "mysql", "mongodb", "vault", "consul", "admin",
        "internal", "checkout", "checkout.payments", "checkout.payments.svc.cluster.local",
    ]
    if not fast:
        dns_found = {}
        def _resolve(name):
            ip = dns_resolve(name)
            return name, ip

        with ThreadPoolExecutor(max_workers=20) as ex:
            for name, ip in ex.map(lambda n: _resolve(n), dns_targets):
                if ip:
                    dns_found[name] = ip

        if dns_found:
            finding("INFO", f"DNS resolved {len(dns_found)} internal service(s)",
                "\n".join([f"{n} → {ip}" for n, ip in list(dns_found.items())[:10]]))
            CTX["dns_found"] = dns_found
        else:
            finding("INFO", "No common service names resolved via DNS", "")

    section("Lateral Movement — Internal API Probe")
    # Combine known from env + DNS found
    targets_to_probe = []
    for name, (ip, port) in svc_env.items():
        targets_to_probe.append((f"http://{ip}:{port}", name))
    if not fast and CTX.get("dns_found"):
        for name, ip in CTX["dns_found"].items():
            targets_to_probe.append((f"http://{ip}:8080", name))

    # Also probe hardcoded likely paths
    for name, ip in (CTX.get("dns_found") or {}).items():
        for endpoint in ["/transactions", "/customers", "/admin", "/health", "/metrics", "/api/v1"]:
            targets_to_probe.append((f"http://{ip}:8080{endpoint}", f"{name}{endpoint}"))

    lateral_found = []
    def _probe(url_name):
        url, label = url_name
        code, body = http_get(url, timeout=3)
        return url, label, code, body[:200] if body else ""

    if targets_to_probe:
        with ThreadPoolExecutor(max_workers=10) as ex:
            for url, label, code, body in ex.map(_probe, targets_to_probe[:20]):
                if code == 200:
                    lateral_found.append((url, code, body))

    if lateral_found:
        for url, code, body in lateral_found:
            is_sensitive = any(kw in body.lower() for kw in
                               ["password","secret","token","card","email","customer","transaction","amount"])
            sev = "CRITICAL" if is_sensitive else "HIGH"
            finding(sev, f"Internal service reachable: {url}",
                f"HTTP {code} | Body preview: {truncate(body, 150)}" +
                ("\n⚠ Response contains sensitive data keywords!" if is_sensitive else ""),
                "Apply Istio mTLS + AuthorizationPolicy or NetworkPolicy to restrict pod-to-pod traffic")
    else:
        finding("PASS", "No unexpected internal services reachable",
            "Istio mTLS or NetworkPolicy appears to be restricting lateral movement")

    section("Port Scan — Common Internal Ports")
    if not fast and CTX.get("dns_found"):
        ports_to_scan = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9200, 27017, 9092]
        open_ports = []

        def _scan(host_port):
            host, port = host_port
            if tcp_open(host, port, timeout=1):
                return host, port
            return None

        scan_targets = [(ip, p) for _, ip in list(CTX["dns_found"].items())[:5]
                        for p in ports_to_scan]
        with ThreadPoolExecutor(max_workers=30) as ex:
            for result in ex.map(_scan, scan_targets):
                if result:
                    open_ports.append(result)

        if open_ports:
            finding("MEDIUM", f"Open ports on internal services: {len(open_ports)} found",
                "\n".join([f"{h}:{p}" for h, p in open_ports[:10]]),
                "Apply NetworkPolicy to restrict inter-pod communication")

    section("Network Sniffing Capability")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s.close()
        finding("HIGH", "NET_RAW capability — network traffic sniffing possible",
            "Can capture plain-text pod-to-pod HTTP traffic with raw sockets",
            "Drop NET_RAW capability | Enable Istio mTLS to encrypt all traffic")
    except PermissionError:
        finding("PASS", "NET_RAW capability denied", "Raw socket sniffing not possible")
    except Exception:
        finding("PASS", "NET_RAW capability denied", "Raw socket sniffing not possible")

# ══════════════════════════════════════════════════════════════════
# PHASE 5: CONTAINER ESCAPE
# ══════════════════════════════════════════════════════════════════
def phase_escape():
    global CURRENT_PHASE
    CURRENT_PHASE = "5"
    phase_header("5", "Container Escape Vectors",
                 "nsenter, chroot, runtime socket, cgroup v1 escape")

    section("nsenter Escape (hostPID + Privileged)")
    pid1_comm = (file_read("/proc/1/comm") or "").strip()
    cap_data = file_read("/proc/self/status") or ""
    cap_eff = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"):
            cap_eff = line.split()[1]
    has_all_caps = int(cap_eff, 16) >= 0x1FFFFFFFFF if cap_eff else False
    has_hostpid = pid1_comm in ("systemd", "init")

    if has_hostpid and has_all_caps:
        finding("CRITICAL", "nsenter escape possible: hostPID=true + privileged=true",
            "Command: nsenter -t 1 -m -u -i -n -p -- /bin/bash\n"
            "Result: full root shell on the node — identical to SSH access",
            "Remove hostPID: true | Set privileged: false | Drop all capabilities")
    elif has_hostpid:
        finding("HIGH", "hostPID=true but not fully privileged (partial escape vector)",
            "Can see all host processes, read /proc/<pid>/environ for credential leak",
            "Remove hostPID: true from pod spec")
    else:
        finding("PASS", "nsenter escape not possible", "hostPID not enabled")

    section("chroot Escape (hostPath)")
    for mp in ["/host", "/hostfs", "/rootfs", "/node", "/mnt/host"]:
        if os.path.exists(f"{mp}/etc/shadow"):
            finding("CRITICAL", f"chroot escape possible via hostPath at {mp}",
                f"Command: chroot {mp} /bin/bash\n"
                f"Result: root shell using node's OS — full node access",
                "Remove hostPath volumes from deployment | Enable PSS Restricted")
            break
    else:
        finding("PASS", "chroot escape not possible", "No host filesystem mount detected")

    section("Container Runtime Socket")
    runtime_socks = {
        "/var/run/docker.sock": "Docker",
        "/run/containerd/containerd.sock": "containerd",
        "/host/run/containerd/containerd.sock": "containerd (via hostPath)",
        "/run/crio/crio.sock": "CRI-O",
    }
    found_sock = False
    for path, runtime in runtime_socks.items():
        if os.path.exists(path):
            finding("CRITICAL", f"{runtime} socket exposed at {path}",
                "Can: create privileged containers, exec into any container,\n"
                "list all running workloads, snapshot/exfiltrate filesystems",
                "Never mount container runtime sockets into application pods")
            found_sock = True
    if not found_sock:
        finding("PASS", "No container runtime socket exposed", "")

    section("cgroup v1 Escape Vector")
    release_agents = []
    try:
        cg_base = "/sys/fs/cgroup"
        for subsys in os.listdir(cg_base):
            ra_path = os.path.join(cg_base, subsys, "release_agent")
            if os.path.exists(ra_path):
                release_agents.append(ra_path)
    except:
        pass

    if release_agents:
        # Test writability (only check, don't write)
        writable_ra = []
        for ra in release_agents[:3]:
            if os.access(ra, os.W_OK):
                writable_ra.append(ra)
        if writable_ra:
            finding("CRITICAL", "cgroup v1 release_agent is writable — host escape possible",
                f"Writable paths: {', '.join(writable_ra)}\n"
                "Privileged containers can write a script to release_agent\n"
                "which executes on the host when a cgroup is released",
                "Disable cgroup v1 | Use cgroup v2 | Drop all capabilities")
        else:
            finding("LOW", "cgroup v1 release_agent present but not writable",
                "Privileged escalation would require additional capabilities",
                "Upgrade to cgroup v2 as defense-in-depth")
    else:
        finding("PASS", "cgroup v1 release_agent not accessible", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 6: NODE-LEVEL COMPROMISE
# ══════════════════════════════════════════════════════════════════
def phase_node():
    global CURRENT_PHASE
    CURRENT_PHASE = "6"
    phase_header("6", "Node-Level Compromise",
                 "Kubelet certs, other pods' SA tokens, host credential files")

    section("Kubelet Certificate Theft")
    kubelet_pki_paths = [
        "/host/var/lib/kubelet/pki",
        "/var/lib/kubelet/pki",
    ]
    found_pki = False
    for pki_dir in kubelet_pki_paths:
        if os.path.isdir(pki_dir):
            try:
                files = os.listdir(pki_dir)
                pem_files = [f for f in files if f.endswith(".pem")]
                if pem_files:
                    finding("CRITICAL", f"Kubelet PKI directory accessible: {pki_dir}",
                        f"Files: {', '.join(pem_files[:5])}\n"
                        "Kubelet client cert = system:node:<nodename> role\n"
                        "Can impersonate kubelet to the API server",
                        "Remove hostPath mounts | PSS Restricted prohibits hostPath: /")
                    found_pki = True
            except:
                pass
    if not found_pki:
        finding("PASS", "Kubelet PKI not accessible", "hostPath mount not present")

    section("Other Pods' Service Account Tokens")
    token_dirs = [
        "/host/var/lib/kubelet/pods",
        "/var/lib/kubelet/pods",
    ]
    stolen_tokens = []
    for base in token_dirs:
        if os.path.isdir(base):
            _, find_out, _ = run_cmd(f"find {base} -name 'token' 2>/dev/null")
            for token_path in find_out.split("\n"):
                token_path = token_path.strip()
                if not token_path:
                    continue
                tok = file_read(token_path)
                if tok:
                    tok = tok.strip()
                    jwt = decode_jwt(tok)
                    sa = jwt.get("kubernetes.io/serviceaccount/service-account.name", "unknown")
                    ns = jwt.get("kubernetes.io/serviceaccount/namespace", "unknown")
                    stolen_tokens.append((sa, ns, token_path))

    if stolen_tokens:
        finding("CRITICAL", f"Found {len(stolen_tokens)} SA token(s) from other pods",
            "\n".join([f"{ns}/{sa} — {path}" for sa, ns, path in stolen_tokens[:8]]),
            "Remove hostPath mounts | PSS Restricted blocks hostPath: /")
        # Check if any stolen token has more permissions than ours
        for sa, ns, path in stolen_tokens[:3]:
            tok = (file_read(path) or "").strip()
            code, resp = k8s_api(f"/api/v1/namespaces/{ns}/secrets", token=tok)
            if code == 200:
                finding("CRITICAL", f"Stolen token for {ns}/{sa} can read secrets!",
                    f"Token from: {path}\nCan now pivot to namespace: {ns}",
                    "PSS Restricted + no hostPath = prevents this entirely")
    else:
        finding("PASS", "No other pods' SA tokens accessible", "")

    section("Sensitive Host Files")
    sensitive_files = [
        ("/host/etc/kubernetes/admin.conf",    "CRITICAL", "Kubernetes admin kubeconfig"),
        ("/host/etc/kubernetes/kubelet.conf",  "HIGH",     "Kubelet kubeconfig"),
        ("/host/var/lib/kubelet/kubeconfig",   "HIGH",     "Kubelet kubeconfig (alternate)"),
        ("/host/home/kubernetes/kube-env",     "HIGH",     "GKE node kube-env"),
        ("/host/etc/shadow",                   "HIGH",     "Node /etc/shadow — password hashes"),
        ("/host/root/.ssh/id_rsa",             "CRITICAL", "Root SSH private key"),
        ("/host/root/.ssh/authorized_keys",    "HIGH",     "Root SSH authorized keys"),
    ]
    found_any = False
    for path, sev_level, desc in sensitive_files:
        if os.path.exists(path):
            content = file_read(path, lines=3) or ""
            finding(sev_level, f"Sensitive file accessible: {desc}",
                f"Path: {path}\nPreview: {truncate(content, 100)}",
                "Remove hostPath mounts | Apply PSS Restricted")
            found_any = True
    if not found_any:
        finding("PASS", "No sensitive host files accessible", "hostPath mount not present")

# ══════════════════════════════════════════════════════════════════
# PHASE 7: CLUSTER PRIVILEGE ESCALATION
# ══════════════════════════════════════════════════════════════════
def phase_privesc():
    global CURRENT_PHASE
    CURRENT_PHASE = "7"
    phase_header("7", "Cluster-Wide Privilege Escalation",
                 "Privileged pod creation, RBAC escalation, webhook manipulation")

    ns = CTX.get("namespace", "default")
    if not CTX.get("token"):
        finding("INFO", "No SA token — escalation checks skipped", "")
        return

    section("Privileged Pod Creation Test")
    # Test if we can create pods in current namespace
    test_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": f"kubexhunt-probe-{int(time.time())}"},
        "spec": {"containers": [{"name": "probe", "image": "busybox", "command": ["sleep", "10"]}]}
    }
    code, resp = k8s_api(f"/api/v1/namespaces/{ns}/pods", method="POST", data=test_pod)
    if code == 201:
        pod_name = resp.get("metadata", {}).get("name", "")
        finding("HIGH", f"Can create pods in namespace '{ns}'",
            f"Created pod: {pod_name}\nWill attempt privileged pod creation...",
            "Remove pod create permission from SA | Apply PSS Restricted")
        # Clean up
        k8s_api(f"/api/v1/namespaces/{ns}/pods/{pod_name}", method="DELETE")

        # Try privileged pod
        priv_pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": f"kubexhunt-priv-{int(time.time())}"},
            "spec": {
                "hostPID": True, "hostNetwork": True,
                "containers": [{
                    "name": "escape",
                    "image": "busybox",
                    "command": ["sleep", "10"],
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host", "mountPath": "/host"}]
                }],
                "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
            }
        }
        code2, resp2 = k8s_api(f"/api/v1/namespaces/{ns}/pods", method="POST", data=priv_pod)
        if code2 == 201:
            priv_name = resp2.get("metadata", {}).get("name", "")
            finding("CRITICAL", "Can create PRIVILEGED pods — full node escape achievable",
                f"Created privileged pod with hostPID/hostNetwork/hostPath: {priv_name}\n"
                "This gives root access to every node this pod is scheduled on",
                "Apply PSS Restricted to namespace | Deny pod create from SA | Use Kyverno")
            k8s_api(f"/api/v1/namespaces/{ns}/pods/{priv_name}", method="DELETE")
        else:
            finding("PASS", "Privileged pod creation blocked", f"HTTP {code2}")
    else:
        finding("PASS", f"Cannot create pods in '{ns}'", f"HTTP {code}")

    section("RBAC Escalation — ClusterRoleBinding Creation")
    test_crb_name = f"kubexhunt-test-{int(time.time())}"
    test_crb = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": test_crb_name},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
        "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": ns}]
    }
    code, resp = k8s_api("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                          method="POST", data=test_crb)
    if code == 201:
        finding("CRITICAL", "Can create ClusterRoleBindings — RBAC escalation possible",
            f"Created CRB: {test_crb_name}\n"
            "Can bind cluster-admin to any service account → permanent cluster takeover",
            "Remove ClusterRoleBinding create permission from SA")
        k8s_api(f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{test_crb_name}",
                method="DELETE")
    else:
        finding("PASS", "Cannot create ClusterRoleBindings", f"HTTP {code}")

    section("Admission Webhook Security")
    code, resp = k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    if code == 200 and resp:
        ignore_webhooks = []
        for wh in resp.get("items", []):
            for hook in wh.get("webhooks", []):
                if hook.get("failurePolicy") == "Ignore":
                    ignore_webhooks.append(wh["metadata"]["name"])
        if ignore_webhooks:
            finding("HIGH", f"Admission webhooks with failurePolicy=Ignore: {len(ignore_webhooks)}",
                f"Webhooks: {', '.join(ignore_webhooks)}\n"
                "If webhook service is down, ALL policies are bypassed silently",
                "Set failurePolicy: Fail on all security-relevant webhooks")
        else:
            finding("PASS", "All admission webhooks use failurePolicy=Fail", "")

    # Check kube-system namespace bypass
    code_test, _ = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_test == 200:
        finding("HIGH", "Can list pods in kube-system namespace",
            "SA has access to kube-system — policies often exclude this namespace",
            "Restrict SA access to own namespace only")

    section("etcd Encryption at Rest")
    # Check via API server flags if accessible
    code_ap, resp_ap = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items", []):
            name = pod.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                for c in pod.get("spec", {}).get("containers", []):
                    cmd = " ".join(c.get("command", []))
                    if "encryption-provider-config" in cmd:
                        finding("PASS", "etcd encryption-at-rest configured",
                            "API server has --encryption-provider-config flag")
                    else:
                        finding("HIGH", "etcd encryption-at-rest not detected",
                            "Secrets may be stored in plaintext in etcd",
                            "Configure --encryption-provider-config on API server")
                break

# ══════════════════════════════════════════════════════════════════
# PHASE 8: PERSISTENCE
# ══════════════════════════════════════════════════════════════════
def phase_persistence():
    global CURRENT_PHASE
    CURRENT_PHASE = "8"
    phase_header("8", "Persistence Techniques",
                 "Backdoor SA, malicious DaemonSet, sidecar injection")

    ns = CTX.get("namespace", "default")
    if not CTX.get("token"):
        finding("INFO", "No SA token — persistence checks skipped", "")
        return

    section("ServiceAccount Creation in kube-system")
    test_sa_name = f"kubexhunt-sa-test-{int(time.time())}"
    code, resp = k8s_api("/api/v1/namespaces/kube-system/serviceaccounts",
                          method="POST",
                          data={"apiVersion":"v1","kind":"ServiceAccount",
                                "metadata":{"name":test_sa_name}})
    if code == 201:
        finding("CRITICAL", "Can create ServiceAccounts in kube-system",
            f"Created: {test_sa_name}\n"
            "Attacker can create backdoor SA and bind cluster-admin to it",
            "Restrict ServiceAccount create permission | Protect kube-system namespace")
        k8s_api(f"/api/v1/namespaces/kube-system/serviceaccounts/{test_sa_name}",
                method="DELETE")
    else:
        finding("PASS", "Cannot create ServiceAccounts in kube-system", f"HTTP {code}")

    section("DaemonSet Creation Test")
    test_ds_name = f"kubexhunt-ds-test-{int(time.time())}"
    ds_spec = {
        "apiVersion": "apps/v1", "kind": "DaemonSet",
        "metadata": {"name": test_ds_name, "namespace": "kube-system"},
        "spec": {
            "selector": {"matchLabels": {"app": "kubexhunt-test"}},
            "template": {
                "metadata": {"labels": {"app": "kubexhunt-test"}},
                "spec": {
                    "tolerations": [{"operator": "Exists"}],
                    "containers": [{"name": "probe", "image": "busybox",
                                   "command": ["sleep", "10"]}]
                }
            }
        }
    }
    code, resp = k8s_api("/apis/apps/v1/namespaces/kube-system/daemonsets",
                          method="POST", data=ds_spec)
    if code == 201:
        finding("CRITICAL", "Can create DaemonSets in kube-system",
            f"Created: {test_ds_name}\n"
            "Runs a container on EVERY node in the cluster — cluster-wide persistence",
            "Remove DaemonSet create permission | Restrict kube-system write access")
        k8s_api(f"/apis/apps/v1/namespaces/kube-system/daemonsets/{test_ds_name}",
                method="DELETE")
    else:
        finding("PASS", "Cannot create DaemonSets in kube-system", f"HTTP {code}")

    section("Deployment Patch (Sidecar Injection)")
    code_d, resp_d = k8s_api(f"/apis/apps/v1/namespaces/{ns}/deployments")
    if code_d == 200 and resp_d:
        deployments = [i["metadata"]["name"] for i in resp_d.get("items", [])]
        # Test patch on first non-critical deployment
        if deployments:
            dep_name = deployments[0]
            patch = [{"op": "test", "path": "/metadata/name", "value": dep_name}]
            code_p, _ = k8s_api(
                f"/apis/apps/v1/namespaces/{ns}/deployments/{dep_name}",
                method="PATCH",
                data=patch
            )
            # Note: We only test with a no-op JSON patch (test operation)
            if code_p in (200, 204):
                finding("HIGH", f"Can patch deployment '{dep_name}' in '{ns}'",
                    "Attacker can inject malicious sidecar containers into existing workloads",
                    "Remove deployment patch permission from SA")
            else:
                finding("PASS", f"Cannot patch deployment '{dep_name}'", f"HTTP {code_p}")

# ══════════════════════════════════════════════════════════════════
# PHASE 9: SUPPLY CHAIN & ADMISSION CONTROL
# ══════════════════════════════════════════════════════════════════
def phase_supply_chain():
    global CURRENT_PHASE
    CURRENT_PHASE = "9"
    phase_header("9", "Supply Chain & Admission Control Gaps",
                 "Image signing, registry credentials, Kyverno policies")

    ns = CTX.get("namespace", "default")

    section("Image Signing Enforcement")
    code, resp = k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    signing_wh = []
    if code == 200 and resp:
        signing_tools = ["kyverno", "cosign", "sigstore", "notary", "connaisseur", "portieris"]
        for wh in resp.get("items", []):
            name = wh["metadata"]["name"].lower()
            if any(t in name for t in signing_tools):
                signing_wh.append(wh["metadata"]["name"])

    if signing_wh:
        finding("PASS", f"Image signing webhook detected: {', '.join(signing_wh)}", "")
    else:
        finding("HIGH", "No image signing admission webhook detected",
            "Unsigned or tampered images can be deployed without verification",
            "Install Kyverno + verifyImages policy | Use cosign to sign all images")

    section("Registry Credential Exposure")
    code, resp = k8s_api(f"/api/v1/namespaces/{ns}/secrets")
    if code == 200 and resp:
        for item in resp.get("items", []):
            if item.get("type") == "kubernetes.io/dockerconfigjson":
                name = item["metadata"]["name"]
                data = item.get("data", {})
                cfg_b64 = data.get(".dockerconfigjson", "")
                if cfg_b64:
                    try:
                        cfg = json.loads(decode_b64(cfg_b64))
                        auths = cfg.get("auths", {})
                        for registry, creds in auths.items():
                            user = creds.get("username", "?")
                            finding("HIGH", f"Registry credentials in secret '{name}'",
                                f"Registry: {registry} | User: {user}\n"
                                "Attacker can pull any image from this registry",
                                "Restrict secret read permissions | Rotate registry credentials")
                    except:
                        finding("MEDIUM", f"Registry secret found but cannot decode: {name}", "")

    section("PSS Enforcement Check")
    code_ns, resp_ns = k8s_api(f"/api/v1/namespaces/{ns}")
    if code_ns == 200 and resp_ns:
        labels = resp_ns.get("metadata", {}).get("labels", {})
        pss_enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        pss_warn = labels.get("pod-security.kubernetes.io/warn", "")
        if pss_enforce == "restricted":
            finding("PASS", f"PSS Restricted enforced on namespace '{ns}'", "")
        elif pss_enforce:
            finding("MEDIUM", f"PSS level '{pss_enforce}' on '{ns}' (not restricted)",
                f"enforce={pss_enforce} warn={pss_warn}",
                "Set pod-security.kubernetes.io/enforce=restricted")
        else:
            finding("HIGH", f"No PSS labels on namespace '{ns}'",
                "No Pod Security Standards enforcement — privileged pods may run",
                "Apply PSS Restricted: kubectl label namespace --overwrite " +
                "pod-security.kubernetes.io/enforce=restricted")

    section("Kyverno Policy Check")
    code_kp, resp_kp = k8s_api("/apis/kyverno.io/v1/clusterpolicies")
    if code_kp == 200 and resp_kp:
        policies = resp_kp.get("items", [])
        enforced = [p["metadata"]["name"] for p in policies
                   if p.get("spec", {}).get("validationFailureAction") == "Enforce"]
        audit_only = [p["metadata"]["name"] for p in policies
                     if p.get("spec", {}).get("validationFailureAction") == "Audit"]
        if enforced:
            finding("PASS", f"Kyverno policies enforced: {len(enforced)}",
                f"Policies: {', '.join(enforced[:5])}")
        if audit_only:
            finding("MEDIUM", f"Kyverno policies in Audit mode only: {len(audit_only)}",
                f"Policies: {', '.join(audit_only[:5])}\nAudit mode logs but does NOT block",
                "Change validationFailureAction from Audit to Enforce")
        if not policies:
            finding("HIGH", "No Kyverno policies found",
                "No admission-level policy enforcement beyond PSS",
                "Install Kyverno and apply registry restriction, non-root, resource limits policies")
    else:
        finding("INFO", "Kyverno CRD not present or not accessible", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 10: EKS-SPECIFIC
# ══════════════════════════════════════════════════════════════════
def phase_eks():
    global CURRENT_PHASE
    CURRENT_PHASE = "10"
    phase_header("10", "EKS-Specific Tests",
                 "aws-auth ConfigMap, IRSA, node IAM role enumeration")

    if CTX.get("cloud") != "AWS":
        finding("INFO", "Not AWS — EKS checks skipped", f"Detected: {CTX.get('cloud','Unknown')}")
        return

    section("aws-auth ConfigMap")
    code, resp = k8s_api("/api/v1/namespaces/kube-system/configmaps/aws-auth")
    if code == 200 and resp:
        data = resp.get("data", {})
        map_roles = data.get("mapRoles", "")
        map_users = data.get("mapUsers", "")
        finding("INFO", "aws-auth ConfigMap readable",
            f"mapRoles entries: {map_roles.count('rolearn:')}\n"
            f"mapUsers entries: {map_users.count('userarn:')}\n"
            f"Review for over-privileged IAM roles mapped to system:masters",
            "Audit all entries in aws-auth for least privilege")

        # Check for system:masters
        if "system:masters" in map_roles or "system:masters" in map_users:
            finding("HIGH", "system:masters group in aws-auth",
                "IAM roles/users mapped to system:masters = cluster-admin equivalent",
                "Replace system:masters with specific ClusterRole bindings")

        # Test write access
        patch_payload = '{"metadata":{"labels":{"kubexhunt-test":"read-check"}}}'
        code_p, _ = k8s_api(
            "/api/v1/namespaces/kube-system/configmaps/aws-auth",
            method="PATCH",
            data=json.loads(patch_payload)
        )
        if code_p == 200:
            finding("CRITICAL", "aws-auth ConfigMap is WRITABLE",
                "Can add any IAM role as cluster-admin — permanent backdoor\n"
                "Impact: Any AWS IAM identity can get kubectl cluster-admin access",
                "Restrict configmap patch/update to kube-system to cluster-admin only\n"
                "Consider using access entries (newer EKS feature) instead of aws-auth")
            # Remove our label
            k8s_api("/api/v1/namespaces/kube-system/configmaps/aws-auth",
                    method="PATCH",
                    data={"metadata":{"labels":{"kubexhunt-test": None}}})
        else:
            finding("PASS", "aws-auth ConfigMap is read-only for this SA", f"HTTP {code_p}")
    else:
        finding("PASS", "aws-auth not accessible", f"HTTP {code}")

    section("IRSA Token Detection")
    role_arn = os.environ.get("AWS_ROLE_ARN", "")
    token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "")
    if role_arn:
        finding("INFO", f"IRSA configured on this pod",
            f"Role ARN: {role_arn}\nToken file: {token_file}\n"
            "Enumerate: aws sts assume-role-with-web-identity --role-arn ... --web-identity-token ...",
            "Scope IRSA role policy to minimum required S3/service permissions")
    else:
        finding("PASS", "No IRSA token on this pod", "AWS_ROLE_ARN not set")

    section("EKS Cluster Info")
    region = CTX.get("aws_region", "")
    account = CTX.get("aws_account", "")
    if region and account:
        finding("INFO", "AWS account enumerated from IMDS",
            f"Account ID: {account} | Region: {region}\n"
            "Use: aws eks list-clusters --region {region}",
            "Block IMDS access to prevent account enumeration")

# ══════════════════════════════════════════════════════════════════
# PHASE 11: GKE-SPECIFIC
# ══════════════════════════════════════════════════════════════════
def phase_gke():
    global CURRENT_PHASE
    CURRENT_PHASE = "11"
    phase_header("11", "GKE-Specific Tests",
                 "Workload Identity, metadata scopes, legacy endpoints")

    if CTX.get("cloud") != "GKE":
        finding("INFO", "Not GKE — GKE checks skipped", f"Detected: {CTX.get('cloud','Unknown')}")
        return

    section("Workload Identity")
    # Already covered in Phase 2 — just check SA annotations
    code, resp = k8s_api(f"/api/v1/namespaces/{CTX.get('namespace','default')}/serviceaccounts")
    if code == 200 and resp:
        for sa in resp.get("items", []):
            ann = sa.get("metadata", {}).get("annotations", {})
            wi = ann.get("iam.gke.io/gcp-service-account", "")
            if wi:
                finding("INFO", f"Workload Identity on SA: {sa['metadata']['name']}",
                    f"Bound to GCP SA: {wi}\n"
                    "Workload Identity is correct — but check GCP SA permissions",
                    "Audit GCP SA IAM bindings for least privilege")

    section("GKE Node SA Scopes")
    code, body = http_get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
        headers={"Metadata-Flavor": "Google"}, timeout=3
    )
    if code == 200:
        scopes = body.strip().split("\n")
        dangerous = [s for s in scopes if "cloud-platform" in s or "devstorage.read_write" in s]
        if dangerous:
            finding("CRITICAL", "Node SA has cloud-platform scope — full GCP API access",
                f"Scopes: {chr(10).join(dangerous)}\n"
                "OAuth token gives access to GCS, Cloud SQL, GCE APIs, etc.",
                "Use Workload Identity | Remove node SA scopes | Use --no-scopes at node creation")
        else:
            finding("MEDIUM", "Node has limited GCP scopes",
                f"Scopes: {', '.join(scopes[:4])}",
                "Move to Workload Identity for zero node SA permissions")

    section("Kubernetes Dashboard Check")
    code_dash, resp_dash = k8s_api("/api/v1/namespaces/kubernetes-dashboard/services")
    if code_dash == 200 and resp_dash:
        items = resp_dash.get("items", [])
        if items:
            finding("MEDIUM", f"Kubernetes Dashboard deployed ({len(items)} service(s))",
                "Dashboard can be exploited if SA has broad permissions\n"
                "Check: kubectl get clusterrolebindings | grep dashboard",
                "Restrict dashboard SA permissions | Disable dashboard if unused")
    else:
        finding("PASS", "Kubernetes Dashboard not found", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 12: RUNTIME SECURITY GAPS
# ══════════════════════════════════════════════════════════════════
def phase_runtime():
    global CURRENT_PHASE
    CURRENT_PHASE = "12"
    phase_header("12", "Runtime Security Gaps",
                 "Tetragon, Falco detection, enforcement probing")

    section("Runtime Security Tool Detection")
    code, resp = k8s_api("/api/v1/namespaces/kube-system/pods")
    tools_found = {}
    if code == 200 and resp:
        tool_map = {
            "tetragon":   ("🔴", "Tetragon eBPF enforcement (kills processes)"),
            "falco":      ("🟡", "Falco detection (alerts only, no blocking)"),
            "sysdig":     ("🟡", "Sysdig runtime monitoring"),
            "aqua":       ("🟡", "Aqua Security agent"),
            "twistlock":  ("🟡", "Twistlock/Prisma Cloud"),
            "datadog":    ("🔵", "Datadog agent"),
        }
        for pod in resp.get("items", []):
            name = pod["metadata"]["name"].lower()
            for tool, (icon, desc) in tool_map.items():
                if tool in name and tool not in tools_found:
                    tools_found[tool] = desc

    if tools_found:
        for tool, desc in tools_found.items():
            finding("INFO", f"Runtime security detected: {desc}", "")
    else:
        finding("HIGH", "No runtime security tooling detected in kube-system",
            "No Tetragon, Falco, or similar agent found\n"
            "Reverse shells, crypto miners, and post-exploitation will go undetected",
            "Install Tetragon (eBPF enforcement) + Falco (alerting)")

    section("Tetragon TracingPolicies")
    code_tp, resp_tp = k8s_api("/apis/cilium.io/v1alpha1/tracingpolicies")
    if code_tp == 200 and resp_tp:
        policies = resp_tp.get("items", [])
        if policies:
            pol_names = [p["metadata"]["name"] for p in policies]
            finding("PASS", f"Tetragon TracingPolicies active: {len(policies)}",
                f"Policies: {', '.join(pol_names)}")
        else:
            finding("HIGH", "Tetragon installed but NO TracingPolicies active",
                "Tetragon is observing only — no enforcement rules applied",
                "Apply block-reverse-shell and block-exec-from-tmp TracingPolicies")
    else:
        finding("INFO", "Tetragon CRD not present", "")

    section("Runtime Enforcement Probing")
    # Test 1: exec from /tmp
    import tempfile, stat
    try:
        test_bin = f"/tmp/kubexhunt-exec-test-{int(time.time())}"
        import shutil
        shutil.copy("/bin/true", test_bin)
        os.chmod(test_bin, stat.S_IRWXU)
        rc, out, err = run_cmd(test_bin, timeout=3)
        os.remove(test_bin)
        if "Killed" in err or "Killed" in out or rc == 137:
            finding("PASS", "Exec from /tmp is BLOCKED",
                "Tetragon block-exec-from-tmp policy active — SIGKILL on execve from /tmp")
        else:
            finding("HIGH", "Exec from /tmp is ALLOWED",
                f"Ran binary from /tmp successfully (rc={rc})\n"
                "Crypto miners and downloaded malware can execute",
                "Apply Tetragon TracingPolicy: block-exec-from-tmp (sys_execve prefix /tmp/)")
    except Exception as e:
        finding("INFO", f"Exec from /tmp test inconclusive", str(e)[:80])

    # Test 2: outbound TCP (using socket, not bash — less intrusive)
    if "tetragon" in tools_found:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 53))
            s.close()
            finding("INFO", "Python outbound TCP allowed to 8.8.8.8:53",
                "DNS egress permitted (expected) — test with known C2 ports for full check")
        except Exception as e:
            if "Killed" in str(e) or "Connection refused" in str(e):
                pass
            else:
                finding("INFO", f"TCP test result: {str(e)[:60]}", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 13: SECRETS & SENSITIVE DATA
# ══════════════════════════════════════════════════════════════════
def phase_secrets():
    global CURRENT_PHASE
    CURRENT_PHASE = "13"
    phase_header("13", "Secrets & Sensitive Data",
                 "Env var credentials, mounted secrets, app config files")

    section("Environment Variable Secret Scan")
    cred_keywords = ["password","passwd","secret","api_key","apikey","private_key",
                     "auth_token","access_token","credential","database_url"]
    skip_keywords = ["kubernetes","service_port","service_host","_path","_home",
                     "_dir","_url","shell","term","lang","pwd","oldpwd"]

    found_envs = []
    for k, v in os.environ.items():
        k_lower = k.lower()
        if any(kw in k_lower for kw in cred_keywords):
            if not any(sk in k_lower for sk in skip_keywords):
                found_envs.append((k, v[:80]))

    if found_envs:
        finding("HIGH", f"Potential credentials in environment variables: {len(found_envs)}",
            "\n".join([f"{k}={v}" for k, v in found_envs[:8]]),
            "Use Kubernetes Secrets mounted as files — not environment variables\n"
            "K8s Secrets as env vars are visible in pod spec and logs")
    else:
        finding("PASS", "No obvious credentials in environment variables", "")

    section("Mounted Secret File Scan")
    secret_paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/ssl/private",
        "/root/.docker/config.json",
        "/root/.aws/credentials",
        "/root/.kube/config",
        "/etc/git-credentials",
        "/run/secrets",
    ]
    found_secrets = []
    for path in secret_paths:
        if os.path.isfile(path):
            content = (file_read(path, lines=2) or "")[:100]
            found_secrets.append((path, content))
        elif os.path.isdir(path):
            try:
                files = os.listdir(path)
                if files:
                    found_secrets.append((path + "/", f"Contains: {', '.join(files[:5])}"))
            except:
                pass

    # Also scan for pem/key files
    _, key_files, _ = run_cmd(
        "find /app /config /etc/app /srv /opt /home 2>/dev/null "
        r"-name '*.pem' -o -name '*.key' -o -name '*.p12' 2>/dev/null | head -10"
    )
    for kf in key_files.split("\n"):
        if kf.strip():
            found_secrets.append((kf.strip(), "PKI key/cert file"))

    if found_secrets:
        finding("MEDIUM", f"Mounted secret files found: {len(found_secrets)}",
            "\n".join([f"{p}: {truncate(v, 80)}" for p, v in found_secrets[:8]]),
            "Audit what files are mounted into containers | Rotate exposed credentials")
    else:
        finding("PASS", "No unexpected secret files found at common paths", "")

    section("Application Config Credential Scan")
    config_dirs = ["/app", "/config", "/etc/app", "/srv", "/opt", "/home"]
    cred_pattern = re.compile(
        r'(?:password|passwd|secret|api_key|apikey|token|credential)\s*[:=]\s*["\']?([^\s"\'<>]{6,})',
        re.IGNORECASE
    )
    found_configs = []
    for d in config_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for fname in files:
                    if any(fname.endswith(ext) for ext in
                           [".conf",".yaml",".yml",".json",".env",".ini",".properties",".xml"]):
                        fpath = os.path.join(root, fname)
                        try:
                            content = file_read(fpath) or ""
                            matches = cred_pattern.findall(content)
                            if matches:
                                found_configs.append((fpath, matches[:3]))
                        except:
                            pass
        except:
            pass

    if found_configs:
        for fpath, matches in found_configs[:5]:
            finding("HIGH", f"Hardcoded credentials in config file: {fpath}",
                f"Values: {', '.join([truncate(m, 40) for m in matches[:3]])}",
                "Move credentials to Kubernetes Secrets | Rotate exposed values")
    else:
        finding("PASS", "No hardcoded credentials found in common config locations", "")

# ══════════════════════════════════════════════════════════════════
# PHASE 14: DoS & RESOURCE EXHAUSTION
# ══════════════════════════════════════════════════════════════════
def phase_dos():
    global CURRENT_PHASE
    CURRENT_PHASE = "14"
    phase_header("14", "DoS & Resource Exhaustion Proof",
                 "Resource limits, quotas, LimitRange — prove missing controls")

    ns = CTX.get("namespace", "default")

    section("Container Resource Limits")
    # Read cgroup limits
    # cgroup v1
    mem_limit = (file_read("/sys/fs/cgroup/memory/memory.limit_in_bytes") or "").strip()
    # cgroup v2
    if not mem_limit:
        mem_limit = (file_read("/sys/fs/cgroup/memory.max") or "").strip()

    if mem_limit in ("9223372036854771712", "9223372036854775807", "max", ""):
        finding("MEDIUM", "No memory limit on this container",
            "Container can consume all available node memory → node OOM\n"
            "Other workloads on the same node affected",
            "Set resources.limits.memory in container spec")
    else:
        try:
            mb = int(mem_limit) // 1024 // 1024
            finding("PASS", f"Memory limit set: {mb} MB", "")
        except:
            finding("PASS", f"Memory limit: {mem_limit}", "")

    cpu_quota = (file_read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") or "").strip()
    if not cpu_quota:
        cpu_quota = (file_read("/sys/fs/cgroup/cpu.max") or "").strip().split()[0]
    if cpu_quota in ("-1", "max", ""):
        finding("MEDIUM", "No CPU limit on this container",
            "Container can consume all CPU on node → CPU starvation for other pods",
            "Set resources.limits.cpu in container spec")
    else:
        finding("PASS", f"CPU limit set: {cpu_quota}µs per period", "")

    section("Namespace ResourceQuota")
    code_rq, resp_rq = k8s_api(f"/api/v1/namespaces/{ns}/resourcequotas")
    if code_rq == 200 and resp_rq:
        items = resp_rq.get("items", [])
        if not items:
            finding("MEDIUM", f"No ResourceQuota in namespace '{ns}'",
                "Unlimited pod, CPU, and memory creation — DoS via resource exhaustion",
                "Apply ResourceQuota to all workload namespaces")
        else:
            for q in items:
                hard = q.get("status", {}).get("hard", {})
                used = q.get("status", {}).get("used", {})
                finding("PASS", f"ResourceQuota active: {q['metadata']['name']}",
                    " | ".join([f"{k}: {used.get(k,'?')}/{v}" for k, v in list(hard.items())[:4]]))

    section("Namespace LimitRange")
    code_lr, resp_lr = k8s_api(f"/api/v1/namespaces/{ns}/limitranges")
    if code_lr == 200 and resp_lr:
        items = resp_lr.get("items", [])
        if not items:
            finding("LOW", f"No LimitRange in namespace '{ns}'",
                "No default resource limits — pods deployed without limits get unlimited resources",
                "Apply LimitRange with default CPU/memory requests and limits")
        else:
            finding("PASS", f"LimitRange active in '{ns}'",
                f"Provides default resource limits for pods without explicit limits")

    section("Audit Logging")
    # Check if audit logging is configured (only visible via API server pod spec)
    code_ap, resp_ap = k8s_api("/api/v1/namespaces/kube-system/pods")
    audit_found = False
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items", []):
            if "kube-apiserver" in pod.get("metadata", {}).get("name", ""):
                for container in pod.get("spec", {}).get("containers", []):
                    cmd_str = " ".join(container.get("command", []))
                    if "--audit-log-path" in cmd_str or "--audit-policy-file" in cmd_str:
                        finding("PASS", "Kubernetes audit logging configured",
                            "API server has --audit-log-path flag")
                        audit_found = True
    if not audit_found:
        finding("LOW", "Kubernetes audit logging not detected",
            "Without audit logs, attacker activity leaves no forensic trail\n"
            "Credential theft, RBAC changes, pod creation — all unrecorded",
            "Enable audit logging with --audit-log-path on API server\n"
            "For EKS: enable CloudWatch audit log type in cluster config")

# ══════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════
def print_final_report(phases_run, elapsed):
    print(f"\n{c(C.CYAN, '═' * 68)}")
    print(c(C.BOLD+C.WHITE, "  KUBEXHUNT — FINAL ASSESSMENT REPORT"))
    print(f"{c(C.CYAN, '═' * 68)}\n")

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "PASS": 0}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  {c(C.GRAY, 'Cluster  :')} {CTX.get('api', '?')}")
    print(f"  {c(C.GRAY, 'Namespace:')} {CTX.get('namespace', '?')}")
    print(f"  {c(C.GRAY, 'SA       :')} {CTX.get('sa_name', 'unknown')}")
    print(f"  {c(C.GRAY, 'Cloud    :')} {CTX.get('cloud', 'Unknown')}")
    print(f"  {c(C.GRAY, 'Duration :')} {elapsed:.1f}s")
    print(f"  {c(C.GRAY, 'Phases   :')} {', '.join(str(p) for p in phases_run)}\n")

    print(f"  {c(C.BOLD, 'Findings Breakdown:')}")
    print(f"  {'─' * 40}")
    print(f"  🔴 CRITICAL : {c(C.RED,    str(counts['CRITICAL']).rjust(4))}")
    print(f"  🟠 HIGH     : {c(C.ORANGE, str(counts['HIGH']).rjust(4))}")
    print(f"  🟡 MEDIUM   : {c(C.YELLOW, str(counts['MEDIUM']).rjust(4))}")
    print(f"  🔵 LOW      : {c(C.BLUE,   str(counts['LOW']).rjust(4))}")
    print(f"  ✅ PASS     : {c(C.GREEN,  str(counts['PASS']).rjust(4))}")
    print(f"  ─────────────────────────────────────────")
    total_issues = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
    print(f"  {'Total Issues':12}: {c(C.BOLD+C.WHITE, str(total_issues).rjust(4))}\n")

    # Risk rating
    if counts["CRITICAL"] > 0:
        risk = c(C.RED+C.BOLD, "🔴 CRITICAL RISK — Immediate action required")
    elif counts["HIGH"] > 2:
        risk = c(C.ORANGE+C.BOLD, "🟠 HIGH RISK — Significant vulnerabilities present")
    elif counts["HIGH"] > 0 or counts["MEDIUM"] > 3:
        risk = c(C.YELLOW+C.BOLD, "🟡 MEDIUM RISK — Important gaps identified")
    else:
        risk = c(C.GREEN+C.BOLD, "🟢 LOW RISK — Good security posture")

    print(f"  Overall Risk: {risk}\n")

    # Critical and High findings summary
    critical_high = [f for f in FINDINGS if f["severity"] in ("CRITICAL", "HIGH")]
    if critical_high:
        print(f"  {c(C.BOLD, 'Critical & High Findings:')}")
        print(f"  {'─' * 64}")
        for i, f in enumerate(critical_high[:15], 1):
            sev_c = C.RED if f["severity"] == "CRITICAL" else C.ORANGE
            icon = "🔴" if f["severity"] == "CRITICAL" else "🟠"
            sev_str = f["severity"].ljust(8)
            print(f"  {icon} {c(sev_c, sev_str)} {c(C.BOLD, f['check'])}")
            if f.get("remediation"):
                print(f"       {c(C.GREEN, '⚑')} {c(C.DIM+C.GREEN, f['remediation'][:80])}")
        if len(critical_high) > 15:
            print(f"  {c(C.GRAY, f'  ... and {len(critical_high)-15} more')}")

    print(f"\n{c(C.CYAN, '═' * 68)}\n")

def save_report(filepath):
    """Save JSON report."""
    report = {
        "tool": "KubeXHunt",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "context": {
            "api": CTX.get("api"),
            "namespace": CTX.get("namespace"),
            "sa": CTX.get("sa_name"),
            "cloud": CTX.get("cloud"),
        },
        "findings": FINDINGS,
        "summary": {
            sev: len([f for f in FINDINGS if f["severity"] == sev])
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
        }
    }
    ext = filepath.rsplit(".", 1)[-1].lower()
    if ext == "json":
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
    else:
        with open(filepath, "w") as f:
            f.write(f"KubeXHunt Security Assessment Report\n")
            f.write(f"Generated: {report['timestamp']}\n")
            f.write(f"Namespace: {CTX.get('namespace')} | SA: {CTX.get('sa_name')} | Cloud: {CTX.get('cloud')}\n\n")
            for finding in FINDINGS:
                f.write(f"[{finding['severity']}] {finding['check']}\n")
                if finding.get("detail"):
                    f.write(f"  Detail: {finding['detail'][:200]}\n")
                if finding.get("remediation"):
                    f.write(f"  Fix: {finding['remediation'][:200]}\n")
                f.write("\n")
    print(f"\n  {c(C.GREEN, '✓')} Report saved: {filepath}")

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
PHASE_MAP = {
    0:  ("Setup & kubectl",          install_kubectl),
    1:  ("Pod & Container Recon",    phase_pod_recon),
    2:  ("Cloud Metadata & IAM",     phase_cloud_metadata),
    3:  ("RBAC & K8s API",           phase_rbac),
    4:  ("Network & Lateral Move",   lambda: phase_network(fast=False)),
    5:  ("Container Escape",         phase_escape),
    6:  ("Node Compromise",          phase_node),
    7:  ("Cluster Escalation",       phase_privesc),
    8:  ("Persistence",              phase_persistence),
    9:  ("Supply Chain & Admission", phase_supply_chain),
    10: ("EKS-Specific",             phase_eks),
    11: ("GKE-Specific",             phase_gke),
    12: ("Runtime Security",         phase_runtime),
    13: ("Secrets & Data",           phase_secrets),
    14: ("DoS & Resource Limits",    phase_dos),
}

def main():
    global NO_COLOR

    parser = argparse.ArgumentParser(
        description="KubeXHunt — Kubernetes Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 kubexhunt.py                          # Full assessment
  python3 kubexhunt.py --phase 2               # Only cloud metadata checks
  python3 kubexhunt.py --phase 3 4             # RBAC + network checks
  python3 kubexhunt.py --fast                  # Skip slow checks (port scan, DNS brute)
  python3 kubexhunt.py --output report.json    # Save JSON report
  python3 kubexhunt.py --no-color              # Plain output (for logging)
  python3 kubexhunt.py --kubectl-only          # Only install kubectl and exit
        """
    )
    parser.add_argument("--phase", nargs="+", type=int,
                        help="Run specific phase(s) only (0-14)")
    parser.add_argument("--fast", action="store_true",
                        help="Skip slow checks (port scanning, DNS brute force)")
    parser.add_argument("--output", metavar="FILE",
                        help="Save report to file (.json or .txt)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--kubectl-only", action="store_true",
                        help="Only install kubectl and exit")

    args = parser.parse_args()
    NO_COLOR = args.no_color

    banner()
    start = time.time()

    # Always run setup first
    install_kubectl()

    if args.kubectl_only:
        print(c(C.GREEN, "\n  ✓ kubectl installed. Run kubexhunt.py without --kubectl-only for full assessment."))
        return

    # Determine which phases to run
    if args.phase:
        phases_to_run = sorted(set(args.phase))
    else:
        phases_to_run = list(range(1, 15))

    # Update network phase for fast mode
    if args.fast and 4 in phases_to_run:
        PHASE_MAP[4] = ("Network & Lateral Move (fast)", lambda: phase_network(fast=True))

    # Run phases
    for phase_num in phases_to_run:
        if phase_num == 0:
            continue  # Already ran
        if phase_num not in PHASE_MAP:
            print(c(C.YELLOW, f"  ⚠ Unknown phase: {phase_num} — skipping"))
            continue
        try:
            PHASE_MAP[phase_num][1]()
        except KeyboardInterrupt:
            print(c(C.YELLOW, f"\n  ⚠ Phase {phase_num} interrupted by user"))
            break
        except Exception as e:
            print(c(C.RED, f"\n  ✗ Phase {phase_num} error: {e}"))

    elapsed = time.time() - start
    phases_run = [0] + phases_to_run
    print_final_report(phases_run, elapsed)

    if args.output:
        save_report(args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c(C.YELLOW, "\n\n  ⚠ Assessment interrupted by user"))
        if FINDINGS:
            elapsed = 0
            print_final_report([], 0)
        sys.exit(0)
