"""Package-native runtime facade for executing extracted phase logic."""

from __future__ import annotations

import base64
import binascii
import os
import random
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from kubexhunt.api.kube import (
    KubernetesApiClient,
    build_ssl_context,
    get_user_agent,
)
from kubexhunt.core.context import Context
from kubexhunt.core.logging import StructuredLogger, log_exception
from kubexhunt.core.state import ScanState
from kubexhunt.core.utils import safe_json_loads


class C:
    """ANSI colors used by the legacy-compatible terminal UI."""

    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


K8S_CVES = [
    {
        "id": "CVE-2018-1002105",
        "desc": "API server privilege escalation via proxy",
        "affected": "< 1.10.11 | 1.11.x < 1.11.5 | 1.12.x < 1.12.3",
        "severity": "CRITICAL",
        "fixed_minor": 13,
    },
    {
        "id": "CVE-2019-11247",
        "desc": "RBAC escalation via CRD subresources",
        "affected": "< 1.13.9 | 1.14.x < 1.14.5",
        "severity": "HIGH",
        "fixed_minor": 15,
    },
    {
        "id": "CVE-2019-9512",
        "desc": "HTTP/2 DoS (Ping Flood)",
        "affected": "< 1.14.0",
        "severity": "HIGH",
        "fixed_minor": 14,
    },
    {
        "id": "CVE-2020-8554",
        "desc": "Man-in-the-middle via ExternalIP service",
        "affected": "all versions (design issue, mitigation via admission)",
        "severity": "MEDIUM",
        "fixed_minor": None,
        "affected_all": True,
    },
    {
        "id": "CVE-2021-25741",
        "desc": "Symlink hostPath escape",
        "affected": "< 1.19.15 | 1.20.x < 1.20.11 | 1.21.x < 1.21.5",
        "severity": "HIGH",
        "fixed_minor": 22,
    },
    {
        "id": "CVE-2022-3294",
        "desc": "Node address bypass — API server SSRF",
        "affected": "< 1.25.4",
        "severity": "HIGH",
        "fixed_minor": 26,
    },
    {
        "id": "CVE-2023-2727",
        "desc": "SA token bypass via projected volumes",
        "affected": "< 1.24.14 | 1.25.x < 1.25.9",
        "severity": "HIGH",
        "fixed_minor": 26,
    },
    {
        "id": "CVE-2023-2728",
        "desc": "Bypassing mountable secrets policy",
        "affected": "< 1.24.14 | 1.25.x < 1.25.9",
        "severity": "HIGH",
        "fixed_minor": 26,
    },
    {
        "id": "CVE-2024-21626",
        "desc": "runc Leaky Vessels /proc/self/fd escape",
        "affected": "runc < 1.1.12 — containerd < 1.7.0 ships affected runc",
        "severity": "CRITICAL",
        "fixed_minor": None,
        "affected_all": False,
        "runc_check": True,
    },
]

KERNEL_CVES = [
    {
        "id": "CVE-2022-0847",
        "desc": "DirtyPipe — arbitrary file overwrite",
        "severity": "CRITICAL",
        "affected": "5.8 – 5.16.11",
        "min": (5, 8, 0),
        "max": (5, 16, 11),
    },
    {
        "id": "CVE-2016-5195",
        "desc": "DirtyCow — privilege escalation",
        "severity": "HIGH",
        "affected": "< 4.8.3",
        "min": (0, 0, 0),
        "max": (4, 8, 3),
    },
    {
        "id": "CVE-2021-3493",
        "desc": "OverlayFS privilege escalation (Ubuntu)",
        "severity": "HIGH",
        "affected": "5.4 – 5.11 (Ubuntu kernels only)",
        "min": (5, 4, 0),
        "max": (5, 11, 999),
        "ubuntu_only": True,
    },
    {
        "id": "CVE-2022-0185",
        "desc": "Heap overflow via CAP_SYS_ADMIN",
        "severity": "CRITICAL",
        "affected": "< 5.16.2",
        "min": (0, 0, 0),
        "max": (5, 16, 2),
    },
    {
        "id": "CVE-2023-0386",
        "desc": "OverlayFS privilege escalation",
        "severity": "HIGH",
        "affected": "< 6.2",
        "min": (0, 0, 0),
        "max": (6, 2, 0),
    },
]

MITRE_MAP = {
    "CRITICAL": ["T1611 Escape to Host", "T1552.007 Container API", "T1610 Deploy Container"],
    "HIGH": ["T1613 Container Discovery", "T1078.004 Cloud Accounts"],
    "MEDIUM": ["T1526 Cloud Service Discovery", "T1538 Cloud Service Dashboard"],
}

MITRE_KEYWORD_MAP = {
    "T1552.007": ["secret", "credential", "token", "password", "api key"],
    "T1611": ["escape", "breakout", "host path", "privileged", "hostpid", "hostipc", "hostnetwork"],
    "T1610": ["deploy container", "create pod", "pod creation"],
    "T1613": ["list pods", "list namespace", "cluster recon", "discovery"],
    "T1078.004": ["aws", "gke", "azure", "iam", "cloud account", "imds", "metadata"],
    "T1526": ["cloud service", "eks", "gke", "aks", "cloud discovery"],
    "T1098": ["clusterrolebinding", "rbac escalation", "privilege escalation", "bind clusterrole"],
    "T1053.007": ["cronjob", "scheduled", "cron"],
    "T1055": ["inject", "sidecar", "controller hijack"],
    "T1562.001": ["disable", "falco", "audit", "detection", "logging"],
    "T1040": ["net_raw", "sniff", "intercept", "network capture"],
    "T1557": ["dns poison", "net_admin", "mitm", "arp"],
    "T1133": ["external service", "nodeport", "loadbalancer", "ingress"],
    "T1190": ["cve", "vulnerability", "exploit", "rce", "injection"],
}

_ACTIVE_RUNTIME: RuntimeFacade | None = None


def set_active_runtime(runtime: RuntimeFacade | None) -> None:
    """Register the package-native runtime for correlation/output helpers."""

    global _ACTIVE_RUNTIME
    _ACTIVE_RUNTIME = runtime


def get_active_runtime() -> RuntimeFacade:
    """Return the current active package-native runtime."""

    if _ACTIVE_RUNTIME is None:
        raise RuntimeError("No active package runtime is registered")
    return _ACTIVE_RUNTIME


@dataclass
class RuntimeFacade:
    """Module-like runtime object used by extracted engines."""

    CTX: Context
    STATE: ScanState
    LOGGER: StructuredLogger
    no_color: bool = False

    def __post_init__(self) -> None:
        self.FINDINGS = self.STATE.findings
        self.ATTACK_GRAPH = self.STATE.attack_graph
        self.TOKEN_SCORES = self.STATE.token_scores
        self.CURRENT_PHASE = self.STATE.current_phase
        self.C = C
        self.os = os
        self.K8S_CVES = K8S_CVES
        self.KERNEL_CVES = KERNEL_CVES
        self.MITRE_MAP = MITRE_MAP
        self._MITRE_KEYWORD_MAP = MITRE_KEYWORD_MAP
        self.API_CLIENT = KubernetesApiClient(
            context=self.CTX,
            logger=self.LOGGER,
            jitter=self.jitter,
            timeout=int(self.CTX.get("timeout_seconds", 8) or 8),
            retries=int(self.CTX.get("retries", 0) or 0),
            verify_tls=bool(self.CTX.get("verify_tls", False)),
            rate_limit_per_second=float(self.CTX.get("rate_limit_per_second", 0.0) or 0.0),
        )

    def c(self, color: str, text: str) -> str:
        """Apply color if enabled."""

        if self.no_color:
            return str(text)
        return f"{color}{text}{C.RESET}"

    def _log_exception(self, message: str, exc: Exception) -> None:
        """Log exceptions through the shared structured logger."""

        log_exception(self.LOGGER, message, exc, self.CTX)

    def phase_header(self, num: str, name: str, desc: str) -> None:
        """Render a phase header matching legacy CLI output."""

        line = "─" * 68
        print(f"\n{self.c(C.CYAN, line)}")
        print(
            f"{self.c(C.BOLD + C.WHITE, f'  PHASE {num:>2}')} {self.c(C.CYAN, '│')} {self.c(C.BOLD + C.YELLOW, name)}"
        )
        print(f"  {self.c(C.GRAY, desc)}")
        print(f"{self.c(C.CYAN, line)}")

    def section(self, title: str) -> None:
        """Render a section heading."""

        print(f"\n  {self.c(C.BOLD + C.MAGENTA, '▸ ' + title)}")

    def info_line(self, msg: str) -> None:
        """Render an informational line."""

        print(f"  {self.c(C.CYAN, '→')} {self.c(C.DIM, str(msg)[:160])}")

    def finding(self, sev_level: str, check: str, detail: Any, remediation: str | None = None) -> None:
        """Render and record a finding."""

        icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ ", "PASS": "✅"}
        color_map = {
            "CRITICAL": C.RED,
            "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW,
            "LOW": C.BLUE,
            "INFO": C.CYAN,
            "PASS": C.GREEN,
        }
        icon = icon_map.get(sev_level, "  ")
        col = color_map.get(sev_level, C.WHITE)
        print(f"  {icon} {self.c(col, f'[{sev_level:8}]')} {self.c(C.BOLD, check)}")
        if detail:
            for line in str(detail).split("\n"):
                if line.strip():
                    print(f"  {self.c(C.GRAY, '│')}          {self.c(C.DIM, line.strip()[:140])}")
        if remediation and sev_level not in ("PASS", "INFO"):
            print(f"  {self.c(C.GRAY, '│')} {self.c(C.GREEN, '⚑ Fix:')} {self.c(C.DIM + C.GREEN, remediation[:140])}")
        self.STATE.findings.append(
            {
                "severity": sev_level,
                "check": check,
                "detail": str(detail),
                "remediation": remediation or "",
                "phase": self.STATE.current_phase,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def jitter(self) -> None:
        """Apply timing jitter in stealth mode."""

        level = self.CTX.get("stealth", 0)
        if level >= 1:
            time.sleep(random.uniform(0.3, 2.0))
        if level >= 2:
            time.sleep(random.uniform(0.5, 1.5))

    def _ssl_ctx(self):
        """Return TLS context used by HTTP helpers."""

        return build_ssl_context()

    def _get_ua(self) -> str:
        """Return the configured user agent."""

        return get_user_agent(self.CTX)

    def k8s_api(self, path: str, method: str = "GET", data: Any = None, token: str | None = None, timeout: int = 8):
        """Call the Kubernetes API."""

        response = self.API_CLIENT.request_k8s(path, method=method, data=data, token=token, timeout=timeout)
        return response.status_code, response.data

    def http_get(self, url: str, headers: dict[str, str] | None = None, timeout: int = 5):
        """Issue a simple HTTP GET."""

        response = self.API_CLIENT.request_text(url, headers=headers, timeout=timeout)
        return response.status_code, response.raw_text or ""

    def http_get_noauth(self, path: str, timeout: int = 5):
        """Call Kubernetes anonymously."""

        response = self.API_CLIENT.request_k8s(path, timeout=timeout, anonymous=True)
        return response.status_code, response.data

    def tcp_open(self, host: str, port: int, timeout: float = 1.5) -> bool:
        """Return whether a TCP port is reachable."""

        try:
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            sock.close()
            return True
        except (OSError, ValueError):
            return False

    def dns_resolve(self, name: str) -> str | None:
        """Resolve an A record."""

        try:
            return socket.gethostbyname(name)
        except (socket.gaierror, OSError):
            return None

    def dns_srv(self, name: str) -> list[str]:
        """Attempt SRV-like name resolution using socket fallback."""

        try:
            results = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
            return [str(result[4][0]) for result in results]
        except (socket.gaierror, OSError):
            return []

    def run_cmd(self, cmd: str, timeout: int = 10):
        """Run a shell command with timeout protection."""

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as exc:
            return -1, "", str(exc)

    def file_read(self, path: str, lines: int | None = None) -> str | None:
        """Read a file with safe fallbacks."""

        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                if lines:
                    return "".join(handle.readline() for _ in range(lines))
                return handle.read()
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
            return None

    def decode_b64(self, value: str) -> str:
        """Decode base64 safely."""

        try:
            return base64.b64decode(value).decode(errors="replace")
        except (ValueError, TypeError, binascii.Error, UnicodeDecodeError, NameError):
            return str(value)

    def decode_jwt(self, token: str) -> dict[str, Any]:
        """Decode a JWT payload safely."""

        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload = parts[1] + "=" * (-len(parts[1]) % 4)
                decoded = base64.urlsafe_b64decode(payload.encode())
                _, parsed = safe_json_loads(decoded, 0, self.CTX, self.LOGGER)
                return parsed or {}
        except (ValueError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
            self._log_exception("JWT decode failed", exc)
        return {}

    def truncate(self, value: Any, max_len: int = 120) -> str:
        """Truncate multiline strings for report display."""

        text = str(value).replace("\n", " ")
        return text[:max_len] + "..." if len(text) > max_len else text

    def add_attack_edge(self, source: str, target: str, relation: str, severity: str = "HIGH") -> None:
        """Append an attack graph edge if it is new."""

        edge = {"from": source, "to": target, "via": relation, "severity": severity}
        if edge not in self.STATE.attack_graph:
            self.STATE.attack_graph.append(edge)

    def score_token(self, token: str, label: str = "current") -> dict[str, Any]:
        """Score a token using SSAR plus fallback probes."""

        namespace = self.CTX.namespace or "default"
        checks = [
            ({"verb": "list", "resource": "secrets", "namespace": namespace}, 20, "namespace-secrets:list"),
            ({"verb": "list", "resource": "secrets"}, 35, "cluster-secrets:list"),
            (
                {"verb": "create", "resource": "serviceaccounts/token", "namespace": namespace},
                20,
                "tokenrequest:create",
            ),
            (
                {"verb": "list", "group": "rbac.authorization.k8s.io", "resource": "clusterrolebindings"},
                25,
                "clusterrolebindings:list",
            ),
            ({"verb": "impersonate", "group": "", "resource": "users"}, 30, "impersonation"),
            (
                {"verb": "create", "group": "rbac.authorization.k8s.io", "resource": "clusterrolebindings"},
                35,
                "clusterrolebinding:create",
            ),
        ]
        capabilities: list[str] = []
        score = 0

        def ssar_allowed(spec: dict[str, Any]) -> bool | None:
            payload = {
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectAccessReview",
                "spec": {
                    "resourceAttributes": {
                        "namespace": spec.get("namespace"),
                        "verb": spec["verb"],
                        "group": spec.get("group", ""),
                        "resource": spec["resource"],
                    }
                },
            }
            code, resp = self.k8s_api(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                method="POST",
                data=payload,
                token=token,
                timeout=5,
            )
            if code == 201 and resp:
                return bool(resp.get("status", {}).get("allowed", False))
            return None

        for spec, points, capability in checks:
            allowed = ssar_allowed(spec)
            if allowed is None:
                fallback = "/api/v1/namespaces"
                if capability.startswith("cluster-secrets"):
                    fallback = "/api/v1/secrets"
                elif capability.startswith("namespace-secrets"):
                    fallback = f"/api/v1/namespaces/{namespace}/secrets"
                elif capability.startswith("clusterrolebindings"):
                    fallback = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
                elif capability.startswith("tokenrequest"):
                    fallback = (
                        f"/api/v1/namespaces/{namespace}/serviceaccounts/{self.CTX.get('sa_name', 'default')}/token"
                    )
                code, _ = self.k8s_api(fallback, token=token, timeout=4)
                allowed = code in (200, 201)
            if allowed:
                score += points
                capabilities.append(capability)

        score = min(score, 100)
        risk_level = "LOW"
        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 55:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        result = {"label": label, "score": score, "capabilities": capabilities, "risk_level": risk_level}
        self.STATE.token_scores.append(result)
        return result

    def print_token_ranking(self) -> None:
        """Print ranked token privilege scores."""

        if not self.STATE.token_scores:
            return
        self.section("Token Privilege Ranking")
        ranked = sorted(self.STATE.token_scores, key=lambda item: item["score"], reverse=True)
        for token in ranked:
            bar = "█" * (token["score"] // 10) + "░" * (10 - token["score"] // 10)
            color = C.RED if token["score"] >= 70 else C.ORANGE if token["score"] >= 40 else C.GREEN
            score_label = f"[{token['score']:3}/100]"
            print(f"  {self.c(color, score_label)} {bar} {self.c(C.BOLD, token['label'])}")
            if token["capabilities"]:
                print(f"           {self.c(C.DIM, ' | '.join(token['capabilities'][:4]))}")
        best = ranked[0]
        self.info_line(f"Best pivot token: {best['label']} (score {best['score']}/100)")

    def build_persistence_options(self) -> list[dict[str, Any]]:
        """Return persistence techniques without mutating by default."""

        namespace = self.CTX.namespace or "default"
        return [
            {
                "name": "malicious-serviceaccount",
                "requires_mutation": True,
                "description": "Create a backdoor service account and bind it later.",
                "manifest": {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "kubexhunt-backdoor", "namespace": namespace},
                },
            },
            {
                "name": "clusterrolebinding-backdoor",
                "requires_mutation": True,
                "description": "Bind cluster-admin to a controlled service account.",
                "manifest": {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "kubexhunt-backdoor-binding"},
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": "cluster-admin",
                    },
                    "subjects": [{"kind": "ServiceAccount", "name": "kubexhunt-backdoor", "namespace": namespace}],
                },
            },
            {
                "name": "cronjob-persistence",
                "requires_mutation": True,
                "description": "Install a recurring CronJob foothold in the current namespace.",
                "manifest": {
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "metadata": {"name": "kubexhunt-backdoor-cron", "namespace": namespace},
                    "spec": {"schedule": "*/15 * * * *"},
                },
            },
        ]

    def _parse_k8s_minor(self, git_ver: str) -> int:
        """Parse Kubernetes minor version from gitVersion."""

        try:
            clean = git_ver.lstrip("v").split("-")[0]
            parts = clean.split(".")
            return int(parts[1]) if len(parts) >= 2 else 0
        except (AttributeError, IndexError, TypeError, ValueError):
            return 0

    def _parse_kernel_ver(self, uname_r: str) -> tuple[int, int, int]:
        """Parse kernel version tuple."""

        try:
            clean = uname_r.split("-")[0]
            parts = clean.split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return major, minor, patch
        except (AttributeError, IndexError, TypeError, ValueError):
            return 0, 0, 0

    def _kernel_ver_in_range(
        self, running: tuple[int, int, int], kve_min: tuple[int, int, int], kve_max: tuple[int, int, int]
    ) -> bool:
        """Return whether running kernel version is within range."""

        return kve_min <= running <= kve_max

    def _check_runc_cve(self, cve: dict[str, Any], git_ver: str) -> None:
        """Check runc-specific CVE applicability."""

        _, out, _ = self.run_cmd("runc --version 2>/dev/null", timeout=3)
        if not out:
            _, out, _ = self.run_cmd("ctr version 2>/dev/null | grep -i runc", timeout=3)
        if out and "1.1." in out:
            match = next((part for part in out.split() if part.startswith("1.1.")), "")
            try:
                patch = int(match.split(".")[2])
                if patch < 12:
                    self.finding(
                        cve["severity"],
                        f"{cve['id']}: {cve['desc']}",
                        f"Affected: {cve['affected']}\nCluster: {git_ver}\nrunc: {match}",
                        "Upgrade runc to >= 1.1.12",
                    )
                    return
            except (IndexError, ValueError):
                pass

    def _check_api_server_public(self) -> None:
        """Check whether the API server resolves to a public IP."""

        api = self.CTX.get("api", "")
        host = api.replace("https://", "").replace("http://", "").split(":")[0]
        resolved = self.dns_resolve(host)
        if not resolved:
            self.finding("INFO", "API server public exposure unknown", f"Could not resolve {host}")
            return
        octets = resolved.split(".")
        is_private = (
            resolved.startswith("10.")
            or resolved.startswith("192.168.")
            or (len(octets) > 1 and octets[0] == "172" and 16 <= int(octets[1]) <= 31)
        )
        if is_private or host.endswith(".svc"):
            self.finding("PASS", "API server is on a private IP address", f"API: {api} → {host} (private/internal)")
        else:
            self.finding(
                "HIGH",
                "API server appears publicly reachable",
                f"API: {api} → {resolved}",
                "Restrict API server exposure to private endpoints",
            )

    def _check_node_public_ips(self) -> None:
        """Check whether worker nodes resolve to public IPs."""

        node_ips = self.CTX.get("node_ips", [])
        if not node_ips:
            self.finding("INFO", "Cannot check node IPs — node list not accessible", "")
            return
        public = []
        for ip in node_ips:
            octets = ip.split(".")
            is_private = (
                ip.startswith("10.")
                or ip.startswith("192.168.")
                or (len(octets) > 1 and octets[0] == "172" and 16 <= int(octets[1]) <= 31)
            )
            if not is_private and not ip.startswith("127."):
                public.append(ip)
        if public:
            self.finding(
                "HIGH",
                f"Worker nodes with public IPs: {len(public)}",
                "\n".join(public[:10]),
                "Use private nodes or restrict node ingress",
            )
        else:
            self.finding("PASS", "Worker nodes are private/internal", ", ".join(node_ips[:6]))

    def _enumerate_argocd(self) -> None:
        """Enumerate ArgoCD-related Kubernetes resources when reachable."""

        namespace = "argocd"
        code, resp = self.k8s_api(f"/api/v1/namespaces/{namespace}/secrets")
        if code == 200 and resp:
            secrets = [item.get("metadata", {}).get("name", "") for item in resp.get("items", [])]
            self.finding(
                "HIGH",
                f"ArgoCD secrets readable: {len(secrets)}",
                "\n".join(secrets[:8]),
                "Restrict ArgoCD secret access",
            )


def new_runtime(
    *, no_color: bool = False, debug: bool = False, verbose: bool = False, json_logs: bool = False
) -> RuntimeFacade:
    """Create and register a new package-native runtime."""

    runtime = RuntimeFacade(
        CTX=Context(debug=debug, verbose=verbose),
        STATE=ScanState(),
        LOGGER=StructuredLogger(verbose=verbose, debug=debug, json_logs=json_logs),
        no_color=no_color,
    )
    set_active_runtime(runtime)
    return runtime
