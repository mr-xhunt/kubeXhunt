"""Setup and environment detection phase."""

from __future__ import annotations

import os
import urllib.request
from datetime import datetime


def detect_cloud(runtime) -> str:
    """Detect cloud provider with metadata and environment fallbacks."""

    aws_markers = [
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AWS_EXECUTION_ENV",
        "EKS_CLUSTER_NAME",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ]
    if any(os.environ.get(marker) for marker in aws_markers):
        return "AWS"

    code, _ = runtime.http_get("http://169.254.169.254/latest/meta-data/", timeout=3)
    if code in (200, 401):
        return "AWS"

    try:
        request = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            data=b"",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600", "User-Agent": runtime._get_ua()},
            method="PUT",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status == 200:
                return "AWS"
    except Exception:
        pass

    code, _ = runtime.http_get("http://169.254.169.254/latest/dynamic/instance-identity/document", timeout=3)
    if code in (200, 401, 403):
        return "AWS"

    code, _ = runtime.http_get("http://metadata.google.internal/", headers={"Metadata-Flavor": "Google"}, timeout=3)
    if code in (200, 403):
        return "GKE"

    code, _ = runtime.http_get(
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        headers={"Metadata-Flavor": "Google"},
        timeout=3,
    )
    if code in (200, 403):
        return "GKE"

    code, _ = runtime.http_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"},
        timeout=3,
    )
    if code in (200, 400, 403):
        return "Azure"

    return "Unknown"


def run_phase_setup(runtime) -> None:
    """Execute phase 0 setup, credential gathering, and environment detection."""

    runtime.CURRENT_PHASE = "0"
    runtime.STATE.current_phase = "0"
    runtime.phase_header(
        "0", "Setup & kubectl Installation", "Detecting environment, installing kubectl, gathering credentials"
    )

    runtime.section("kubectl Detection")
    rc, out, _ = runtime.run_cmd("kubectl version --client 2>/dev/null")
    if rc == 0 and out:
        runtime.info_line(f"kubectl present: {out.split(chr(10))[0]}")
        runtime.CTX["kubectl"] = True
    else:
        runtime.info_line("kubectl not found — searching for alternatives...")
        kubectl_found = False
        search_paths = [
            "/usr/local/bin/kubectl",
            "/usr/bin/kubectl",
            "/bin/kubectl",
            "/host/usr/local/bin/kubectl",
            "/host/usr/bin/kubectl",
            "/tmp/kubectl",
        ]
        for path in search_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                rc_k, out_k, _ = runtime.run_cmd(f"{path} version --client 2>/dev/null")
                if rc_k == 0:
                    runtime.run_cmd(
                        f"ln -sf {path} /usr/local/bin/kubectl 2>/dev/null || cp {path} /tmp/kubectl 2>/dev/null"
                    )
                    runtime.info_line(f"kubectl found at {path}")
                    runtime.CTX["kubectl"] = True
                    kubectl_found = True
                    runtime.finding("PASS", "kubectl found on host filesystem", f"Path: {path}")
                    break

        if not kubectl_found:
            runtime.info_line("Attempting kubectl download...")
            _, arch, _ = runtime.run_cmd("uname -m")
            goarch = "arm64" if "aarch64" in arch or "arm64" in arch else "amd64"
            _, ver, _ = runtime.run_cmd(
                "curl -sL --max-time 5 https://dl.k8s.io/release/stable.txt 2>/dev/null || echo v1.29.0"
            )
            version = ver.strip() or "v1.29.0"
            url = f"https://dl.k8s.io/release/{version}/bin/linux/{goarch}/kubectl"
            for cmd in [
                f"curl -sLf --max-time 15 -o /tmp/kubectl {url} 2>/dev/null || wget -q --timeout=15 -O /tmp/kubectl {url} 2>/dev/null",
                "chmod +x /tmp/kubectl",
                "ln -sf /tmp/kubectl /usr/local/bin/kubectl 2>/dev/null",
            ]:
                runtime.run_cmd(cmd)
            rc2, out2, _ = runtime.run_cmd("/tmp/kubectl version --client 2>/dev/null")
            if rc2 == 0:
                runtime.CTX["kubectl"] = True
                runtime.finding("PASS", "kubectl downloaded successfully", out2.split("\n")[0] if out2 else "")
            else:
                runtime.CTX["kubectl"] = False
                runtime.finding(
                    "INFO",
                    "kubectl not available — using Python urllib for all API calls",
                    "All K8s API checks will use direct HTTP — kubectl-specific checks skipped",
                )

    runtime.section("Credential Gathering")
    token = runtime.file_read("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if token:
        token = token.strip()
        runtime.CTX["token"] = token
        jwt = runtime.decode_jwt(token)
        namespace = jwt.get("kubernetes.io/serviceaccount/namespace", "")
        sa_name = jwt.get("kubernetes.io/serviceaccount/service-account.name", "")
        if not namespace or not sa_name:
            subject = jwt.get("sub", "")
            if subject.startswith("system:serviceaccount:"):
                parts = subject.split(":")
                if len(parts) == 4:
                    namespace = parts[2]
                    sa_name = parts[3]
        if not namespace:
            namespace = (runtime.file_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace") or "").strip()
        exp = jwt.get("exp", 0)
        aud = jwt.get("aud", [])
        runtime.finding(
            "INFO",
            "SA token present",
            f"Namespace: {namespace} | SA: {sa_name} | Expires: {datetime.fromtimestamp(exp) if exp else 'never'}\nAudience: {aud}",
        )
        runtime.CTX["namespace"] = namespace
        runtime.CTX["sa_name"] = sa_name
        if not aud or aud == [""] or (isinstance(aud, list) and len(aud) == 0):
            runtime.finding(
                "HIGH",
                "SA token has no audience claim — token replay risk",
                "Token can potentially be replayed against OIDC or external services",
                "Use bound service account tokens with specific audience",
            )
        runtime.score_token(token, f"{namespace}/{sa_name}")
    else:
        runtime.finding("LOW", "No SA token mounted", "automountServiceAccountToken: false or no SA")
        runtime.CTX["token"] = ""
        runtime.CTX["namespace"] = os.environ.get("POD_NAMESPACE", "default")

    ns_file = runtime.file_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    if ns_file and not runtime.CTX.get("namespace"):
        runtime.CTX["namespace"] = ns_file.strip()
    if not runtime.CTX.get("namespace"):
        runtime.CTX["namespace"] = "default"

    ca_cert = runtime.file_read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if ca_cert:
        runtime.CTX["ca_cert"] = ca_cert
        runtime.finding(
            "INFO",
            "CA cert mounted",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt — usable for API MITM awareness",
        )

    runtime.section("API Server")
    api_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    runtime.CTX["api"] = f"https://{api_host}:{api_port}"
    runtime.CTX.api_server = runtime.CTX["api"]
    runtime.info_line(f"API server: {runtime.CTX['api']}")

    code, _ = runtime.k8s_api(f"/api/v1/namespaces/{runtime.CTX['namespace']}")
    if code == 200:
        runtime.finding("PASS", "Kubernetes API reachable", runtime.CTX["api"])
        runtime.CTX["api_ok"] = True
    elif code == 403:
        runtime.finding("INFO", "API reachable — SA has limited RBAC access", f"HTTP {code}")
        runtime.CTX["api_ok"] = True
    elif code == 401:
        runtime.finding(
            "INFO",
            "API reachable — no SA token or token rejected (HTTP 401)",
            f"{runtime.CTX['api']}\nMost API-dependent checks will be skipped",
        )
        runtime.CTX["api_ok"] = False
    else:
        runtime.finding("INFO", f"API unreachable (HTTP {code})", runtime.CTX["api"])
        runtime.CTX["api_ok"] = False

    runtime.section("kubectl In-Cluster Config")
    if runtime.CTX.get("kubectl") and runtime.CTX.get("token") and runtime.CTX.get("api"):
        rc_cfg, cfg_out, _ = runtime.run_cmd("kubectl config current-context 2>/dev/null", timeout=3)
        if rc_cfg != 0 or not cfg_out.strip():
            api = runtime.CTX["api"]
            token = runtime.CTX["token"]
            ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            sa_name = runtime.CTX.get("sa_name", "sa")
            namespace = runtime.CTX.get("namespace", "default")
            cmds = [
                f"kubectl config set-cluster in-cluster --server={api} --certificate-authority={ca_path} 2>/dev/null",
                f"kubectl config set-credentials {sa_name} --token={token} 2>/dev/null",
                f"kubectl config set-context default --cluster=in-cluster --user={sa_name} --namespace={namespace} 2>/dev/null",
                "kubectl config use-context default 2>/dev/null",
            ]
            for cmd in cmds:
                runtime.run_cmd(cmd, timeout=5)
            rc_v, out_v, _ = runtime.run_cmd(
                f"kubectl get pods -n {namespace} --request-timeout=5s 2>/dev/null", timeout=8
            )
            if rc_v == 0 or "forbidden" in (out_v or "").lower() or "Error from server" in (out_v or ""):
                runtime.info_line("kubectl configured with in-cluster SA token")
            else:
                runtime.info_line("kubectl configured — limited by SA RBAC permissions")
        else:
            runtime.info_line(f"kubectl already has context: {cfg_out.strip()}")

    runtime.section("Cloud Provider Detection")
    cloud = detect_cloud(runtime)
    runtime.CTX["cloud"] = cloud
    runtime.finding("INFO", f"Cloud provider: {cloud}", "Provider-specific checks will activate in later phases")
    runtime.info_line(
        f"Namespace: {runtime.CTX['namespace']} | SA: {runtime.CTX.get('sa_name', 'unknown')} | Cloud: {cloud}"
    )
