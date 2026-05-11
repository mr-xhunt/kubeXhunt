"""Network engine."""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def run_phase_network(legacy, fast: bool = False) -> None:
    """Execute the extracted network recon and lateral movement phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "4"
    legacy.phase_header(
        "4",
        "Network Recon & Lateral Movement",
        "Service discovery, DNS SRV, port scan, etcd, NodePort, NetworkPolicy, sniffing",
    )

    legacy.section("Service Discovery via Env Vars")
    svc_env = {}
    for key, value in legacy.os.environ.items():
        if key.endswith("_SERVICE_HOST"):
            svc_name = key[: -len("_SERVICE_HOST")].lower().replace("_", "-")
            port_key = key[: -len("_SERVICE_HOST")] + "_SERVICE_PORT"
            port = legacy.os.environ.get(port_key, "?")
            svc_env[svc_name] = (value, port)
    if svc_env:
        legacy.finding(
            "INFO",
            f"Auto-injected {len(svc_env)} service endpoint(s)",
            "\n".join([f"{name}: {host}:{port}" for name, (host, port) in list(svc_env.items())[:8]]),
        )
        legacy.CTX["known_services"] = svc_env

    legacy.section("NetworkPolicy Enumeration")
    code_np, resp_np = legacy.k8s_api("/apis/networking.k8s.io/v1/networkpolicies")
    if code_np == 200 and resp_np:
        policies = resp_np.get("items", [])
        if not policies:
            legacy.finding(
                "HIGH",
                "Zero NetworkPolicies exist cluster-wide",
                "All pods can freely communicate with all other pods",
                "Apply default-deny NetworkPolicy to all namespaces",
            )
            legacy.add_attack_edge(
                "Compromised Pod",
                "Any Pod",
                "No NetworkPolicy → unrestricted lateral movement",
                "HIGH",
            )
        else:
            namespaces_covered = {policy.get("metadata", {}).get("namespace", "") for policy in policies}
            legacy.finding(
                "INFO",
                f"{len(policies)} NetworkPolicies across {len(namespaces_covered)} namespace(s)",
                f"Namespaces with policies: {', '.join(list(namespaces_covered)[:8])}",
            )
    else:
        legacy.finding("INFO", f"Cannot list NetworkPolicies (HTTP {code_np})", "")

    legacy.section("NodePort & LoadBalancer Services")
    code_svc, resp_svc = legacy.k8s_api("/api/v1/services")
    if code_svc == 200 and resp_svc:
        external = []
        for svc in resp_svc.get("items", []):
            service_type = svc.get("spec", {}).get("type", "")
            if service_type in ("NodePort", "LoadBalancer"):
                name = svc["metadata"]["name"]
                namespace = svc["metadata"]["namespace"]
                ports = svc.get("spec", {}).get("ports", [])
                ingress = [
                    item.get("ip", "") or item.get("hostname", "")
                    for item in svc.get("status", {}).get("loadBalancer", {}).get("ingress", [])
                ]
                external.append(f"{namespace}/{name} ({service_type}) ports:{ports} LB:{ingress}")
        if external:
            legacy.finding(
                "MEDIUM",
                f"{len(external)} externally exposed service(s)",
                "\n".join(external[:8]),
                "Review NodePort/LoadBalancer services — apply NetworkPolicy egress rules",
            )

    legacy.section("DNS Enumeration")
    dns_targets = [
        "payment-api",
        "payment-api.payments",
        "payments",
        "billing",
        "auth",
        "api",
        "backend",
        "database",
        "db",
        "redis",
        "postgres",
        "mysql",
        "mongodb",
        "vault",
        "consul",
        "admin",
        "internal",
        "checkout",
        "grafana",
        "prometheus",
        "kibana",
        "elasticsearch",
        "rabbitmq",
        "kafka",
        "zookeeper",
        "jenkins",
        "gitlab",
        "harbor",
    ]
    dns_found = {}
    if not fast:

        def _resolve(name: str):
            ip = legacy.dns_resolve(name)
            return name, ip

        with ThreadPoolExecutor(max_workers=20) as executor:
            for name, ip in executor.map(_resolve, dns_targets):
                if ip:
                    dns_found[name] = ip
        if dns_found:
            legacy.finding(
                "INFO",
                f"DNS resolved {len(dns_found)} internal service(s)",
                "\n".join([f"{name} → {ip}" for name, ip in list(dns_found.items())[:10]]),
            )
            legacy.CTX["dns_found"] = dns_found

        legacy.section("DNS SRV Records")
        srv_targets = [
            "_http._tcp.kubernetes.default.svc.cluster.local",
            "_https._tcp.kubernetes.default.svc.cluster.local",
        ]
        for name in dns_found:
            srv_targets.append(f"_http._tcp.{name}.svc.cluster.local")
        srv_found = {}
        for srv in srv_targets[:10]:
            ips = legacy.dns_srv(srv)
            if ips:
                srv_found[srv] = ips
        if srv_found:
            legacy.finding(
                "INFO",
                f"SRV records resolved: {len(srv_found)} hidden services",
                "\n".join([f"{key} → {value}" for key, value in list(srv_found.items())[:5]]),
                "Review SRV-exposed services for unintended exposure",
            )

    legacy.section("Internal API Probe (Lateral Movement)")
    targets = []
    for name, (ip, port) in svc_env.items():
        targets.append((f"http://{ip}:{port}", name))
    for name, ip in (legacy.CTX.get("dns_found") or {}).items():
        for endpoint in ["/", "/api/v1", "/health", "/metrics", "/admin", "/transactions", "/customers"]:
            targets.append((f"http://{ip}:8080{endpoint}", f"{name}{endpoint}"))

    lateral_found = []

    def _probe(url_label):
        url, label = url_label
        code, body = legacy.http_get(url, timeout=3)
        return url, label, code, (body or "")[:400]

    if targets:
        with ThreadPoolExecutor(max_workers=10) as executor:
            for url, _label, code, body in executor.map(_probe, targets[:25]):
                if code == 200:
                    lateral_found.append((url, code, body))

    extra_targets = []
    for url, _code, body in lateral_found:
        try:
            resp_json = json.loads(body)
            advertised = []
            if isinstance(resp_json, dict):
                for key in ["endpoints", "paths", "routes", "links", "urls"]:
                    value = resp_json.get(key, [])
                    if isinstance(value, list):
                        advertised.extend([str(item) for item in value if str(item).startswith("/")])
                if "paths" in resp_json and isinstance(resp_json["paths"], dict):
                    advertised.extend(list(resp_json["paths"].keys())[:20])
            parsed = url.split("//", 1)
            if len(parsed) == 2:
                host_part = parsed[1].split("/")[0]
                base_url = f"{parsed[0]}//{host_part}"
            else:
                base_url = url
            for endpoint in advertised[:15]:
                full = f"{base_url}{endpoint}"
                if full not in [target[0] for target in targets] and full not in [
                    found_url for found_url, _, _ in lateral_found
                ]:
                    extra_targets.append((full, f"advertised:{endpoint}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    if extra_targets:
        legacy.info_line(f"Recursively probing {len(extra_targets)} advertised endpoint(s)...")
        with ThreadPoolExecutor(max_workers=8) as executor:
            for url, _label, code, body in executor.map(_probe, extra_targets[:20]):
                if code == 200:
                    lateral_found.append((url, code, body))

    if lateral_found:
        for url, code, body in lateral_found:
            sensitive = any(
                keyword in body.lower()
                for keyword in [
                    "password",
                    "secret",
                    "token",
                    "card",
                    "email",
                    "customer",
                    "transaction",
                    "credit",
                    "ssn",
                    "dob",
                    "account",
                ]
            )
            legacy.finding(
                "CRITICAL" if sensitive else "HIGH",
                f"Internal service reachable: {url}",
                f"HTTP {code} | {legacy.truncate(body, 150)}"
                + ("\n⚠ Sensitive keywords in response!" if sensitive else ""),
                "Apply Istio mTLS + AuthorizationPolicy or NetworkPolicy",
            )
            if sensitive:
                legacy.add_attack_edge("Compromised Pod", "Internal Data", f"HTTP lateral → {url}", "CRITICAL")
    else:
        istio_active = "istio" in (legacy.CTX.get("runtime_tools") or [])
        if istio_active:
            legacy.finding(
                "PASS",
                "No internal services reachable — Istio mTLS + AuthorizationPolicy enforced",
                "All HTTP probes blocked\nIstio PeerAuthentication and AuthorizationPolicy active",
            )
        else:
            legacy.finding(
                "PASS", "No unexpected internal services reachable", "mTLS or NetworkPolicy restricting traffic"
            )

    legacy.section("Port Scan — Internal Services")
    if not fast and legacy.CTX.get("dns_found"):
        ports = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9200, 27017, 9092, 2379, 2380]
        open_ports = []

        def _scan(host_port):
            host, port = host_port
            return (host, port) if legacy.tcp_open(host, port, 1) else None

        scan_targets = [(ip, port) for _, ip in list(legacy.CTX["dns_found"].items())[:5] for port in ports]
        with ThreadPoolExecutor(max_workers=30) as executor:
            for result in executor.map(_scan, scan_targets):
                if result:
                    open_ports.append(result)
        if open_ports:
            istio_present = "istio" in (legacy.CTX.get("runtime_tools") or [])
            if istio_present:
                legacy.finding(
                    "INFO",
                    f"Open TCP ports detected ({len(open_ports)}) — Istio mTLS may restrict HTTP",
                    "\n".join([f"{host}:{port}" for host, port in open_ports[:12]])
                    + "\nIstio sidecar intercepts all traffic — verify AuthorizationPolicy blocks HTTP access",
                    "Verify with: kubectl get authorizationpolicies -A",
                )
            else:
                legacy.finding(
                    "MEDIUM",
                    f"Open ports on internal services: {len(open_ports)}",
                    "\n".join([f"{host}:{port}" for host, port in open_ports[:12]]),
                    "Apply NetworkPolicy or Istio AuthorizationPolicy to restrict inter-pod traffic",
                )
            legacy.CTX["open_ports"] = open_ports

    legacy.section("Service Mesh Detection")
    sidecar_found = []
    mesh_type = ""

    for pod in legacy.CTX.get("all_pods") or []:
        for container in pod.get("spec", {}).get("containers", []):
            name = container.get("name", "").lower()
            if any(sidecar in name for sidecar in ["istio-proxy", "linkerd-proxy", "envoy", "cilium-agent"]):
                sidecar_found.append(name)

    if "istio" in legacy.CTX.get("runtime_tools", []):
        mesh_type = "Istio"
    elif not mesh_type:
        mesh_crd_checks = [
            ("/apis/networking.istio.io/v1alpha3/peerauthentications", "Istio"),
            ("/apis/networking.istio.io/v1beta1/peerauthentications", "Istio"),
            ("/apis/security.istio.io/v1/authorizationpolicies", "Istio"),
            ("/apis/security.istio.io/v1beta1/authorizationpolicies", "Istio"),
            ("/apis/networking.istio.io/v1alpha3/virtualservices", "Istio"),
            ("/apis/linkerd.io/v1alpha2/serviceprofiles", "Linkerd"),
        ]
        for path, mesh_candidate in mesh_crd_checks:
            code_m, _ = legacy.k8s_api(path, timeout=3)
            if code_m in (200, 403):
                mesh_type = mesh_candidate
                break

    if sidecar_found:
        legacy.finding(
            "INFO",
            "Service mesh sidecars detected in pod specs",
            f"Sidecars: {', '.join(sorted(set(sidecar_found))[:5])}\n"
            "Attack vectors: sidecar injection, mTLS bypass, policy misconfiguration",
            "Review mesh AuthorizationPolicies for wildcard rules",
        )
    elif mesh_type:
        legacy.finding(
            "INFO",
            f"{mesh_type} service mesh detected via CRDs",
            "Mesh CRDs present — mTLS and AuthorizationPolicies may be active\n"
            "This explains blocked lateral movement to payment-api",
            "Verify: kubectl get peerauthentication -A | kubectl get authorizationpolicies -A",
        )
        legacy.CTX["runtime_tools"] = list(set(legacy.CTX.get("runtime_tools", []) + ["istio"]))
    else:
        legacy.finding("INFO", "No service mesh detected", "Pod-to-pod traffic likely unencrypted")

    if mesh_type == "Istio" or "istio" in (legacy.CTX.get("runtime_tools") or []):
        for pa_path in [
            "/apis/security.istio.io/v1/peerauthentications",
            "/apis/networking.istio.io/v1beta1/peerauthentications",
            "/apis/networking.istio.io/v1alpha3/peerauthentications",
        ]:
            code_pa, resp_pa = legacy.k8s_api(pa_path, timeout=4)
            if code_pa == 200 and resp_pa:
                peer_authentications = resp_pa.get("items", [])
                strict = [
                    policy
                    for policy in peer_authentications
                    if policy.get("spec", {}).get("mtls", {}).get("mode") == "STRICT"
                ]
                if strict:
                    legacy.finding(
                        "PASS",
                        f"Istio PeerAuthentication STRICT mTLS: {len(strict)} policy/ies",
                        "\n".join(
                            [f"{policy['metadata']['namespace']}/{policy['metadata']['name']}" for policy in strict[:5]]
                        ),
                    )
                elif peer_authentications:
                    legacy.finding(
                        "MEDIUM",
                        "Istio PeerAuthentication present but not STRICT",
                        f"{len(peer_authentications)} policies — check for PERMISSIVE mode",
                        "Set mtls.mode: STRICT on all namespaces",
                    )
                break
            if code_pa == 403:
                legacy.finding("INFO", "Istio PeerAuthentication CRD present (cannot read — 403)", "")
                break

    legacy.section("Network Sniffing Capability")
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        raw_socket.close()
        legacy.finding(
            "HIGH",
            "NET_RAW — traffic sniffing possible via raw sockets",
            "Can capture plain-text HTTP traffic between pods",
            "Drop NET_RAW | Enable Istio mTLS",
        )
    except PermissionError:
        legacy.finding("PASS", "NET_RAW denied — sniffing not possible", "")
    except (AttributeError, OSError):
        legacy.finding("PASS", "NET_RAW denied", "")


class NetworkEngine(LegacyFunctionEngine):
    """Network recon engine."""

    def __init__(self) -> None:
        super().__init__(name="network", phase="4", function_name="phase_network")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted network phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_network(legacy, fast=getattr(_config, "fast", False))
