"""Supply-chain engine."""

from __future__ import annotations

import base64
import json

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.engines.base import LegacyFunctionEngine


def probe_registry(legacy, registry, user, password, secret_name) -> None:
    """Attempt to list repositories using stolen registry credentials."""

    base = registry.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    auth_header = base64.b64encode(f"{user}:{password}".encode()).decode()
    for endpoint in ["/v2/_catalog", "/api/v2.0/repositories?page_size=20", "/v2/", "/api/v2.0/projects"]:
        code, body = legacy.http_get(
            f"{base}{endpoint}",
            headers={"Authorization": f"Basic {auth_header}"},
            timeout=5,
        )
        if code == 200:
            legacy.finding(
                "CRITICAL",
                f"Registry '{registry}' authenticated — catalog accessible",
                f"Secret: {secret_name} | Endpoint: {endpoint}\n"
                f"Response: {legacy.truncate(body, 200)}\n"
                "Can pull/push images — supply chain backdoor possible",
                "Rotate registry credentials immediately | Restrict imagePullSecret access",
            )
            legacy.add_attack_edge(
                f"Registry Secret {secret_name}",
                "Private Registry",
                f"Authenticated pull/push on {registry}",
                "CRITICAL",
            )
            return
        if code == 401:
            legacy.finding(
                "MEDIUM",
                f"Registry '{registry}' reachable but credentials rejected",
                f"HTTP 401 on {endpoint} — credentials may be expired",
                "Verify credentials are current | Rotate registry secret",
            )
            return


def run_phase_supply_chain(legacy) -> None:
    """Execute the extracted supply-chain and admission control phase."""

    legacy.CURRENT_PHASE = legacy.STATE.current_phase = "9"
    legacy.phase_header(
        "9",
        "Supply Chain & Admission Control",
        "Image signing, registry creds, PSS, Kyverno, admission plugins",
    )

    namespace = legacy.CTX.get("namespace", "default")

    legacy.section("Image Signing Enforcement")
    code, resp = legacy.k8s_api("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
    signing_webhooks = []
    signing_tools = ["kyverno", "cosign", "sigstore", "notary", "connaisseur", "portieris"]
    if code == 200 and resp:
        for webhook in resp.get("items", []):
            if any(tool in webhook["metadata"]["name"].lower() for tool in signing_tools):
                signing_webhooks.append(webhook["metadata"]["name"])

    if not signing_webhooks and code in (401, 403):
        kyverno_via_apis = "kyverno" in legacy.CTX.get("runtime_tools", [])
        kyverno_paths = [
            "/apis/kyverno.io/v1/clusterpolicies",
            "/apis/kyverno.io/v2beta1/clusterpolicies",
            "/apis/kyverno.io/v2/clusterpolicies",
        ]
        for kyverno_path in kyverno_paths:
            code_kp, resp_kp = legacy.k8s_api(kyverno_path, timeout=4)
            if code_kp == 200 and resp_kp:
                policies = resp_kp.get("items", [])
                verify_policies = [
                    policy["metadata"]["name"]
                    for policy in policies
                    if "verifyimage" in str(policy.get("spec", {})).lower()
                    or "verify-image" in policy["metadata"]["name"].lower()
                ]
                if verify_policies:
                    signing_webhooks = [f"Kyverno verifyImages: {', '.join(verify_policies[:3])}"]
                else:
                    signing_webhooks = [f"Kyverno installed ({len(policies)} policies — check verifyImages)"]
                break
            if code_kp == 403:
                signing_webhooks = ["Kyverno (CRD present, policies not readable — 403)"]
                break
        if not signing_webhooks and kyverno_via_apis:
            signing_webhooks = ["Kyverno (detected via API group discovery — SA lacks policy list permission)"]

    if signing_webhooks:
        legacy.finding("PASS", f"Image signing / admission control: {', '.join(signing_webhooks)}", "")
    elif code in (401, 403):
        legacy.finding(
            "INFO",
            f"Cannot list admission webhooks (HTTP {code}) — image signing status unknown",
            "Webhook list requires cluster-level permission\n"
            "Check manually: kubectl get validatingwebhookconfigurations",
            "Ensure Kyverno verifyImages or cosign admission webhook is configured",
        )
    else:
        legacy.finding(
            "HIGH",
            "No image signing admission webhook",
            "Unsigned/tampered images can be deployed without verification",
            "Install Kyverno + verifyImages | Use cosign to sign all images",
        )

    legacy.section("Registry Credential Exposure")
    code, resp = legacy.k8s_api(f"/api/v1/namespaces/{namespace}/secrets")
    if code == 200 and resp:
        for item in resp.get("items", []):
            if item.get("type") == "kubernetes.io/dockerconfigjson":
                name = item["metadata"]["name"]
                config_b64 = item.get("data", {}).get(".dockerconfigjson", "")
                if config_b64:
                    try:
                        config = json.loads(legacy.decode_b64(config_b64))
                        for registry, creds in config.get("auths", {}).items():
                            user = creds.get("username", "?")
                            auth_raw = creds.get("auth", "")
                            password = ""
                            if auth_raw:
                                try:
                                    decoded_auth = legacy.decode_b64(auth_raw)
                                    if ":" in decoded_auth:
                                        password = decoded_auth.split(":", 1)[1]
                                except Exception:
                                    pass
                            if not password:
                                password = creds.get("password", "")
                            legacy.finding(
                                "HIGH",
                                f"Registry creds in secret '{name}'",
                                f"Registry: {registry} | User: {user}",
                                "Restrict secret read | Rotate registry credentials",
                            )
                            if password:
                                probe_registry(legacy, registry, user, password, name)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass

    legacy.section("imagePullSecrets on Pod Specs")
    for pod in legacy.CTX.get("all_pods") or []:
        image_pull_secrets = pod.get("spec", {}).get("imagePullSecrets", [])
        if image_pull_secrets:
            pod_name = pod["metadata"]["name"]
            pod_namespace = pod["metadata"]["namespace"]
            legacy.finding(
                "MEDIUM",
                f"Pod {pod_namespace}/{pod_name} has imagePullSecrets",
                f"Secrets: {', '.join([secret.get('name', '') for secret in image_pull_secrets])}\n"
                "If secret is readable, attacker can pull private images",
                "Restrict secret read permissions",
            )
            break

    legacy.section("PSS Enforcement")
    code_ns, resp_ns = legacy.k8s_api(f"/api/v1/namespaces/{namespace}")
    if code_ns == 200 and resp_ns:
        labels = resp_ns.get("metadata", {}).get("labels", {})
        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        warn = labels.get("pod-security.kubernetes.io/warn", "")
        if enforce == "restricted":
            legacy.finding("PASS", f"PSS Restricted enforced on '{namespace}'", "")
        elif enforce:
            legacy.finding(
                "MEDIUM",
                f"PSS level '{enforce}' on '{namespace}' (not restricted)",
                f"enforce={enforce} warn={warn}",
                "Set pod-security.kubernetes.io/enforce=restricted",
            )
        else:
            legacy.finding(
                "HIGH",
                f"No PSS labels on '{namespace}'",
                "No Pod Security Standards enforcement",
                "kubectl label namespace --overwrite pod-security.kubernetes.io/enforce=restricted",
            )
    elif code_ns in (401, 403):
        legacy.finding(
            "INFO",
            f"Cannot read namespace '{namespace}' labels (HTTP {code_ns}) — PSS status unknown",
            f"Check manually: kubectl get namespace {namespace} -o jsonpath='{{.metadata.labels}}'",
        )

    legacy.section("Kyverno Policies")
    kyverno_found = False
    if "kyverno" in legacy.CTX.get("runtime_tools", []):
        kyverno_found = True
        legacy.info_line("Kyverno confirmed via API group discovery (cilium.io/kyverno.io present)")
    for kyverno_path in [
        "/apis/kyverno.io/v1/clusterpolicies",
        "/apis/kyverno.io/v2beta1/clusterpolicies",
        "/apis/kyverno.io/v2/clusterpolicies",
    ]:
        code_kp, resp_kp = legacy.k8s_api(kyverno_path, timeout=5)
        if code_kp == 200 and resp_kp:
            policies = resp_kp.get("items", [])
            enforced = []
            audit_only = []
            for policy in policies:
                spec = policy.get("spec", {})
                action = spec.get("validationFailureAction", "")
                if not action:
                    for rule in spec.get("rules", []):
                        validate = rule.get("validate", {})
                        action = validate.get("failureAction", "") or spec.get("validationFailureAction", "")
                        if action:
                            break
                if action.lower() in ("enforce", "enforce"):
                    enforced.append(policy["metadata"]["name"])
                elif action.lower() in ("audit", ""):
                    audit_only.append(policy["metadata"]["name"])
                else:
                    enforced.append(policy["metadata"]["name"])

            if enforced:
                legacy.finding(
                    "PASS",
                    f"Kyverno ClusterPolicies enforced: {len(enforced)}",
                    f"Policies: {', '.join(enforced[:6])}",
                )
            if audit_only:
                legacy.finding(
                    "MEDIUM",
                    f"Kyverno in Audit mode: {len(audit_only)} policies",
                    f"Policies: {', '.join(audit_only[:5])}\nAudit logs but does NOT block",
                    "Change validationFailureAction: Audit → Enforce",
                )
            if not policies:
                legacy.finding(
                    "HIGH",
                    "Kyverno CRD present but no ClusterPolicies found",
                    "Kyverno is installed but no policies are active",
                    "Apply Kyverno policies: registry restriction, non-root, resource limits",
                )
            kyverno_found = True
            break
        if code_kp == 403:
            legacy.finding(
                "PASS",
                "Kyverno installed — ClusterPolicies not readable (HTTP 403)",
                "Kyverno CRD is present, policies enforced but cannot be enumerated\n"
                "Check: kubectl get clusterpolicies",
                "",
            )
            kyverno_found = True
            break

    if not kyverno_found:
        legacy.finding("INFO", "Kyverno CRD not present", "No Kyverno policy engine detected")

    legacy.section("Admission Plugin Detection")
    code_ap, resp_ap = legacy.k8s_api("/api/v1/namespaces/kube-system/pods")
    if code_ap == 200 and resp_ap:
        for pod in resp_ap.get("items", []):
            if "kube-apiserver" in pod.get("metadata", {}).get("name", ""):
                for container in pod.get("spec", {}).get("containers", []):
                    command = " ".join(container.get("command", []))
                    if "AlwaysAdmit" in command:
                        legacy.finding(
                            "CRITICAL",
                            "AlwaysAdmit admission plugin enabled",
                            "ALL admission control bypassed — any pod, any config accepted",
                            "Remove AlwaysAdmit from --enable-admission-plugins",
                        )
                        legacy.add_attack_edge(
                            "SA Token",
                            "Node Root",
                            "AlwaysAdmit → unconstrained pod creation",
                            "CRITICAL",
                        )
                    if "PodSecurity" not in command:
                        legacy.finding(
                            "HIGH",
                            "PodSecurity admission plugin not detected",
                            "PSS enforcement may not be active at API server level",
                            "Add PodSecurity to --enable-admission-plugins",
                        )
                    if "NodeRestriction" not in command:
                        legacy.finding(
                            "MEDIUM",
                            "NodeRestriction admission plugin not detected",
                            "Nodes may be able to modify labels/annotations of other nodes",
                            "Add NodeRestriction to --enable-admission-plugins",
                        )
                break
    elif code_ap in (401, 403):
        legacy.finding(
            "INFO",
            f"Cannot list kube-system pods (HTTP {code_ap}) — admission plugins not inspectable",
            "Admission plugin check requires kube-system pod list permission\n"
            "Check manually: kubectl -n kube-system get pod -l component=kube-apiserver -o yaml | grep admission",
        )


class SupplyChainEngine(LegacyFunctionEngine):
    """Supply-chain engine."""

    def __init__(self) -> None:
        super().__init__(name="supply_chain", phase="9", function_name="phase_supply_chain")

    async def run(self, _context, _config, _state, _api_client):
        """Execute the extracted supply-chain phase via the legacy compatibility layer."""

        legacy = load_legacy_module()
        return run_phase_supply_chain(legacy)
