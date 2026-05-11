# Security Policy

## Reporting Security Vulnerabilities

KubeXHunt is a security assessment tool. We take security seriously and appreciate responsible disclosure.

**⚠️ DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, email security vulnerabilities to: **security@kubexhunt.io** (to be created) or contact the maintainers privately.

### Reporting Process

1. **Email the vulnerability** with:
   - Description of the vulnerability
   - Steps to reproduce (if applicable)
   - Potential impact
   - Suggested fix (if you have one)

2. **Include your PGP key** if you prefer encrypted communication (optional)

3. **Allow 90 days** for the maintainers to:
   - Acknowledge receipt
   - Investigate and confirm
   - Develop and test a fix
   - Release a patched version
   - Publish a security advisory

4. **After 90 days**, the vulnerability becomes public (if still unfixed, we'll provide timeline)

## Vulnerability Disclosure Policy

- **Scope**: Vulnerabilities in KubeXHunt code and dependencies
- **Out of scope**: 
  - Kubernetes design issues (report to Kubernetes security team)
  - Cloud provider IAM issues (report to the cloud provider)
  - General security recommendations ("add more logging")

## Security Best Practices for KubeXHunt Users

### Before Running KubeXHunt

1. **Understand the risk**: KubeXHunt *actively probes* your cluster and may:
   - Create test objects (pods, roles, etc.) if `--mutate` is enabled
   - Generate audit log entries
   - Consume bandwidth and CPU

2. **Get authorization**: Only run against clusters you own or have explicit written permission to test

3. **Use `--no-mutate` mode** for production clusters (read-only reconnaissance)

4. **Monitor execution**: Watch for errors or unexpected behavior

### After Running KubeXHunt

1. **Review findings carefully**: Some may be false positives
2. **Prioritize remediation** by severity and exploitability
3. **Test fixes** in non-production environments first
4. **Verify resolution** by running KubeXHunt again

## Dependency Security

KubeXHunt strives for **zero external dependencies** in the core tool (Python stdlib only).

- Dependencies are intentionally minimal to reduce supply chain risk
- Container image uses `alpine:latest` base for minimal attack surface
- SBOM (Software Bill of Materials) is generated at build time

## Code Security

### Input Validation

- All user input (API responses, environment variables, files) is validated
- JSON parsing handles malformed data gracefully
- No shell command injection risks (subprocess calls use `shell=False`)

### Credential Handling

- Kubernetes tokens are kept in memory only
- Tokens are never logged (sanitized from debug output)
- No credentials are written to disk (except as explicitly requested in reports)
- IMDS credentials are cleared after use

### Network Security

- HTTPS is used for external API calls
- TLS certificate verification is enabled by default
- Proxy support for network isolation (via `--proxy` flag)

## Testing & Continuous Integration

All code changes go through:

1. **Linting**: `ruff check` enforces code quality
2. **Type checking**: `mypy` validates type safety
3. **Unit tests**: `pytest` runs 60%+ coverage
4. **Integration tests**: Real Kubernetes-in-Docker cluster
5. **Security scanning**: Container images scanned for CVEs

## Incident Response

If a critical vulnerability is discovered:

1. A patch release is issued immediately
2. Security advisory is published
3. Existing users are notified via:
   - GitHub Security Advisory
   - Release notes
   - Twitter/Mastodon (when available)

## Security Contacts

- **Email**: security@kubexhunt.io (to be created)
- **Maintainers**: See CONTRIBUTING.md

## Version Support

- **Current**: Receives security patches
- **Previous**: Receives critical patches only
- **Older**: Unsupported; users should upgrade

Example:
- v1.2.0: Current (all patches)
- v1.1.x: Previous (critical only)
- v1.0.x: Older (unsupported)

## Responsible Disclosure Timeline

| Event | Days Since Report |
|-------|-------------------|
| Initial response | < 1 |
| Fix confirmed | < 7 |
| Patch released | < 30 |
| CVE assigned (if applicable) | < 60 |
| Public advisory | 90 |

## Credits

Security researchers who responsibly report vulnerabilities will be credited in the advisory (unless they request anonymity).

---

Thank you for helping keep KubeXHunt secure. 🔒
