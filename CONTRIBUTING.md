# Contributing to KubeXHunt

Thank you for your interest in contributing to KubeXHunt! We welcome contributions in the form of:

- **Bug reports** (GitHub Issues)
- **Security vulnerabilities** (see [SECURITY.md](SECURITY.md))
- **Feature requests and discussions** (GitHub Discussions)
- **Code contributions** (Pull Requests)
- **Documentation improvements**
- **Test coverage**
- **Integration examples** (Splunk, Falco, Slack, etc.)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please review and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- Python 3.9+
- `pip` for dependency management
- `git` for version control

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/mr-xhunt/kubeX.git
cd kubeX

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=kubexhunt

# Run linting
ruff check kubexhunt/
mypy kubexhunt/
```

## Development Workflow

1. **Create a branch** for your feature/fix:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```

2. **Write code** following these principles:
   - Preserve existing behavior (see MIGRATION_BLUEPRINT.md)
   - Add tests for new functionality
   - Use type hints (Python 3.9+)
   - Keep functions focused and testable

3. **Test your changes**:
   ```bash
   pytest tests/ -v
   ruff check kubexhunt/
   mypy kubexhunt/
   ```

4. **Commit with descriptive messages**:
   ```bash
   git commit -m "feat: add CVSS scoring to findings"
   git commit -m "fix: kubelet port enumeration timeout"
   git commit -m "docs: add cloud credential pivoting examples"
   ```

5. **Push and open a Pull Request**:
   ```bash
   git push origin feature/my-awesome-feature
   ```

## Pull Request Guidelines

- **Title**: Clear, concise, and actionable (e.g., "Add MITRE ATT&CK mapping to findings")
- **Description**: Explain *what* you changed and *why*
- **Testing**: Include test cases for new functionality
- **Documentation**: Update relevant docstrings and README sections
- **Scope**: Keep PRs focused; avoid combining unrelated changes

### PR Template

```markdown
## Description
Brief explanation of the change.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How did you test this? (manual testing, pytest, etc.)

## Checklist
- [ ] Code follows project style (ruff, mypy)
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No new warnings introduced
```

## Architecture and Design

### Project Structure

```
kubexhunt/
  cli/              # CLI argument parsing and dispatch
  core/             # Core models, logging, opsec rating system
  api/              # Kubernetes API client
  engines/          # Phase modules (pod, RBAC, cloud, etc.)
  correlation/      # Attack path and graph analysis
  exploit/          # Exploitation modules (daemonset, hostpath, etc.)
  output/           # Report formatters (JSON, HTML, SARIF, etc.)
  services/         # Orchestration and scan workflow
  plugins/          # Extensibility framework
  mappings/         # MITRE, CWE, CIS mappings
  data/             # Static data (CVE database, wordlists, etc.)

tests/              # Test suite
```

### Adding a New Phase/Engine

1. Create a new file in `kubexhunt/engines/my_feature.py`
2. Implement the phase function:
   ```python
   def run_phase_my_feature(ctx, state, **kwargs):
       """Phase description.
       
       Args:
           ctx: PackageContext
           state: PackageScanState
       """
       findings = []
       # ... implementation ...
       return findings
   ```
3. Register in `kubexhunt/engines/registry.py`
4. Add tests in `tests/test_engines_my_feature.py`
5. Document in `PHASES.md`

### Adding a New Finding Type

1. Create a `Finding` instance in your engine:
   ```python
   from kubexhunt.core.models import Finding, Severity, Remediation, RemediationStep
   
   finding = Finding(
       id="FEATURE-001",
       title="Descriptive title",
       severity=Severity.CRITICAL,
       confidence=0.95,
       category="Privilege Escalation",
       phase="Phase X",
       observed=True,
       description="Technical explanation",
       remediation=Remediation(
           summary="How to fix this",
           steps=[
               RemediationStep(step="First step", effort="LOW"),
               RemediationStep(step="Second step", effort="MEDIUM"),
           ],
       ),
       mitre=["T1078.001", "T1087.002"],
       cwe=["CWE-276"],
       tags=["kubernetes", "rbac"],
   )
   ```
2. Add to `state.findings`

### Adding a New Report Format

1. Create a new file in `kubexhunt/output/my_format_report.py`
2. Implement the formatter:
   ```python
   def generate_my_format_report(findings, attack_graph, ctx):
       """Generate report in my format."""
       # ... implementation ...
       return report_content
   ```
3. Register in `kubexhunt/output/__init__.py`
4. Test in `tests/test_output_my_format.py`

## Coding Standards

### Style

- Use `ruff` for formatting: `ruff format kubexhunt/`
- Use `ruff check` for linting: `ruff check kubexhunt/`
- Use `mypy` for type checking: `mypy kubexhunt/`

### Type Hints

```python
def scan_cluster(ctx: Context, phases: list[int]) -> dict[str, Any]:
    """Scan the cluster for vulnerabilities."""
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def find_rbac_escalation(ctx: Context) -> list[Finding]:
    """Identify RBAC paths to privilege escalation.
    
    Args:
        ctx: Execution context with API access.
    
    Returns:
        List of findings representing RBAC escalation paths.
    """
    pass
```

### Testing

- Aim for 60%+ code coverage
- Test public APIs, not implementation details
- Use pytest fixtures for common setup

```python
def test_rbac_escalation_detection():
    """Test that wildcard ClusterRoles are detected."""
    # Arrange
    finding = Finding(...)
    
    # Act
    result = analyze_finding(finding)
    
    # Assert
    assert result.severity == Severity.CRITICAL
```

## Reporting Issues

### Bug Reports

Include:
- KubeXHunt version
- Python version
- Kubernetes cluster version
- Steps to reproduce
- Expected vs. actual behavior
- Logs (redacted for sensitive data)

### Feature Requests

Include:
- Problem statement (what gap does this fill?)
- Proposed solution
- Alternative approaches
- Use case examples

## Security Vulnerabilities

**Do not** open a public GitHub issue for security vulnerabilities. Please report through the process described in [SECURITY.md](SECURITY.md).

## Documentation

- Update docstrings when modifying functions
- Update README.md for user-facing changes
- Add examples in `examples/` for new capabilities
- Update `PHASES.md` for new phases
- Update `ARCHITECTURE.md` for structural changes

## Release Process

1. Update version in `kubexhunt/__init__.py`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v1.2.0`
4. Push tag: `git push origin v1.2.0`
5. GitHub Actions will build and publish artifacts

## Questions?

- Open a GitHub Discussion for general questions
- Check existing issues/PRs before creating duplicates
- Join our Discord/Slack community (when available)

---

Thank you for helping make KubeXHunt better! 🚀
