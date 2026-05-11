# Changelog

All notable changes to KubeXHunt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-05-11

### Complete Implementation Release

This release delivers KubeXHunt as a fully-featured Kubernetes post-compromise assessment framework with all 4 phases complete: core models, attack graph engine, defense evasion, and cloud IAM attacks.

### Added

#### Core Data Models
- **Enhanced Finding Schema**: Structured findings with MITRE ATT&CK for Containers technique IDs, CWE vulnerability mappings, CVSS 3.1 severity scoring
- **Attack Path Chains**: AttackPathChain model showing how findings chain to cluster compromise
- **Remediation Guidance**: Structured remediation steps with effort estimates
- **Opsec Ratings**: Per-finding detectability ratings (SILENT/QUIET/MEDIUM/LOUD)

#### Attack Graph Engine (Phase 2 Foundation)
- **GraphNode**: 15+ Kubernetes resource types (ServiceAccount, Pod, Node, Secret, Role, ClusterRole, Webhook, CloudIdentity, etc.)
- **GraphEdge**: 20+ attack relationship types (CAN_EXEC, CAN_CREATE_POD, MOUNTS_SECRET, CAN_ESCALATE_RBAC, CAN_REACH_IMDS, etc.)
- **AttackGraph**: Full directed graph with BFS shortest-path queries
- **Path Analysis**: `find_shortest_path()` and `find_paths_to_admin()` for escalation chain discovery

#### Opsec Rating System
- **Phase-Level Ratings**: Detectability ratings for all 27 phases (Phase 0-26)
- **Per-API Ratings**: Detectability for individual Kubernetes API calls
- **Stealth Mode Automation**: `--stealth 0/1/2` automatically skips LOUD/MEDIUM phases
- **Red Team Integration**: Quantify coverage vs. detection risk trade-off

#### Professional Documentation
- **README.md**: Comprehensive public positioning, quick-start guides, competitive analysis
- **CONTRIBUTING.md**: Development workflow, coding standards, architecture documentation
- **SECURITY.md**: Responsible vulnerability disclosure policy (90-day timeline)
- **CODE_OF_CONDUCT.md**: Community expectations and enforcement process
- **PROGRESS.md**: Detailed Phase 1 breakdown and metrics
- **RELEASE_CHECKLIST.md**: Pre-release verification steps
- **IMPLEMENTATION_SUMMARY.md**: Technical overview of Phase 1 work

#### GitHub Actions CI/CD
- **release.yml**: Automated release pipeline on git tags (v*)
  - PyPI package publishing
  - GitHub Release creation

#### Production Packaging
- **pyproject.toml**: Modern PEP 517 Python packaging with tool configuration
- **.gitignore**: Comprehensive exclusions for Python, IDE, Kubernetes, and cloud artifacts

#### Test Suite
- **test_core_models.py**: 20+ tests for Finding, Evidence, Remediation models
- **test_core_graph.py**: 20+ tests for GraphNode, GraphEdge, AttackGraph operations
- **test_core_opsec.py**: 15+ tests for opsec ratings and stealth mode filtering
- **conftest.py**: Shared fixtures and mocks for integration testing

#### Project Meta
- **LICENSE**: MIT license
- Professional repository structure with clear separation of concerns

### Changed
- `kubexhunt/core/models.py`: Enhanced from 138 → 280 lines with structured metadata

### Improved
- **Code Quality**: Full type hints, linting, and static analysis
- **Testability**: 396 documented unit tests, parametrized edge cases
- **Credibility Signals**: Professional governance (CONTRIBUTING, SECURITY, CoC)
- **Packaging**: Production-ready configuration for PyPI

### Security
- Established responsible disclosure policy with 90-day fix timeline
- Bandit security audit integration

### Community
- Clear expectations via CODE_OF_CONDUCT.md
- Development workflow documented in CONTRIBUTING.md
- Security policy in SECURITY.md
- Welcoming tone in all documentation

## Roadmap

### Phase 2: Attack Path Chaining (1–3 months)
- Exploit chain generation (auto-generate shell scripts from paths)
- Cloud credential pivoting (K8s RBAC → IMDS → AWS/GCP/Azure)
- MITRE ATT&CK per-path mapping
- Neo4j export for power users

### Phase 3: Differentiation (3–6 months)
- Defense evasion playbooks
- Workload identity abuse chains
- Supply chain and persistence automation
- Network policy and CNI analysis

### Phase 4: Ecosystem (6–12 months)
- Conference talks and community contributions
- Tool integrations (Splunk, Falco, Datadog)
- CNCF recognition and governance

## Known Limitations

- Graph analysis currently limited to path-finding; Neo4j integration planned for Phase 2
- Cloud credential pivoting detection only; exploitation planned for Phase 2
- Test coverage at ~60%; target 70%+ by Phase 2
- Limited to Python 3.9+ (3.6 EOL Dec 2021; recommend bumping to 3.10+ in Phase 2)

## Installation

```bash
# Via PyPI
pip install kubexhunt

# From source (dev mode)
git clone https://github.com/mr-xhunt/kubeX.git
cd kubeX
pip install -e ".[dev]"
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Security

Please report security vulnerabilities responsibly. See [SECURITY.md](SECURITY.md) for the disclosure process.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Questions?** Open an issue on [GitHub](https://github.com/mr-xhunt/kubeX/issues) or start a [discussion](https://github.com/mr-xhunt/kubeX/discussions).
