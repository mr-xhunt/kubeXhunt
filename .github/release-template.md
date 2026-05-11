# KubeXHunt v2.0.0

Kubernetes post-compromise security assessment framework - Complete Feature Release

## Complete Implementation (Phases 1-4)

### Phase 1: MVP Credibility Foundation ✅
- **Enhanced Finding Schema**: Structured findings with MITRE ATT&CK for Containers, CWE, CVSS 3.1 severity
- **Attack Graph Engine**: GraphNode/GraphEdge model with BFS shortest-path queries
- **Opsec Rating System**: 4-level detectability ratings (SILENT/QUIET/MEDIUM/LOUD) for red team operations
- **Professional Documentation**: README, CONTRIBUTING, SECURITY, and CODE_OF_CONDUCT

### Phase 2: Attack Path Chaining ✅
- GraphNode/GraphEdge/AttackGraph data model with full query capabilities
- Shortest-path queries for escalation discovery
- Foundation for automated exploit chain generation

### Phase 3: Defense Evasion & Advanced Techniques ✅
- Runtime security evasion techniques
- Workload identity abuse chains
- Persistence automation
- Network policy analysis

### Phase 4: Supply Chain & Cloud IAM Attacks ✅
- Supply chain attack modules (registry poisoning, CI/CD abuse)
- Cloud IAM escalation (AWS/GCP/Azure backdoor chains)
- Secret extraction and threat detection
- **396 comprehensive unit tests with ~60% coverage**

## Installation

```bash
pip install kubexhunt
```

## Usage

```bash
# Basic scan (read-only)
kubexhunt --help

# Run assessment
python3 -m kubexhunt --output report.json

# Stealth mode
python3 -m kubexhunt --stealth 2 --no-mutate
```

## Key Features

✅ Zero external dependencies for core functionality  
✅ 396 unit tests, ~60% code coverage  
✅ Multi-phase enumeration (27 phases)  
✅ MITRE ATT&CK for Containers mapping  
✅ Opsec ratings for red team planning  
✅ Professional CI/CD infrastructure  
✅ Modern Python packaging (pyproject.toml)  

## Documentation

- [README](https://github.com/mr-xhunt/kubeX/blob/main/README.md) - Quick start and feature overview
- [CONTRIBUTING](https://github.com/mr-xhunt/kubeX/blob/main/CONTRIBUTING.md) - Development workflow
- [SECURITY](https://github.com/mr-xhunt/kubeX/blob/main/SECURITY.md) - Vulnerability disclosure
- [CHANGELOG](https://github.com/mr-xhunt/kubeX/blob/main/CHANGELOG.md) - Full release notes

## Roadmap

- **Phase 2 (1-3 months)**: Exploit chain generation, cloud credential pivoting
- **Phase 3 (3-6 months)**: Defense evasion playbooks, advanced techniques
- **Phase 4 (6-12 months)**: Ecosystem integrations, conference talks

## License

MIT License - See [LICENSE](https://github.com/mr-xhunt/kubeX/blob/main/LICENSE) for details

---

**Ready to assess your cluster?**

```bash
pip install kubexhunt
kubexhunt --help
```
