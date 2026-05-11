"""Integration checks for CLI and report parity during the modular migration."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEGACY_SCRIPT = REPO_ROOT / "kubexhunt.py"


def run_command(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a CLI command in the repository root and capture text output."""

    return subprocess.run(
        [sys.executable, *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_phase_list_matches_between_entrypoints() -> None:
    """`python kubexhunt.py` and `python -m kubexhunt` should expose the same phase list."""

    legacy = run_command(str(LEGACY_SCRIPT), "--phase-list")
    module = run_command("-m", "kubexhunt", "--phase-list")

    assert legacy.returncode == 0, legacy.stderr
    assert module.returncode == 0, module.stderr
    assert legacy.stdout == module.stdout


def test_migrated_phase_report_generation_smoke(tmp_path: Path) -> None:
    """Recently migrated phases should still generate reports successfully."""

    report_path = tmp_path / "network-report.html"
    result = run_command(str(LEGACY_SCRIPT), "--phase", "4", "--fast", "--no-mutate", "--output", str(report_path))

    assert result.returncode == 0, result.stderr
    assert report_path.exists()
    html = report_path.read_text(encoding="utf-8", errors="replace")
    assert "KubeXHunt" in html
    assert "Network Recon" in result.stdout


def test_module_entrypoint_generates_same_html_title(tmp_path: Path) -> None:
    """The module entrypoint should remain report-compatible with the legacy script."""

    legacy_report = tmp_path / "legacy.html"
    module_report = tmp_path / "module.html"

    legacy = run_command(str(LEGACY_SCRIPT), "--phase", "15", "--no-mutate", "--output", str(legacy_report))
    module = run_command("-m", "kubexhunt", "--phase", "15", "--no-mutate", "--output", str(module_report))

    assert legacy.returncode == 0, legacy.stderr
    assert module.returncode == 0, module.stderr
    assert legacy_report.exists()
    assert module_report.exists()

    legacy_html = legacy_report.read_text(encoding="utf-8", errors="replace")
    module_html = module_report.read_text(encoding="utf-8", errors="replace")
    assert "KubeXHunt" in legacy_html
    assert "KubeXHunt" in module_html
    assert "Cluster Intelligence" in legacy_html
    assert "Cluster Intelligence" in module_html


def test_recently_migrated_late_phases_generate_reports(tmp_path: Path) -> None:
    """Late-phase engine extractions should still complete and emit HTML reports."""

    phases = {
        "5": "Container Escape Vectors",
        "13": "Secrets & Sensitive Data",
        "18": "Helm & Application Secret Extraction",
        "23": "Real-World Attack Chain Simulation",
        "24": "Stealth & Evasion Analysis",
    }

    for phase, title in phases.items():
        report_path = tmp_path / f"phase-{phase}.html"
        result = run_command(str(LEGACY_SCRIPT), "--phase", phase, "--no-mutate", "--output", str(report_path))

        assert result.returncode == 0, result.stderr
        assert report_path.exists()
        html = report_path.read_text(encoding="utf-8", errors="replace")
        assert "KubeXHunt" in html
        assert title in result.stdout
