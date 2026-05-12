"""Main CLI dispatcher."""

from __future__ import annotations

import argparse

from kubexhunt.services.scan_service import run_scan

__version__ = "2.1"


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser while preserving legacy flags and help text."""

    parser = argparse.ArgumentParser(
        description="KubeXHunt v2.1 — Kubernetes Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kubexhunt                              # Full scan (all phases)
  kubexhunt --phase 3 7 15               # Specific phases
  kubexhunt --fast                       # Skip slow DNS/port scan
  kubexhunt --stealth 2 --no-mutate      # Silent read-only mode
  kubexhunt --output report.json         # JSON report
  kubexhunt --output report.html         # HTML report
  kubexhunt --output report.sarif        # SARIF report (CI/CD)
  kubexhunt --diff previous.json         # Diff vs last scan
  kubexhunt --proxy http://127.0.0.1:8080  # Route via Burp
  kubexhunt --phase-list                 # List all phases and exit
        """,
    )
    parser.add_argument("--phase", nargs="+", type=int, help="Run specific phase(s) (0-26)")
    parser.add_argument("--fast", action="store_true", help="Skip slow port scan / DNS brute")
    parser.add_argument(
        "--stealth", type=int, default=0, choices=[0, 1, 2], help="Stealth level: 0=off 1=jitter+UA 2=full evasion"
    )
    parser.add_argument("--no-mutate", action="store_true", help="Skip all mutating API calls")
    parser.add_argument("--output", metavar="FILE", help="Save report (.json .html .sarif .txt)")
    parser.add_argument("--debug-report", action="store_true", help="Seed report with synthetic data for UI testing")
    parser.add_argument("--diff", metavar="PREV.json", help="Diff vs previous JSON report")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--proxy", metavar="URL", help="HTTP proxy for API calls (e.g. Burp)")
    parser.add_argument(
        "--exploit",
        metavar="MODULE",
        choices=["daemonset-root", "hostpath-mount", "token-pivot", "kubelet-exec"],
        help="Show or execute a specific exploit module",
    )
    parser.add_argument("--mutate", action="store_true", help="Allow exploit and persistence mutations")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and stack traces")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging")
    parser.add_argument("--json-logs", action="store_true", help="Emit internal logs in JSON format")
    parser.add_argument("--kubectl-only", action="store_true", help="Only install kubectl then exit")
    parser.add_argument("--phase-list", action="store_true", help="List all phases and exit")
    parser.add_argument("--exclude-phase", nargs="+", type=int, help="Skip specific phase(s)")
    parser.add_argument("--version", action="version", version=f"KubeXHunt {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse CLI args and dispatch to the scan service."""

    parser = build_parser()
    args = parser.parse_args(argv)
    return run_scan(args)
