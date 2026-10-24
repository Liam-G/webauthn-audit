from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .artifacts import ArtifactError
from .audit import audit_files
from .catalog import list_rules
from .config import ConfigError, load_policy
from .models import Severity
from .reporting import apply_baseline, baseline_fingerprints, render_json, render_sarif, render_text


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="webauthn-audit", description="Offline-first WebAuthn/passkey ceremony auditor"
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    lint = commands.add_parser(
        "lint", help="audit options, responses, or paired ceremony envelopes"
    )
    lint.add_argument("artifacts", nargs="+", type=Path)
    lint.add_argument("--config", type=Path)
    lint.add_argument("--profile", choices=("baseline", "passkey", "high-assurance"))
    lint.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    lint.add_argument("--output", type=Path)
    lint.add_argument("--baseline", type=Path)
    lint.add_argument("--fail-on", choices=tuple(item.name.lower() for item in Severity))
    lint.add_argument("--no-color", action="store_true")
    commands.add_parser("rules", help="list checks and normative references")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "rules":
        for rule in list_rules():
            print(
                f"{rule.id}\t{rule.severity.name.lower()}\t{rule.title}\t{rule.references[0].url}"
            )
        return 0
    try:
        policy = load_policy(args.config, profile=args.profile)
        if args.fail_on:
            from dataclasses import replace

            policy = replace(policy, fail_on=Severity.parse(args.fail_on))
        result = audit_files(args.artifacts, policy)
        if args.baseline:
            result = apply_baseline(result, baseline_fingerprints(args.baseline))
    except (ConfigError, ArtifactError, ValueError) as exc:
        print(f"webauthn-audit: error: {exc}", file=sys.stderr)
        return 3
    if args.format == "json":
        rendered = render_json(result, policy)
    elif args.format == "sarif":
        rendered = render_sarif(result, policy)
    else:
        use_color = (
            not args.no_color
            and args.output is None
            and sys.stdout.isatty()
            and os.getenv("NO_COLOR") is None
        )
        rendered = render_text(result, policy, color=use_color)
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"webauthn-audit: error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 3
    else:
        sys.stdout.write(rendered)
    return 2 if any(f.rule.severity >= policy.fail_on for f in result.active(policy)) else 0
