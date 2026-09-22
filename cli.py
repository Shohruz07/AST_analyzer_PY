#!/usr/bin/env python
"""
CLI для AST Security Analyzer.
Используется в CI/CD и pre-commit hooks.

Примеры:
    python cli.py --full --project .
    python cli.py --incremental --base=HEAD~1
    python cli.py --staged
    python cli.py --file path/to/file.py
"""
import argparse
import json
import sys
from pathlib import Path

from app.analyzer import DataFlowAnalyzer
from app.incremental import IncrementalAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="AST Security Analyzer (CLI mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--project', type=Path, default=Path('.'),
                        help='Project root (default: current dir)')
    parser.add_argument('--file', type=Path,
                        help='Analyze a single file')
    parser.add_argument('--full', action='store_true',
                        help='Full analysis (ignore cache)')
    parser.add_argument('--incremental', action='store_true',
                        help='Incremental analysis (git diff)')
    parser.add_argument('--staged', action='store_true',
                        help='Analyze staged files (pre-commit)')
    parser.add_argument('--base', default='HEAD~1',
                        help='Git ref to compare against (default: HEAD~1)')
    parser.add_argument('--output', '-o', type=Path,
                        help='Save results to JSON file')
    parser.add_argument('--stats', action='store_true',
                        help='Print statistics')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Only output JSON')

    args = parser.parse_args()

    # ---- Single file mode ----
    if args.file:
        if not args.file.exists():
            print(f"File not found: {args.file}", file=sys.stderr)
            return 2
        code = args.file.read_text(encoding='utf-8')
        analyzer = DataFlowAnalyzer(code)
        findings = analyzer.analyze()
        results = {str(args.file): findings}
        _output(results, args)
        return 1 if findings else 0

    # ---- Incremental / full / staged ----
    analyzer = IncrementalAnalyzer(args.project)

    if args.staged:
        if not args.quiet:
            print("[mode] staged (pre-commit)")
        results = analyzer.analyze_staged()
    elif args.incremental:
        if not args.quiet:
            print(f"[mode] incremental (base={args.base})")
        results = analyzer.analyze_incremental(args.base)
    elif args.full:
        if not args.quiet:
            print("[mode] full")
        results = analyzer.analyze_full()
    else:
        parser.print_help()
        return 2

    if args.stats and not args.quiet:
        analyzer.print_stats()

    _output(results, args)

    total = sum(len(v) for v in results.values())
    return 1 if total > 0 else 0


def _output(results: dict, args):
    total = sum(len(v) for v in results.values())

    if args.output:
        args.output.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )
        if not args.quiet:
            print(f"[out] Saved: {args.output}")

    if not args.quiet:
        print(f"\n[result] Total findings: {total}")

    # Краткая сводка
    if not args.quiet and total > 0:
        for path, findings in results.items():
            if findings:
                print(f"  {path}: {len(findings)} findings")


if __name__ == '__main__':
    sys.exit(main())