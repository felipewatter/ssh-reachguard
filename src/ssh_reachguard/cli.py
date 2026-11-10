"""Offline command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .engine import audit, build_fleet, compare, explain, is_blocked, query_matrix, timestamp
from .io import read_json, sarif, write_json
from .parser import InputError


def _args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog='sshreachguard', description='SSH authorized_keys reachability and regression gate (offline model).')
    p.add_argument('--version', action='version', version='SSH ReachGuard 1.0.0')
    sub = p.add_subparsers(dest='operation', required=True)
    for cmd in ('audit', 'explain', 'assert', 'compare'):
        t = sub.add_parser(cmd)
        if cmd == 'compare':
            t.add_argument('--baseline', required=True)
            t.add_argument('--candidate', required=True)
        else:
            t.add_argument('--fleet', required=True)
        if cmd in ('explain', 'assert', 'compare'):
            t.add_argument('--queries' if cmd != 'explain' else '--query', required=True)
        t.add_argument('--at', help='UTC time YYYY-MM-DDTHH:MM:SSZ (default: current UTC)')
        t.add_argument('--format', choices=['json', 'text'], default='text')
        t.add_argument('--output', help='Write full JSON report; refuses to overwrite')
        if cmd in ('audit', 'compare'):
            t.add_argument('--fail-on', choices=['none','low','medium','high','critical'], default='high')
            t.add_argument('--max-hosts', type=int, default=3)
            t.add_argument('--sarif', help='Write SARIF 2.1.0 findings, refuses to overwrite')
    return p.parse_args(argv)


def _summarize(report: dict, cmd: str) -> str:
    if cmd == 'audit':
        summary = report['summary']
        lines = [f"Hosts={summary['hosts']} accounts={summary['accounts']} entries={summary['authorized_entries']} owners={summary['owners']}",
                 f"Findings={summary['findings']} severity={summary['severity']}"]
        lines.extend(f"{f['severity'].upper()} {f['rule']} {f['host']}/{f['account']} {f['fingerprint']} {f['detail']}" for f in report['findings'])
        return '\n'.join(lines)
    if cmd == 'explain':
        return f"{report['owner']} -> {report['host']}/{report['account']} [{report['mode']}] : {'ALLOWED IN MODEL' if report['allowed_in_model'] else 'DENIED IN MODEL'} ({len(report['matching_entries'])} matching entries)"
    if cmd == 'assert':
        return f"Assertions: {report['passed']}/{report['total']} passed\n" + '\n'.join(
            f"#{i + 1}: {'PASS' if q['assertion_passed'] else 'FAIL'} expected={q['expected']} actual={q['allowed_in_model']}" for i, q in enumerate(report['results']))
    return f"Access introduced={report['summary']['introduced_access']} removed={report['summary']['removed_access']} new findings={report['summary']['new_findings']} resolved findings={report['summary']['resolved_findings']}"


def main(argv: list[str] | None = None) -> int:
    try:
        args = _args(argv)
        at = timestamp(args.at)
        if args.operation == 'compare':
            baseline = build_fleet(read_json(args.baseline))
            candidate = build_fleet(read_json(args.candidate))
            matrix = query_matrix(read_json(args.queries))
            report = compare(baseline, candidate, matrix, at, args.max_hosts)
            blocked = report['summary']['introduced_access'] > 0 or is_blocked(report['new_findings'], args.fail_on)
            report['gate'] = 'blocked' if blocked else 'passed'
            findings = report['new_findings']
        else:
            fleet = build_fleet(read_json(args.fleet))
            if args.operation == 'audit':
                report = audit(fleet, at, args.max_hosts)
                blocked = is_blocked(report['findings'], args.fail_on)
                report['gate'] = 'blocked' if blocked else 'passed'
                findings = report['findings']
            elif args.operation == 'explain':
                report = explain(fleet, read_json(args.query), at)
                blocked = 'assertion_passed' in report and not report['assertion_passed']
                findings = []
            else:
                matrix = query_matrix(read_json(args.queries))
                # An assertion matrix must define expectations for every query.
                if any('expect' not in q for q in matrix):
                    raise InputError('all assertion queries require an expect boolean')
                results = [explain(fleet, q, at) for q in matrix]
                passed = sum(r['assertion_passed'] for r in results)
                report = {'schema':1, 'total':len(results), 'passed':passed, 'results':results}
                blocked = passed != len(results)
                findings = []
        if hasattr(args, 'sarif') and args.sarif and args.output:
            from pathlib import Path
            if Path(args.sarif).absolute() == Path(args.output).absolute():
                raise InputError('--sarif and --output cannot use the same path')
        if args.output:
            write_json(args.output, report)
        if hasattr(args, 'sarif') and args.sarif:
            write_json(args.sarif, sarif(findings))
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) if args.format == 'json' else _summarize(report, args.operation))
        return 1 if blocked else 0
    except (InputError, OSError, TypeError) as exc:
        print(f'ERROR: {str(exc)[:200]}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
