"""Bounded JSON input, safe report output, SARIF for CI integrations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from .parser import InputError

MAX_INPUT_BYTES = 2_000_000
RULES = {
    'SRG001': 'Chave SSH não atribuída a proprietário conhecido',
    'SRG002': 'Root com chave amplamente irrestrita',
    'SRG003': 'Root sem limitação de origem',
    'SRG004': 'Port forwarding permitido para root',
    'SRG005': 'Root sem comando forçado',
    'SRG006': 'Root sem expiração de chave',
    'SRG007': 'Host crítico sem restrição de origem',
    'SRG008': 'Chave expirada ainda autorizada',
    'SRG009': 'Chave compartilhada por múltiplos proprietários',
    'SRG010': 'Proprietário desativado com acesso autorizado',
    'SRG011': 'Chave duplicada na mesma conta',
    'SRG012': 'Chave alcança mais hosts que o limite configurado',
}


def _distinct_pairs(items: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in items:
        if key in result:
            raise InputError(f'duplicate JSON key: {key[:40]}')
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InputError(f'invalid JSON constant: {value}')


def _ancestors_secure(path: Path) -> None:
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise InputError('symlink paths are forbidden')


def read_json(filename: str) -> Any:
    path = Path(filename)
    _ancestors_secure(path)
    try:
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
                raise InputError('input is not a regular bounded file')
            raw = stream.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise InputError('input is too large')
    except OSError as exc:
        raise InputError(f'cannot read input file: {exc.strerror or type(exc).__name__}') from exc
    try:
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_distinct_pairs, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise InputError(f'invalid UTF-8 JSON: {str(exc)[:120]}') from exc


def write_json(filename: str, report: Any) -> None:
    path = Path(filename)
    _ancestors_secure(path)
    data = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    if len(data) > 8_000_000:
        raise InputError('report exceeds size limit')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except OSError as exc:
        raise InputError(f'cannot create output file (will not overwrite): {exc.strerror or type(exc).__name__}') from exc


def sarif(findings: list[dict]) -> dict:
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'SSH ReachGuard', 'version': '1.0.0',
                                'informationUri': 'https://github.com/felipewatter/ssh-reachguard',
                                'rules': [{'id': code, 'shortDescription': {'text': desc}}
                                          for code, desc in RULES.items()]}},
            'results': [{
                'ruleId': f['rule'], 'level': ('error' if f['severity'] in ('critical', 'high') else 'warning'),
                'message': {'text': f['detail']},
                'partialFingerprints': {'sshReachGuard/v1': f['id']},
                'properties': {'severity': f['severity'], 'host': f['host'],
                               'account': f['account'], 'keyFingerprint': f['fingerprint']},
            } for f in findings],
        }],
    }
