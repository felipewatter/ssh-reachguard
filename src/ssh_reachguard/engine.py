"""Deterministic, offline SSH authorized-key reachability model."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any

from .parser import InputError, Key, TYPES, parse, source_matches

SEVERITY = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
KINDS = {'low', 'medium', 'high', 'critical'}
MODES = {'authenticate', 'shell', 'pty', 'tcp-forward', 'agent-forward', 'x11-forward'}


def _object(obj: Any, label: str, required: set[str], allowed: set[str]) -> dict:
    if not isinstance(obj, dict) or not required <= obj.keys() or set(obj) - allowed:
        raise InputError(f'unsupported fields or missing fields in {label}')
    return obj


def _name(text: Any, label: str) -> str:
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}', text):
        raise InputError(f'invalid {label}')
    return text


def _unique(items: list[str], label: str) -> None:
    if len(items) != len(set(items)):
        raise InputError(f'duplicate {label}')


def timestamp(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise InputError('time must be ISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZ')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InputError('invalid UTC timestamp') from exc


@dataclass(frozen=True)
class Entry:
    host: str
    host_critical: bool
    account: str
    key: Key
    ordinal: int


@dataclass
class Fleet:
    owners: dict[str, tuple[str, tuple[str, ...]]]
    entries: list[Entry]
    hosts: set[str]
    accounts: set[tuple[str, str]]


def build_fleet(obj: Any) -> Fleet:
    _object(obj, 'fleet', {'schema', 'owners', 'hosts'}, {'schema', 'owners', 'hosts'})
    if type(obj['schema']) is not int or obj['schema'] != 1:
        raise InputError('schema must equal 1')
    owners = obj['owners']
    hosts = obj['hosts']
    if not isinstance(owners, list) or not isinstance(hosts, list) or len(owners) > 500 or len(hosts) > 150:
        raise InputError('fleet size limit exceeded')
    names: list[str] = []
    owner_map: dict[str, tuple[str, tuple[str, ...]]] = {}
    for owner in owners:
        _object(owner, 'owner', {'id', 'keys'}, {'id', 'keys', 'status'})
        name = _name(owner['id'], 'owner id')
        status = owner.get('status', 'active')
        if status not in ('active', 'disabled'):
            raise InputError('owner status must be active/disabled')
        keys = owner['keys']
        if not isinstance(keys, list) or not keys or len(keys) > 100:
            raise InputError('owner keys must be a nonempty list (maximum 100)')
        fp: list[str] = []
        for key_line in keys:
            if not isinstance(key_line, str):
                raise InputError('public key must be a string')
            if not key_line.strip() or key_line.strip().split(maxsplit=1)[0] not in TYPES:
                raise InputError('owner public key must not have authorized_keys options')
            key = parse(key_line)
            # Owner registration is a bare public key, not a privilege policy.
            if any([key.restricted, key.forced_command, key.from_limited, key.expiry, not key.pty, not key.port_forward]):
                raise InputError('owner public keys must not contain authorized_keys options')
            fp.append(key.fingerprint)
        _unique(fp, 'owner key')
        owner_map[name] = (status, tuple(fp))
        names.append(name)
    _unique(names, 'owner')
    entries: list[Entry] = []
    seen_hosts: list[str] = []
    seen_accounts: set[tuple[str, str]] = set()
    for host in hosts:
        _object(host, 'host', {'name', 'accounts'}, {'name', 'accounts', 'critical'})
        host_name = _name(host['name'], 'host name')
        if type(host.get('critical', False)) is not bool:
            raise InputError('host critical must be boolean')
        critical = host.get('critical', False)
        seen_hosts.append(host_name)
        accounts = host['accounts']
        if not isinstance(accounts, list) or len(accounts) > 200:
            raise InputError('host accounts must be an array (maximum 200)')
        account_names: list[str] = []
        for account in accounts:
            _object(account, 'account', {'name', 'authorized_keys'}, {'name', 'authorized_keys'})
            account_name = _name(account['name'], 'account name')
            account_names.append(account_name)
            lines = account['authorized_keys']
            if not isinstance(lines, list) or len(lines) > 300:
                raise InputError('authorized_keys must be an array (maximum 300)')
            seen_accounts.add((host_name, account_name))
            for ix, line in enumerate(lines):
                # Blank lines and comments should be removed before producing fleet snapshots.
                if not isinstance(line, str):
                    raise InputError('authorized_keys line must be a string')
                entries.append(Entry(host_name, critical, account_name, parse(line), ix + 1))
        _unique(account_names, f'account in {host_name}')
    _unique(seen_hosts, 'host')
    if len(entries) > 12000:
        raise InputError('fleet key count exceeds 12000')
    return Fleet(owner_map, entries, set(seen_hosts), seen_accounts)


def owner_index(fleet: Fleet) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, (_, keys) in fleet.owners.items():
        for fp in keys:
            out.setdefault(fp, []).append(name)
    return {key: sorted(val) for key, val in out.items()}


def _finding(code: str, severity: str, host: str, account: str, fingerprint: str, detail: str) -> dict:
    identity = f'{code}:{host}:{account}:{fingerprint}'
    return {
        'id': hashlib.sha256(identity.encode()).hexdigest()[:20],
        'rule': code, 'severity': severity, 'host': host, 'account': account,
        'fingerprint': fingerprint, 'detail': detail,
    }


def audit(fleet: Fleet, at: datetime, max_hosts: int = 3) -> dict:
    if type(max_hosts) is not int or not (1 <= max_hosts <= 150):
        raise InputError('max_hosts must be between 1 and 150')
    findings: list[dict] = []
    index = owner_index(fleet)
    reach: dict[str, set[str]] = {}
    duplicates: dict[tuple[str, str, str], int] = {}
    for entry in fleet.entries:
        k = entry.key
        owner_names = index.get(k.fingerprint, [])
        reach.setdefault(k.fingerprint, set()).add(entry.host)
        duplicate_key = (entry.host, entry.account, k.fingerprint)
        duplicates[duplicate_key] = duplicates.get(duplicate_key, 0) + 1
        def add(code: str, sev: str, detail: str) -> None:
            findings.append(_finding(code, sev, entry.host, entry.account, k.fingerprint, detail))
        if not owner_names:
            add('SRG001', 'high', 'Chave autorizada sem proprietário no inventário')
        if entry.account == 'root':
            if not any((k.restricted, k.from_limited, k.forced_command, k.expiry)):
                add('SRG002', 'critical', 'Root com chave sem restrições de origem, comando, expiração ou restrict')
            if not k.from_limited:
                add('SRG003', 'high', 'Root sem restrição de origem numérica (from=)')
            if k.port_forward:
                add('SRG004', 'high', 'Root permite port forwarding pela política da chave')
            if not k.forced_command:
                add('SRG005', 'medium', 'Root sem comando forçado nesta chave')
            if k.expiry is None:
                add('SRG006', 'medium', 'Root sem expiração nesta chave')
        if entry.host_critical and not k.from_limited:
            add('SRG007', 'high', 'Host crítico sem restrição de origem numérica')
        if k.expiry is not None and at >= k.expiry:
            add('SRG008', 'medium', 'Chave expirada permanece no snapshot de autorizações')
        if len(owner_names) > 1:
            add('SRG009', 'high', 'Mesma chave atribuída a múltiplos proprietários')
        if any(fleet.owners[name][0] == 'disabled' for name in owner_names):
            add('SRG010', 'high', 'Proprietário desativado ainda possui uma chave autorizada')
    for (host, account, fp), count in duplicates.items():
        if count > 1:
            findings.append(_finding('SRG011', 'medium', host, account, fp, f'Chave repetida {count} vezes na conta'))
    for fp, host_names in reach.items():
        if len(host_names) > max_hosts:
            findings.append(_finding('SRG012', 'high', '*', '*', fp, f'Mesma chave alcança {len(host_names)} hosts; limite {max_hosts}'))
    findings = sorted({f['id']: f for f in findings}.values(), key=lambda f: (f['rule'], f['host'], f['account'], f['fingerprint']))
    counts = {severity: sum(f['severity'] == severity for f in findings) for severity in SEVERITY}
    return {'schema': 1, 'evaluated_at': at.isoformat().replace('+00:00', 'Z'),
            'summary': {'hosts': len(fleet.hosts), 'accounts': len(fleet.accounts),
                        'authorized_entries': len(fleet.entries), 'unique_keys': len(reach),
                        'owners': len(fleet.owners), 'findings': len(findings), 'severity': counts},
            'findings': findings}


def _query(obj: Any, fleet: Fleet) -> dict:
    _object(obj, 'query', {'owner', 'host', 'account', 'source_ip'},
            {'owner', 'host', 'account', 'source_ip', 'mode', 'expect'})
    for field in ('owner', 'host', 'account'):
        _name(obj[field], field)
    try:
        ipaddress.ip_address(obj['source_ip'])
    except (ValueError, TypeError) as exc:
        raise InputError('query source_ip must be numeric IPv4/IPv6') from exc
    mode = obj.get('mode', 'authenticate')
    if mode not in MODES:
        raise InputError('unsupported request mode')
    if 'expect' in obj and type(obj['expect']) is not bool:
        raise InputError('query expect must be boolean')
    if obj['owner'] not in fleet.owners or obj['host'] not in fleet.hosts or (obj['host'], obj['account']) not in fleet.accounts:
        # Allow a missing owner/host/account to evaluate to deny so comparisons can express additions.
        pass
    return {**obj, 'mode': mode}


def explain(fleet: Fleet, query: dict, at: datetime) -> dict:
    q = _query(query, fleet)
    owner = fleet.owners.get(q['owner'])
    allowed = []
    rejected = []
    if owner is not None and owner[0] == 'active':
        keys = set(owner[1])
        for entry in fleet.entries:
            if entry.host != q['host'] or entry.account != q['account'] or entry.key.fingerprint not in keys:
                continue
            key = entry.key
            reasons: list[str] = []
            if key.expiry and at >= key.expiry:
                reasons.append('expired')
            if not source_matches(key, q['source_ip']):
                reasons.append('source_denied')
            if q['mode'] == 'shell' and key.forced_command:
                reasons.append('forced_command')
            if q['mode'] == 'pty' and not key.pty:
                reasons.append('pty_disabled')
            if q['mode'] == 'tcp-forward' and not key.port_forward:
                reasons.append('port_forward_disabled')
            if q['mode'] == 'agent-forward' and not key.agent_forward:
                reasons.append('agent_forward_disabled')
            if q['mode'] == 'x11-forward' and not key.x11_forward:
                reasons.append('x11_forward_disabled')
            item = {'fingerprint': key.fingerprint, 'line': entry.ordinal,
                    'forced_command': key.forced_command,
                    'from_limited': key.from_limited, 'expiry': key.expiry.isoformat().replace('+00:00','Z') if key.expiry else None}
            if reasons:
                rejected.append({**item, 'reasons': reasons})
            else:
                allowed.append(item)
    # A matching principal possessing an authorized public key does not demonstrate
    # possession of the private key, successful SSH auth or live server configuration.
    result = {k: q[k] for k in ('owner', 'host', 'account', 'source_ip', 'mode')}
    result.update({'allowed_in_model': bool(allowed), 'matching_entries': allowed,
                   'rejected_entries': rejected, 'owner_status': owner[0] if owner else 'not_found',
                   'scope': 'declarative authorized_keys snapshot only'})
    if 'expect' in q:
        result['expected'] = q['expect']
        result['assertion_passed'] = q['expect'] == result['allowed_in_model']
    return result


def query_matrix(data: Any) -> list[dict]:
    _object(data, 'matrix', {'schema', 'queries'}, {'schema', 'queries'})
    if type(data['schema']) is not int or data['schema'] != 1:
        raise InputError('matrix schema must equal 1')
    queries = data['queries']
    if not isinstance(queries, list) or not (1 <= len(queries) <= 1000):
        raise InputError('matrix must contain 1..1000 queries')
    return queries


def compare(baseline: Fleet, candidate: Fleet, queries: list[dict], at: datetime, max_hosts: int = 3) -> dict:
    before = audit(baseline, at, max_hosts)
    after = audit(candidate, at, max_hosts)
    old = {f['id']: f for f in before['findings']}
    new = {f['id']: f for f in after['findings']}
    changes = []
    for ix, query in enumerate(queries):
        b = explain(baseline, query, at)
        a = explain(candidate, query, at)
        if not b['allowed_in_model'] and a['allowed_in_model']:
            status = 'introduced'
        elif b['allowed_in_model'] and not a['allowed_in_model']:
            status = 'removed'
        else:
            status = 'unchanged'
        changes.append({'query_index': ix, 'query': {k: a[k] for k in ('owner','host','account','source_ip','mode')},
                        'before': b['allowed_in_model'], 'after': a['allowed_in_model'], 'status': status})
    return {'schema': 1, 'evaluated_at': at.isoformat().replace('+00:00', 'Z'),
            'coverage': 'only supplied explicit query matrix',
            'new_findings': sorted((new[k] for k in new.keys() - old.keys()), key=lambda x: x['id']),
            'resolved_findings': sorted((old[k] for k in old.keys() - new.keys()), key=lambda x: x['id']),
            'persistent_findings': len(new.keys() & old.keys()), 'access_changes': changes,
            'summary': {'introduced_access': sum(x['status'] == 'introduced' for x in changes),
                        'removed_access': sum(x['status'] == 'removed' for x in changes),
                        'new_findings': len(new.keys() - old.keys()),
                        'resolved_findings': len(old.keys() - new.keys())}}


def is_blocked(findings: list[dict], fail_on: str) -> bool:
    if fail_on == 'none':
        return False
    if fail_on not in SEVERITY:
        raise InputError('invalid --fail-on severity')
    return any(SEVERITY[item['severity']] >= SEVERITY[fail_on] for item in findings)
