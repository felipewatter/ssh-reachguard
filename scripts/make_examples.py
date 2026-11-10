"""Developer-only synthetic public-key fixture creation. Never writes private keys."""
from pathlib import Path
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

root = Path(__file__).resolve().parents[1] / 'examples'

def pub():
    private = Ed25519PrivateKey.generate()
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode('ascii')

ops, ci, retired, orphan = (pub() for _ in range(4))
root_safe = f'restrict,from="10.20.0.0/16",command="/usr/local/sbin/backup",expiry-time="20271231235959Z" {ops} backup-robot'
root_risky = f'command="/usr/local/sbin/backup",expiry-time="20271231235959Z" {ops} backup-robot'
web_safe = f'restrict,from="10.20.0.0/16",expiry-time="20271231235959Z" {ci} deploy-key'
retired_key = f'restrict,from="10.20.0.0/16",expiry-time="20260101000000Z" {retired} disabled-user'

baseline = {
    'schema': 1,
    'owners': [
        {'id': 'ops-backup', 'keys': [ops]},
        {'id': 'ci-deployer', 'keys': [ci]},
        {'id': 'retired-contractor', 'keys': [retired], 'status': 'disabled'},
    ],
    'hosts': [
        {'name': 'bastion-01', 'critical': True, 'accounts': [
            {'name': 'root', 'authorized_keys': [root_safe]},
            {'name': 'deployer', 'authorized_keys': [web_safe]},
        ]},
        {'name': 'web-01', 'critical': False, 'accounts': [
            {'name': 'deployer', 'authorized_keys': [web_safe]},
        ]},
    ],
}
candidate = json.loads(json.dumps(baseline))
candidate['hosts'][0]['accounts'][0]['authorized_keys'] = [root_risky, orphan]
candidate['hosts'][1]['accounts'][0]['authorized_keys'].append(retired_key)
queries = {
    'schema': 1,
    'queries': [
        {'owner': 'ops-backup', 'host': 'bastion-01', 'account': 'root',
         'source_ip': '10.20.1.5', 'mode': 'authenticate', 'expect': True},
        {'owner': 'ops-backup', 'host': 'bastion-01', 'account': 'root',
         'source_ip': '198.51.100.15', 'mode': 'authenticate', 'expect': False},
        {'owner': 'ops-backup', 'host': 'bastion-01', 'account': 'root',
         'source_ip': '10.20.1.5', 'mode': 'tcp-forward', 'expect': False},
        {'owner': 'ops-backup', 'host': 'bastion-01', 'account': 'root',
         'source_ip': '10.20.1.5', 'mode': 'shell', 'expect': False},
        {'owner': 'ci-deployer', 'host': 'web-01', 'account': 'deployer',
         'source_ip': '10.20.2.1', 'mode': 'authenticate', 'expect': True},
        {'owner': 'retired-contractor', 'host': 'web-01', 'account': 'deployer',
         'source_ip': '10.20.1.5', 'mode': 'authenticate', 'expect': False},
    ],
}
for name, data in [('baseline.json', baseline), ('candidate-risky.json', candidate), ('queries.json', queries)]:
    (root / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
(root / 'query.json').write_text(json.dumps(queries['queries'][1], indent=2) + '\n', encoding='utf-8')
