from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples'
AT = '2026-11-10T12:00:00Z'

def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding='utf-8'))

def pub(owner='ops-backup'):
    fleet = load('baseline.json')
    return next(o['keys'][0] for o in fleet['owners'] if o['id'] == owner)
