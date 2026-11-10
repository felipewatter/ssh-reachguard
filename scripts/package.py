#!/usr/bin/env python3
"""Deterministic auditable source ZIP and SHA-256 manifest (stdlib only)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
FILENAME = 'ssh-reachguard-v1.0.0-source.zip'
HEAD = {'.gitignore', 'LICENSE', 'README.md', 'README.en.md', 'SECURITY.md',
        'CHANGELOG.md', 'CONTRIBUTING.md', 'RELEASE_NOTES.md', 'pyproject.toml'}
PREFIXES = ('src/', 'tests/', 'docs/', 'examples/', 'scripts/', '.github/workflows/', '.github/')
BLOCKED = ('__pycache__', '.egg-info', '/dist/', '/build/', '.pytest_cache')
FORBIDDEN = [rb'-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED|ED25519|) ?PRIVATE KEY-----',
             rb'ghp_[A-Za-z0-9]{36}', rb'github_pat_[A-Za-z0-9_]{30,}']


def candidates() -> list[Path]:
    result=[]
    for p in ROOT.rglob('*'):
        if p.is_symlink():
            raise ValueError('symlink is not allowed in source tree: ' + str(p))
        if not p.is_file():
            continue
        rel=p.relative_to(ROOT).as_posix()
        if any(part in rel for part in BLOCKED) or rel.startswith(('dist/', 'build/', '.git/')) or rel.endswith(('.pyc', '.pyo')):
            continue
        if rel in HEAD or rel.startswith(PREFIXES):
            if any(part.startswith('.') for part in p.relative_to(ROOT).parts) and not rel.startswith('.github/') and rel != '.gitignore':
                raise ValueError('unexpected hidden source artifact: ' + rel)
            result.append(p)
    return sorted(result, key=lambda p: p.relative_to(ROOT).as_posix())


def build() -> tuple[Path, str, int]:
    files=candidates()
    if len(files) < 15 or not (ROOT/'.github/workflows/ci.yml') in files:
        raise ValueError('required release source files are missing')
    DIST.mkdir(exist_ok=True)
    zipfile_path=DIST/FILENAME
    temp=DIST/(FILENAME + '.tmp')
    try:
        with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for file in files:
                rel=file.relative_to(ROOT).as_posix()
                data=file.read_bytes()
                if len(data) > 2_000_000:
                    raise ValueError(f'oversized source file: {rel}')
                if any(re.search(pattern, data) for pattern in FORBIDDEN):
                    raise ValueError(f'potential credential material found: {rel}')
                info=zipfile.ZipInfo(rel, (2020,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED
                info.external_attr=0o100644 << 16
                info.create_system=3
                output.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temp,zipfile_path)
    finally:
        temp.unlink(missing_ok=True)
    digest=hashlib.sha256(zipfile_path.read_bytes()).hexdigest()
    (DIST/(FILENAME+'.sha256')).write_text(digest+'  '+FILENAME+'\n', encoding='ascii')
    return zipfile_path,digest,len(files)


if __name__ == '__main__':
    try:
        p,digest,num=build()
        print(f'{num} source files | {p.stat().st_size} bytes | SHA-256 {digest}')
    except (OSError, ValueError) as exc:
        print(f'PACKAGING ERROR: {exc}',file=sys.stderr)
        raise SystemExit(1)
