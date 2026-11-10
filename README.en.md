# SSH ReachGuard — English overview

**Offline SSH public-key access reachability, blast-radius indicators, and change-regression gate.**

![CI](https://github.com/felipewatter/ssh-reachguard/actions/workflows/ci.yml/badge.svg) · [Português (complete documentation)](README.md) · [MIT](LICENSE)

## Scope

This tool processes **explicit local JSON snapshots** of OpenSSH `authorized_keys` entries, their owners, hosts and target accounts. It computes SHA-256 public-key fingerprints, evaluates a narrow documented subset of key restrictions against an explicit source IP and timestamp, reports exposure indicators and compares a baseline with a candidate configuration using a finite access-test matrix.

**A positive result is not proof of live SSH access.** The tool never connects to servers, runs SSH, executes supplied commands or reads `sshd_config`. It cannot establish that the claimant controls a private key, that host access is available, or that any SSH user certificate, `Match` directive, PAM, root login or external restriction would allow the connection.

## Implemented functionality

- Structural decoding of OpenSSH public-key blobs for Ed25519, RSA (2048–16384-bit), ECDSA NIST curves and FIDO Ed25519. Computes `SHA256:` fingerprints from the raw binary SSH key blob. This is **not full cryptographic verification**.
- Restriction subset: `restrict`, `no-pty`/`pty`, forwarding restrictions and their reopeners, `command="..."`, numeric IP/CIDR-only `from="..."`, `expiry-time="YYYYMMDDHHMMSSZ"` (UTC). Unsupported options **fail closed** with exit status 2.
- Fleet inventory: active/disabled owners; critical hosts; per-account public keys; duplicate/unknown owner and key-reuse analysis.
- Query evaluation: `authenticate`, `shell`, `pty`, `tcp-forward`, `agent-forward`, `x11-forward`.
- 12 documented risk signals, deterministic findings IDs, configurable risk threshold, JSON and SARIF 2.1.0 reports.
- Delta analysis: added/resolved/persistent findings and introduced/removed access **for the explicitly supplied matrix only**. Any introduced access in the matrix blocks the compare gate even if `--fail-on none`.
- Zero external runtime dependencies; 2 MB input bound; duplicate-key JSON and symlink rejection; non-overwriting outputs; reproducible release ZIP + SHA-256.

## Install and run

```bash
git clone https://github.com/felipewatter/ssh-reachguard.git
cd ssh-reachguard
python -m pip install -e .
sshreachguard --version
sshreachguard audit --fleet examples/baseline.json --at 2026-11-10T12:00:00Z
sshreachguard assert --fleet examples/baseline.json --queries examples/queries.json --at 2026-11-10T12:00:00Z
sshreachguard explain --fleet examples/baseline.json --query examples/query.json --at 2026-11-10T12:00:00Z --format json
sshreachguard compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --at 2026-11-10T12:00:00Z --sarif report.sarif
```

To run without installation: `PYTHONPATH=src python -m ssh_reachguard ...` (PowerShell: `$env:PYTHONPATH='src'`).

**Exit codes:** `0` pass, `1` policy gate/assertion/access-regression failure, `2` invalid input, unsupported syntax or operation failure. The sample baseline has no findings; the risky candidate introduces two modeled access permissions and multiple risk signals.

## Security restrictions

Do not upload production keys, access inventories, host details or SSH private keys to public repositories. Test examples use synthetic public-only fixtures generated without saving private keys. This model cannot cover SSH certificates, revocation, DNS wildcard semantics, `sshd_config`, or auxiliary authentication systems. Reported owner IDs are declarations, **not** authenticated identities.

See [threat model](docs/THREAT_MODEL.md), [semantics](docs/SEMANTICS.md), [rules](docs/RULES.md), [architecture](docs/ARCHITECTURE.md) and [security policy](SECURITY.md).

## Test and release

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/package.py
```

CI covers Ubuntu and Windows with Python 3.11/3.13. Only a successful full matrix may publish the v1.0.0 release. **Release and CI badges describe real GitHub results only once the repository has been published and the workflows have run.**

Created by [Felipe Silva](https://github.com/felipewatter). MIT-licensed. This is an engineering/educational v1.0.0 release; it has not received an independent security audit.
