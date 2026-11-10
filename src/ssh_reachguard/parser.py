"""Strict, deliberately partial OpenSSH authorized_keys parser (no SSH execution)."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import struct

MAX_LINE = 8192
TYPES = {
    'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'sk-ssh-ed25519@openssh.com',
}
BARE_OPTIONS = {
    'restrict', 'no-pty', 'no-agent-forwarding', 'no-port-forwarding',
    'no-X11-forwarding', 'no-user-rc', 'pty', 'agent-forwarding',
    'port-forwarding', 'X11-forwarding', 'user-rc',
}
VALUE_OPTIONS = {'command', 'from', 'expiry-time'}

class InputError(ValueError):
    """Invalid or unsupported data; callers must fail closed."""

@dataclass(frozen=True)
class Key:
    fingerprint: str
    kind: str
    restricted: bool
    pty: bool
    port_forward: bool
    agent_forward: bool
    x11_forward: bool
    user_rc: bool
    forced_command: bool
    from_positive: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    from_negative: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    expiry: datetime | None

    @property
    def from_limited(self) -> bool:
        return bool(self.from_positive) and all(net.prefixlen > 0 for net in self.from_positive)


def _tokenize(line: str) -> list[str]:
    """Split authorized_keys fields outside quoted option strings."""
    tokens: list[str] = []
    current: list[str] = []
    quote = False
    escape = False
    for ch in line:
        if escape:
            # Preserve escaping for option-value processing below.
            current.extend(('\\', ch))
            escape = False
        elif ch == '\\' and quote:
            escape = True
        elif ch == '"':
            quote = not quote
            current.append(ch)
        elif ch.isspace() and not quote:
            if current:
                tokens.append(''.join(current))
                current = []
        else:
            current.append(ch)
    if quote or escape:
        raise InputError('unclosed or invalid quoted option')
    if current:
        tokens.append(''.join(current))
    return tokens


def _options(raw: str) -> dict[str, str | None]:
    parts: list[str] = []
    item: list[str] = []
    quoted = False
    escaped = False
    for ch in raw:
        if escaped:
            item.extend(('\\', ch))
            escaped = False
        elif ch == '\\' and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
            item.append(ch)
        elif ch == ',' and not quoted:
            parts.append(''.join(item))
            item = []
        else:
            item.append(ch)
    if quoted or escaped:
        raise InputError('malformed quoted option')
    parts.append(''.join(item))
    found: dict[str, str | None] = {}
    for part in parts:
        name, sep, value = part.partition('=')
        if name in found:
            raise InputError('duplicate option')
        if not sep:
            if name not in BARE_OPTIONS:
                raise InputError(f'unsupported option: {name[:40]}')
            found[name] = None
        else:
            if name not in VALUE_OPTIONS:
                raise InputError(f'unsupported option: {name[:40]}')
            if not (len(value) >= 2 and value[0] == value[-1] == '"'):
                raise InputError('option values must be quoted')
            content = value[1:-1]
            if '\\' in content:
                content = re.sub(r'\\(["\\])', r'\1', content)
                if '\\' in content:
                    raise InputError('unsupported escape sequence')
            if not content or any(ord(ch) < 32 for ch in content):
                raise InputError('empty or control-character option value')
            found[name] = content
    return found


def _read_ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise InputError('truncated public key')
    size = struct.unpack_from('>I', data, offset)[0]
    end = offset + 4 + size
    if end > len(data) or size > 8192:
        raise InputError('invalid SSH string length')
    return data[offset + 4:end], end


def _validate_blob(kind: str, raw: str) -> bytes:
    if len(raw) > 12000 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', raw):
        raise InputError('invalid public-key base64')
    try:
        blob = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InputError('invalid public-key base64') from exc
    if not blob or base64.b64encode(blob).decode('ascii').rstrip('=') != raw.rstrip('='):
        raise InputError('noncanonical public-key base64')
    key_type, pos = _read_ssh_string(blob, 0)
    if key_type != kind.encode('ascii'):
        raise InputError('SSH key type does not match its encoded payload')
    if kind == 'ssh-ed25519':
        pub, pos = _read_ssh_string(blob, pos)
        if len(pub) != 32:
            raise InputError('invalid Ed25519 public key length')
    elif kind == 'sk-ssh-ed25519@openssh.com':
        pub, pos = _read_ssh_string(blob, pos)
        application, pos = _read_ssh_string(blob, pos)
        if len(pub) != 32 or not application.startswith(b'ssh:') or len(application) > 255:
            raise InputError('invalid FIDO SSH key fields')
    elif kind == 'ssh-rsa':
        exponent, pos = _read_ssh_string(blob, pos)
        modulus, pos = _read_ssh_string(blob, pos)
        if not exponent or not modulus or exponent[0] & 0x80 or modulus[0] & 0x80:
            raise InputError('invalid RSA mpint')
        e = int.from_bytes(exponent, 'big')
        n = int.from_bytes(modulus, 'big')
        if e < 3 or not e & 1 or n.bit_length() < 2048 or n.bit_length() > 16384 or not n & 1:
            raise InputError('unsupported or weak RSA public key')
    else:
        curve, pos = _read_ssh_string(blob, pos)
        point, pos = _read_ssh_string(blob, pos)
        bits = int(kind.removeprefix('ecdsa-sha2-nistp'))
        expected_len = {256: 65, 384: 97, 521: 133}[bits]
        if curve != f'nistp{bits}'.encode() or len(point) != expected_len or point[0] != 4:
            raise InputError('invalid ECDSA curve/point shape')
    if pos != len(blob):
        raise InputError('unexpected bytes after public key')
    return blob


def parse(line: str) -> Key:
    if not isinstance(line, str) or not line or len(line.encode('utf-8')) > MAX_LINE:
        raise InputError('invalid authorized_keys line length')
    if '\x00' in line or '\r' in line or '\n' in line:
        raise InputError('only one authorized_keys line is allowed')
    tokens = _tokenize(line.strip())
    if len(tokens) < 2:
        raise InputError('invalid authorized_keys line')
    if tokens[0] in TYPES:
        raw_opts = None
        keytype, keydata = tokens[0], tokens[1]
    elif len(tokens) >= 3 and tokens[1] in TYPES:
        raw_opts = tokens[0]
        keytype, keydata = tokens[1], tokens[2]
    else:
        raise InputError('unsupported or missing SSH public-key type')
    opts = _options(raw_opts) if raw_opts else {}
    blob = _validate_blob(keytype, keydata)
    restricted = 'restrict' in opts
    def enabled(name: str) -> bool:
        positive = name
        negative = 'no-' + name
        if positive in opts and negative in opts:
            raise InputError('conflicting restriction options')
        return positive in opts or (not restricted and negative not in opts)
    positive: list[ipaddress._BaseNetwork] = []
    negative: list[ipaddress._BaseNetwork] = []
    if 'from' in opts:
        for item in str(opts['from']).split(','):
            neg = item.startswith('!')
            token = item[1:] if neg else item
            if not token or '%' in token:
                raise InputError('unsupported from= pattern')
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise InputError('from= accepts numeric IP/CIDR only') from exc
            (negative if neg else positive).append(network)
        if not positive:
            raise InputError('from= must include a positive IP/CIDR')
    expiry = None
    if 'expiry-time' in opts:
        value = str(opts['expiry-time'])
        if not re.fullmatch(r'\d{14}Z', value):
            raise InputError('expiry-time requires YYYYMMDDHHMMSSZ (UTC)')
        try:
            expiry = datetime.strptime(value, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise InputError('invalid expiry-time') from exc
    if 'command' in opts and not str(opts['command']).strip():
        raise InputError('empty forced command')
    return Key(
        fingerprint='SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('='),
        kind=keytype,
        restricted=restricted,
        pty=enabled('pty'),
        port_forward=enabled('port-forwarding'),
        agent_forward=enabled('agent-forwarding'),
        x11_forward=enabled('X11-forwarding'),
        user_rc=enabled('user-rc'),
        forced_command='command' in opts,
        from_positive=tuple(positive),
        from_negative=tuple(negative),
        expiry=expiry,
    )


def source_matches(key: Key, source_ip: str) -> bool:
    try:
        source = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise InputError('source_ip must be a valid numeric IP address') from exc
    return (
        not key.from_positive or any(source in subnet for subnet in key.from_positive)
    ) and not any(source in subnet for subnet in key.from_negative)
