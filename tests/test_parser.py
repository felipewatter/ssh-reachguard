import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import random
import struct
import unittest

from ssh_reachguard.parser import InputError, parse, source_matches
from support import pub

PUBLIC = pub()


def ssh_string(data):
    return struct.pack('>I', len(data)) + data


class ParserTests(unittest.TestCase):
    def test_ed25519_fingerprint_matches_raw_wire_hash(self):
        key = parse(PUBLIC)
        blob = base64.b64decode(PUBLIC.split()[1])
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        self.assertEqual(key.fingerprint, expected)

    def test_unrestricted_defaults(self):
        k = parse(PUBLIC)
        self.assertTrue(k.pty and k.port_forward and k.agent_forward and k.x11_forward)
        self.assertFalse(k.forced_command)

    def test_restrict_disables_all_flags(self):
        k = parse('restrict ' + PUBLIC)
        self.assertFalse(k.pty or k.port_forward or k.agent_forward or k.x11_forward or k.user_rc)

    def test_restrict_selective_pty_reenable(self):
        k = parse('restrict,pty ' + PUBLIC)
        self.assertTrue(k.pty)
        self.assertFalse(k.port_forward)

    def test_restrict_selective_port_reenable(self):
        k = parse('restrict,port-forwarding ' + PUBLIC)
        self.assertTrue(k.port_forward)
        self.assertFalse(k.agent_forward)

    def test_no_port_forwarding(self):
        self.assertFalse(parse('no-port-forwarding ' + PUBLIC).port_forward)

    def test_no_agent_forwarding(self):
        self.assertFalse(parse('no-agent-forwarding ' + PUBLIC).agent_forward)

    def test_no_pty(self):
        self.assertFalse(parse('no-pty ' + PUBLIC).pty)

    def test_no_x11_forwarding(self):
        self.assertFalse(parse('no-X11-forwarding ' + PUBLIC).x11_forward)

    def test_no_user_rc(self):
        self.assertFalse(parse('no-user-rc ' + PUBLIC).user_rc)

    def test_multiple_flags(self):
        k = parse('no-pty,no-X11-forwarding,no-agent-forwarding ' + PUBLIC)
        self.assertFalse(k.pty or k.x11_forward or k.agent_forward)

    def test_forced_command_and_comma_inside_quotes(self):
        k = parse('restrict,command="/usr/bin/echo hello,world" ' + PUBLIC)
        self.assertTrue(k.forced_command)

    def test_quoted_whitespace(self):
        k = parse('command="/bin/echo a b" ' + PUBLIC)
        self.assertTrue(k.forced_command)

    def test_escaped_quote_in_command(self):
        k = parse('command="/bin/echo \\"hi\\"" ' + PUBLIC)
        self.assertTrue(k.forced_command)

    def test_ipv4_source(self):
        k = parse('from="192.0.2.0/24" ' + PUBLIC)
        self.assertTrue(source_matches(k, '192.0.2.17'))
        self.assertFalse(source_matches(k, '198.51.100.1'))

    def test_ipv6_source(self):
        k = parse('from="2001:db8::/32" ' + PUBLIC)
        self.assertTrue(source_matches(k, '2001:db8:1::2'))
        self.assertFalse(source_matches(k, '2001:dead::1'))

    def test_ipv4_exclusion(self):
        k = parse('from="10.0.0.0/8,!10.9.0.0/16" ' + PUBLIC)
        self.assertTrue(source_matches(k, '10.8.1.2'))
        self.assertFalse(source_matches(k, '10.9.1.2'))

    def test_ipv4_host_source(self):
        k = parse('from="10.20.1.1" ' + PUBLIC)
        self.assertTrue(source_matches(k, '10.20.1.1'))
        self.assertFalse(source_matches(k, '10.20.1.2'))

    def test_expiry_utc(self):
        k = parse('expiry-time="20271231235959Z" ' + PUBLIC)
        self.assertEqual(k.expiry, datetime(2027,12,31,23,59,59,tzinfo=timezone.utc))

    def test_key_comment_is_ignored(self):
        self.assertEqual(parse(PUBLIC+' comment ignored').fingerprint, parse(PUBLIC).fingerprint)

    def test_whitespace_between_tokens(self):
        keytype, value = PUBLIC.split()
        self.assertEqual(parse(f'{keytype}\t{value}').fingerprint, parse(PUBLIC).fingerprint)

    def test_malformed_or_unsupported_options_are_rejected(self):
        cases = [
            'environment="X=Y"', 'permitopen="host:22"', 'cert-authority',
            'from="*.example.org"', 'from="!10.0.0.0/8"', 'from=""',
            'from="10.0.0.0/8,example.net"', 'expiry-time="20271231"',
            'expiry-time="20271301235959Z"', 'command=""', 'command="x',
            'from=10.0.0.0/8', 'no-pty,pty', 'restrict,restrict',
            'command="a",command="b"', 'port-forwarding,no-port-forwarding',
            'from="10.0.0.1%eth0"', 'tunnel="0"', 'verify-required',
        ]
        for opt in cases:
            with self.subTest(option=opt), self.assertRaises(InputError):
                parse(opt + ' ' + PUBLIC)

    def test_reject_newline_cr_and_null(self):
        for line in [PUBLIC+'\n', PUBLIC+'\r', PUBLIC+'\x00']:
            with self.subTest(kind=repr(line[-1])), self.assertRaises(InputError):
                parse(line)

    def test_reject_empty_and_oversized(self):
        for line in ['', ' ', 'x'*8193]:
            with self.subTest(length=len(line)), self.assertRaises(InputError):
                parse(line)

    def test_reject_unsupported_keytype(self):
        with self.assertRaises(InputError):
            parse('ssh-dss '+PUBLIC.split()[1])

    def test_reject_mismatched_blob_type(self):
        with self.assertRaises(InputError):
            parse('ssh-rsa '+PUBLIC.split()[1])

    def test_reject_invalid_base64(self):
        with self.assertRaises(InputError):
            parse(PUBLIC[:-5]+'$$$')

    def test_reject_blob_trailing_bytes(self):
        kind, b64 = PUBLIC.split()
        malformed = base64.b64encode(base64.b64decode(b64) + b'garbage').decode()
        with self.assertRaises(InputError):
            parse(f'{kind} {malformed}')

    def test_reject_wrong_ed25519_key_length(self):
        invalid = ssh_string(b'ssh-ed25519') + ssh_string(b'\x11'*31)
        with self.assertRaises(InputError):
            parse('ssh-ed25519 '+base64.b64encode(invalid).decode())

    def test_reject_oversized_ssh_string(self):
        bad = ssh_string(b'ssh-ed25519') + struct.pack('>I', 2**24) + b'\x11'*8
        with self.assertRaises(InputError):
            parse('ssh-ed25519 '+base64.b64encode(bad).decode())

    def test_reject_invalid_ip(self):
        with self.assertRaises(InputError):
            source_matches(parse(PUBLIC), 'example.com')

    def test_same_key_with_options_has_identical_fingerprint(self):
        self.assertEqual(parse(PUBLIC).fingerprint, parse('restrict '+PUBLIC).fingerprint)

    def test_catch_all_from_not_considered_meaningfully_limited(self):
        k = parse('from="0.0.0.0/0" ' + PUBLIC)
        self.assertFalse(k.from_limited)
        self.assertTrue(source_matches(k, '198.51.100.1'))

    def test_mixed_catch_all_from_not_considered_limited(self):
        k = parse('from="10.0.0.0/8,0.0.0.0/0" ' + PUBLIC)
        self.assertFalse(k.from_limited)

    def test_structural_rsa_with_valid_modulus_size(self):
        exponent = ssh_string(b'\x01\x00\x01')
        modulus = ssh_string(b'\x00\x80' + b'\x03' * 254 + b'\x05')
        blob = ssh_string(b'ssh-rsa') + exponent + modulus
        self.assertEqual(parse('ssh-rsa '+base64.b64encode(blob).decode()).kind, 'ssh-rsa')

    def test_structural_rsa_weak_1024_rejected(self):
        exponent = ssh_string(b'\x03')
        modulus = ssh_string(b'\x00\x80'+b'\x03'*126+b'\x05')
        blob = ssh_string(b'ssh-rsa')+exponent+modulus
        with self.assertRaises(InputError):
            parse('ssh-rsa '+base64.b64encode(blob).decode())

    def test_structural_ecdsa_p256(self):
        kind=b'ecdsa-sha2-nistp256'
        blob=ssh_string(kind)+ssh_string(b'nistp256')+ssh_string(b'\x04'+b'\x01'*64)
        self.assertEqual(parse(kind.decode()+' '+base64.b64encode(blob).decode()).kind,kind.decode())

    def test_invalid_ecdsa_curve_rejected(self):
        kind=b'ecdsa-sha2-nistp256'
        blob=ssh_string(kind)+ssh_string(b'nistp384')+ssh_string(b'\x04'+b'\x01'*64)
        with self.assertRaises(InputError):
            parse(kind.decode()+' '+base64.b64encode(blob).decode())

    def test_structural_fido_ed25519(self):
        kind=b'sk-ssh-ed25519@openssh.com'
        blob=ssh_string(kind)+ssh_string(b'\x11'*32)+ssh_string(b'ssh:test')
        self.assertEqual(parse(kind.decode()+' '+base64.b64encode(blob).decode()).kind,kind.decode())

    def test_bad_fido_application_rejected(self):
        kind=b'sk-ssh-ed25519@openssh.com'
        blob=ssh_string(kind)+ssh_string(b'\x11'*32)+ssh_string(b'not-ssh')
        with self.assertRaises(InputError):
            parse(kind.decode()+' '+base64.b64encode(blob).decode())

    def test_parser_fuzz_mutations_do_not_throw_unexpected_exception(self):
        rnd = random.Random(12345)
        alphabet = 'abcdef=,\\"\t \n\r0123456789!?@#$%^&*()'+PUBLIC
        for _ in range(1200):
            base = PUBLIC if rnd.randint(0, 1) else 'restrict,from="10.0.0.0/8" '+PUBLIC
            pos = rnd.randrange(len(base))
            candidate = base[:pos] + rnd.choice(alphabet) + base[pos+1:]
            try:
                parse(candidate)
            except InputError:
                pass


if __name__ == '__main__':
    unittest.main()
