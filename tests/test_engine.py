from copy import deepcopy
import unittest

from ssh_reachguard.engine import audit, build_fleet, compare, explain, is_blocked, owner_index, query_matrix, timestamp
from ssh_reachguard.parser import InputError
from support import load, pub, AT


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.raw = load('baseline.json')
        self.fleet = build_fleet(self.raw)
        self.at = timestamp(AT)

    def test_initial_audit_has_no_findings(self):
        self.assertEqual(audit(self.fleet, self.at)['findings'], [])

    def test_baseline_inventory_counts(self):
        s = audit(self.fleet, self.at)['summary']
        self.assertEqual((s['hosts'],s['accounts'],s['authorized_entries'],s['owners']), (2,3,3,3))

    def test_known_owner_can_authenticate(self):
        q = load('queries.json')['queries'][0]
        self.assertTrue(explain(self.fleet, q, self.at)['allowed_in_model'])

    def test_outside_ip_denied(self):
        self.assertFalse(explain(self.fleet, load('queries.json')['queries'][1], self.at)['allowed_in_model'])

    def test_port_forward_denied(self):
        self.assertFalse(explain(self.fleet, load('queries.json')['queries'][2], self.at)['allowed_in_model'])

    def test_forced_shell_denied(self):
        self.assertFalse(explain(self.fleet, load('queries.json')['queries'][3], self.at)['allowed_in_model'])

    def test_disabled_owner_denied(self):
        f = deepcopy(self.raw)
        f['hosts'][1]['accounts'][0]['authorized_keys'] = [pub('retired-contractor')]
        result = explain(build_fleet(f), {'owner':'retired-contractor','host':'web-01','account':'deployer','source_ip':'10.20.1.1'}, self.at)
        self.assertEqual(result['owner_status'], 'disabled')
        self.assertFalse(result['allowed_in_model'])

    def test_missing_owner_denied(self):
        query = {'owner': 'nobody', 'host': 'web-01', 'account': 'deployer','source_ip':'10.20.1.1'}
        self.assertFalse(explain(self.fleet, query, self.at)['allowed_in_model'])

    def test_missing_host_denied(self):
        query = {'owner': 'ci-deployer', 'host': 'host-missing', 'account': 'deployer','source_ip':'10.20.1.1'}
        self.assertFalse(explain(self.fleet, query, self.at)['allowed_in_model'])

    def test_missing_account_denied(self):
        query = {'owner': 'ci-deployer', 'host': 'web-01', 'account': 'root','source_ip':'10.20.1.1'}
        self.assertFalse(explain(self.fleet, query, self.at)['allowed_in_model'])

    def test_expired_key_denied(self):
        later = timestamp('2028-01-01T00:00:00Z')
        self.assertFalse(explain(self.fleet, load('queries.json')['queries'][0], later)['allowed_in_model'])

    def test_expiry_boundary(self):
        exactly = timestamp('2027-12-31T23:59:59Z')
        self.assertFalse(explain(self.fleet, load('queries.json')['queries'][0], exactly)['allowed_in_model'])

    def test_error_unknown_request_mode(self):
        q = dict(load('queries.json')['queries'][0], mode='raw-pty')
        with self.assertRaises(InputError): explain(self.fleet,q,self.at)

    def test_conflicting_query_expect_type(self):
        q = dict(load('queries.json')['queries'][0], expect=1)
        with self.assertRaises(InputError): explain(self.fleet,q,self.at)

    def test_all_example_assertions_pass(self):
        for q in load('queries.json')['queries']:
            r=explain(self.fleet,q,self.at)
            self.assertTrue(r['assertion_passed'],q)

    def test_candidate_introduces_access_and_risks(self):
        changes = compare(self.fleet, build_fleet(load('candidate-risky.json')), load('queries.json')['queries'], self.at)
        self.assertEqual(changes['summary']['introduced_access'], 2)
        self.assertGreaterEqual(changes['summary']['new_findings'], 8)
        self.assertEqual(changes['summary']['removed_access'], 0)

    def test_no_change_compare(self):
        changes = compare(self.fleet,self.fleet,load('queries.json')['queries'],self.at)
        self.assertEqual(changes['new_findings'], [])
        self.assertTrue(all(q['status']=='unchanged' for q in changes['access_changes']))

    def test_compare_marks_removed_access(self):
        smaller = deepcopy(self.raw)
        smaller['hosts'][1]['accounts'][0]['authorized_keys'] = []
        result = compare(self.fleet,build_fleet(smaller),load('queries.json')['queries'],self.at)
        self.assertEqual(result['summary']['removed_access'], 1)

    def test_candidate_risk_rules(self):
        report=audit(build_fleet(load('candidate-risky.json')),self.at)
        codes={f['rule'] for f in report['findings']}
        self.assertTrue({'SRG001','SRG002','SRG003','SRG004','SRG005','SRG006','SRG007','SRG008','SRG010'}<=codes)

    def test_risk_for_shared_identity(self):
        f=deepcopy(self.raw)
        f['owners'].append({'id':'fake-additional-owner','keys':[pub('ops-backup')]})
        findings=audit(build_fleet(f),self.at)['findings']
        self.assertTrue(any(x['rule']=='SRG009' for x in findings))

    def test_duplicate_account_key(self):
        f=deepcopy(self.raw)
        f['hosts'][0]['accounts'][0]['authorized_keys'] *= 2
        findings=audit(build_fleet(f),self.at)['findings']
        self.assertTrue(any(x['rule']=='SRG011' for x in findings))

    def test_wide_reach(self):
        f=deepcopy(self.raw)
        for n in range(4):
            f['hosts'].append({'name':f'extra-{n}','accounts':[{'name':'deployer','authorized_keys':[pub('ci-deployer')]}]})
        findings=audit(build_fleet(f),self.at,max_hosts=3)['findings']
        self.assertTrue(any(x['rule']=='SRG012' for x in findings))

    def test_audit_stable_id(self):
        first=audit(build_fleet(load('candidate-risky.json')),self.at)
        second=audit(build_fleet(load('candidate-risky.json')),self.at)
        self.assertEqual(first,second)

    def test_gate_threshold(self):
        findings=audit(build_fleet(load('candidate-risky.json')),self.at)['findings']
        self.assertTrue(is_blocked(findings,'high'))
        self.assertTrue(is_blocked(findings,'critical'))
        self.assertFalse(is_blocked(findings,'none'))
        self.assertFalse(is_blocked([], 'critical'))

    def test_keys_shared_between_hosts_do_not_require_multiple_owner_entries(self):
        self.assertEqual(len(owner_index(self.fleet)[next(iter(owner_index(self.fleet)))]), 1)

    def test_schema_reject_bool(self):
        f=deepcopy(self.raw);f['schema']=True
        with self.assertRaises(InputError):build_fleet(f)

    def test_unknown_root_field_rejected(self):
        f=deepcopy(self.raw);f['surprise']='bad'
        with self.assertRaises(InputError):build_fleet(f)

    def test_duplicate_host_rejected(self):
        f=deepcopy(self.raw);f['hosts'].append(f['hosts'][0])
        with self.assertRaises(InputError):build_fleet(f)

    def test_duplicate_account_rejected(self):
        f=deepcopy(self.raw);f['hosts'][0]['accounts'].append(f['hosts'][0]['accounts'][0])
        with self.assertRaises(InputError):build_fleet(f)

    def test_duplicate_owner_rejected(self):
        f=deepcopy(self.raw);f['owners'].append(f['owners'][0])
        with self.assertRaises(InputError):build_fleet(f)

    def test_bad_owner_status_rejected(self):
        f=deepcopy(self.raw);f['owners'][0]['status']='terminated'
        with self.assertRaises(InputError):build_fleet(f)

    def test_bad_host_critical_type_rejected(self):
        f=deepcopy(self.raw);f['hosts'][0]['critical']=1
        with self.assertRaises(InputError):build_fleet(f)

    def test_duplicate_key_for_owner_rejected(self):
        f=deepcopy(self.raw);f['owners'][0]['keys']*=2
        with self.assertRaises(InputError):build_fleet(f)

    def test_invalid_matrix_empty(self):
        with self.assertRaises(InputError):query_matrix({'schema':1,'queries':[]})

    def test_invalid_matrix_schema(self):
        with self.assertRaises(InputError):query_matrix({'schema':'1','queries':load('queries.json')['queries']})

    def test_timestamp_is_utc(self):
        self.assertEqual(timestamp(AT).utcoffset().total_seconds(),0)

    def test_timestamp_invalid(self):
        for value in ['2026-01-01', '2026-02-30T00:00:00Z','2026-01-01T00:00:00+00:00']:
            with self.subTest(value=value),self.assertRaises(InputError): timestamp(value)

    def test_max_hosts_invalid(self):
        with self.assertRaises(InputError):audit(self.fleet,self.at,0)

    def test_reject_invalid_owner_key_options(self):
        f=deepcopy(self.raw);f['owners'][0]['keys']=['restrict '+pub('ops-backup')]
        with self.assertRaises(InputError):build_fleet(f)

    def test_empty_host_accounts_valid(self):
        f=deepcopy(self.raw);f['hosts'][0]['accounts']=[]
        self.assertEqual(len(build_fleet(f).accounts),1)

    def test_query_cannot_include_unknown_fields(self):
        q=dict(load('queries.json')['queries'][0],secret='oops')
        with self.assertRaises(InputError):explain(self.fleet,q,self.at)


if __name__=='__main__': unittest.main()
