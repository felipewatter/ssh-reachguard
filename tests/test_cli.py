import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from ssh_reachguard.cli import main
from ssh_reachguard.io import read_json, sarif, write_json
from ssh_reachguard.parser import InputError
from support import EXAMPLES, AT, load


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_audit_baseline_success(self):
        code, text, _ = self.run_cli('audit','--fleet',str(EXAMPLES/'baseline.json'),'--at',AT)
        self.assertEqual(code,0); self.assertIn('Findings=0',text)

    def test_audit_risky_blocked(self):
        code,text,_=self.run_cli('audit','--fleet',str(EXAMPLES/'candidate-risky.json'),'--at',AT)
        self.assertEqual(code,1);self.assertIn('SRG002',text)

    def test_audit_none_threshold_no_block(self):
        code,_,_=self.run_cli('audit','--fleet',str(EXAMPLES/'candidate-risky.json'),'--at',AT,'--fail-on','none')
        self.assertEqual(code,0)

    def test_compare_access_expansion_block(self):
        code,text,_=self.run_cli('compare','--baseline',str(EXAMPLES/'baseline.json'),'--candidate',str(EXAMPLES/'candidate-risky.json'),'--queries',str(EXAMPLES/'queries.json'),'--at',AT)
        self.assertEqual(code,1);self.assertIn('Access introduced=2',text)

    def test_compare_never_ignores_access_expansion_when_none(self):
        code,_,_=self.run_cli('compare','--baseline',str(EXAMPLES/'baseline.json'),'--candidate',str(EXAMPLES/'candidate-risky.json'),'--queries',str(EXAMPLES/'queries.json'),'--at',AT,'--fail-on','none')
        self.assertEqual(code,1)

    def test_explain_denied(self):
        code,text,_=self.run_cli('explain','--fleet',str(EXAMPLES/'baseline.json'),'--query',str(EXAMPLES/'query.json'),'--at',AT)
        self.assertEqual(code,0);self.assertIn('DENIED IN MODEL',text)

    def test_assert_matrix_pass(self):
        code,text,_=self.run_cli('assert','--fleet',str(EXAMPLES/'baseline.json'),'--queries',str(EXAMPLES/'queries.json'),'--at',AT)
        self.assertEqual(code,0);self.assertIn('6/6 passed',text)

    def test_assert_matrix_fails_on_mismatch(self):
        matrix=load('queries.json')
        matrix['queries'][0]['expect']=False
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fail.json';target.write_text(json.dumps(matrix))
            code,text,_=self.run_cli('assert','--fleet',str(EXAMPLES/'baseline.json'),'--queries',str(target),'--at',AT)
            self.assertEqual(code,1); self.assertIn('FAIL',text)

    def test_audit_json_format(self):
        code,text,_=self.run_cli('audit','--fleet',str(EXAMPLES/'baseline.json'),'--at',AT,'--format','json')
        self.assertEqual(code,0);self.assertEqual(json.loads(text)['summary']['findings'],0)

    def test_report_files_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            report=Path(temp)/'audit.json';sarif_path=Path(temp)/'audit.sarif'
            common=['audit','--fleet',str(EXAMPLES/'baseline.json'),'--at',AT,'--output',str(report),'--sarif',str(sarif_path)]
            code,_,_=self.run_cli(*common)
            self.assertEqual(code,0)
            self.assertTrue(report.exists());self.assertTrue(sarif_path.exists())
            self.assertEqual(json.loads(sarif_path.read_text())['version'],'2.1.0')
            code,_,err=self.run_cli(*common)
            self.assertEqual(code,2);self.assertIn('will not overwrite',err)

    def test_input_output_same_file_forbidden_by_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fleet.json';target.write_text((EXAMPLES/'baseline.json').read_text())
            code,_,err=self.run_cli('audit','--fleet',str(target),'--output',str(target),'--at',AT)
            self.assertEqual(code,2)
            self.assertEqual(json.loads(target.read_text())['schema'],1)

    def test_bad_json_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'bad.json';target.write_text('{bad')
            code,_,err=self.run_cli('audit','--fleet',str(target))
            self.assertEqual(code,2); self.assertIn('invalid UTF-8 JSON',err)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'bad.json';target.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(InputError):read_json(str(target))

    def test_nan_json_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'bad.json';target.write_text('{"x":NaN}')
            with self.assertRaises(InputError):read_json(str(target))

    def test_large_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'huge.json';target.write_bytes(b' ' * 2_000_001)
            with self.assertRaises(InputError):read_json(str(target))

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            alias=Path(temp)/'alias.json'
            try: alias.symlink_to(EXAMPLES/'baseline.json')
            except (OSError,NotImplementedError): self.skipTest('symlinks unavailable')
            with self.assertRaises(InputError):read_json(str(alias))

    def test_symlink_output_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'target.json';target.write_text('original')
            alias=Path(temp)/'alias.json'
            try: alias.symlink_to(target)
            except (OSError,NotImplementedError): self.skipTest('symlinks unavailable')
            with self.assertRaises(InputError):write_json(str(alias),{'test':1})
            self.assertEqual(target.read_text(),'original')

    def test_max_hosts_negative_exit_two(self):
        code,_,err=self.run_cli('audit','--fleet',str(EXAMPLES/'baseline.json'),'--at',AT,'--max-hosts','-1')
        self.assertEqual(code,2);self.assertIn('max_hosts',err)

    def test_sarif_contains_stable_fingerprints(self):
        report=[{'rule':'SRG001','severity':'high','detail':'test', 'id':'stableid', 'host':'h', 'account':'a', 'fingerprint':'fp'}]
        value=sarif(report)
        self.assertEqual(value['runs'][0]['results'][0]['partialFingerprints']['sshReachGuard/v1'],'stableid')

    def test_no_private_public_key_blob_in_json_report(self):
        code,text,_=self.run_cli('audit','--fleet',str(EXAMPLES/'candidate-risky.json'),'--at',AT,'--format','json')
        self.assertEqual(code,1)
        public_b64=load('baseline.json')['owners'][0]['keys'][0].split()[1]
        self.assertNotIn(public_b64,text)


if __name__ == '__main__':unittest.main()
