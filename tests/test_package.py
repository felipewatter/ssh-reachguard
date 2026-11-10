from pathlib import Path
import hashlib
import io
import json
import zipfile
import unittest
import sys

from support import ROOT
sys.path.insert(0, str(ROOT / 'scripts'))


class PackagingTests(unittest.TestCase):
    def test_package_reproducible_bytes(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        from package import build
        first, digest1, count = build()
        bytes1 = first.read_bytes()
        second, digest2, _ = build()
        self.assertEqual(bytes1, second.read_bytes())
        self.assertEqual(digest1, digest2)
        self.assertGreaterEqual(count, 20)

    def test_package_integrity(self):
        from package import build
        archive, digest, count = build()
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
        checksum = (archive.parent / (archive.name + '.sha256')).read_text(encoding='ascii')
        self.assertEqual(checksum, f'{digest}  {archive.name}\n')
        with zipfile.ZipFile(archive, 'r') as z:
            self.assertEqual(z.testzip(),None)
            self.assertEqual(len(z.namelist()),count)

    def test_archive_excludes_sensitive_content_and_build_artifacts(self):
        from package import build
        archive,_,_=build()
        with zipfile.ZipFile(archive,'r') as z:
            for name in z.namelist():
                self.assertNotIn('__pycache__',name)
                self.assertNotIn('.egg-info',name)
                self.assertNotIn('dist/',name)
                self.assertNotIn('.venv/',name)
                self.assertNotIn('.pem',name)

    def test_zip_is_deterministic_metadata(self):
        from package import build
        archive,_,_=build()
        with zipfile.ZipFile(archive) as z:
            for meta in z.infolist():
                self.assertEqual(meta.date_time,(2020,1,1,0,0,0))
                self.assertEqual((meta.external_attr >> 16) & 0o777,0o644)

    def test_expected_docs_and_workflows_included(self):
        from package import build
        archive,_,_=build()
        with zipfile.ZipFile(archive) as z:
            names=set(z.namelist())
            self.assertTrue({'README.md','README.en.md','LICENSE','SECURITY.md','RELEASE_NOTES.md','.github/workflows/ci.yml',
                             'src/ssh_reachguard/parser.py','tests/test_engine.py'} <= names)


if __name__=='__main__':unittest.main()
