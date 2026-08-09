# test_credential_scanner.py

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import credential_scanner as scanner

class ScannerTestCase(unittest.TestCase):
    def scan_line(self, text, filename="test.py"):
        with redirect_stdout(io.StringIO()):
            return scanner.scan_line(Path(filename), 1, text)


class PrivateKeyTests(ScannerTestCase):
    
    def test_complete_private_key_block_is_detected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "private.pem"
            path.write_text(
                "-----BEGIN PRIVATE KEY-----\n"
                "ExamplePrivateKeyMaterial1234567890\n"
                "-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                findings = scanner.scan_file(path)

            self.assertEqual(len(findings), 1)
            self.assertIn("Type: private_key", findings[0])
    
    def test_private_key_marker_inside_comment_does_not_start_block(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "example.py"
            path.write_text(
                "# Example marker: -----BEGIN PRIVATE KEY-----\n"
                'password = "RealSecretAfterComment123"\n',
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                findings = scanner.scan_file(path)

            self.assertEqual(len(findings), 1)
            self.assertIn("RealSecretAfterComment123", findings[0])


class SelfExclusionTests(ScannerTestCase):
    
    def test_scanner_source_is_excluded(self):
        self.assertTrue(scanner.is_scanner_file(Path(scanner.__file__)))


    def test_scanner_output_is_excluded(self):
        output = Path(scanner.__file__).resolve().parent / "credentials.txt"
        self.assertTrue(scanner.is_scanner_file(output))

    def test_unrelated_credentials_txt_is_not_excluded(self):
        with TemporaryDirectory() as directory:
            unrelated = Path(directory) / "credentials.txt"
            self.assertFalse(scanner.is_scanner_file(unrelated))
    
class FileSelectionTests(ScannerTestCase):

    def test_env_variant_is_interesting(self):
        self.assertTrue(scanner.is_interesting_file(Path(".env.production")))

    def test_similar_env_name_is_not_interesting(self):
        self.assertFalse(scanner.is_interesting_file(Path(".environment")))

    def test_pem_and_key_extensions_are_allowed(self):
        self.assertTrue(scanner.should_scan_file(Path("server.pem")))
        self.assertTrue(scanner.should_scan_file(Path("private.key")))


class DetectionTests(ScannerTestCase):
    
    def test_plain_password_is_detected(self):
        findings = self.scan_line('password = "RealSecret12345"')
        self.assertEqual(len(findings), 1)
        self.assertIn("RealSecret12345", findings[0])

    def test_prefixed_password_is_detected(self):
        findings = self.scan_line('DB_PASSWORD = "DatabaseSecret12345"')
        self.assertEqual(len(findings), 1)

    def test_aws_secret_access_key_is_detected(self):
        findings = self.scan_line('AWS_SECRET_ACCESS_KEY = "AwsSecretValue123456"')
        self.assertEqual(len(findings), 1)
        self.assertIn("SECRET_ACCESS_KEY", findings[0].upper())

    def test_connection_uri_is_detected(self):
        findings = self.scan_line(
            'DATABASE_URL = "postgresql://dbuser:RealDatabasePass123@localhost/app"'
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Type: connection_uri", findings[0])

    def test_connection_uri_placeholder_is_ignored(self):
        findings = self.scan_line(
            'DATABASE_URL = "postgresql://user:password@localhost/app"'
        )
        self.assertEqual(findings, [])


class FalsePositiveTests(ScannerTestCase):
    
    def test_placeholder_password_is_ignored(self):
        findings = self.scan_line('password = "password"')
        self.assertEqual(findings, [])

    def test_environment_reference_is_ignored(self):
        findings = self.scan_line('password = os.getenv("PASSWORD")')
        self.assertEqual(findings, [])
        
    def test_python_type_annotation_is_ignored(self):
        findings = self.scan_line("password: str")
        self.assertEqual(findings, [])

    def test_parenthesized_config_literal_is_not_discarded(self):
        findings = self.scan_line("password=(ActualSecret12345)", "test.cfg")
        self.assertEqual(len(findings), 1)

    def test_parenthesized_python_expression_is_ignored(self):
        findings = self.scan_line(
            'password=(self.password.encode("utf-8"))',
            "test.py",
        )
        self.assertEqual(findings, [])

    def test_powershell_subexpression_is_ignored(self):
        findings = self.scan_line(
            "password=$(Get-SecretFromVault)",
            "test.ps1",
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
