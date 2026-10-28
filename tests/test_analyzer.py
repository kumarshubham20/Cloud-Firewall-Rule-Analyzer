import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from analyzer import analyze_rules, load_rules, validate_rule, write_html_report


class AnalyzerTests(unittest.TestCase):
    def test_public_ssh_is_high(self):
        report = analyze_rules([{
            "source": "0.0.0.0/0", "protocol": "tcp", "port": 22, "action": "allow"
        }])
        self.assertEqual(report["findings"][0]["severity"], "HIGH")

    def test_private_ssh_not_flagged_as_public(self):
        report = analyze_rules([{
            "source": "10.0.0.0/8", "protocol": "tcp", "port": 22, "action": "allow"
        }])
        self.assertEqual(report["findings"], [])

    def test_public_https_is_informational(self):
        report = analyze_rules([{
            "source": "0.0.0.0/0", "protocol": "tcp", "port": 443, "action": "allow"
        }])
        self.assertEqual(report["findings"][0]["severity"], "INFO")

    def test_invalid_port_is_rejected(self):
        errors = validate_rule({
            "source": "0.0.0.0/0", "protocol": "tcp", "port": 70000, "action": "allow"
        }, 1)
        self.assertTrue(any("65535" in error for error in errors))

    def test_invalid_rule_is_counted(self):
        report = analyze_rules([{
            "source": "bad", "protocol": "tcp", "port": 22, "action": "allow"
        }])
        self.assertEqual(report["summary"]["invalid_rules"], 1)
        self.assertTrue(report["validation_errors"])

    def test_json_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps([{
                "source": "0.0.0.0/0", "protocol": "tcp", "port": 443, "action": "allow"
            }]), encoding="utf-8")
            self.assertEqual(len(load_rules(path)), 1)

    def test_port_range_detects_sensitive_port(self):
        report = analyze_rules([{
            "source": "0.0.0.0/0", "protocol": "tcp", "port": "20-25", "action": "allow"
        }])
        self.assertTrue(any("SSH" in finding["title"] for finding in report["findings"]))

    def test_html_report_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            write_html_report(analyze_rules([]), path)
            self.assertIn("Cloud Firewall Rule Analyzer", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
