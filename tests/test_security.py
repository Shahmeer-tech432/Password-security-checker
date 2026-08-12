"""
Unit Tests for Security Educational Module & Privacy Compliance (src/security.py)
"""

import unittest
import hashlib
from src.security import SecurityEducationalModule


class TestSecurityEducationalModule(unittest.TestCase):

    def test_sha256_demo_digest(self):
        sample = "Cybersecurity Educational Test"
        result = SecurityEducationalModule.generate_sha256_demo(sample)
        
        expected_digest = hashlib.sha256(sample.encode('utf-8')).hexdigest()
        self.assertEqual(result["hex_digest"], expected_digest)
        self.assertEqual(result["algorithm"], "SHA-256")

    def test_empty_sample_demo(self):
        result = SecurityEducationalModule.generate_sha256_demo("")
        self.assertEqual(result["hex_digest"], "")
        self.assertIn("Enter sample text", result["status"])


if __name__ == "__main__":
    unittest.main()
