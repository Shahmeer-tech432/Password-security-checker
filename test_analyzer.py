"""
Unit Tests for Password Analysis Engine (src/analyzer.py)
"""

import unittest
from src.analyzer import PasswordAnalyzer, AnalysisResult


class TestPasswordAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_empty_password(self):
        result = self.analyzer.analyze("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.strength_label, "VERY WEAK")
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertEqual(result.password_len, 0)

    def test_common_passwords(self):
        common_samples = ["123456", "password", "qwerty", "admin", "letmein", "password123"]
        for sample in common_samples:
            result = self.analyzer.analyze(sample)
            self.assertLessEqual(result.score, 25, f"Common password '{sample}' scored too high: {result.score}")
            self.assertIn(result.strength_label, ["VERY WEAK", "WEAK"])
            # Verify common password checklist item is FAIL
            common_item = next(item for item in result.checklist if item["name"] == "Not a common password")
            self.assertEqual(common_item["status"], "FAIL")

    def test_repeated_characters(self):
        result = self.analyzer.analyze("aaaaaaaaaaaa")
        rep_item = next(item for item in result.checklist if item["name"] == "No excessive repetition")
        self.assertEqual(rep_item["status"], "WARNING")
        self.assertTrue(any("identical" in w or "character" in w for w in result.warnings))

    def test_sequential_patterns(self):
        result = self.analyzer.analyze("abcdefg1234")
        pattern_item = next(item for item in result.checklist if item["name"] == "Not an obvious pattern")
        self.assertEqual(pattern_item["status"], "WARNING")

    def test_medium_password(self):
        result = self.analyzer.analyze("Password123!")
        self.assertGreaterEqual(result.score, 40)
        self.assertIn(result.strength_label, ["FAIR", "GOOD"])

    def test_very_strong_passphrase(self):
        result = self.analyzer.analyze("Correct-Horse-Battery-Staple-2026!#")
        self.assertGreaterEqual(result.score, 85)
        self.assertIn(result.strength_label, ["STRONG", "VERY STRONG"])
        self.assertGreater(result.entropy_bits, 100.0)

    def test_checklist_structure(self):
        result = self.analyzer.analyze("TestPass123!")
        self.assertEqual(len(result.checklist), 8)
        names = [item["name"] for item in result.checklist]
        expected_names = [
            "Length", "Lowercase letters", "Uppercase letters", "Numbers",
            "Special characters", "No excessive repetition",
            "Not a common password", "Not an obvious pattern"
        ]
        self.assertEqual(names, expected_names)


if __name__ == "__main__":
    unittest.main()
