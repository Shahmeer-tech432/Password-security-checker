"""
Unit Tests for Cryptographically Secure Password Generator (src/generator.py)
"""

import unittest
import string
from src.generator import PasswordGenerator


class TestPasswordGenerator(unittest.TestCase):

    def test_default_generation(self):
        pwd = PasswordGenerator.generate(length=16)
        self.assertEqual(len(pwd), 16)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in PasswordGenerator.SYMBOLS for c in pwd))

    def test_custom_lengths(self):
        for length in [8, 12, 24, 32, 64]:
            pwd = PasswordGenerator.generate(length=length)
            self.assertEqual(len(pwd), length)

    def test_category_selection(self):
        # Digits only
        pwd_digits = PasswordGenerator.generate(length=12, include_uppercase=False, include_lowercase=False, include_numbers=True, include_symbols=False)
        self.assertTrue(all(c.isdigit() for c in pwd_digits))

        # Uppercase & Symbols only
        pwd_custom = PasswordGenerator.generate(length=14, include_uppercase=True, include_lowercase=False, include_numbers=False, include_symbols=True)
        self.assertTrue(all(c in string.ascii_uppercase or c in PasswordGenerator.SYMBOLS for c in pwd_custom))

    def test_invalid_parameters(self):
        # Length too short
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(length=5)

        # Length too long
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(length=100)

        # No categories selected
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(length=16, include_uppercase=False, include_lowercase=False, include_numbers=False, include_symbols=False)

    def test_randomness_uniqueness(self):
        # Multiple generations should produce distinct passwords
        passwords = {PasswordGenerator.generate(length=20) for _ in range(50)}
        self.assertEqual(len(passwords), 50)


if __name__ == "__main__":
    unittest.main()
