"""
Password Security Analyzer - Cryptographically Secure Generator

Uses Python's built-in `secrets` module to generate passwords with true OS-provided
cryptographic randomness (OS CSPRNG / /dev/urandom).

PRIVACY & SECURITY GUARANTEE:
- Uses `secrets.choice` and `secrets.SystemRandom()` exclusively.
- Never uses standard unseeded pseudorandom generator (`random`).
- Guarantees representation across all selected character sets.
"""

import secrets
import string
from typing import List


class PasswordGenerator:
    """
    Cryptographically secure password generator using `secrets` standard library module.
    """

    UPPERCASE = string.ascii_uppercase
    LOWERCASE = string.ascii_lowercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    @classmethod
    def generate(
        cls,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_numbers: bool = True,
        include_symbols: bool = True
    ) -> str:
        """
        Generates a cryptographically secure random password.

        Args:
            length: Password length (8 to 64)
            include_uppercase: Include A-Z
            include_lowercase: Include a-z
            include_numbers: Include 0-9
            include_symbols: Include special characters

        Returns:
            Generated password string.

        Raises:
            ValueError: If length is out of range or no character sets are selected.
        """
        if length < 8 or length > 64:
            raise ValueError("Password length must be between 8 and 64 characters.")

        categories: List[str] = []
        if include_uppercase:
            categories.append(cls.UPPERCASE)
        if include_lowercase:
            categories.append(cls.LOWERCASE)
        if include_numbers:
            categories.append(cls.DIGITS)
        if include_symbols:
            categories.append(cls.SYMBOLS)

        if not categories:
            raise ValueError("At least one character category must be selected.")

        if length < len(categories):
            raise ValueError(f"Length ({length}) must be at least equal to selected categories count ({len(categories)}).")

        # Guarantee at least 1 character from each selected category
        password_chars: List[str] = [secrets.choice(cat) for cat in categories]

        # Combine all allowed characters for remaining fill
        combined_pool = "".join(categories)
        remaining_length = length - len(password_chars)

        for _ in range(remaining_length):
            password_chars.append(secrets.choice(combined_pool))

        # Securely shuffle using CSPRNG
        sys_random = secrets.SystemRandom()
        sys_random.shuffle(password_chars)

        return "".join(password_chars)
