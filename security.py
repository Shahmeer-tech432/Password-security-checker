"""
Password Security Analyzer - Educational Security & Hashing Module

Provides educational hash generation (SHA-256) for sample demonstration texts,
explains cryptographic concepts, and ensures zero-storage security compliance.

CRITICAL SECURITY PRINCIPLE:
This module NEVER automatically hashes or persists actual analyzed passwords.
Educational hash functions operate strictly on sample text explicitly typed into
the educational demonstration tool.
"""

import hashlib
from typing import Dict, Any


class SecurityEducationalModule:
    """
    Educational reference module explaining cryptographic hashing vs encryption
    and modern key-stretching algorithms.
    """

    HASHING_VS_ENCRYPTION_TEXT = (
        "🔐 HASHING (One-Way Function)\n"
        "• Converts input data into a unique fixed-length mathematical digest.\n"
        "• Deterministic (same input always produces identical hash).\n"
        "• Irreversible by design (you cannot 'decrypt' a hash back to plaintext).\n"
        "• Purpose: Verifying integrity and storing password verifiers safely.\n\n"
        "🔑 ENCRYPTION (Two-Way Function)\n"
        "• Transforms plaintext data into ciphertext using a secret key.\n"
        "• Reversible with the correct secret key.\n"
        "• Purpose: Confidentiality of data in transit or at rest."
    )

    MODERN_PASSWORD_HASHING_TEXT = (
        "🛡️ MODERN PASSWORD HASHING ALGORITHMS\n\n"
        "Fast cryptographic hash functions (like raw SHA-256 or MD5) are NOT recommended for storing user passwords!\n"
        "Attacking GPUs can calculate billions of SHA-256 hashes per second.\n\n"
        "Modern systems use dedicated, computationally expensive Key Derivation Functions (KDFs):\n\n"
        "1. Argon2 (Winner of Password Hashing Competition)\n"
        "   - Argon2id is the modern industry standard, providing memory-hard protection against GPU/ASIC attacks.\n\n"
        "2. bcrypt\n"
        "   - Configurable work factor (cost factor) to slow down brute-force attacks.\n\n"
        "3. scrypt\n"
        "   - Memory-hard algorithm designed to make hardware parallel attacks expensive.\n\n"
        "4. PBKDF2 (Password-Based Key Derivation Function 2)\n"
        "   - NIST approved, uses thousands of iterative hashing rounds (e.g. SHA-256)."
    )

    @staticmethod
    def generate_sha256_demo(sample_text: str) -> Dict[str, str]:
        """
        Generates SHA-256 hash digest for an educational sample string.

        Args:
            sample_text: Explicit text provided in the educational hash demo tab.

        Returns:
            Dict containing input length, digest hex, and algorithm details.
        """
        if not sample_text:
            return {
                "algorithm": "SHA-256",
                "input_length": "0 bytes",
                "hex_digest": "",
                "bit_length": "256 bits (64 hex characters)",
                "status": "Enter sample text to compute hash"
            }

        encoded_data = sample_text.encode('utf-8')
        digest = hashlib.sha256(encoded_data).hexdigest()

        return {
            "algorithm": "SHA-256",
            "input_length": f"{len(encoded_data)} bytes",
            "hex_digest": digest,
            "bit_length": "256 bits (64 hex characters)",
            "status": "Computed successfully (Educational demonstration only)"
        }
