"""
Password Security Analyzer - Analysis Engine

Provides transparent scoring, Shannon entropy calculation, character diversity analysis,
common password detection, and structural pattern detection.

PRIVACY GUARANTEE:
All processing happens purely in-memory. Inputs are evaluated dynamically
and never saved, stored, logged, or transmitted.
"""

import math
import re
import string
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


# Local dataset of common weak passwords and prefixes (Educational sample)
COMMON_PASSWORDS: set = {
    "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "password123", "admin", "welcome", "letmein", "iloveyou", "sunshine",
    "princess", "dragon", "football", "monkey", "master", "654321",
    "password1", "123123", "admin123", "root", "toor", "pass1234",
    "charlie", "donald", "shadow", "abc123", "p@ssword", "p@ssw0rd",
    "111111", "000000", "quertyuiop", "asdfghjkl", "zxcvbnm"
}

# Keyboard row patterns to detect predictable spatial walks
KEYBOARD_PATTERNS: list = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "qazwsxedc", "rfvtgbyhn", "ujmkol"
]


@dataclass
class AnalysisResult:
    """Dataclass holding the result of a password security analysis."""
    password_len: int
    score: int                            # 0 to 100
    strength_label: str                   # VERY WEAK, WEAK, FAIR, GOOD, STRONG, VERY STRONG
    entropy_bits: float                   # Shannon entropy estimate
    checklist: List[Dict[str, str]]       # Requirement items with PASS, WARNING, or FAIL
    warnings: List[str]                   # List of specific warning messages
    recommendations: List[str]           # Dynamic security advice
    char_counts: Dict[str, int]           # Lowercase, uppercase, digit, symbol counts
    crack_time_info: List[Dict[str, str]] = None  # Crack-time estimates (no password data)

    def __post_init__(self):
        if self.crack_time_info is None:
            self.crack_time_info = []


class PasswordAnalyzer:
    """
    Engine for evaluating password security based on multi-factor heuristics:
    - Length scaling
    - Character diversity
    - Shannon Entropy
    - Common password & variation matching
    - Repetition and sequential pattern penalties
    """

    def __init__(self):
        self.symbols = set(string.punctuation)

    def analyze(self, password: str) -> AnalysisResult:
        """
        Main analysis pipeline. Accepts a password string and returns a comprehensive AnalysisResult.
        """
        if not password:
            return AnalysisResult(
                password_len=0,
                score=0,
                strength_label="VERY WEAK",
                entropy_bits=0.0,
                checklist=[
                    {"name": "Length", "status": "FAIL", "detail": "0 characters (Empty)"},
                    {"name": "Lowercase letters", "status": "FAIL", "detail": "Missing"},
                    {"name": "Uppercase letters", "status": "FAIL", "detail": "Missing"},
                    {"name": "Numbers", "status": "FAIL", "detail": "Missing"},
                    {"name": "Special characters", "status": "FAIL", "detail": "Missing"},
                    {"name": "No excessive repetition", "status": "PASS", "detail": "No repetition"},
                    {"name": "Not a common password", "status": "PASS", "detail": "No common password detected"},
                    {"name": "Not an obvious pattern", "status": "PASS", "detail": "No pattern detected"}
                ],
                warnings=["Password field is empty."],
                recommendations=["Enter a password to analyze its strength, or use the generator."],
                char_counts={"lowercase": 0, "uppercase": 0, "digits": 0, "symbols": 0}
            )

        length = len(password)
        lower_cnt = sum(1 for c in password if c.islower())
        upper_cnt = sum(1 for c in password if c.isupper())
        digit_cnt = sum(1 for c in password if c.isdigit())
        symbol_cnt = sum(1 for c in password if c in self.symbols or (not c.isalnum() and not c.isspace()))
        
        char_counts = {
            "lowercase": lower_cnt,
            "uppercase": upper_cnt,
            "digits": digit_cnt,
            "symbols": symbol_cnt
        }

        # Calculate pool size & Shannon Entropy
        pool_size = 0
        if lower_cnt > 0: pool_size += 26
        if upper_cnt > 0: pool_size += 26
        if digit_cnt > 0: pool_size += 10
        if symbol_cnt > 0: pool_size += 32

        entropy_bits = length * math.log2(pool_size) if pool_size > 0 else 0.0

        # Run heuristic checks
        is_common, common_msg = self._check_common_password(password)
        has_pattern, pattern_msg = self._check_patterns(password)
        has_repetition, rep_msg = self._check_repetition(password)

        # Build requirement checklist
        checklist = []

        # 1. Length
        if length >= 16:
            checklist.append({"name": "Length", "status": "PASS", "detail": f"{length} characters (Excellent length)"})
        elif length >= 12:
            checklist.append({"name": "Length", "status": "PASS", "detail": f"{length} characters (Good length)"})
        elif length >= 8:
            checklist.append({"name": "Length", "status": "WARNING", "detail": f"{length} characters (Consider 12-16+ characters)"})
        else:
            checklist.append({"name": "Length", "status": "FAIL", "detail": f"{length} characters (Too short - min 8 required)"})

        # 2. Lowercase
        if lower_cnt > 0:
            checklist.append({"name": "Lowercase letters", "status": "PASS", "detail": f"Found ({lower_cnt})"})
        else:
            checklist.append({"name": "Lowercase letters", "status": "FAIL", "detail": "Missing lowercase (a-z)"})

        # 3. Uppercase
        if upper_cnt > 0:
            checklist.append({"name": "Uppercase letters", "status": "PASS", "detail": f"Found ({upper_cnt})"})
        else:
            checklist.append({"name": "Uppercase letters", "status": "FAIL", "detail": "Missing uppercase (A-Z)"})

        # 4. Numbers
        if digit_cnt > 0:
            checklist.append({"name": "Numbers", "status": "PASS", "detail": f"Found ({digit_cnt})"})
        else:
            checklist.append({"name": "Numbers", "status": "FAIL", "detail": "Missing digits (0-9)"})

        # 5. Special Characters
        if symbol_cnt > 0:
            checklist.append({"name": "Special characters", "status": "PASS", "detail": f"Found ({symbol_cnt})"})
        else:
            checklist.append({"name": "Special characters", "status": "FAIL", "detail": "Missing special symbols"})

        # 6. No excessive repetition
        if has_repetition:
            checklist.append({"name": "No excessive repetition", "status": "WARNING", "detail": rep_msg})
        else:
            checklist.append({"name": "No excessive repetition", "status": "PASS", "detail": "No repetitive character clusters"})

        # 7. Not a common password
        if is_common:
            checklist.append({"name": "Not a common password", "status": "FAIL", "detail": common_msg})
        else:
            checklist.append({"name": "Not a common password", "status": "PASS", "detail": "Passes dictionary check"})

        # 8. Not an obvious pattern
        if has_pattern:
            checklist.append({"name": "Not an obvious pattern", "status": "WARNING", "detail": pattern_msg})
        else:
            checklist.append({"name": "Not an obvious pattern", "status": "PASS", "detail": "No obvious sequential/keyboard pattern"})

        # Compute Score (0 - 100)
        score, warnings, recommendations = self._calculate_score_and_recommendations(
            length=length,
            lower_cnt=lower_cnt,
            upper_cnt=upper_cnt,
            digit_cnt=digit_cnt,
            symbol_cnt=symbol_cnt,
            entropy_bits=entropy_bits,
            is_common=is_common,
            common_msg=common_msg,
            has_pattern=has_pattern,
            pattern_msg=pattern_msg,
            has_repetition=has_repetition,
            rep_msg=rep_msg
        )

        # Label assignment based on final score
        strength_label = self._score_to_label(score)

        return AnalysisResult(
            password_len=length,
            score=score,
            strength_label=strength_label,
            entropy_bits=round(entropy_bits, 1),
            checklist=checklist,
            warnings=warnings,
            recommendations=recommendations,
            char_counts=char_counts,
            crack_time_info=self._estimate_crack_time(entropy_bits)
        )

    def _estimate_crack_time(self, entropy_bits: float) -> List[Dict[str, str]]:
        """
        Estimate brute-force time for several real-world attack scenarios.
        Uses only the entropy value — no password data.

        Returns list of dicts: [{"scenario", "speed", "time", "icon"}]
        """
        if entropy_bits <= 0:
            instant = self._s2h(0)
            return [
                {"scenario": "All scenarios", "speed": "any",
                 "time": "Instantly", "icon": "\u26a0"},
            ]

        # Average guesses = 2^(entropy-1)  (50% of keyspace on average)
        avg_guesses = 2 ** max(0, entropy_bits - 1)

        scenarios = [
            ("Online  (rate-limited)",    10,                "\U0001f310"),
            ("Online  (unprotected API)", 1_000,             "\U0001f4bb"),
            ("Offline (bcrypt / Argon2)", 100_000,           "\U0001f6e1"),
            ("Offline (SHA-256 GPU)",     10_000_000_000,    "\U0001f4a5"),
            ("Cluster (nation-state)",    1_000_000_000_000, "\U0001f30d"),
        ]

        results = []
        for name, speed, icon in scenarios:
            secs = avg_guesses / speed
            results.append({
                "scenario": name,
                "speed": self._format_speed(speed),
                "time": self._s2h(secs),
                "icon": icon,
            })
        return results

    @staticmethod
    def _format_speed(n: int) -> str:
        if n >= 1_000_000_000_000: return f"{n // 1_000_000_000_000:,}T/s"
        if n >= 1_000_000_000:     return f"{n // 1_000_000_000:,}B/s"
        if n >= 1_000_000:         return f"{n // 1_000_000:,}M/s"
        if n >= 1_000:             return f"{n // 1_000:,}K/s"
        return f"{n}/s"

    @staticmethod
    def _s2h(seconds: float) -> str:
        """Convert seconds to a human-readable time string."""
        if seconds < 1:                      return "Instantly"
        if seconds < 60:                     return f"{seconds:.1f} sec"
        if seconds < 3_600:                  return f"{seconds/60:.1f} min"
        if seconds < 86_400:                 return f"{seconds/3_600:.1f} hrs"
        if seconds < 86_400 * 30:            return f"{seconds/86_400:.1f} days"
        if seconds < 86_400 * 365:           return f"{seconds/(86_400*30):.1f} months"
        if seconds < 86_400 * 365 * 1e3:    return f"{seconds/(86_400*365):.1f} years"
        if seconds < 86_400 * 365 * 1e6:    return f"{seconds/(86_400*365*1e3):.2g}K years"
        if seconds < 86_400 * 365 * 1e9:    return f"{seconds/(86_400*365*1e6):.2g}M years"
        if seconds < 86_400 * 365 * 1e12:   return f"{seconds/(86_400*365*1e9):.2g}B years"
        return "> heat death of universe"

    def _check_common_password(self, password: str) -> Tuple[bool, str]:
        """Detect exact common passwords and simple variations."""
        lower_pass = password.lower().strip()
        
        # Exact match
        if lower_pass in COMMON_PASSWORDS:
            return True, "Exact match with a known commonly used password"

        # Simple suffix variations like password1, admin123!
        stripped = re.sub(r'[\d!@#$%^&*()_+=\-\[\]{}|;:,.<>?/\s]+$', '', lower_pass)
        if stripped in COMMON_PASSWORDS and len(stripped) >= 4:
            return True, f"Based on common weak base word '{stripped}'"

        # Leetspeak simple replacements (e.g. p@ssword -> password)
        leet_clean = lower_pass.translate(str.maketrans("@1035$", "aieoss"))
        if leet_clean in COMMON_PASSWORDS:
            return True, "Common password using simple substitution (e.g., @ for a)"

        return False, ""

    def _check_patterns(self, password: str) -> Tuple[bool, str]:
        """Detect sequential numbers/letters and keyboard row walks."""
        lower_pass = password.lower()

        # Keyboard walk checks (>= 4 consecutive chars)
        for pattern in KEYBOARD_PATTERNS:
            for i in range(len(pattern) - 3):
                sub = pattern[i:i+4]
                if sub in lower_pass:
                    return True, f"Contains predictable keyboard sequence ('{sub}')"

        # Sequential numbers (e.g. 1234, 5678, 9876)
        digits = "01234567890"
        digits_rev = "09876543210"
        for i in range(len(digits) - 3):
            sub = digits[i:i+4]
            if sub in lower_pass:
                return True, f"Contains sequential number sequence ('{sub}')"
            sub_r = digits_rev[i:i+4]
            if sub_r in lower_pass:
                return True, f"Contains reverse number sequence ('{sub_r}')"

        # Sequential letters (e.g. abcd, zyxw)
        alpha = "abcdefghijklmnopqrstuvwxyz"
        alpha_rev = "zyxwvutsrqponmlkjihgfedcba"
        for i in range(len(alpha) - 3):
            sub = alpha[i:i+4]
            if sub in lower_pass:
                return True, f"Contains alphabetical sequence ('{sub}')"
            sub_r = alpha_rev[i:i+4]
            if sub_r in lower_pass:
                return True, f"Contains reverse alphabetical sequence ('{sub_r}')"

        # Repeated block pattern (e.g. abcabc, 123123)
        if len(password) >= 6:
            half = len(password) // 2
            if password[:half] == password[half:half*2]:
                return True, "Contains repeating block structure"

        return False, ""

    def _check_repetition(self, password: str) -> Tuple[bool, str]:
        """Detect 3+ identical consecutive characters or high character frequency dominance."""
        # 3+ identical consecutive chars (e.g. aaa)
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True, f"Contains 3 or more identical consecutive characters ('{password[i]*3}')"

        # Character dominance check (single character makes up > 40% of password if length >= 6)
        if len(password) >= 6:
            freq: Dict[str, int] = {}
            for char in password:
                freq[char] = freq.get(char, 0) + 1
            max_char_count = max(freq.values())
            if max_char_count / len(password) > 0.40:
                return True, "Over 40% of password consists of the same character"

        return False, ""

    def _calculate_score_and_recommendations(
        self,
        length: int,
        lower_cnt: int,
        upper_cnt: int,
        digit_cnt: int,
        symbol_cnt: int,
        entropy_bits: float,
        is_common: bool,
        common_msg: str,
        has_pattern: bool,
        pattern_msg: str,
        has_repetition: bool,
        rep_msg: str
    ) -> Tuple[int, List[str], List[str]]:
        """Calculate numerical score (0-100), warnings list, and security recommendations."""
        score = 0
        warnings = []
        recommendations = []

        # 1. Base Score from Length (Up to 55 points)
        if length < 8:
            score += length * 2.5           # 0 to 17.5
        elif length <= 11:
            score += 20 + (length - 8) * 4   # 20 to 32
        elif length <= 15:
            score += 35 + (length - 11) * 3  # 35 to 47
        else:
            score += 48 + min(7, (length - 15) * 1) # 48 to 55

        # 2. Diversity Points (Up to 30 points)
        types_count = sum(1 for c in [lower_cnt, upper_cnt, digit_cnt, symbol_cnt] if c > 0)
        score += types_count * 6             # Up to 24 points for all 4 types

        if lower_cnt > 0 and upper_cnt > 0:
            score += 2
        if symbol_cnt >= 2:
            score += 4

        # 3. Entropy Bonus (Up to 15 points)
        if entropy_bits >= 80:
            score += 15
        elif entropy_bits >= 60:
            score += 10
        elif entropy_bits >= 40:
            score += 5

        # 4. Apply Deductions & Hard Caps
        if is_common:
            warnings.append(f"⚠ {common_msg}")
            score -= 50
            score = min(score, 15)          # Cap common passwords at max 15 points

        if has_pattern:
            warnings.append(f"⚠ {pattern_msg}")
            score -= 15

        if has_repetition:
            warnings.append(f"⚠ {rep_msg}")
            score -= 10

        if length < 8:
            warnings.append("⚠ Password is too short (< 8 characters).")
            score = min(score, 25)          # Cap short passwords at max 25 points

        # Clamp score between 0 and 100
        final_score = max(0, min(100, int(score)))

        # Build dynamic recommendations
        if length < 12:
            recommendations.append("Increase length: Aim for at least 12–16+ characters or use a multi-word passphrase.")
        if lower_cnt == 0:
            recommendations.append("Add lowercase letters (a–z).")
        if upper_cnt == 0:
            recommendations.append("Add uppercase letters (A–Z).")
        if digit_cnt == 0:
            recommendations.append("Include digits (0–9) to increase entropy.")
        if symbol_cnt == 0:
            recommendations.append("Add special characters (e.g. !@#$%) for maximum resistance against dictionary attacks.")
        if is_common:
            recommendations.append("Avoid using known passwords or dictionary words. Choose a unique combination.")
        if has_pattern:
            recommendations.append("Avoid predictable sequence walks (like 'qwerty' or '1234').")
        if has_repetition:
            recommendations.append("Avoid repeating characters consecutively.")
        if final_score >= 85 and not warnings:
            recommendations.append("Excellent password strength! Ensure you use a unique password for each account.")

        return final_score, warnings, recommendations

    def _score_to_label(self, score: int) -> str:
        """Map numerical score to textual strength classification."""
        if score <= 20:
            return "VERY WEAK"
        elif score <= 40:
            return "WEAK"
        elif score <= 60:
            return "FAIR"
        elif score <= 80:
            return "GOOD"
        elif score <= 94:
            return "STRONG"
        else:
            return "VERY STRONG"
