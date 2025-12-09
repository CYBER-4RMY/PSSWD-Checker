#!/usr/bin/env python3
"""
psswd_checker.py - Robust password strength and breach checker.

Features:
 - CLI with flags: --password (not recommended), --generate, --no-breach, --common-file
 - Hidden password input via getpass by default
 - Length, complexity, repeat, sequential checks
 - Charset-based entropy estimate
 - Leet-normalization to detect obvious leet-mapped common passwords
 - Optional breach check via Have I Been Pwned (k-Anonymity)
 - Secure generator using secrets
"""

from __future__ import annotations
import argparse
import getpass
import hashlib
import math
import re
import sys
import time
from collections import Counter
from typing import Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry
import logging
import secrets
import string

# -------------------------
# Configuration & Logging
# -------------------------
APP_NAME = "PSSWD-Checker"
DEFAULT_MIN_LENGTH = 12
PWNED_API_URL = "https://api.pwnedpasswords.com/range/{}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("psswd_checker")

# -------------------------
# Utilities / Colors
# -------------------------
class Ansi:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def colored(text: str, color: str) -> str:
    return f"{color}{text}{Ansi.RESET}"

# -------------------------
# Common Passwords (minimal fallback)
# -------------------------
MINIMAL_COMMON = {
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "letmein",
    "iloveyou", "admin", "welcome"
}

# -------------------------
# Leet speak normalization
# -------------------------
LEET_MAP = str.maketrans({
    "4": "a", "@": "a",
    "8": "b",
    "3": "e",
    "6": "g",
    "1": "i", "!": "i", "l": "l",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t"
})

def leet_normalize(s: str) -> str:
    """Return a lowercase, leet-normalized version for comparison against common words."""
    return s.translate(LEET_MAP).lower()

# -------------------------
# Checks
# -------------------------
def check_length(password: str, min_len: int = DEFAULT_MIN_LENGTH) -> bool:
    return len(password) >= min_len

def check_complexity(password: str) -> bool:
    return bool(
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=;\\/\[\]`~]', password)
    )

def check_repeated(password: str) -> bool:
    # No char repeated 3 or more times consecutively
    return re.search(r'(.)\1{2,}', password) is None

def check_sequential(password: str, seq_len: int = 3) -> bool:
    """
    Detect ascending or descending sequences of letters or digits of length seq_len.
    Uses sliding window on ASCII codepoints for performance.
    """
    p = password
    if len(p) < seq_len:
        return True

    def is_seq(s: str) -> bool:
        # all letters or all digits
        if all(ch.isalpha() for ch in s):
            vals = [ord(ch.lower()) for ch in s]
        elif all(ch.isdigit() for ch in s):
            vals = [ord(ch) for ch in s]
        else:
            return False
        # ascending
        if all(vals[i + 1] - vals[i] == 1 for i in range(len(vals) - 1)):
            return True
        # descending
        if all(vals[i] - vals[i + 1] == 1 for i in range(len(vals) - 1)):
            return True
        return False

    for i in range(len(p) - seq_len + 1):
        if is_seq(p[i:i + seq_len]):
            return False
    return True

def estimate_charset_size(password: str) -> int:
    size = 0
    if re.search(r'[a-z]', password):
        size += 26
    if re.search(r'[A-Z]', password):
        size += 26
    if re.search(r'[0-9]', password):
        size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=;\\/\[\]`~]', password):
        # conservative estimate for common punctuation
        size += 32
    return size or 1

def entropy_charset(password: str) -> float:
    """Estimate entropy as length * log2(charset_size)"""
    charset = estimate_charset_size(password)
    return len(password) * math.log2(charset) if charset > 1 else 0.0

def shannon_entropy(password: str) -> float:
    """Shannon entropy per symbol (useful for diagnostics)."""
    if not password:
        return 0.0
    freq = Counter(password)
    probs = [v / len(password) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

# -------------------------
# Common pattern check
# -------------------------
def load_common_passwords(path: Optional[str]) -> set:
    if not path:
        return MINIMAL_COMMON
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            items = {line.strip() for line in fh if line.strip()}
        logger.info("Loaded %d common entries from %s", len(items), path)
        return items or MINIMAL_COMMON
    except Exception as e:
        logger.warning("Failed to load common-file '%s': %s", path, e)
        return MINIMAL_COMMON

def check_common(password: str, common_set: Iterable[str]) -> bool:
    """Return True if not common."""
    p_lower = password.lower()
    if p_lower in common_set:
        return False
    # leet-normalize and compare
    normalized = leet_normalize(password)
    if normalized in common_set:
        return False
    # also test substrings (e.g. 'password123')
    for common in common_set:
        if common and common in p_lower:
            return False
        if common and common in normalized:
            return False
    return True

# -------------------------
# Pwned password check (k-Anonymity)
# -------------------------
def requests_session_with_retries(total_retries: int = 3, backoff: float = 0.3) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": f"{APP_NAME}/1.0"})
    return s

def check_pwned(password: str, session: Optional[requests.Session] = None, timeout: float = 5.0) -> Optional[int]:
    """
    Returns:
      - integer count if found in Pwned DB
      - 0 if not found
      - None if check couldn't be completed (network error)
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    session = session or requests_session_with_retries()
    try:
        resp = session.get(PWNED_API_URL.format(prefix), timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.debug("Pwned API request failed: %s", e)
        return None
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        h, count = line.split(":")
        if h == suffix:
            try:
                return int(count)
            except ValueError:
                return 1
    return 0

# -------------------------
# Strength scoring & feedback
# -------------------------
def evaluate_password(password: str, common_set: Iterable[str], min_len: int = DEFAULT_MIN_LENGTH
                      ) -> Tuple[str, List[str], dict]:
    """
    Returns: (label, feedback_list, details_dict)
    label: 'Very Weak'|'Weak'|'Medium'|'Strong'
    """
    feedback: List[str] = []
    details = {}
    # basic checks
    length_ok = check_length(password, min_len)
    complexity_ok = check_complexity(password)
    repeated_ok = check_repeated(password)
    sequential_ok = check_sequential(password)
    common_ok = check_common(password, common_set)

    sh_entropy = shannon_entropy(password)
    charset_entropy = entropy_charset(password)

    details.update({
        "length_ok": length_ok,
        "complexity_ok": complexity_ok,
        "repeated_ok": repeated_ok,
        "sequential_ok": sequential_ok,
        "common_ok": common_ok,
        "shannon_entropy": round(sh_entropy, 3),
        "charset_entropy": round(charset_entropy, 3),
        "length": len(password)
    })

    # scoring (simple and explainable)
    score = 0
    if length_ok:
        score += 2  # length matters most
    if complexity_ok:
        score += 2
    if repeated_ok:
        score += 1
    if sequential_ok:
        score += 1
    if common_ok:
        score += 2
    # entropy bonus
    if charset_entropy >= 60:
        score += 2
    elif charset_entropy >= 40:
        score += 1

    # Feedback messages
    if not length_ok:
        feedback.append(f"Password should be at least {min_len} characters.")
    if not complexity_ok:
        feedback.append("Include uppercase, lowercase, digits, and special characters.")
    if not repeated_ok:
        feedback.append("Avoid repeating the same character 3 or more times in a row.")
    if not sequential_ok:
        feedback.append("Avoid short ascending or descending character sequences (e.g., 'abc', '123').")
    if not common_ok:
        feedback.append("Password is too common or easily guessable (or leet-equivalent).")

    # Entropy feedback
    if charset_entropy < 28:
        feedback.append("Entropy is low; consider increasing length and character variety.")
    elif charset_entropy < 45:
        feedback.append("Entropy is moderate; consider adding length and mixed character classes.")
    else:
        feedback.append("Entropy is good.")

    # Label
    if score >= 8:
        label = "Strong"
    elif score >= 5:
        label = "Medium"
    elif score >= 3:
        label = "Weak"
    else:
        label = "Very Weak"

    return label, feedback, details

# -------------------------
# Secure password generator
# -------------------------
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?|\\`~"
    # ensure at least one char from each class
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r'[A-Z]', pwd) and re.search(r'[a-z]', pwd)
                and re.search(r'[0-9]', pwd) and re.search(r'[!@#$%^&*()_\-+=\[\]{};:,.<>/?|\\`~]', pwd)):
            return pwd

# -------------------------
# CLI and main
# -------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=APP_NAME, description="Password strength and breach checker")
    p.add_argument("--password", "-p", help="Password to check (not recommended; will appear in shell history)")
    p.add_argument("--min-length", "-m", type=int, default=DEFAULT_MIN_LENGTH, help=f"Minimum password length (default {DEFAULT_MIN_LENGTH})")
    p.add_argument("--no-breach", action="store_true", help="Skip Have I Been Pwned breach check")
    p.add_argument("--common-file", "-c", help="Path to a common-password file (one entry per line). If omitted, a minimal internal list is used.")
    p.add_argument("--generate", "-g", type=int, metavar="LEN", help="Generate a secure password of length LEN and exit")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose (debug) logging")
    return p.parse_args()

def main() -> int:
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.generate:
        length = max(8, args.generate)
        pwd = generate_password(length)
        print(colored("Generated password:", Ansi.BLUE), pwd)
        return 0

    common_set = load_common_passwords(args.common_file)

    # Acquire password safely
    if args.password:
        pwd = args.password
        logger.warning("You passed a password on the command line; this can be insecure.")
    else:
        try:
            pwd = getpass.getpass("-->> Enter a password to check (input hidden): ")
        except Exception as e:
            logger.error("Failed to read password: %s", e)
            return 2

    if not pwd:
        logger.error("No password supplied.")
        return 2

    # Evaluate
    label, feedback, details = evaluate_password(pwd, common_set, args.min_length)

    print("\n" + colored("Password Strength:", Ansi.BOLD), colored(label, Ansi.GREEN if label == "Strong" else (Ansi.YELLOW if label == "Medium" else Ansi.RED)))
    print(colored("Details:", Ansi.BOLD))
    print(f" - Length: {details['length']}")
    print(f" - Shannon entropy (per symbol aggregated): {details['shannon_entropy']}")
    print(f" - Charset-based entropy estimate: {details['charset_entropy']} bits")
    print(f" - Length check: {'OK' if details['length_ok'] else 'FAIL'}")
    print(f" - Complexity check: {'OK' if details['complexity_ok'] else 'FAIL'}")
    print(f" - Repetition check: {'OK' if details['repeated_ok'] else 'FAIL'}")
    print(f" - Sequential check: {'OK' if details['sequential_ok'] else 'FAIL'}")
    print(f" - Common/leet check: {'OK' if details['common_ok'] else 'FAIL'}")

    print(colored("\nFeedback:", Ansi.BOLD))
    for m in feedback:
        print(" -", m)

    # Breach check
    if not args.no_breach:
        print(colored("\nBreach check (Have I Been Pwned):", Ansi.BOLD))
        session = requests_session_with_retries()
        result = check_pwned(pwd, session=session)
        if result is None:
            print(colored(" -> Could not complete breach check (network or API issue).", Ansi.YELLOW))
        elif result == 0:
            print(colored(" -> Not found in the breach database (good).", Ansi.GREEN))
        else:
            print(colored(f" -> Found in {result} breaches! Change it immediately.", Ansi.RED))
    else:
        print(colored("\nBreach check skipped (offline mode).", Ansi.YELLOW))

    # Suggest a generated password if weak
    if label in ("Very Weak", "Weak"):
        suggested = generate_password(max(16, args.min_length))
        print(colored("\nSuggestion:", Ansi.BOLD), "Consider using the generated strong password below and storing it in a password manager.")
        print(suggested)

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        raise SystemExit(1)
