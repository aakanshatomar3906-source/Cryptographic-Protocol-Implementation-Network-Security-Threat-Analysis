#!/usr/bin/env python3
"""
RSA implementation for CampusConnect assignment.

Features:
- Accepts two distinct primes p and q.
- Computes n = p * q and phi(n) = (p-1)*(q-1).
- Selects a valid public exponent e (1 < e < phi(n), coprime to phi(n)).
- Computes private exponent d as the modular inverse of e mod phi(n),
  choosing the smallest non-negative solution (0 <= d < phi(n)).
- Encrypts m as c = m^e mod n.
- Decrypts c as m' = c^d mod n.
- Prints all intermediate values and verifies correctness.
- Supports:
  - Test case (a): p=3, q=11, e=3, m=4 (from the worked example).
  - Test case (b): an additional pair of your choice.
"""

import sys
import math


def is_prime(n: int) -> bool:
    """Check if n is prime (simple trial division, sufficient for small numbers)."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.isqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def mod_inverse(e: int, phi: int) -> int:
    """
    Compute the modular inverse d of e modulo phi, i.e., d * e mod phi = 1.
    Returns the smallest non-negative d in [0, phi-1].
    Uses the extended Euclidean algorithm.
    """
    if e == 0:
        raise ValueError("e must be non-zero to compute modular inverse.")

    # Extended Euclidean Algorithm
    old_r, r = phi, e
    old_s, s = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    # old_r is gcd(e, phi), old_s is the inverse (possibly negative)
    if old_r != 1:
        raise ValueError(f"e and phi({phi}) are not coprime; gcd = {old_r}")

    d = old_s % phi
    return d


def gcd(a: int, b: int) -> int:
    """Compute GCD of a and b."""
    while b:
        a, b = b, a % b
    return a


def rsa_example(p: int, q: int, e: int, m: int) -> None:
    """
    Run a single RSA example with given p, q, e, m.
    Prints all intermediate values and verifies encryption/decryption.
    """

    # Validity checks
    if not (is_prime(p) and is_prime(q)):
        raise ValueError(f"p={p} and q={q} must both be prime.")
    if p == q:
        raise ValueError(f"p and q must be distinct primes (p={p}, q={q}).")
    if not (1 < e < (p - 1) * (q - 1)):
        raise ValueError(f"e={e} must satisfy 1 < e < phi(n).")
    if gcd(e, (p - 1) * (q - 1)) != 1:
        raise ValueError(f"e={e} must be coprime to phi(n).")
    if not (0 <= m < p * q):
        raise ValueError(f"message m={m} must satisfy 0 <= m < n (n={p*q}).")

    # Key generation
    n = p * q
    phi = (p - 1) * (q - 1)

    # Compute d as modular inverse of e mod phi
    d = mod_inverse(e, phi)

    # Ensure d is in [0, phi-1]
    if not (0 <= d < phi):
        raise ValueError(f"d={d} is not in range [0, phi-1].")

    # Encryption: c = m^e mod n
    c = pow(m, e, n)

    # Decryption: m' = c^d mod n
    m_prime = pow(c, d, n)

    # Print intermediate values
    print(f"\n=== RSA Example ===")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p * q = {n}")
    print(f"phi(n) = (p-1)*(q-1) = {phi}")
    print(f"e = {e}")
    print(f"d = {d} (modular inverse of e mod phi(n))")
    print(f"m = {m}")
    print(f"c = m^e mod n = {c}")
    print(f"m' = c^d mod n = {m_prime}")

    # Verify correctness
    if m_prime != m:
        print(f"ERROR: Decrypted message {m_prime} != original message {m}")
        sys.exit(1)
    else:
        print(f"SUCCESS: Decrypted message matches original message.")


def main() -> None:
    """
    Run two test cases:
      (a) p=3, q=11, e=3, m=4 (from the worked example).
      (b) Additional case: p=7, q=13, e=5, m=10.
    """

    # Test case (a): from the worked example
    print("Running test case (a): p=3, q=11, e=3, m=4")
    rsa_example(p=3, q=11, e=3, m=4)

    # Test case (b): additional example
    print("\nRunning test case (b): p=7, q=13, e=5, m=10")
    rsa_example(p=7, q=13, e=5, m=10)


if __name__ == "__main__":
    main()
