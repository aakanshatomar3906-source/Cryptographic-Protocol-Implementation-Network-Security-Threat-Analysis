#!/usr/bin/env python3
"""
Diffie-Hellman key exchange implementation for CampusConnect assignment.

Features:
- Accepts a public prime p and a public base alpha (primitive root modulo p).
- Accepts private keys a (Alice) and b (Bob).
- Computes A = alpha^a mod p and B = alpha^b mod p.
- Computes shared secret:
    K_Alice = B^a mod p
    K_Bob   = A^b mod p
- Prints both K values and asserts they match.
- Supports:
  - Test case: p=29, alpha=2, a=5, b=12 (from the worked example).
  - Additional case: p=37, alpha=2, a=7, b=15.
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


def is_primitive_root(alpha: int, p: int) -> bool:
    """
    Check if alpha is a primitive root modulo p (p is prime).
    alpha is a primitive root if its order modulo p is p-1.
    We check that for all prime factors q of (p-1), alpha^((p-1)/q) != 1 mod p.
    """
    if p == 2:
        return alpha == 1

    phi = p - 1
    # Find prime factors of phi
    factors = set()
    n = phi
    # Factor 2
    while n % 2 == 0:
        factors.add(2)
        n //= 2
    # Odd factors
    f = 3
    while f * f <= n:
        while n % f == 0:
            factors.add(f)
            n //= f
        f += 2
    if n > 1:
        factors.add(n)

    # Check primitive root condition
    for q in factors:
        if pow(alpha, phi // q, p) == 1:
            return False
    return True


def diffie_hellman_example(p: int, alpha: int, a: int, b: int) -> None:
    """
    Run a single Diffie-Hellman example with given p, alpha, a, b.
    Prints all intermediate values and verifies that both parties compute the same K.
    """

    # Validity checks
    if not is_prime(p):
        raise ValueError(f"p={p} must be prime.")
    if not is_primitive_root(alpha, p):
        raise ValueError(f"alpha={alpha} must be a primitive root modulo p={p}.")
    if not (1 < a < p - 1):
        raise ValueError(f"Alice's private key a={a} must satisfy 1 < a < p-1.")
    if not (1 < b < p - 1):
        raise ValueError(f"Bob's private key b={b} must satisfy 1 < b < p-1.")

    # Public values
    A = pow(alpha, a, p)  # Alice's public value
    B = pow(alpha, b, p)  # Bob's public value

    # Shared secrets
    K_Alice = pow(B, a, p)
    K_Bob   = pow(A, b, p)

    # Print intermediate values
    print(f"\n=== Diffie-Hellman Example ===")
    print(f"p = {p}")
    print(f"alpha = {alpha}")
    print(f"Alice's private key a = {a}")
    print(f"Bob's private key b = {b}")
    print(f"A = alpha^a mod p = {A}")
    print(f"B = alpha^b mod p = {B}")
    print(f"K_Alice = B^a mod p = {K_Alice}")
    print(f"K_Bob   = A^b mod p = {K_Bob}")

    # Verify correctness
    if K_Alice != K_Bob:
        print(f"ERROR: Shared secrets do not match (K_Alice={K_Alice}, K_Bob={K_Bob})")
        sys.exit(1)
    else:
        print(f"SUCCESS: Both parties computed the same shared secret K = {K_Alice}.")


def main() -> None:
    """
    Run two test cases:
      (a) p=29, alpha=2, a=5, b=12 (from the worked example).
      (b) Additional case: p=37, alpha=2, a=7, b=15.
    """

    # Test case (a): from the worked example
    print("Running test case (a): p=29, alpha=2, a=5, b=12")
    diffie_hellman_example(p=29, alpha=2, a=5, b=12)

    # Test case (b): additional example
    print("\nRunning test case (b): p=37, alpha=2, a=7, b=15")
    diffie_hellman_example(p=37, alpha=2, a=7, b=15)


if __name__ == "__main__":
    main()
