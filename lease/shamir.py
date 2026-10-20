"""Shamir (t, n) secret sharing over GF(2^8), applied byte-wise.

Field: GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1.
Share i is evaluated at the abscissa x_i = i (1 <= i <= 255).
"""
import os

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables():
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply by the generator 0x03
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def split(secret: bytes, t: int, n: int, rng=os.urandom):
    """Return a list of n shares (x_i, y_i bytes) of `secret`."""
    if not (1 <= t <= n <= 255):
        raise ValueError("need 1 <= t <= n <= 255")
    L = len(secret)
    # coefficient j of the polynomial of byte b is coeffs[j][b]
    coeffs = [secret] + [rng(L) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = bytearray(L)
        # Horner evaluation, byte-wise
        for b in range(L):
            acc = 0
            for j in range(t - 1, -1, -1):
                acc = gf_mul(acc, x) ^ coeffs[j][b]
            y[b] = acc
        shares.append((x, bytes(y)))
    return shares


def lagrange_at_zero(xs):
    lam = []
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i != j:
                num = gf_mul(num, xj)
                den = gf_mul(den, xi ^ xj)
        lam.append(gf_div(num, den))
    return lam


def combine(shares):
    """Reconstruct the secret from any t shares [(x_i, y_i), ...]."""
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate abscissae")
    lam = lagrange_at_zero(xs)
    L = len(shares[0][1])
    out = bytearray(L)
    for (x, y), l in zip(shares, lam):
        for b in range(L):
            out[b] ^= gf_mul(y[b], l)
    return bytes(out)
