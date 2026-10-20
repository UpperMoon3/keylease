"""Cryptographic primitives and wire encoding used by the prototype.

AES-256-GCM, HKDF-SHA256, Ed25519, X25519 and ML-KEM-768 (FIPS 203) come from
`cryptography` (OpenSSL backend). The pure-Python `kyber-py` implementation is
used only as an independent cross-check (tests/test_interop.py).
"""
import os
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey, MLKEM768PublicKey)

__all__ = [
    "rand", "aead_seal", "aead_open", "hkdf", "sha256", "enc", "dec",
    "SigKey", "verify", "InvalidSignature", "InvalidTag",
    "HybridKEM", "KEM_STATS",
]

RAW = serialization.Encoding.Raw
RAWPUB = serialization.PublicFormat.Raw
RAWPRIV = serialization.PrivateFormat.Raw
NOENC = serialization.NoEncryption()


def rand(n):
    return os.urandom(n)


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(struct.pack(">I", len(p)))
        h.update(p)
    return h.digest()


def hkdf(ikm, info, length=32, salt=None):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


def aead_seal(key, pt, ad=b""):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, pt, ad)


def aead_open(key, ct, ad=b""):
    return AESGCM(key).decrypt(ct[:12], ct[12:], ad)


# --- canonical length-prefixed encoding (also used to count wire bytes) ---

def enc(*fields):
    out = bytearray()
    for f in fields:
        if isinstance(f, int):
            f = struct.pack(">Q", f)
        elif isinstance(f, str):
            f = f.encode()
        out += struct.pack(">I", len(f)) + f
    return bytes(out)


def dec(buf):
    """Inverse of enc(); raises ValueError on malformed input."""
    fields, i = [], 0
    while i < len(buf):
        if i + 4 > len(buf):
            raise ValueError("truncated encoding")
        (L,) = struct.unpack(">I", buf[i:i + 4])
        if i + 4 + L > len(buf):
            raise ValueError("truncated field")
        fields.append(buf[i + 4:i + 4 + L])
        i += 4 + L
    return fields


class SigKey:
    """Ed25519 signing key."""

    def __init__(self, sk=None):
        self.sk = sk or Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes(RAW, RAWPUB)

    def sign(self, msg):
        return self.sk.sign(msg)


def verify(pk, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


KEM_STATS = {"x25519": 0, "mlkem": 0}

# Simulated discrete-log oracle of a CRQC (experiment E5 only): maps every
# X25519 public key generated in the process to its private key.
DLOG_ORACLE = {}


XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")      # "\\.//^\\"


def xwing_combiner(ss_m, ss_x, ct_x, pk_x):
    """X-Wing combiner (Barbosa et al., IACR CiC 2024):
    SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def _derive(ss, label, ct, public):
    # bind the KEM key to the application context and to the full ciphertext
    return hkdf(ss, label + sha256(ct, public))


class HybridKEM:
    """X25519 + ML-KEM-768 hybrid KEM with the X-Wing combiner; the X-Wing
    shared secret is then bound to the application label with HKDF.
    `pq=False` gives the classical-only (hashed X25519) variant used in E3."""

    def __init__(self, pq=True):
        self.pq = pq
        self.x_sk = X25519PrivateKey.generate()
        self.x_pk = self.x_sk.public_key().public_bytes(RAW, RAWPUB)
        DLOG_ORACLE[self.x_pk] = self.x_sk.private_bytes(RAW, RAWPRIV, NOENC)
        if pq:
            self.k_dk = MLKEM768PrivateKey.generate()
            self.k_ek = self.k_dk.public_key().public_bytes_raw()
        else:
            self.k_ek, self.k_dk = b"", None

    @property
    def public(self):
        return enc(self.x_pk, self.k_ek)

    def __deepcopy__(self, memo):
        return self                      # key objects are not copyable

    @staticmethod
    def encaps(public, label):
        x_pk, k_ek = dec(public)
        e = X25519PrivateKey.generate()
        e_pk = e.public_key().public_bytes(RAW, RAWPUB)
        ss_x = e.exchange(X25519PublicKey.from_public_bytes(x_pk))
        KEM_STATS["x25519"] += 1
        if k_ek:
            ss_k, ct_k = MLKEM768PublicKey.from_public_bytes(k_ek).encapsulate()
            KEM_STATS["mlkem"] += 1
            ss = xwing_combiner(ss_k, ss_x, e_pk, x_pk)
        else:
            ct_k = b""
            ss = hashlib.sha3_256(ss_x + e_pk + x_pk).digest()
        ct = enc(e_pk, ct_k)
        return _derive(ss, label, ct, public), ct

    def decaps(self, ct, label):
        e_pk, ct_k = dec(ct)
        if bool(ct_k) != self.pq:
            raise ValueError("ciphertext does not match the key type")
        ss_x = self.x_sk.exchange(X25519PublicKey.from_public_bytes(e_pk))
        if ct_k:
            ss = xwing_combiner(self.k_dk.decapsulate(ct_k), ss_x, e_pk,
                                self.x_pk)
        else:
            ss = hashlib.sha3_256(ss_x + e_pk + self.x_pk).digest()
        return _derive(ss, label, ct, self.public)

    def x25519_private_bytes(self):
        """Exposed only to the simulated quantum adversary (experiment E12)."""
        return self.x_sk.private_bytes(RAW, RAWPRIV, NOENC)


def crqc_recover_x25519(public, ct, x_priv_oracle, label, kem_ss=None):
    """Simulated CRQC: given the X25519 secret (the oracle), recompute the
    transport key. Succeeds only if the ML-KEM component is absent or
    `kem_ss` is supplied (it is never supplied in the experiments)."""
    x_pk, k_ek = dec(public)
    e_pk, ct_k = dec(ct)
    if ct_k and kem_ss is None:
        return None
    sk = X25519PrivateKey.from_private_bytes(x_priv_oracle)
    ss_x = sk.exchange(X25519PublicKey.from_public_bytes(e_pk))
    ss = (xwing_combiner(kem_ss, ss_x, e_pk, x_pk) if ct_k else
          hashlib.sha3_256(ss_x + e_pk + x_pk).digest())
    return _derive(ss, label, ct, public)
