"""A compact Double Ratchet (Perrin and Marlinspike, 2016), used only to show
that the storage layer composes with a real, evolving session state.

The session is assumed established (by X3DH/PQXDH); the channel protocol is
not a contribution of this work. The state serialises to bytes so that it
can be stored as an ordinary record of the storage layer.
"""
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from .prims import hkdf, enc, dec, aead_seal, aead_open, RAW, RAWPUB, \
    RAWPRIV, NOENC

MAX_SKIP = 1000


def _kdf_rk(rk, dh_out):
    out = hkdf(dh_out, b"dr-rk", 64, salt=rk)
    return out[:32], out[32:]


def _kdf_ck(ck):
    return (hmac.new(ck, b"\x02", hashlib.sha256).digest(),
            hmac.new(ck, b"\x01", hashlib.sha256).digest())


def _pub(sk):
    return sk.public_key().public_bytes(RAW, RAWPUB)


def _dh(sk, pk):
    return sk.exchange(X25519PublicKey.from_public_bytes(pk))


class Session:
    def __init__(self):
        self.dhs = None
        self.dhr = b""
        self.rk = self.cks = self.ckr = b""
        self.ns = self.nr = self.pn = 0
        self.skipped = {}

    @classmethod
    def alice(cls, sk, bob_pub):
        s = cls()
        s.dhs = X25519PrivateKey.generate()
        s.dhr = bob_pub
        s.rk, s.cks = _kdf_rk(sk, _dh(s.dhs, bob_pub))
        return s

    @classmethod
    def bob(cls, sk, bob_priv):
        s = cls()
        s.dhs = bob_priv
        s.rk = sk
        return s

    # ------------------------------------------------------------ messaging
    def encrypt(self, pt, ad=b""):
        self.cks, mk = _kdf_ck(self.cks)
        header = enc(_pub(self.dhs), self.pn, self.ns)
        self.ns += 1
        return enc(header, aead_seal(mk, pt, ad + header))

    def decrypt(self, msg, ad=b""):
        """Transactional receive: the state is replaced only if the AEAD tag
        verifies, so a forged or replayed message cannot desynchronise it."""
        header, ct = dec(msg)
        dh, pn, n = dec(header)
        pn, n = int.from_bytes(pn, "big"), int.from_bytes(n, "big")
        key = (dh, n)
        if key in self.skipped:
            mk = self.skipped[key]
            pt = aead_open(mk, ct, ad + header)
            del self.skipped[key]
            return pt
        trial = self.clone()
        if dh != trial.dhr:
            trial._skip(pn)
            trial._dh_ratchet(dh)
        trial._skip(n)
        trial.ckr, mk = _kdf_ck(trial.ckr)
        trial.nr += 1
        pt = aead_open(mk, ct, ad + header)      # raises on forgery
        self.__dict__.update(trial.__dict__)
        return pt

    def _skip(self, until):
        if self.nr + MAX_SKIP < until:
            raise ValueError("too many skipped messages")
        if self.ckr:
            while self.nr < until:
                self.ckr, mk = _kdf_ck(self.ckr)
                self.skipped[(self.dhr, self.nr)] = mk
                self.nr += 1

    def _dh_ratchet(self, dh):
        self.pn, self.ns, self.nr = self.ns, 0, 0
        self.dhr = dh
        self.rk, self.ckr = _kdf_rk(self.rk, _dh(self.dhs, self.dhr))
        self.dhs = X25519PrivateKey.generate()
        self.rk, self.cks = _kdf_rk(self.rk, _dh(self.dhs, self.dhr))

    # -------------------------------------------------------- serialisation
    def clone(self):
        return Session.loads(self.dumps())

    def dumps(self):
        sk = self.dhs.private_bytes(RAW, RAWPRIV, NOENC)
        skipped = enc(*[enc(d, n, mk) for (d, n), mk in self.skipped.items()])
        return enc(sk, self.dhr, self.rk, self.cks, self.ckr, self.ns,
                   self.nr, self.pn, skipped)

    @classmethod
    def loads(cls, b):
        f = dec(b)
        s = cls()
        s.dhs = X25519PrivateKey.from_private_bytes(f[0])
        s.dhr, s.rk, s.cks, s.ckr = f[1], f[2], f[3], f[4]
        s.ns, s.nr, s.pn = (int.from_bytes(x, "big") for x in f[5:8])
        for item in dec(f[8]):
            d, n, mk = dec(item)
            s.skipped[(d, int.from_bytes(n, "big"))] = mk
        return s
