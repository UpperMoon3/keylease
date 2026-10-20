"""Simulated hardware key store (Secure Enclave / StrongBox / TPM model).

Keys are generated inside and never exported. Each key has an access class
that mirrors the platform mechanisms:

  * "afu"      usable after the first unlock since boot, also while the
               screen is locked (iOS ...AfterFirstUnlock, Android keys without
               user-authentication binding);
  * "presence" usable only within a short window after the user has
               authenticated (iOS .userPresence / Android
               setUserAuthenticationParameters).

The device state is one of "bfu" (before first unlock), "locked" (after
first unlock, screen locked) and "unlocked". An adversary is modelled by the
access level it obtains to this object, never by reading its fields.
"""
from .prims import SigKey, aead_seal, aead_open, rand


class AccessDenied(Exception):
    pass


class KeyStore:
    def __init__(self):
        self._sig = {"auth": SigKey(), "presence": SigKey()}
        self._seal = {"seal_afu": rand(32), "seal_presence": rand(32)}
        self._class = {"auth": "afu", "presence": "presence",
                       "seal_afu": "afu", "seal_presence": "presence"}
        self.state = "unlocked"
        self.calls = 0          # number of key-store operations (audit aid)

    # ------------------------------------------------------------------ access
    def _check(self, name):
        cls = self._class[name]
        if self.state == "bfu":
            raise AccessDenied("key store locked (BFU)")
        if cls == "presence" and self.state != "unlocked":
            raise AccessDenied("user presence required")
        self.calls += 1

    def public(self, name):
        return self._sig[name].pk

    def sign(self, name, msg):
        self._check(name)
        return self._sig[name].sign(msg)

    def seal(self, name, data, ad=b""):
        self._check(name)
        return aead_seal(self._seal[name], data, ad)

    def open(self, name, blob, ad=b""):
        self._check(name)
        return aead_open(self._seal[name], blob, ad)


class AdversaryKeyStore:
    """What an adversary who exercises the key store obtains: the same
    operations, at a fixed access level, without the key material."""

    def __init__(self, ks: KeyStore, level: str):
        assert level in ("none", "afu", "full")
        self._ks, self.level = ks, level

    def _with_state(self, fn, *a):
        saved = self._ks.state
        self._ks.state = {"none": "bfu", "afu": "locked",
                          "full": "unlocked"}[self.level]
        try:
            return fn(*a)
        finally:
            self._ks.state = saved

    def public(self, name):
        return self._ks.public(name)

    def sign(self, name, msg):
        return self._with_state(self._ks.sign, name, msg)

    def seal(self, name, data, ad=b""):
        return self._with_state(self._ks.seal, name, data, ad)

    def open(self, name, blob, ad=b""):
        return self._with_state(self._ks.open, name, blob, ad)
