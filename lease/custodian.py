"""Lease custodian: stores one Shamir share per device and epoch and enforces
the lease policy (renewal, expiry, revocation, erasure, audit).

A custodian never holds anything that decrypts device data on its own: the
key-encryption key is derived from the custodian factor *and* a device factor
that never leaves the device.

Requests that extend a lease (PUT, RENEW, REACTIVATE) must carry a fresh
one-time challenge issued by this custodian, so that a signed request that
was withheld by the network cannot be delivered later to extend the lease.
Uploads are encrypted to a one-time upload key bound to that challenge and
erased after use, and every PUT is acknowledged with the custodian's
signature over the stored share record.
"""
import os
from dataclasses import dataclass, field

from .prims import (enc, dec, verify, aead_seal, aead_open, sha256, HybridKEM,
                    SigKey)

OPS = ("PUT", "RENEW", "GET", "REACTIVATE", "REVOKE")
SIGNER = {"PUT": "presence", "RENEW": "presence", "GET": "auth",
          "REACTIVATE": "owner", "REVOKE": "owner"}
CHALLENGED = {"PUT": "put", "RENEW": "renew", "REACTIVATE": "reactivate"}


class Clock:
    """Simulated time. Custodians register a timer callback so that erasure
    at the horizon happens without any request arriving."""

    def __init__(self, t=0.0):
        self.t = t
        self.timers = []

    def now(self):
        return self.t

    def advance(self, dt):
        self.t += dt
        for cb in self.timers:
            cb()


@dataclass
class Policy:
    lease: float = 72 * 3600.0       # L: lease length after a renewal
    hard: float = 30 * 86400.0       # H: erase shares H after lease end
    challenge: float = 120.0         # validity of a one-time challenge (s)
    get_rate: int = 0                # max GETs per hour (0 = unlimited)


@dataclass
class DeviceRecord:
    pk: dict
    counters: dict = field(default_factory=lambda: {k: -1 for k in
                                                     ("auth", "presence",
                                                      "owner")})
    slots: dict = field(default_factory=dict)   # epoch -> (share record, sig)
    committed: int = 0
    max_epoch: int = 0
    lease_until: float = 0.0
    revoked: bool = False
    erased: bool = False
    nonces: dict = field(default_factory=dict)  # nonce -> (time, kind, kem)
    log: list = field(default_factory=list)


class Custodian:
    def __init__(self, cid, clock, policy=None, pq=True, notify=None):
        self.cid = cid
        self.clock = clock
        self.policy = policy or Policy()
        self.pq = pq
        self.sig = SigKey()              # signs challenges and PUT receipts
        self.dev = {}
        self.notify = notify if notify is not None else []
        if hasattr(clock, "timers"):
            clock.timers.append(self.sweep_all)
        # fault switches used by the experiments (honest by default)
        self.tamper = False
        self.ignore_revoke = False
        self.ignore_expiry = False
        self.get_signer = "auth"         # "presence" = strict mode
        self.skip_presence = False       # deviating: accept AFU-signed GET

    @property
    def pk(self):
        return self.sig.pk

    # ------------------------------------------------------------ enrolment
    def enroll(self, dev_id, pk_auth, pk_presence, pk_owner, now_lease=True):
        self.dev[dev_id] = DeviceRecord(
            pk={"auth": pk_auth, "presence": pk_presence, "owner": pk_owner})
        if now_lease:
            self.dev[dev_id].lease_until = self.clock.now() + self.policy.lease

    # --------------------------------------------------------------- policy
    def _sweep(self, r):
        now = self.clock.now()
        for nonce in [k for k, v in r.nonces.items()
                      if now - v[0] > self.policy.challenge]:
            del r.nonces[nonce]                  # erases one-time upload keys
        if self.ignore_expiry:
            return
        if now >= r.lease_until + self.policy.hard and not r.erased:
            r.slots.clear()
            r.erased = True

    def sweep_all(self):
        """Timer: erase expired leases and stale challenges autonomously."""
        for r in self.dev.values():
            self._sweep(r)

    def _active(self, r):
        return self.ignore_expiry or self.clock.now() < r.lease_until

    def _log(self, r, dev_id, what):
        entry = (self.clock.now(), self.cid, dev_id, what)
        r.log.append(entry)
        self.notify.append(entry)        # stands in for alert delivery

    def _deny(self, r, dev_id, op, why):
        self._log(r, dev_id, "DENIED %s: %s" % (op, why))
        return enc("ERR", why)

    # -------------------------------------------------------------- request
    def handle(self, req: bytes) -> bytes:
        try:
            body, sig = dec(req)
            f = dec(body)
            op, cid, dev_id = f[0].decode(), int.from_bytes(f[1], "big"), f[2]
        except Exception:
            return enc("ERR", "malformed")
        if cid != self.cid or dev_id not in self.dev:
            return enc("ERR", "bad request")
        r = self.dev[dev_id]
        self._sweep(r)
        if op == "NONCE":
            return self._challenge(r, dev_id, f[3].decode())
        if op not in OPS:
            return enc("ERR", "bad request")
        ctr, args = int.from_bytes(f[3], "big"), f[4:]
        signer = self.get_signer if op == "GET" else SIGNER[op]
        if op == "GET" and self.skip_presence and \
                verify(r.pk["auth"], sig, body):
            signer = "auth"
        if not verify(r.pk[signer], sig, body):
            return self._deny(r, dev_id, op, "bad signature")
        if ctr <= r.counters[signer]:
            return self._deny(r, dev_id, op, "replay")
        r.counters[signer] = ctr
        kem = None
        if op in CHALLENGED:
            got = r.nonces.pop(args[-1], None)
            if got is None or got[1] != CHALLENGED[op]:
                return self._deny(r, dev_id, op, "stale or unknown challenge")
            kem = got[2]
        return getattr(self, "_op_" + op)(r, dev_id, args, kem)

    def _challenge(self, r, dev_id, kind):
        if kind not in CHALLENGED.values():
            return enc("ERR", "bad request")
        if len(r.nonces) >= 64:                  # bound outstanding state
            del r.nonces[min(r.nonces, key=lambda k: r.nonces[k][0])]
        nonce = os.urandom(16)
        kem = HybridKEM(pq=self.pq) if kind == "put" else None
        upk = kem.public if kem else b""
        r.nonces[nonce] = (self.clock.now(), kind, kem)
        sig = self.sig.sign(enc("NONCE", self.cid, dev_id, kind, nonce, upk))
        return enc("OK", nonce, upk, sig)

    # ------------------------------------------------------------ operations
    def _op_REVOKE(self, r, dev_id, args, kem):
        self._log(r, dev_id, "REVOKE")
        if not self.ignore_revoke:
            r.revoked = True
            r.slots.clear()
        return enc("OK")

    def _op_REACTIVATE(self, r, dev_id, args, kem):
        if (r.revoked or r.erased) and not self.ignore_revoke:
            return self._deny(r, dev_id, "REACTIVATE", "revoked or erased")
        r.lease_until = self.clock.now() + self.policy.lease
        self._log(r, dev_id, "REACTIVATE")
        return enc("OK")

    def _op_RENEW(self, r, dev_id, args, kem):
        committed = int.from_bytes(args[0], "big")
        if r.revoked and not self.ignore_revoke:
            return self._deny(r, dev_id, "RENEW", "revoked")
        if not self._active(r):
            return self._deny(r, dev_id, "RENEW", "dormant")
        r.lease_until = self.clock.now() + self.policy.lease
        self._set_committed(r, committed)
        self._log(r, dev_id, "RENEW c=%d" % committed)
        return enc("OK")

    def _set_committed(self, r, c):
        # keep the named committed epoch and anything newer (a pending one)
        if c in r.slots or c >= r.committed:
            r.committed = max(r.committed, c)
            for e in list(r.slots):
                if e < r.committed:
                    del r.slots[e]

    def _op_PUT(self, r, dev_id, args, kem):
        epoch, committed = (int.from_bytes(a, "big") for a in args[:2])
        kem_ct, box = args[2], args[3]
        if r.revoked and not self.ignore_revoke:
            return self._deny(r, dev_id, "PUT", "revoked")
        if not self._active(r):
            return self._deny(r, dev_id, "PUT", "dormant")
        if epoch <= r.max_epoch:
            return self._deny(r, dev_id, "PUT", "stale epoch")
        try:
            key = kem.decaps(kem_ct, b"lease-put")
            record = aead_open(key, box, enc("PUT", self.cid, dev_id, epoch))
            rec, rsig = dec(record)
            x, y, e, d, i = dec(rec)
        except Exception:
            return self._deny(r, dev_id, "PUT", "undecryptable")
        if int.from_bytes(e, "big") != epoch or d != dev_id \
                or int.from_bytes(i, "big") != self.cid:
            return self._deny(r, dev_id, "PUT", "inconsistent record")
        r.max_epoch = epoch
        # two-version retention: the new (pending) epoch and the committed one
        r.slots = {k: v for k, v in r.slots.items() if k == committed}
        r.slots[epoch] = (rec, rsig)
        r.committed = committed
        r.lease_until = self.clock.now() + self.policy.lease
        self._log(r, dev_id, "PUT e=%d" % epoch)
        receipt = self.sig.sign(enc("ACK", self.cid, dev_id, epoch,
                                    sha256(rec)))
        return enc("OK", receipt)

    def _op_GET(self, r, dev_id, args, kem):
        epoch = int.from_bytes(args[0], "big")
        eph_pub = args[1]
        if r.revoked and not self.ignore_revoke:
            return self._deny(r, dev_id, "GET", "revoked")
        if not self._active(r):
            return self._deny(r, dev_id, "GET", "dormant")
        if epoch not in r.slots:
            return self._deny(r, dev_id, "GET", "absent")
        if self.policy.get_rate:
            hour = [e for e in r.log if e[3].startswith("GET")
                    and e[0] > self.clock.now() - 3600]
            if len(hour) >= self.policy.get_rate:
                return self._deny(r, dev_id, "GET", "rate")
        self._log(r, dev_id, "GET e=%d" % epoch)
        rec, rsig = r.slots[epoch]
        if self.tamper:
            x, y, e, d, i = dec(rec)
            y = bytes([y[0] ^ 1]) + y[1:]
            rec = enc(x, y, e, d, i)
        key, kem_ct = HybridKEM.encaps(eph_pub, b"lease-get")
        box = aead_seal(key, enc(rec, rsig),
                        enc("GET", self.cid, dev_id, epoch))
        return enc("OK", kem_ct, box)
