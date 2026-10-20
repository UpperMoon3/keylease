"""Messenger-side storage layer with leased, threshold-custodied keys.

Persistent state (`disk`, a dict whose top-level assignments are the atomic
writes of the model):

  kdev     device factor K_dev, sealed under an "afu" key-store key
  ctr      per-signer request counters (public)
  cpk      the custodians' receipt-verification keys (from enrollment)
  committed {epoch, kc}       the committed epoch and its key-check value
  pending   {epoch, kc, wraps} a rotation in flight (two-phase), or None
  next_epoch                 epochs are never reused
  wraps    rid -> AEAD(KEK_e, record key)
  records  rid -> AEAD(record key, plaintext)

KEK_e = HKDF(K_dev || K_cust,e) where K_cust,e is Shamir-shared (t, n) across
the custodians. Nothing on the disk and nothing at the custodians decrypts a
record on its own.
"""
import itertools

from . import shamir
from .prims import (rand, hkdf, enc, dec, aead_seal, aead_open, verify,
                    sha256, HybridKEM, InvalidTag)
from .keystore import AccessDenied
from .net import Unreachable

CHECK = b"lease-key-check"


class Crash(Exception):
    pass


class LeaseError(Exception):
    pass


class Owner:
    """The owner's off-device authority (a second device or a recovery key)."""

    def __init__(self, sigkey):
        self.key = sigkey
        self.ctr = 0

    def _req(self, op, cid, dev_id, *args):
        self.ctr += 1
        body = enc(op, cid, dev_id, self.ctr, *args)
        return enc(body, self.key.sign(body))

    def revoke(self, net, dev_id):
        return self._broadcast(net, "REVOKE", dev_id)

    def reactivate(self, net, dev_id):
        return self._broadcast(net, "REACTIVATE", dev_id)

    def _broadcast(self, net, op, dev_id):
        ok = 0
        for cid, c in net.c.items():
            args = ()
            if op == "REACTIVATE":            # lease extension: challenged
                resp = dec(c.handle(challenge_request(cid, dev_id,
                                                      "reactivate")))
                if resp[0] != b"OK" or not verify(
                        c.pk, resp[3], enc("NONCE", cid, dev_id, "reactivate",
                                           resp[1], resp[2])):
                    continue
                args = (resp[1],)
            if dec(c.handle(self._req(op, cid, dev_id, *args)))[0] == b"OK":
                ok += 1
        return ok


def challenge_request(cid, dev_id, kind):
    """Unsigned request for a one-time challenge (and, for uploads, a
    one-time upload key) from custodian `cid`."""
    return enc(enc("NONCE", cid, dev_id, kind), b"")


class LeaseClient:
    def __init__(self, dev_id, ks, net, disk, t, n, w=None, pq=True,
                 device_factor=True, get_signer="auth", crash_at=(),
                 kdev_seal=None):
        self.dev, self.ks, self.net, self.disk = dev_id, ks, net, disk
        self.t, self.n, self.w = t, n, (w or t)
        self.pq = pq
        self.device_factor = device_factor
        self.get_signer = get_signer
        # K_dev is sealed under a key of the same access class as GET: in
        # strict mode it needs user presence locally, so that a coalition of
        # custodians that skips the presence check cannot help an AFU
        # adversary (Proposition 1).
        self.kdev_seal = kdev_seal or ("seal_presence"
                                       if get_signer == "presence"
                                       else "seal_afu")
        self.crash_at = set(crash_at)
        self.kek = None          # volatile memory only
        self.epoch = None

    # ------------------------------------------------------------ helpers
    def _crash(self, point):
        if point in self.crash_at:
            raise Crash(point)

    def _req(self, op, cid, signer, *args):
        ctr = dict(self.disk["ctr"])
        ctr[signer] += 1
        self.disk["ctr"] = ctr                       # atomic write
        body = enc(op, cid, self.dev, ctr[signer], *args)
        return enc(body, self.ks.sign(signer, body))

    def _challenge(self, cid, kind):
        """Fetch a fresh one-time challenge (and upload key) from `cid` and
        check the custodian's signature over it."""
        try:
            resp = dec(self.net.send(cid, challenge_request(cid, self.dev,
                                                            kind)))
        except ValueError:
            raise Unreachable(cid)
        if len(resp) < 4 or resp[0] != b"OK" or not verify(
                self.disk["cpk"][cid], resp[3],
                enc("NONCE", cid, self.dev, kind, resp[1], resp[2])):
            raise Unreachable(cid)
        return resp[1], resp[2]

    def _kdev(self):
        if not self.device_factor:
            return b""
        return self.ks.open(self.kdev_seal, self.disk["kdev"], self.dev)

    def _kek(self, kcust, epoch):
        return hkdf(self._kdev() + kcust, b"lease-kek" + enc(self.dev, epoch))

    @staticmethod
    def _kc(kek, dev, epoch):
        return aead_seal(kek, CHECK, enc(dev, epoch))

    @staticmethod
    def _kc_ok(kek, kc, dev, epoch):
        try:
            return aead_open(kek, kc, enc(dev, epoch)) == CHECK
        except InvalidTag:
            return False

    # -------------------------------------------------------------- setup
    @classmethod
    def setup(cls, dev_id, ks, net, owner_pk, t, n, w=None, **kw):
        disk = {"ctr": {"auth": 0, "presence": 0}, "committed": None,
                "pending": None, "next_epoch": 1, "wraps": {}, "records": {},
                # custodian receipt keys, registered at enrollment
                "cpk": {cid: c.pk for cid, c in net.c.items()}}
        for c in net.c.values():
            c.enroll(dev_id, ks.public("auth"), ks.public("presence"),
                     owner_pk)
        self = cls(dev_id, ks, net, disk, t, n, w, **kw)
        disk["kdev"] = ks.seal(self.kdev_seal, rand(32), dev_id)
        self._rotate(initial=True)
        return self

    # ------------------------------------------------------ custody I/O
    def _put_all(self, epoch, committed, kcust):
        shares = shamir.split(kcust, self.t, self.n)
        acks = 0
        for (x, y), cid in zip(shares, sorted(self.net.c)):
            self._crash("put:%d" % acks)
            rec = enc(x, y, epoch, self.dev, cid)
            rsig = self.ks.sign("presence", b"share" + rec)
            try:
                nonce, upk = self._challenge(cid, "put")
                key, kct = HybridKEM.encaps(upk, b"lease-put")
                box = aead_seal(key, enc(rec, rsig),
                                enc("PUT", cid, self.dev, epoch))
                resp = dec(self.net.send(cid, self._req(
                    "PUT", cid, "presence", epoch, committed, kct, box,
                    nonce)))
                # count only receipts signed by the custodian over this share
                if len(resp) > 1 and resp[0] == b"OK" and verify(
                        self.disk["cpk"][cid], resp[1],
                        enc("ACK", cid, self.dev, epoch, sha256(rec))):
                    acks += 1
            except (Unreachable, ValueError):
                pass
        return acks

    def fetch(self, epoch):
        """GET the shares of `epoch` from every reachable custodian and return
        those whose device signature verifies (Byzantine custodians are
        detected, not trusted)."""
        eph = HybridKEM(pq=self.pq)
        good, errors = [], []
        pk_presence = self.ks.public("presence")
        for cid in sorted(self.net.c):
            try:
                resp = dec(self.net.send(
                    cid, self._req("GET", cid, self.get_signer, epoch,
                                   eph.public)))
            except (Unreachable, ValueError, IndexError):
                errors.append((cid, "unreachable"))
                continue
            if not resp or resp[0] != b"OK" or len(resp) < 3:
                errors.append((cid, resp[1].decode(errors="replace")
                               if len(resp) > 1 else "empty or short reply"))
                continue
            try:                         # a malformed reply costs one share
                key = eph.decaps(resp[1], b"lease-get")
                rec, rsig = dec(aead_open(key, resp[2],
                                          enc("GET", cid, self.dev, epoch)))
                x, y, e, d, i = dec(rec)
            except Exception:
                errors.append((cid, "malformed reply"))
                continue
            if (verify(pk_presence, rsig, b"share" + rec)
                    and int.from_bytes(e, "big") == epoch and d == self.dev
                    and int.from_bytes(i, "big") == cid):
                good.append((int.from_bytes(x, "big"), y))
            else:
                errors.append((cid, "invalid share"))
        self.last_errors = errors
        return good

    def _reconstruct(self, shares, epoch, kc):
        if len(shares) < self.t:
            raise LeaseError("only %d of t=%d shares (%s)" % (
                len(shares), self.t, getattr(self, "last_errors", "")))
        for subset in itertools.combinations(shares, self.t):
            kek = self._kek(shamir.combine(list(subset)), epoch)
            if self._kc_ok(kek, kc, self.dev, epoch):
                return kek
        raise LeaseError("no consistent subset")

    # ------------------------------------------------------- life cycle
    def unlock(self):
        """Obtain KEK_e (volatile). Runs the resume rule first if a rotation
        was interrupted."""
        if self.kek is not None:
            return
        p = self.disk["pending"]
        if p is not None:
            shares = self.fetch(p["epoch"])
            if len(shares) >= self.w:
                kek = self._reconstruct(shares, p["epoch"], p["kc"])
                self._promote(p)
                self.kek, self.epoch = kek, p["epoch"]
                self._commit_notice()
                return
            self.disk["pending"] = None                  # abandon (atomic)
        c = self.disk["committed"]
        self.kek = self._reconstruct(self.fetch(c["epoch"]), c["epoch"],
                                     c["kc"])
        self.epoch = c["epoch"]

    def lock(self):
        self.kek = None
        self.epoch = None

    def renew(self):
        ok = 0
        committed = self.disk["committed"]["epoch"]
        for cid in sorted(self.net.c):
            self._crash("notice:%d" % ok)
            try:
                nonce, _ = self._challenge(cid, "renew")
                resp = dec(self.net.send(cid, self._req(
                    "RENEW", cid, "presence", committed, nonce)))
                if resp and resp[0] == b"OK":
                    ok += 1
            except (Unreachable, ValueError):
                pass
        return ok

    _commit_notice = renew

    def rotate(self):
        self.unlock()
        return self._rotate()

    def _rotate(self, initial=False):
        epoch = self.disk["next_epoch"]
        self.disk["next_epoch"] = epoch + 1                       # atomic
        kcust = rand(32)
        kek = self._kek(kcust, epoch)
        wraps = {}
        for rid in self.disk["records"]:
            rk = aead_open(self.kek, self.disk["wraps"][rid],
                           enc(self.dev, self.epoch, rid))
            wraps[rid] = aead_seal(kek, rk, enc(self.dev, epoch, rid))
        pending = {"epoch": epoch, "kc": self._kc(kek, self.dev, epoch),
                   "wraps": wraps}
        self._crash("before-pending")
        self.disk["pending"] = pending                            # atomic
        self._crash("after-pending")
        committed = 0 if initial else self.disk["committed"]["epoch"]
        acks = self._put_all(epoch, committed, kcust)
        self._crash("before-promote")
        if acks < self.w:
            self.disk["pending"] = None
            raise LeaseError("write quorum not reached (%d < %d)" %
                             (acks, self.w))
        self._promote(pending)
        self.kek, self.epoch = kek, epoch
        self._crash("after-promote")
        self._commit_notice()
        return acks

    def _promote(self, p):
        # one atomic write of the whole committed view
        d = dict(self.disk)
        d["committed"] = {"epoch": p["epoch"], "kc": p["kc"]}
        d["wraps"] = p["wraps"]
        d["pending"] = None
        self.disk.clear()
        self.disk.update(d)

    # ------------------------------------------------------- data plane
    def put_record(self, rid, pt):
        if self.kek is None:
            raise LeaseError("locked")
        rk = rand(32)
        # one atomic write of ciphertext and wrap
        self.disk.update({
            "records": {**self.disk["records"],
                        rid: aead_seal(rk, pt, rid.encode())},
            "wraps": {**self.disk["wraps"],
                      rid: aead_seal(self.kek, rk,
                                     enc(self.dev, self.epoch, rid))}})

    def get_record(self, rid):
        if self.kek is None:
            raise LeaseError("locked")
        rk = aead_open(self.kek, self.disk["wraps"][rid],
                       enc(self.dev, self.epoch, rid))
        return aead_open(rk, self.disk["records"][rid], rid.encode())

    def delete_record(self, rid):
        r = dict(self.disk["records"])
        w = dict(self.disk["wraps"])
        r.pop(rid, None)
        w.pop(rid, None)
        self.disk.update({"records": r, "wraps": w})       # one atomic write
