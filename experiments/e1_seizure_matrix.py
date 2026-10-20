"""E1: seizure scenarios against all designs.

Every cell is produced by running the adversary: it takes the disk image
taken at seizure (or an older one), obtains the stated key-store access at
time tau after seizure, and runs the application's own unlock path against
the real custodian code. Deviating custodians are modelled by switching off
their policy checks (expiry, revocation, and in S11 the presence check).
"""
import json

from common import (World, DESIGNS, DESIGN_LABEL, HOUR, OUT, AdversaryKeyStore)
from lease import shamir
from lease.client import LeaseClient
from lease.prims import dec

L = 72 * HOUR
SECRET = b"the message the owner cares about"


def prepare(design):
    w = World(design, lease=L)
    w.user_unlock()
    for i in range(10):
        w.client.put_record("m%d" % i, b"message %d" % i)
    w.client.put_record("secret", SECRET)
    w.user_lock()                      # device seized locked (AFU)
    return w


def attempt(w, image, level, tau, rid="secret", get_signer=None):
    w.clock.advance(tau)
    before = w.audit_entries()
    got = w.adversary_read(image, level, rid, get_signer)
    return got == SECRET, w.audit_entries() - before


def s1(w):
    return attempt(w, w.image(), "none", 0)


def s2(w):
    """Disk image plus the stored state of every custodian (all operators
    collude or are compelled); no key-store access."""
    image = w.image()
    if w.net is None:
        return attempt(w, image, "none", 0)
    e = image["committed"]["epoch"]
    shares = []
    for c in w.custodians:
        rec, _ = c.dev[w.dev].slots[e]
        x, y, *_ = dec(rec)
        shares.append((int.from_bytes(x, "big"), y))
    kcust = shamir.combine(shares[:w.t])
    adv = LeaseClient(w.dev, AdversaryKeyStore(w.ks, "none"), None, image,
                      w.t, w.n, device_factor=False)
    # K_dev is sealed in the key store, which this adversary cannot use: the
    # best it can do is derive the KEK without it (correct only for B3)
    kek = adv._kek(kcust, e)
    if not LeaseClient._kc_ok(kek, image["committed"]["kc"], w.dev, e):
        return False, 0
    adv.kek, adv.epoch = kek, e
    return adv.get_record("secret") == SECRET, 0


def s3(w):
    return attempt(w, w.image(), "afu", 0)


def s4(w):
    return attempt(w, w.image(), "afu", L + HOUR)


def s5(w):
    return attempt(w, w.image(), "full", 0)


def s6(w):
    return attempt(w, w.image(), "full", L + HOUR)


def s7(w):
    image = w.image()
    w.clock.advance(1 * HOUR)
    if w.net is not None:
        w.owner.revoke(w.net, w.dev)
    return attempt(w, image, "full", 1 * HOUR)


def _collude(w, k, presence=False):
    """k custodians (all of them if fewer exist) ignore expiry and
    revocation; with presence=True they also serve AFU-signed GETs."""
    if w.net is None:
        return
    for c in w.custodians[:k]:
        c.ignore_expiry = True
        c.ignore_revoke = True
        c.skip_presence = presence


def collude_after_lease(k):
    def fn(w):
        _collude(w, k)
        return attempt(w, w.image(), "full", L + HOUR)
    return fn


def s11(w):
    """AFU access at seizure (no passcode) while three custodians serve
    GET requests signed with the AFU key, skipping the presence check that
    strict mode relies on."""
    _collude(w, 3, presence=True)
    return attempt(w, w.image(), "afu", 0, get_signer="auth")


def s12(w):
    """An old image (e.g. a leaked backup) still holds a message the owner
    has since deleted; the owner keeps using the device; the adversary later
    obtains full key-store access while the lease is active."""
    old = w.image()
    w.clock.advance(HOUR)
    w.user_unlock()
    w.client.delete_record("secret")
    if w.net is not None:
        w.client.rotate()
    w.user_lock()
    return attempt(w, old, "full", HOUR)


SCENARIOS = [
    ("S1", "Disk image only", s1),
    ("S2", "Disk image + storage of every custodian / server", s2),
    ("S3", "AFU key-store use (no passcode), at seizure", s3),
    ("S4", "AFU key-store use, after lease (73 h)", s4),
    ("S5", "Passcode / full key-store use, at seizure", s5),
    ("S6", "Passcode / full key-store use, after lease (73 h)", s6),
    ("S7", "Full use at 2 h; owner revoked at 1 h", s7),
    ("S8", "As S6; one custodian ignores expiry and revocation",
     collude_after_lease(1)),
    ("S9", "As S6; two custodians (t-1) ignore expiry and revocation",
     collude_after_lease(2)),
    ("S10", "As S6; three custodians (t) ignore expiry and revocation",
     collude_after_lease(3)),
    ("S11", "AFU use at seizure; three custodians skip the presence check",
     s11),
    ("S12", "Message deleted, epoch rotated; old image + full use", s12),
]


def main():
    rows = []
    for sid, desc, fn in SCENARIOS:
        row = {"id": sid, "scenario": desc}
        for d in DESIGNS + ["L-strict-afu"]:
            w = prepare(d)
            rec, logged = fn(w)
            row[d] = {"recovered": rec, "audit_entries": logged}
        rows.append(row)
        print(sid, desc)
        print("   ", "  ".join("%s:%s%s" % (
            d, "BROKEN" if row[d]["recovered"] else "safe",
            "(logged %d)" % row[d]["audit_entries"]
            if row[d]["audit_entries"] else "")
            for d in DESIGNS + ["L-strict-afu"]))
    with open(OUT + "/e1_matrix.json", "w") as f:
        json.dump({"designs": DESIGN_LABEL, "lease_hours": L / HOUR,
                   "rows": rows}, f, indent=1)


if __name__ == "__main__":
    main()
