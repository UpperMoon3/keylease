"""E3: robustness of the custody protocol and the transport.

(a) Byzantine custodian: one or t-1 custodians return altered shares.
(b) Replay: a network adversary replays captured RENEW and GET requests.
(c) Unsigned / wrongly signed operations: the adversary with AFU key-store
    access tries to renew a lease and to put a new epoch (both need the
    presence-bound key) and to reactivate a dormant lease (owner key).
(d) Harvest-now-decrypt-later against expiry: custody traffic of an honest
    unlock is recorded; after the lease has expired the adversary obtains a
    CRQC (simulated discrete-log oracle for every X25519 key) and AFU access
    to the seized device. Classical-only transport versus hybrid transport.
"""
import copy
import json

from common import World, HOUR, OUT, AdversaryKeyStore, LeaseError
from lease import shamir
from lease.client import LeaseClient
from lease.prims import (dec, enc, aead_open, DLOG_ORACLE, crqc_recover_x25519,
                         InvalidTag)
from lease.keystore import AccessDenied

L = 72 * HOUR
res = {}


def fresh(**kw):
    w = World("L-bg", lease=L, **kw)
    w.user_unlock()
    w.client.put_record("secret", b"s3cret")
    return w


# (a) Byzantine custodians -----------------------------------------------
out = []
for k in (1, 2, 3):
    w = fresh()
    for c in w.custodians[:k]:
        c.tamper = True
    w.user_lock()
    w.ks.state = "unlocked"
    try:
        w.client.unlock()
        ok = w.client.get_record("secret") == b"s3cret"
    except LeaseError:
        ok = False
    out.append({"tampering_custodians": k, "unlock_ok": ok,
                "detected": [e for e in w.client.last_errors
                             if e[1] == "invalid share"].__len__()})
    print("byzantine", out[-1])
res["byzantine"] = out

# (b) Replay -----------------------------------------------------------------
w = fresh()
w.net.record = True
w.client.renew()
w.user_lock()
w.ks.state = "locked"
w.client.unlock()
w.net.record = False
renews = [(cid, req) for cid, req, resp in w.net.transcript
          if dec(dec(req)[0])[0] == b"RENEW"]
gets = [(cid, req) for cid, req, resp in w.net.transcript
        if dec(dec(req)[0])[0] == b"GET"]
w.clock.advance(L - HOUR)
replayed = [dec(w.net.c[cid].handle(req))[1].decode() for cid, req in renews]
replayed_get = [dec(w.net.c[cid].handle(req))[1].decode() for cid, req in gets]
w.clock.advance(2 * HOUR)
after = w.adversary_read(w.image(), "afu", "secret")
res["replay"] = {"renew_replies": replayed, "get_replies": replayed_get,
                 "lease_extended_by_replay": after is not None}
print("replay", res["replay"])

# (c) Operations without the required key ---------------------------------
w = fresh()
w.user_lock()
adv = LeaseClient(w.dev, AdversaryKeyStore(w.ks, "afu"), w.net,
                  copy.deepcopy(w.client.disk), w.t, w.n, w.w)
r = {}
try:
    adv.renew()
    r["renew"] = "accepted"
except AccessDenied as e:
    r["renew"] = "AccessDenied (presence key)"
try:
    adv.unlock()
    adv._rotate()
    r["rotate"] = "accepted"
except AccessDenied:
    r["rotate"] = "AccessDenied (presence key)"
# an adversary who forges the owner request with the device key
from lease.client import Owner
from lease.prims import SigKey
fake = Owner(SigKey())
w.clock.advance(L + HOUR)
r["reactivate_with_wrong_key"] = fake.reactivate(w.net, w.dev)
res["missing_key"] = r
print("missing key", r)


# (d) HNDL against expiry ------------------------------------------------------
def hndl(pq):
    w = World("L-bg", lease=L, pq=pq)
    w.user_unlock()
    w.client.put_record("secret", b"s3cret")
    w.user_lock()
    w.ks.state = "locked"
    w.net.record = True
    w.client.unlock()              # honest background unlock, recorded
    w.client.lock()
    w.net.record = False
    image = w.image()
    w.clock.advance(L + HOUR)      # lease expired, custodians refuse
    denied = w.adversary_read(image, "afu", "secret") is None
    # CRQC: recover the transport keys of the recorded GET responses
    shares = []
    for cid, req, resp in w.net.transcript:
        body = dec(dec(req)[0])
        if body[0] != b"GET":
            continue
        epoch, eph_pub = int.from_bytes(body[4], "big"), body[5]
        r = dec(resp)
        x_pk = dec(eph_pub)[0]
        key = crqc_recover_x25519(eph_pub, r[1], DLOG_ORACLE[x_pk],
                                  b"lease-get")
        if key is None:
            continue
        try:
            rec, _ = dec(aead_open(key, r[2], enc("GET", cid, w.dev, epoch)))
        except InvalidTag:
            continue
        x, y, *_ = dec(rec)
        shares.append((int.from_bytes(x, "big"), y))
    recovered = False
    if len(shares) >= w.t:
        adv = LeaseClient(w.dev, AdversaryKeyStore(w.ks, "afu"), None,
                          copy.deepcopy(image), w.t, w.n)
        e = image["committed"]["epoch"]
        adv.kek = adv._kek(shamir.combine(shares[:w.t]), e)
        adv.epoch = e
        recovered = adv.get_record("secret") == b"s3cret"
    return {"transport": "X25519+ML-KEM-768" if pq else "X25519 only",
            "custodians_refuse_after_lease": denied,
            "shares_recovered_from_transcript": len(shares),
            "data_recovered": recovered}


res["hndl"] = [hndl(False), hndl(True)]
for h in res["hndl"]:
    print("hndl", h)

# (e) Delayed delivery of withheld lease-extending requests -----------------
# The network withholds every RENEW the honest device sends after seizure
# time 0 and delivers the captured requests at hour 71; the AFU adversary
# then tries to open the store at hour 73 (after the lease).
from lease.prims import dec as _dec
w = fresh()
held = []


def withhold(cid, req):
    if _dec(_dec(req)[0])[0] == b"RENEW":
        held.append((cid, req))
        return "drop"
    return None


w.net.intercept = withhold
w.client.renew()                     # honest renewal, withheld by the network
w.net.intercept = None
w.user_lock()
w.clock.advance(71 * HOUR)
late = [_dec(w.net.c[cid].handle(req))[1].decode() for cid, req in held]
w.clock.advance(2 * HOUR)
res["delayed_renewal"] = {
    "withheld_requests": len(held), "replies_at_71h": late,
    "afu_reads_after_lease": w.adversary_read(w.image(), "afu", "secret")
    is not None}
print("delayed renewal", res["delayed_renewal"])

# (f) Forged upload receipts ------------------------------------------------
# The network drops every PUT of a rotation and answers "OK" itself; the
# device must not promote the new epoch, and its data must stay readable.
w = fresh()


def forge(cid, req):
    if _dec(_dec(req)[0])[0] == b"PUT":
        return enc("OK")
    return None


w.net.intercept = forge
try:
    w.client.rotate()
    rotated = True
except LeaseError:
    rotated = False
w.net.intercept = None
w.client.lock()
w.client.unlock()
res["forged_receipts"] = {"rotation_promoted": rotated,
                          "data_readable_after":
                          w.client.get_record("secret") == b"s3cret"}
print("forged receipts", res["forged_receipts"])

# (g) Malformed and truncated replies -----------------------------------------
w = fresh()
w.user_lock()


def garble(cid, req):
    if cid in (1, 2) and _dec(_dec(req)[0])[0] == b"GET":
        # custodian 1: well-formed but bogus ciphertext; custodian 2: empty
        return enc("OK", b"\x00" * 10, b"garbage") if cid == 1 else b""
    return None


w.net.intercept = garble
w.ks.state = "unlocked"
try:
    w.client.unlock()
    ok = w.client.get_record("secret") == b"s3cret"
except LeaseError:
    ok = False
w.net.intercept = None
errs = list(w.client.last_errors)
# second pass: truncated encodings from the same two custodians
w.client.lock()


def truncate(cid, req):
    if cid in (1, 2) and _dec(_dec(req)[0])[0] == b"GET":
        return b"\x00\x00\x00\x09OK" if cid == 1 else b"\x01"
    return None


w.net.intercept = truncate
try:
    w.client.unlock()
    ok2 = w.client.get_record("secret") == b"s3cret"
except LeaseError:
    ok2 = False
w.net.intercept = None
res["malformed_replies"] = {"garbled_custodians": 2,
                            "unlock_ok_bogus_and_empty": ok,
                            "unlock_ok_truncated": ok2,
                            "errors": errs + list(w.client.last_errors)}
print("malformed", res["malformed_replies"])

# (h) Autonomous erasure and terminal state ------------------------------------
w = fresh()
w.user_lock()
w.clock.advance(L + 30 * 24 * HOUR + HOUR)    # no request reaches custodians
present = sum(1 for c in w.custodians if c.dev[w.dev].slots)
react = w.owner.reactivate(w.net, w.dev)
res["autonomous_erasure"] = {"custodians_still_holding_shares": present,
                             "reactivations_accepted_after_erasure": react}
print("erasure", res["autonomous_erasure"])

# (i) Forward secrecy of uploads -------------------------------------------------
# Record the PUT traffic of a rotation, then give the adversary the complete
# state of every custodian afterwards (all outstanding challenge keys included)
# and try to decrypt the recorded uploads.
w = fresh()
w.net.record = True
w.client.rotate()
w.net.record = False
recorded = [(cid, req) for cid, req, resp in w.net.transcript
            if _dec(_dec(req)[0])[0] == b"PUT"]
opened = 0
for cid, req in recorded:
    body = _dec(_dec(req)[0])
    kem_ct, box, nonce = body[6], body[7], body[8]
    for r in w.custodians[cid - 1].dev.values():      # custodian compromise
        if nonce in r.nonces:
            opened += 1
res["upload_forward_secrecy"] = {"recorded_uploads": len(recorded),
                                 "decryptable_after_custodian_compromise":
                                 opened}
print("upload FS", res["upload_forward_secrecy"])

# (j) Delayed delivery of withheld uploads ------------------------------------
w = fresh()
held = []


def hold_puts(cid, req):
    if _dec(_dec(req)[0])[0] == b"PUT":
        held.append((cid, req))
        return "drop"
    return None


w.net.intercept = hold_puts
try:
    w.client.rotate()
except LeaseError:
    pass                                   # no receipts: rotation aborts
w.net.intercept = None
w.clock.advance(300)                       # longer than the challenge validity
late_put = [_dec(w.net.c[cid].handle(req))[1].decode() for cid, req in held]
res["delayed_upload"] = {"withheld_uploads": len(held), "replies": late_put}
print("delayed upload", res["delayed_upload"])

# (k) Erasure exactly at the horizon -------------------------------------------
w = fresh()
w.user_lock()
c0 = w.custodians[0]
deadline = c0.dev[w.dev].lease_until + c0.policy.hard
w.clock.advance(deadline - 1 - w.clock.now())
before = bool(c0.dev[w.dev].slots)
w.clock.advance(1)
after = bool(c0.dev[w.dev].slots)
res["erasure_boundary"] = {"shares_one_second_before": before,
                           "shares_at_horizon": after}
print("erasure boundary", res["erasure_boundary"])

with open(OUT + "/e3_robustness.json", "w") as f:
    json.dump(res, f, indent=1)
