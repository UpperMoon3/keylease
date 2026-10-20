"""E2: exhaustive crash-consistency check of epoch rotation.

For every configuration (t, n, w), every crash point of the rotation, and
every set A of custodians reachable at resume, a rebooted client resumes from
the persisted disk alone. The outcome (pre-rotation state, post-rotation
state, or failure) is compared with the prediction of Proposition 3, and the
guarantee "resume succeeds whenever |A| >= n - w + t" is checked. Two naive
single-version protocols are run for contrast.
"""
import copy
import itertools
import json

from common import OUT, Clock, Policy, Custodian, Network, KeyStore, Owner, \
    SigKey, LeaseClient, LeaseError
from lease.client import Crash
from lease.prims import enc

CONFIGS = [(2, 3, 2), (2, 3, 3), (3, 5, 3), (3, 5, 4), (3, 5, 5), (4, 7, 5),
           (5, 9, 6), (7, 11, 7), (7, 11, 9)]
DEV = b"dev"


def crash_points(n):
    return (["before-pending", "after-pending"] +
            ["put:%d" % k for k in range(n)] +
            ["before-promote", "after-promote"] +
            ["notice:%d" % k for k in range(n)])


def build(t, n, w, cls_c=Custodian, cls_l=LeaseClient, prior="all"):
    clock = Clock()
    cs = [cls_c(i, clock, Policy(), pq=False) for i in range(1, n + 1)]
    net = Network(cs)
    ks = KeyStore()
    owner = Owner(SigKey())
    if prior == "quorum":                 # epoch 1 reaches only w custodians
        net.up = set(range(1, w + 1))
    c = cls_l.setup(DEV, ks, net, owner.key.pk, t, n, w, pq=False)
    net.up = set(range(1, n + 1))
    for i in range(4):
        c.put_record("r%d" % i, b"record %d" % i)
    return clock, cs, net, ks, c


def holders(cs, epoch):
    return {c.cid for c in cs if epoch in c.dev[DEV].slots}


def snapshot(cs, disk):
    return [copy.deepcopy(c.dev[DEV]) for c in cs], copy.deepcopy(disk)


def restore(cs, snap):
    recs, disk = snap
    for c, r in zip(cs, recs):
        c.dev[DEV] = copy.deepcopy(r)
    return copy.deepcopy(disk)


def predict(t, w, disk, cs, A, old, new):
    if disk["pending"] is not None:
        if len(A & holders(cs, new)) >= w:
            return "post"
        return "pre" if len(A & holders(cs, old)) >= t else "fail"
    ec = disk["committed"]["epoch"]
    if len(A & holders(cs, ec)) >= t:
        return "post" if ec == new else "pre"
    return "fail"


def resume(t, n, w, net, ks, disk, A, cls_l=LeaseClient):
    net.up = set(A)
    c = cls_l(DEV, ks, net, disk, t, n, w, pq=False)
    try:
        c.unlock()
    except LeaseError:
        return "fail", None
    for i in range(4):
        assert c.get_record("r%d" % i) == b"record %d" % i
    return c.epoch, c


def run_two_phase(t, n, w, prior):
    stats = dict(cases=0, pre=0, post=0, fail=0, mismatch=0,
                 guarantee_violations=0, continued=0)
    for cp in crash_points(n):
        clock, cs, net, ks, c = build(t, n, w, prior=prior)
        old = c.disk["committed"]["epoch"]
        new = c.disk["next_epoch"]
        c.crash_at = {cp}
        try:
            c.rotate()
        except Crash:
            pass
        snap = snapshot(cs, c.disk)
        for k in range(1, n + 1):
            for A in itertools.combinations(range(1, n + 1), k):
                A = set(A)
                disk = restore(cs, snap)
                exp = predict(t, w, disk, cs, A, old, new)
                got, client = resume(t, n, w, net, ks, disk, A)
                got_s = "fail" if got == "fail" else (
                    "post" if got == new else "pre")
                stats["cases"] += 1
                stats[got_s] += 1
                if got_s != exp:
                    stats["mismatch"] += 1
                if len(A) >= n - w + t and got_s == "fail":
                    stats["guarantee_violations"] += 1
                # the session continues: rotate again with every custodian
                # up, lock, and unlock from the custodians
                if client is not None and len(A) == n:
                    net.up = set(range(1, n + 1))
                    client.rotate()
                    client.put_record("after", b"x")
                    client.lock()
                    client.unlock()
                    assert client.get_record("after") == b"x"
                    stats["continued"] += 1
    return stats


# ------------------------------------------------- naive single-version
class SingleVersionCustodian(Custodian):
    def _op_PUT(self, r, dev_id, args, kem):
        resp = super()._op_PUT(r, dev_id, args, kem)
        epoch = int.from_bytes(args[0], "big")
        r.slots = {e: v for e, v in r.slots.items() if e == epoch}
        return resp


class NaiveClient(LeaseClient):
    order = "mask-first"

    def _rotate(self, initial=False):
        epoch = self.disk["next_epoch"]
        self.disk["next_epoch"] = epoch + 1
        from lease.prims import rand, aead_open, aead_seal
        kcust = rand(32)
        kek = self._kek(kcust, epoch)
        wraps = {rid: aead_seal(kek, aead_open(
            self.kek, self.disk["wraps"][rid], enc(self.dev, self.epoch, rid)),
            enc(self.dev, epoch, rid)) for rid in self.disk["records"]}
        new = {"epoch": epoch, "kc": self._kc(kek, self.dev, epoch),
               "wraps": wraps}
        if self.order == "mask-first":
            self._crash("before-pending")
            self._promote(new)
            self._crash("after-pending")
            self._put_all(epoch, epoch, kcust)
            self._crash("before-promote")
        else:
            self._crash("before-pending")
            self._crash("after-pending")
            self._put_all(epoch, epoch, kcust)
            self._crash("before-promote")
            self._promote(new)
        self.kek, self.epoch = kek, epoch
        self._crash("after-promote")


class NaiveQuorumFirst(NaiveClient):
    order = "quorum-first"


def run_naive(t, n, w, cls_l):
    lost = []
    for cp in crash_points(n):
        if cp.startswith("notice"):
            continue
        clock, cs, net, ks, c = build(t, n, w, SingleVersionCustodian, cls_l)
        c.crash_at = {cp}
        try:
            c.rotate()
        except Crash:
            pass
        got, _ = resume(t, n, w, net, ks, copy.deepcopy(c.disk),
                        set(range(1, n + 1)), cls_l)
        if got == "fail":
            lost.append(cp)
    return lost


def main():
    out = []
    for (t, n, w) in CONFIGS:
        for prior in (["all", "quorum"] if w < n else ["all"]):
            s = run_two_phase(t, n, w, prior)
            s.update(t=t, n=n, w=w, prior=prior)
            out.append(s)
            print("two-phase", (t, n, w), prior, s)
    naive = []
    for (t, n, w) in CONFIGS:
        for cls_l in (NaiveClient, NaiveQuorumFirst):
            lost = run_naive(t, n, w, cls_l)
            naive.append(dict(t=t, n=n, w=w, order=cls_l.order,
                              crash_points=len(crash_points(n)) - n,
                              lost_with_all_custodians_up=lost))
            print("naive", cls_l.order, (t, n, w), "lost at", lost)
    with open(OUT + "/e2_crash.json", "w") as f:
        json.dump({"two_phase": out, "naive": naive}, f, indent=1)


if __name__ == "__main__":
    main()
