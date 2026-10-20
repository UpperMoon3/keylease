"""Conventional at-rest designs against which the lease design is compared.

B0 plain        the data key is stored in the clear (the model of the
                ratchet literature, where storage is trusted);
B1 ks-afu       the data key is sealed under a key-store key usable after
                first unlock (deployed practice: background message receipt);
B2 ks-presence  the data key is sealed under a key that needs user presence.

B3 (a single remote key server, Keypad-like) is LeaseClient with t = n = 1,
no device factor and an unbounded lease; see experiments/common.py.

All designs use the same record format: per-record keys wrapped under the
data key, so that differences are due to key custody only.
"""
from .prims import rand, enc, aead_seal, aead_open
from .client import LeaseError

SEAL = {"plain": None, "ks-afu": "seal_afu", "ks-presence": "seal_presence"}


class LocalClient:
    def __init__(self, dev_id, ks, disk, mode):
        self.dev, self.ks, self.disk, self.mode = dev_id, ks, disk, mode
        self.dek = None

    @classmethod
    def setup(cls, dev_id, ks, mode):
        disk = {"wraps": {}, "records": {}}
        dek = rand(32)
        disk["dek"] = dek if mode == "plain" else ks.seal(SEAL[mode], dek,
                                                          dev_id)
        self = cls(dev_id, ks, disk, mode)
        self.dek = dek
        return self

    def unlock(self):
        if self.dek is None:
            d = self.disk["dek"]
            self.dek = d if self.mode == "plain" else \
                self.ks.open(SEAL[self.mode], d, self.dev)

    def lock(self):
        self.dek = None

    def put_record(self, rid, pt):
        if self.dek is None:
            raise LeaseError("locked")
        rk = rand(32)
        self.disk["records"] = {**self.disk["records"],
                                rid: aead_seal(rk, pt, rid.encode())}
        self.disk["wraps"] = {**self.disk["wraps"],
                              rid: aead_seal(self.dek, rk, enc(self.dev, rid))}

    def get_record(self, rid):
        rk = aead_open(self.dek, self.disk["wraps"][rid], enc(self.dev, rid))
        return aead_open(rk, self.disk["records"][rid], rid.encode())

    def delete_record(self, rid):
        r, w = dict(self.disk["records"]), dict(self.disk["wraps"])
        r.pop(rid, None)
        w.pop(rid, None)
        self.disk["records"], self.disk["wraps"] = r, w
