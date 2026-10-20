"""Shared construction of the six designs compared in the experiments."""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lease.custodian import Custodian, Clock, Policy          # noqa: E402
from lease.net import Network                                   # noqa: E402
from lease.keystore import KeyStore, AdversaryKeyStore, AccessDenied  # noqa
from lease.client import LeaseClient, Owner, LeaseError         # noqa: E402
from lease.baselines import LocalClient                         # noqa: E402
from lease.prims import SigKey, InvalidTag                      # noqa: E402

HOUR = 3600.0
DAY = 86400.0
OUT = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(OUT, exist_ok=True)

DESIGNS = ["B0", "B1", "B2", "B3", "B4", "L-bg", "L-strict"]
DESIGN_LABEL = {
    "B0": "B0 plain",
    "B1": "B1 key store (AFU)",
    "B2": "B2 key store (presence)",
    "B3": "B3 single key server",
    "B4": "B4 single lease custodian",
    "L-bg": "Lease (3,5), background",
    "L-strict": "Lease (3,5), strict",
    # strict mode before the fix of Proposition 1 (K_dev under an AFU key);
    # run only to document the counterexample, not part of the design
    "L-strict-afu": "Lease (3,5), strict, AFU-sealed K_dev",
}
STRICT = ("L-strict", "L-strict-afu")


class World:
    """One device of one user, its custodians, and the owner authority."""

    def __init__(self, design, t=3, n=5, w=None, lease=72 * HOUR,
                 hard=30 * DAY, pq=True, dev=b"device-A"):
        self.design, self.dev = design, dev
        self.clock = Clock()
        self.ks = KeyStore()
        self.owner = Owner(SigKey())
        self.t, self.n, self.w, self.pq = t, n, w or t, pq
        if design in ("B0", "B1", "B2"):
            mode = {"B0": "plain", "B1": "ks-afu", "B2": "ks-presence"}[design]
            self.net = None
            self.client = LocalClient.setup(dev, self.ks, mode)
            self.mode = mode
            return
        if design in ("B3", "B4"):
            # B3: one server, no device factor, no expiry (Keypad-like);
            # B4: one custodian with the same lease, device factor and
            # rotation as KeyLease, i.e. KeyLease without the threshold
            t = n = 1
            self.t = self.n = self.w = 1
            if design == "B3":
                lease = 1e18
        pol = Policy(lease=lease, hard=hard)
        self.custodians = [Custodian(i, self.clock, pol, pq=pq)
                           for i in range(1, n + 1)]
        if design in STRICT:
            for c in self.custodians:
                c.get_signer = "presence"
        self.net = Network(self.custodians)
        self.client = LeaseClient.setup(
            dev, self.ks, self.net, self.owner.key.pk, self.t, self.n, self.w,
            pq=pq, device_factor=(design != "B3"),
            get_signer="presence" if design in STRICT else "auth",
            kdev_seal="seal_afu" if design == "L-strict-afu" else None)

    # ----------------------------------------------------------- user side
    def user_unlock(self):
        self.ks.state = "unlocked"
        self.client.unlock()
        if self.net is not None:
            self.client.renew()

    def user_lock(self):
        self.client.lock()
        self.ks.state = "locked"

    def image(self):
        return copy.deepcopy(self.client.disk)

    def audit_entries(self):
        if self.net is None:
            return 0
        return sum(len(c.dev[self.dev].log) for c in self.custodians
                   if self.dev in c.dev)

    # ------------------------------------------------------ adversary side
    def adversary_client(self, image, level, get_signer=None):
        aks = AdversaryKeyStore(self.ks, level)
        if self.net is None:
            return LocalClient(self.dev, aks, copy.deepcopy(image), self.mode)
        return LeaseClient(
            self.dev, aks, self.net, copy.deepcopy(image), self.t, self.n,
            self.w, pq=self.pq, device_factor=(self.design != "B3"),
            get_signer=get_signer or self.client.get_signer,
            kdev_seal=self.client.kdev_seal)

    def adversary_read(self, image, level, rid, get_signer=None):
        """Run the application's own unlock path with the adversary's
        key-store access; return the plaintext or None."""
        try:
            c = self.adversary_client(image, level, get_signer)
            c.unlock()
            return c.get_record(rid)
        except (AccessDenied, LeaseError, InvalidTag, KeyError) as e:
            self.last_failure = type(e).__name__ + ": " + str(e)[:80]
            return None
