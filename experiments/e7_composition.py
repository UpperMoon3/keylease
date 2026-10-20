"""E7: composition with a Double Ratchet in both operating modes.

Bob's messenger stores its ratchet session and message history in the
storage layer. While Bob's device is locked, Alice sends a burst of messages
that arrive out of order.

strict mode     Bob's messenger cannot open its store while locked; it queues
                the (end-to-end encrypted) ciphertexts and processes the
                backlog at the next unlock.
background mode Bob's messenger reopens its store while locked with the AFU
                key and processes the messages as they arrive.

The experiment checks that every message is delivered exactly once in both
modes, that the session survives lock/unlock cycles and a rotation, and what
an AFU adversary seizing the locked device can read in each mode.
"""
import json
import os
import random

from common import World, OUT, HOUR, LeaseError, AccessDenied
from lease.ratchet import Session
from lease.prims import RAW, RAWPUB, rand, enc, dec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

random.seed(7)
BURST = 200


def run(mode):
    w = World("L-strict" if mode == "strict" else "L-bg")
    w.user_unlock()
    sk = rand(32)
    bp = X25519PrivateKey.generate()
    alice = Session.alice(sk, bp.public_key().public_bytes(RAW, RAWPUB))
    bob = Session.bob(sk, bp)
    bob_store = w.client
    # a short conversation while Bob is present
    for i in range(5):
        m = alice.encrypt(b"hello %d" % i)
        bob_store.put_record("msg:%d" % i, bob.decrypt(m))
        bob_store.put_record("session:alice", bob.dumps())
        bob_store.put_record("msg:r%d" % i, b"reply")
        alice.decrypt(bob.encrypt(b"reply"))
    w.user_lock()
    del bob                                      # memory wiped at lock
    burst = [(i, alice.encrypt(b"burst %d" % i)) for i in range(BURST)]
    random.shuffle(burst)                         # out-of-order delivery
    queue = []
    processed_locked = 0
    for i, ct in burst:
        if mode == "strict":
            opened = True
            try:
                w.client.unlock()                 # needs the presence key
            except AccessDenied:
                opened = False
            assert not opened, "strict mode opened while locked"
            queue.append(ct)                      # store ciphertext as is
        else:
            w.client.unlock()                     # AFU key, lease active
            s = Session.loads(w.client.get_record("session:alice"))
            w.client.put_record("msg:b%d" % i, s.decrypt(ct))
            w.client.put_record("session:alice", s.dumps())
            w.client.lock()
            processed_locked += 1
    # Bob unlocks: process the backlog
    w.user_unlock()
    s = Session.loads(w.client.get_record("session:alice"))
    for ct in queue:
        pt = s.decrypt(ct)
        i = int(pt.split()[1])
        w.client.put_record("msg:b%d" % i, pt)
    w.client.put_record("session:alice", s.dumps())
    w.client.rotate()
    w.user_lock()
    w.user_unlock()
    s = Session.loads(w.client.get_record("session:alice"))
    delivered = sum(1 for i in range(BURST)
                    if w.client.get_record("msg:b%d" % i) == b"burst %d" % i)
    # the conversation continues in both directions after all of this
    alice.decrypt(s.encrypt(b"back"))
    ok_after = s.decrypt(alice.encrypt(b"again")) == b"again"
    w.client.put_record("session:alice", s.dumps())
    w.user_lock()
    # seizure of the locked device during an active lease: AFU adversary
    adv = w.adversary_read(w.image(), "afu", "session:alice")
    adv_reads_session = adv is not None
    return {"mode": mode, "burst": BURST,
            "processed_while_locked": processed_locked,
            "queued_ciphertexts": len(queue),
            "delivered_after_unlock": delivered,
            "conversation_continues": ok_after,
            "afu_adversary_reads_session_during_lease": adv_reads_session,
            "skipped_keys_in_session": len(s.skipped),
            "session_record_bytes": len(s.dumps())}


res = [run("strict"), run("background")]
for r in res:
    print(r)
json.dump(res, open(OUT + "/e7_composition.json", "w"), indent=1)
