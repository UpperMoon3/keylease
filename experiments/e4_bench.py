"""E4: CPU time and traffic of the storage layer.

All custodians run in-process, so the CPU time of an operation is the sum of
the client's and the custodians' work (an upper bound of the client's own
cost). Each figure is the median of REPS runs after WARM warm-up runs.
"""
import json
import os
import platform
import statistics
import subprocess
import time

from common import World, OUT, HOUR, DAY
from lease import shamir
from lease.prims import (SigKey, verify, HybridKEM, aead_seal, aead_open,
                         rand, hkdf)
from lease.ratchet import Session
from lease.prims import RAW, RAWPUB
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from kyber_py.ml_kem import ML_KEM_768

REPS, WARM = 41, 5


class Stat(float):
    """A median that also carries the quartiles and the 5th/95th
    percentiles of the sample; serialised by expand()."""


def expand(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = expand(v)
            if isinstance(v, Stat):
                out[k + "_q1"], out[k + "_q3"] = v.q1, v.q3
                out[k + "_p5"], out[k + "_p95"] = v.p5, v.p95
        return out
    if isinstance(obj, list):
        return [expand(v) for v in obj]
    if isinstance(obj, Stat):
        return float(obj)
    return obj


def bench(fn, reps=REPS, setup=None):
    for _ in range(WARM):
        a = setup() if setup else None
        fn(a) if setup else fn()
    ts = []
    for _ in range(reps):
        a = setup() if setup else None
        t0 = time.perf_counter()
        fn(a) if setup else fn()
        ts.append((time.perf_counter() - t0) * 1000)
    s = Stat(statistics.median(ts))
    q = statistics.quantiles(ts, n=20, method="inclusive")
    s.p5, s.p95 = q[0], q[-1]
    qq = statistics.quantiles(ts, n=4, method="inclusive")
    s.q1, s.q3 = qq[0], qq[2]
    return s


def machine():
    try:
        cpu = subprocess.check_output(["sysctl", "-n",
                                       "machdep.cpu.brand_string"]).decode()
    except Exception:
        cpu = platform.processor()
    return {"cpu": cpu.strip(), "os": platform.platform(),
            "python": platform.python_version()}


res = {"machine": machine(), "reps": REPS}
print(res["machine"])

# ------------------------------------------------------------ primitives
p = {}
sk = SigKey()
msg = rand(200)
sig = sk.sign(msg)
p["Ed25519 sign"] = bench(lambda: sk.sign(msg))
p["Ed25519 verify"] = bench(lambda: verify(sk.pk, sig, msg))
xa, xb = X25519PrivateKey.generate(), X25519PrivateKey.generate()
xbp = xb.public_key()
p["X25519 exchange"] = bench(lambda: xa.exchange(xbp))
ek, dk = ML_KEM_768.keygen()
_, ct = ML_KEM_768.encaps(ek)
p["ML-KEM-768 keygen (pure Python)"] = bench(lambda: ML_KEM_768.keygen())
p["ML-KEM-768 encaps (pure Python)"] = bench(lambda: ML_KEM_768.encaps(ek))
p["ML-KEM-768 decaps (pure Python)"] = bench(lambda: ML_KEM_768.decaps(dk, ct))
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
nk = MLKEM768PrivateKey.generate()
npk = nk.public_key()
_, nct = npk.encapsulate()
p["ML-KEM-768 keygen (OpenSSL)"] = bench(MLKEM768PrivateKey.generate)
p["ML-KEM-768 encaps (OpenSSL)"] = bench(npk.encapsulate)
p["ML-KEM-768 decaps (OpenSSL)"] = bench(lambda: nk.decapsulate(nct))
nd = MLDSA65PrivateKey.generate()
ndp = nd.public_key()
nsig = nd.sign(msg)
p["ML-DSA-65 sign (OpenSSL)"] = bench(lambda: nd.sign(msg))
p["ML-DSA-65 verify (OpenSSL)"] = bench(lambda: ndp.verify(nsig, msg))
from dilithium_py.ml_dsa import ML_DSA_65
dpk, dsk = ML_DSA_65.keygen()
dsig = ML_DSA_65.sign(dsk, msg)
p["ML-DSA-65 sign (pure Python)"] = bench(lambda: ML_DSA_65.sign(dsk, msg),
                                          reps=21)
p["ML-DSA-65 verify (pure Python)"] = bench(
    lambda: ML_DSA_65.verify(dpk, msg, dsig), reps=21)
res["sizes"] = {"ed25519_sig": 64, "ml_dsa_65_sig": len(dsig),
                "ml_dsa_65_pk": len(dpk), "mlkem768_ek": len(ek),
                "mlkem768_ct": len(ct)}
k = rand(32)
blob = rand(1024)
c1k = aead_seal(k, blob)
p["AES-256-GCM seal 1 KiB"] = bench(lambda: aead_seal(k, blob))
p["AES-256-GCM open 1 KiB"] = bench(lambda: aead_open(k, c1k))
p["HKDF-SHA256"] = bench(lambda: hkdf(k, b"x"))
for t, n in [(2, 3), (3, 5), (5, 9), (7, 11)]:
    s = rand(32)
    sh = shamir.split(s, t, n)
    p["Shamir split 32 B (%d,%d)" % (t, n)] = bench(lambda: shamir.split(s, t, n))
    p["Shamir combine 32 B (%d,%d)" % (t, n)] = bench(
        lambda: shamir.combine(sh[:t]))
res["primitives_ms"] = p
for kk, v in p.items():
    print("%-40s %8.3f ms" % (kk, v))

# ------------------------------------------------------------ operations
ops = []


def op_row(cfg, pq, design="L-bg", history=100):
    t, n = cfg
    w = World(design, t=t, n=n, pq=pq)
    w.user_unlock()
    for i in range(history):
        w.client.put_record("m%d" % i, rand(200))
    row = {"t": t, "n": n, "pq": pq, "history": history, "design": design}

    def unlock_cold():
        w.client.lock()
        w.client.unlock()
    row["unlock_ms"] = bench(unlock_cold)
    w.net.reset_counters()
    unlock_cold()
    row["unlock_bytes_up"], row["unlock_bytes_down"] = w.net.bytes_up, \
        w.net.bytes_down
    row["renew_ms"] = bench(lambda: w.client.renew())
    w.net.reset_counters()
    w.client.renew()
    row["renew_bytes"] = w.net.bytes_up + w.net.bytes_down
    row["rotate_ms"] = bench(lambda: w.client.rotate(), reps=21)
    w.net.reset_counters()
    w.client.rotate()
    row["rotate_bytes"] = w.net.bytes_up + w.net.bytes_down
    row["put_record_ms"] = bench(lambda: w.client.put_record("x", msg))
    row["get_record_ms"] = bench(lambda: w.client.get_record("x"))
    return row


for cfg in [(2, 3), (3, 5), (5, 9), (7, 11)]:
    for pq in (True, False):
        r = op_row(cfg, pq)
        ops.append(r)
        print(r)
for hist in (1000, 10000):
    r = op_row((3, 5), True, history=hist)
    ops.append(r)
    print(r)
res["operations"] = ops

# --- local baseline (B1) record operations for comparison
w = World("B1")
w.user_unlock()
w.client.put_record("x", msg)
res["B1_put_record_ms"] = bench(lambda: w.client.put_record("x", msg))
res["B1_get_record_ms"] = bench(lambda: w.client.get_record("x"))
res["B1_unlock_ms"] = bench(lambda: (w.client.lock(), w.client.unlock()))

# --- composition with a Double Ratchet: per-message storage cost
w = World("L-bg")
w.user_unlock()
skr = rand(32)
bp = X25519PrivateKey.generate()
a = Session.alice(skr, bp.public_key().public_bytes(RAW, RAWPUB))
b = Session.bob(skr, bp)


def one_message():
    m = a.encrypt(b"x" * 100)
    w.client.put_record("session:alice", a.dumps())
    b.decrypt(m)


res["dr_message_with_session_store_ms"] = bench(one_message)
res["dr_message_without_store_ms"] = bench(
    lambda: b.decrypt(a.encrypt(b"x" * 100)))
res["dr_session_record_bytes"] = len(a.dumps())
print({k: v for k, v in res.items() if k.startswith(("B1", "dr"))})

with open(OUT + "/e4_bench.json", "w") as f:
    json.dump(expand(res), f, indent=1)
