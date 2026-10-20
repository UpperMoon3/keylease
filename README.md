# KeyLease — prototype, experiments and raw results

Reproducibility package for "KeyLease: Threshold-Leased Key Custody for
Time-Bounded At-Rest Protection of Seized Endpoints in Managed Device Fleets".

    lease/        Shamir over GF(2^8), simulated keystore (AFU / presence
                  access classes), custodian, client (two-phase rotation,
                  resume rule), baselines B0-B2, hybrid X25519+ML-KEM-768
                  KEM, compact Double Ratchet
    experiments/  e1  seizure scenarios S1-S12 against B0-B4 and KeyLease
                  e2  exhaustive crash-consistency check (242,324 resumes)
                  e3  Byzantine custodians, malformed replies, replay,
                      delayed delivery, forged receipts, autonomous erasure,
                      upload forward secrecy, HNDL attack on expiry
                  e4  CPU time (median, IQR, p5/p95) and wire bytes
                  e5  RTT collection (TCP handshake, 11 endpoints)
                  e6  placements, availability, lockout, traffic models
                  e7  composition with the Double Ratchet
                  e8  cumulative-exposure bound on the KeyLease schedule,
                      validated by enumeration and Monte Carlo
                  make_tables.py / make_figs.py -> ../paper/{tables,figs}
    android/      E9: Android Keystore benchmark app (Java, built with the SDK
                  command-line tools by build.sh; prebuilt keylease-bench.apk).
                  Install, run, then read files/keystore_bench.json with
                  `adb shell run-as kz.keylease.bench cat files/keystore_bench.json`
    results/      raw JSON results and the logs of the reported runs
                  (e9_keystore_run1/2.json: POCO X8 Pro, Android 16, MT6899)
    tests/        cross-checks (ML-KEM interop with kyber-py, Shamir)
    SHA256SUMS    hashes of every file in this package

Requirements: Python >= 3.10 and the packages in requirements.txt:
cryptography >= 47 (native ML-KEM and ML-DSA), numpy, matplotlib, and
kyber-py / dilithium-py (pure-Python cross-checks, imported by tests/ and e4).
Tested environment: Python 3.10.12, cryptography 50.0.2 (OpenSSL backend),
numpy 2.2.6, matplotlib 3.10.9, kyber-py 1.2.0, dilithium-py 1.5.1.

    pip install -r requirements.txt
    ./run_all.sh     # e2 takes ~40 min; e5 measures live RTTs (~7 min) and is
                     # skipped if results/e5_rtt_samples.json exists

Reported numbers were produced on an Apple M1 (macOS, Python 3.10.12,
cryptography 50.0.2, OpenSSL backend). Custodians run in-process and the
keystore is simulated; see the paper for the scope of each experiment.
