"""E5 (data collection): round-trip times from the test client to candidate
custodian locations operated by different providers.

The TCP handshake time (SYN -> SYN/ACK) to a public HTTPS endpoint is one
network round-trip; on a warm TLS 1.3 connection a custody request costs one
round-trip plus server processing, so these samples are a lower bound of the
per-request network time. Samples are interleaved across endpoints in rounds
so that all endpoints see the same network conditions.
"""
import json
import socket
import sys
import time

from common import OUT

ENDPOINTS = {
    "AWS Frankfurt": "dynamodb.eu-central-1.amazonaws.com",
    "AWS Stockholm": "dynamodb.eu-north-1.amazonaws.com",
    "AWS UAE": "dynamodb.me-central-1.amazonaws.com",
    "AWS Mumbai": "dynamodb.ap-south-1.amazonaws.com",
    "AWS Virginia": "dynamodb.us-east-1.amazonaws.com",
    "AWS Tokyo": "dynamodb.ap-northeast-1.amazonaws.com",
    "Hetzner Falkenstein": "fsn1-speed.hetzner.com",
    "Hetzner Helsinki": "hel1-speed.hetzner.com",
    "Yandex Moscow": "storage.yandexcloud.net",
    "Cloudflare anycast": "1.1.1.1",
    "Google anycast": "www.google.com",
}
ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 40


def rtt(host):
    t0 = time.perf_counter()
    s = socket.create_connection((host, 443), timeout=4)
    dt = (time.perf_counter() - t0) * 1000
    s.close()
    return dt


def main():
    addr = {}
    for name, host in ENDPOINTS.items():
        try:
            addr[name] = socket.gethostbyname(host)   # resolve once
        except OSError as e:
            print("skip", name, e)
    samples = {k: [] for k in addr}
    for k in addr:                                     # warm-up, discarded
        try:
            rtt(addr[k])
        except OSError:
            pass
    for r in range(ROUNDS):
        for k in addr:
            try:
                samples[k].append(rtt(addr[k]))
            except OSError:
                samples[k].append(None)
        time.sleep(1.0)
    meta = {"rounds": ROUNDS, "started_utc": time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "client_country": "KZ",
        "method": "TCP connect time to port 443, resolved address"}
    with open(OUT + "/e5_rtt_samples.json", "w") as f:
        json.dump({"meta": meta, "endpoints": ENDPOINTS, "addr": addr,
                   "samples_ms": samples}, f, indent=1)
    for k, v in samples.items():
        ok = sorted(x for x in v if x is not None)
        if ok:
            print("%-22s n=%d median=%.1f p95=%.1f" % (
                k, len(ok), ok[len(ok) // 2], ok[int(len(ok) * .95) - 1]))


if __name__ == "__main__":
    main()
