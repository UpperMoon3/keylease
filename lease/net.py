"""In-process network between devices and custodians.

Counts bytes in both directions, can take custodians down, and records every
exchange (the transcript a harvest-now-decrypt-later adversary would store).
"""


class Unreachable(Exception):
    pass


class Network:
    def __init__(self, custodians):
        self.c = {c.cid: c for c in custodians}
        self.up = set(self.c)
        self.device_online = True
        self.bytes_up = 0
        self.bytes_down = 0
        self.msgs = 0
        self.record = False
        self.transcript = []
        self.crash_hook = None     # called before every request (fault inj.)
        # active network adversary: intercept(cid, req) returns None to
        # deliver, "drop" to drop, or bytes to answer in the custodian's place
        self.intercept = None

    def send(self, cid, req):
        if self.crash_hook:
            self.crash_hook(cid, req)
        if not self.device_online or cid not in self.up:
            raise Unreachable(cid)
        forged = self.intercept(cid, req) if self.intercept else None
        if forged == "drop":
            raise Unreachable(cid)
        resp = forged if forged is not None else self.c[cid].handle(req)
        self.bytes_up += len(req)
        self.bytes_down += len(resp)
        self.msgs += 1
        if self.record:
            self.transcript.append((cid, req, resp))
        return resp

    def reset_counters(self):
        self.bytes_up = self.bytes_down = self.msgs = 0
