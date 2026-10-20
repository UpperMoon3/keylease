"""Cross-checks of the primitives against independent implementations."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from kyber_py.ml_kem import ML_KEM_768
from lease import shamir


def test_mlkem_interop():
    for _ in range(20):
        k = MLKEM768PrivateKey.generate()
        ek = k.public_key().public_bytes_raw()
        ss, ct = ML_KEM_768.encaps(ek)        # pure Python encapsulation
        assert k.decapsulate(ct) == ss        # OpenSSL decapsulation


def test_shamir():
    for t, n in [(1, 1), (2, 3), (3, 5), (5, 9), (7, 11)]:
        for _ in range(20):
            s = os.urandom(32)
            sh = shamir.split(s, t, n)
            assert shamir.combine(random.sample(sh, t)) == s


if __name__ == "__main__":
    test_mlkem_interop()
    test_shamir()
    print("ok")
