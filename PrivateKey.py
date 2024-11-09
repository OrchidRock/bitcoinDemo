import hashlib
import hmac
from random import randint
from unittest import TestCase

from S256Point import SECP_256K1_G, SECP_256K1_N, Signature


class PrivateKey:

    def __init__(self, secret):
        self.secret = secret
        self.point = secret * SECP_256K1_G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * SECP_256K1_G).x.num
        k_inv = pow(k, (SECP_256K1_N - 2), SECP_256K1_N)
        s = (z + r * self.secret) * k_inv % SECP_256K1_N
        if s > SECP_256K1_N / 2:
            s = SECP_256K1_N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        """
        RFC 6979
        IMPORTANT: every signature must has a deterministic unique k.
        """
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > SECP_256K1_N:
            z -= SECP_256K1_N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if 1 <= candidate < SECP_256K1_N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()


class PrivateKeyTest(TestCase):

    def test_sign(self):
        pk = PrivateKey(randint(0, SECP_256K1_N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))