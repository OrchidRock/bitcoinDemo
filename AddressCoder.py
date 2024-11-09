from Crypto.Hash import SHA256
from Crypto.Hash import RIPEMD160

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def hash160(s):
    """
    sha256 followed by ripemd160
    :param s:
    :return:
    """
    return RIPEMD160.new(SHA256.new(s).digest()).digest()


def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def double_hash256(s):
    """
    two rounds of sha256 to against birthday attack.
    """
    return SHA256.new(SHA256.new(s).digest()).digest()

def encode_base58_checksum(b):
    return encode_base58(b + double_hash256(b)[:4])