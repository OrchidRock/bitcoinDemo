from Crypto.Hash import SHA256
from Crypto.Hash import RIPEMD160

BASE58_ALPHABET_TABLE = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

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
        result = BASE58_ALPHABET_TABLE[mod] + result
    return prefix + result

def hash256(s):
    """
    two rounds of sha256 to against birthday attack.
    """
    return SHA256.new(SHA256.new(s).digest()).digest()

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

def read_varint(s):
    '''
    read_varint reads a variable integer from a stream
    '''
    len_int = s.read(1)[0]
    if len_int == 0xfd:
        # 0xfd means the next two bytes are the number
        return int.from_bytes(s.read(2), 'little')
    elif len_int == 0xfe:
        # 0xfe means the next four bytes are the number
        return int.from_bytes(s.read(4), 'little')
    elif len_int == 0xff:
        # 0xff means the next eight bytes are the number
        return int.from_bytes(s.read(8), 'little')
    else:
        # anything else is just the integer
        return len_int

def encode_varint(len_int):
    '''
    encodes an integer as a varint
    '''
    if len_int < 0xfd:
        return bytes([len_int])
    elif len_int < 0x10000:
        return b'\xfd' + len_int.to_bytes(2, 'little')
    elif len_int < 0x100000000:
        return b'\xfe' + len_int.to_bytes(4, 'little')
    elif len_int < 0x10000000000000000:
        return b'\xff' + len_int.to_bytes(8, 'little')
    else:
        raise ValueError('integer too large: {}'.format(len_int))