from unittest import TestCase

from Crypto.Util.py3compat import BytesIO
from io import BytesIO
from AddressCoder import double_hash256
from Script import Script


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


class Transaction:
    def __init__(self, version, tx_ins, tx_outs, lock_time, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.lock_time = lock_time
        self.testnet = testnet

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'Transaction: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime:{}'.format(
            self.identifier(),
            self.version,
            tx_ins,
            tx_outs,
            self.lock_time
        )

    def identifier(self):
        """
        Human-readable hexadecimal of the transaction.
        :return:
        """
        return self.hash().hex()

    def hash(self):
        return double_hash256(self.serialize())[::-1]

    def serialize(self):
        result = self.version.to_bytes(4, 'little')
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += self.lock_time.to_bytes(4, 'little')
        return result

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        version = int.from_bytes(s.read(4), 'little')
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TransactionInput.parse(s))

        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TransactionOutput.parse(s))

        lock_time = int.from_bytes(s.read(4), 'little')
        return cls(version, inputs, outputs, lock_time, testnet)


class TransactionInput:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(), self.prev_index)

    def fetch_transactions(self, testnet=False):
        return TransactionFetcher.fetch(self.prev_tx.hex(), testnet)

    def value(self, testnet=False):
        """
        Get the output value by looking up the tx hash.
        Returns the amount in satoshi.
        """
        tx = self.fetch_transactions(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        tx = self.fetch_transactions(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey

    def serialize(self):
        result = self.prev_tx[::-1]
        result += self.prev_index.to_bytes(4, 'little')
        result += self.script_sig.serialize()
        result += self.sequence.to_bytes(4, 'little')
        return result

    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1]
        prev_index = int.from_bytes(s.read(4), 'little')
        script_sig = Script.parse(s)
        sequence = int.from_bytes(s.read(4), 'little')
        return cls(prev_tx, prev_index, script_sig, sequence)

    def fee(self):
        pass


class TransactionOutput:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        amount = int.from_bytes(s.read(8), 'little')
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self):
        result = self.amount.to_bytes(8, 'little')
        result += self.script_pubkey.serialize()
        return result


class TransactionFetcher:
    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        return Transaction(0, [], [], 0)


class TransactionTest(TestCase):

    def test_repr(self):
        tx = Transaction(version='1.0', tx_ins=[], tx_outs=[], lock_time=0, testnet=False)
        print(tx)

    def test_varint(self):
        self.assertEqual(encode_varint(252), b'\xfc')
        self.assertEqual(read_varint(BytesIO(b'\xfc')), 252)
        self.assertEqual(encode_varint(255), b'\xfd\xff\x00')
        self.assertEqual(read_varint(BytesIO(b'\xfd\xff\x00')), 255)
        self.assertEqual(encode_varint(70015), b'\xfe\x7f\x11\x01\x00')
        self.assertEqual(read_varint(BytesIO(b'\xfe\x7f\x11\x01\x00')), 70015)
        self.assertEqual(encode_varint(18005558675309), b'\xff\x6d\xc7\xed\x3e\x60\x10\x00\x00')
        self.assertEqual(read_varint(BytesIO(b'\xff\x6d\xc7\xed\x3e\x60\x10\x00\x00')), 18005558675309)



