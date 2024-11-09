from FieldElement import FieldElement

SECP_256K1_P = 2 ** 256 - 2 ** 32 - 977

class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=SECP_256K1_P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)




if __name__ == '__main__':
    print(S256Field(12))