class FieldElement:
    """
    Field Element Class
    """
    def __init__(self, num, prime):
        if num > prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.num, self.prime)

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different fields.')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different fields.')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if not isinstance(other, self.__class__):
            num = (self.num * other) % self.prime
            return self.__class__(num, self.prime)
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different fields.')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        # pow function has supported negative exponent
        exponent = exponent % (self.prime - 1)
        num = pow(self.num, exponent, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different fields.')
        return self.__mul__(other ** (self.prime - 2))



if __name__ == '__main__':
    a = FieldElement(7 ,13)
    b = FieldElement(12,13)
    c = FieldElement(6,13)
    print(a == b)
    print(a == a)
    print(a + b == c)
    print(a == c - b)
    print(b == c - a)
    print(a * b == c)
    print(a ** 3)

    d = FieldElement(2, 19)
    e = FieldElement(7, 19)
    f = FieldElement(5, 19)
    print(d / e)
    print(e / f)

    h = FieldElement(8, 13)
    print(a**-3)
    print(a*3)



