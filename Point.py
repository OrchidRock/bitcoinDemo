import unittest

from FieldElement import FieldElement
class Point:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None or self.y is None:
            return
        if self.y ** 2 != self.x ** 3 + a * x + b:
            raise ValueError('({} {}) is not on the curve'.format(x, y))

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.x == other.x and self.y == other.y

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(self, other))
        if self.x is None or self.y is None:
            return other
        if other.x is None or other.y is None:
            return self

        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            new_x = s * s - self.x - other.x
            new_y = s * (self.x - new_x) - self.y
            return self.__class__(new_x, new_y, self.a, self.b)

        if self.y != other.y or self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        s = (3 * (self.x ** 2) + self.a) / (2 * self.y)
        new_x = s * s - 2 * self.x
        new_y = s * (self.x - new_x) - self.y
        return self.__class__(new_x, new_y, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self  # <1>
        result = self.__class__(None, None, self.a, self.b)  # <2>
        while coef:
            if coef & 1:  # <3>
                result += current
            current += current  # <4>
            coef >>= 1  # <5>
        return result


class PointTest(unittest.TestCase):

    def test_ne(self):
        a = Point(x=3, y=-7, a=5, b=7)
        b = Point(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_on_curve(self):
        with self.assertRaises(ValueError):
            Point(x=-2, y=4, a=5, b=7)
        # these should not raise an error
        Point(x=3, y=-7, a=5, b=7)
        Point(x=18, y=77, a=5, b=7)

    def test_add0(self):
        a = Point(x=None, y=None, a=5, b=7)
        b = Point(x=2, y=5, a=5, b=7)
        c = Point(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = Point(x=3, y=7, a=5, b=7)
        b = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = Point(x=-1, y=1, a=5, b=7)
        self.assertEqual(a + a, Point(x=18, y=-77, a=5, b=7))


if __name__ == '__main__':
    P1 = Point(-1, -1, 5, 7)
    P2 = Point(-1, 1 ,5, 7)
    P3 = Point(2, 5, 5, 7)
    inf = Point(None, None, 5, 7)
    print(P1 == P2)
    print(P1 + inf)
    print(inf + P2)
    print(P1 + P2)
    print(P1 + P1)
    #print(P2 + P3)
    #print(P3 + P2)
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    x = FieldElement(15, prime)
    y = FieldElement(86, prime)
    p = Point(x, y, a, b)
    print(7 * p)