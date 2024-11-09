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
        if self.x is None or self.y is None:
            return 'Point(infinity)'
        return 'Point({}, {})_{}_{}'.format(self.x, self.y, self.a, self.b)

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
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        if self.x == other.x:
            if self.y != other.y:
                return self.__class__(None, None, self.a, self.b)
            else:
                s = (3 * (self.x ** 2) + self.a) / (2 * self.y)
                new_x = s * s - 2 * self.x
                new_y = s * (self.x - new_x) - self.y
                return self.__class__(new_x, new_y, self.a, self.b)
        else:
            s = (other.y - self.y) / (other.x - self.x)
            new_x = s * s - self.x - other.x
            new_y = s * (self.x - new_x) - self.y
            return self.__class__(new_x, new_y, self.a, self.b)



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