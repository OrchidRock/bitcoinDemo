
from FieldElement import FieldElement
from Point import Point

if __name__ == '__main__':
    a = FieldElement(0, 223)
    b = FieldElement(7, 223)
    x = FieldElement(192, 223)
    y = FieldElement(105, 223)

    p1 = Point(x, y, a, b)
    print(p1)