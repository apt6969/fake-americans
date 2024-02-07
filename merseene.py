import math
import time
import sys
import random

# Define some mersenne primes and some useless non-prime integers
A_LARGE_USELESS_INT = sys.maxsize // 69696696969699
BIT_1024_INT = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137211
mersenne_primes = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457]
not_merseene = [69, 69696696969699, A_LARGE_USELESS_INT]

class EllipticCurve:
    """
    Simple representation of an elliptic curve.
    y^2 = x^3 + ax + b over finite field of prime p.
    """
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

        self.discriminant = -16 * (4 * a**3 + 27 * b**2)
        if self.discriminant == 0:
            raise ValueError("The curve {} is not smooth!".format(self))

    def is_on_curve(self, point):
        if point is None:
            # None represents the point at infinity.
            return True

        x, y = point
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

    def add_points(self, point1, point2):
        if point1 is None:
            # None represents the point at infinity.
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return None  # Point at infinity

        if x1 == x2:
            m = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)

        x3 = m**2 - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.p, -y3 % self.p)

        return result


def is_prime(n): # Using elliptical curve cryptography
    """
    Simple primality test using elliptic curves.
    """
    if n <= 1:
        print("line 63")
        return False

    # Choose random elliptic curve parameters
    a = random.randrange(0, n)
    b = random.randrange(0, n)
    curve = EllipticCurve(a, b, n)

    # Choose a random point on the curve
    x = random.randrange(0, n)
    y = random.randrange(0, n)
    point = (x, y)
    if not curve.is_on_curve(point):
        return False
    else:
        print(f"PRIME!{n}")
        sys.exit()


# def is_prime(n): # Explicitly declares Newton's Method with limit to iterations; possible minor speed ups
#     """
#     The only change from the stupid baseline method is how fast it converts for the max_divisor + 1 search reduce
#     Newton's Method converges at log(n) faster than the stupid method
#     """
#     if n < 2:
#         return False
#     if n in (2, 3):
#         return True
#     if n % 2 == 0:
#         return False

#     def f(x):
#         return x**2 - n

#     def df(x):
#         return 2 * x

#     # Optimized initial guess (approximate square root of n)
#     x = n // 2
#     for _ in range(20):  # Limiting iterations to 20
#         next_x = x - f(x) / df(x)
#         if abs(next_x - x) < 1:
#             x = int(next_x)
#             break
#         x = next_x

#     # Check for integer square root
#     return x * x != n
    
def newton_sqrt_floor(n):
    if n == 0 or n == 1:
        return n
    guess = n // 2
    while True:
        new_guess = (guess + n // guess) // 2
        if new_guess == guess:
            break
        guess = new_guess
    return guess

# def is_prime(n): # Slow method using Newton's Method by importing math.isqrt()?
#     """
#     Baseline method?
#     """
#     if n <= 1:
#         return False
#     if n <= 3:
#         return True
#     if n % 2 == 0:
#         return False
#     max_divisor = newton_sqrt_floor(n) # This already implements Newton's Method for calculating floor of sqrt of integers
#     for d in range(3, max_divisor + 1, 2):
#         if n % d == 0:
#             return False
#     return True

def is_mersenne_prime(p):
    """
    Calculates the Mersenne number for the given p which is a Mersenne Prime or NOT
    Then loops some s = 4, for _ in range(p - 2): s = (s ** 2 - 2) % mersenne_number, return True when s = (s ** 2 - 2) % mersenne_number == 0; else returns False
    """
    if not is_prime(p):
        print("line 142 not prime")
        return False
    else:
        print(f"Prime! {p}")
        sys.exit()
    mersenne_number = 2 ** p - 1
    s = 4
    for _ in range(p - 2):
        s = (s ** 2 - 2) % mersenne_number
    return s == 0

if __name__ == "__main__":
    #for p in BIT_1024_INT : #mersenne_primes: # not_merseene:
    start_time = time.time()
    LARGE_INT = BIT_1024_INT - 1000000000000
    BIT_1024_INT_LIST = []
    for _ in range(1000000000000):
        BIT_1024_INT_LIST.append(LARGE_INT)
        LARGE_INT+=1
    for p in BIT_1024_INT_LIST:
        is_prime(p)
        #print(f"Is 2^{p} - 1 a Mersenne prime? {is_mersenne_prime(p)}")
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed Time: {elapsed_time} seconds")
