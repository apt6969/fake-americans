import sys
import math
import time
import random
import concurrent.futures
from sympy import isprime
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
    
# def newton_sqrt_floor(n):
#     if n == 0 or n == 1:
#         return n
#     guess = n // 2
#     while True:
#         new_guess = (guess + n // guess) // 2
#         if new_guess == guess:
#             break
#         guess = new_guess
#     return guess
def is_prime(n): # Slow method using Newton's Method by importing math.isqrt()?
    """
    Baseline method?
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    max_divisor = math.sqrt(n) # This already implements Newton's Method for calculating floor of sqrt of integers
    for d in range(3, max_divisor + 1, 2):
        if n % d == 0:
            return False
    return True
is_prime(545374067809707964731492122366891431224132080998116346215916393094860665924559647608132117262600993611978645898078512636554935410088592031805489882538777399539453149421096494769304912614024102579848425806795819098385943271304662280060645276950943150508950126267899958600005039800013267918400452648902940476175250815097737826955502656182280007423713017646775622921964459376384348139672044027808757847174972703338912570407450308052960128219252289006663246782918023621203691221406122565758878759582449613182871861216138684037513813941522603250896380850472849584248628939841925868524998450480560257827525057780635745746257671052874483314773516393160752865414215110832485162198069317625813204758084002713811717998154460845723090593703197655332702442869717416438714083703747685496755934378179985195058510911808374729310484928503131806041353357704078533287568640513511155463782455138379580260439152316205524682284377460483661491229592381713691895136224219009263488882470536357805790217345413729669995980707121370705299558713030278241881878157263805681329314191684310578996819010439268837772668394957847117216977833157535043606767735127835156002065362747917254178719826914468038540489275289456483953676390027467810780545397922586477057986463739938763869280004102059279465002388874363880926906755246920290930799326105802980154178202970910594857018934363109740749363801826808149428087411206516742719392662012375709708591506140539104864651768686402287186047614351811388181972645434903129211177574253785519809693724814933404094384831407889076539696589546571824170380869290909781501497211395377477530644409154215039372430780245317704000126710824302023030113981047799333481703499511710556793401515150721048911283071482063370390062547568751995990904215831768341958312672775081507926613384494723979974348336276735378444496871645254766800901128738720377881582816530895896682981891597231842778761676305756175863872135661183167305552247607486857172315951739617650831533383036713431738098187040761593773505299580395238298549806563767245975485550218668797704674993411831523092855809743190328058066437700901701260184739760292760615253840030263932394351413014314312125285344871543311485187377409506446977291310905377851553136625396831845835897389227671044634170034404360128969876574483348032126381264090274019078891161521547996119015171579653355958420896667874975554884853380659812968882406707786434446661780079089597755060508685758366364323357584532928945366177955328837280080465087168511)

# Define some mersenne primes and some useless non-prime integers
A_LARGE_USELESS_INT = sys.maxsize // 69696696969699
BIT_1024_INT = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137211
mersenne_primes = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457]
not_merseene = [69, 69696696969699, A_LARGE_USELESS_INT]
for _ in mersenne_primes:
    print(f"is {_} Merseene prime prime? {isprime(_)}")
for n in not_merseene:
    print(f"is {n} non-prime prime? {isprime(n)}")
# class EllipticCurve:
#     """
#     Simple representation of an elliptic curve.
#     y^2 = x^3 + ax + b over finite field of prime p.
#     """
#     def __init__(self, a, b, p):
#         self.a = a
#         self.b = b
#         self.p = p

#         self.discriminant = -16 * (4 * a**3 + 27 * b**2)
#         if self.discriminant == 0:
#             raise ValueError("The curve {} is not smooth!".format(self))

#     def is_on_curve(self, point):
#         if point is None:
#             # None represents the point at infinity.
#             return True

#         x, y = point
#         return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

#     def add_points(self, point1, point2):
#         if point1 is None:
#             # None represents the point at infinity.
#             return point2
#         if point2 is None:
#             return point1

#         x1, y1 = point1
#         x2, y2 = point2

#         if x1 == x2 and y1 != y2:
#             return None  # Point at infinity

#         if x1 == x2:
#             m = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
#         else:
#             m = (y2 - y1) * pow(x2 - x1, -1, self.p)

#         x3 = m**2 - x1 - x2
#         y3 = y1 + m * (x3 - x1)
#         result = (x3 % self.p, -y3 % self.p)

#         return result


# def is_prime(n): # Using elliptical curve cryptography
#     """
#     Simple primality test using elliptic curves.
#     """
#     print(f"n is {n}")
#     if n <= 1:
#         print("line 63")
#         return False

#     # Choose random elliptic curve parameters
#     a = random.randrange(0, n)
#     b = random.randrange(0, n)
#     curve = EllipticCurve(a, b, n)

#     # Choose a random point on the curve
#     x = random.randrange(0, n)
#     y = random.randrange(0, n)
#     point = (x, y)
#     if not curve.is_on_curve(point):
#         print("NOT PRIME; NOT ON CURVE")
#         return False
#     else:
#         print(f"PRIME!{n}")
#         sys.exit()
sys.set_int_max_str_digits(999999999)

print("7 is prime?", isprime(7))

print("69 is prime?", isprime(69))

def binary_viewer_for_ints(number):
    binary_representation = bin(number)[2:]  # Convert the number to binary and remove the '0b' prefix
    return binary_representation


def thread_prime(list_of_int_crap, max_threads=1000):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(isprime, cra and print(f"Prime False! {cra}") if not isprime(cra) else print(f"Prime True! {cra}")) for cra in list_of_int_crap]
        concurrent.futures.wait(futures)

# Example usage:
number = 2**8191-1
another_number = 2 ** 8000
binary_representation = binary_viewer_for_ints(number)
# binary_another = binary_viewer_for_ints(another_number)
# new_binary = binary_representation - binary_another
len_binary = len(binary_representation)
rand_digit = random.randint(2, len_binary - 1)
#binary_representation[rand_digit] = "0"
list_of_crap = [*range(2, len_binary - 1)]
rand_list_of_crap = sorted(list_of_crap, key=lambda x: random.random())
#print(rand_list_of_crap)

int_from_crap = int(binary_representation, 2)
list_of_int_crap = []

#print(int_from_crap, 'line 156')
for poop in range(1000000, 2000000):
    list_of_int_crap.append(int_from_crap - poop*2)
#print(list_of_int_crap)

# thread_prime(list_of_int_crap)

crap_list = []

def get_list_of_crap(binary_representation):
    for c in binary_representation:
        crap_list.append(c)

get_list_of_crap(binary_representation=binary_representation)

def thread_crap(crap_list, max_threads=1000):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(from_list_of_crap, cra) for cra in crap_list]
        concurrent.futures.wait(futures)

def from_list_of_crap(crap_list):
    
    new_binary_str = ""
    rand_int = random.randint(2, len(crap_list) - 2)
    rand_int2 = random.randint(2, len(crap_list) - 2)
    for idx, char in enumerate(crap_list):
        if idx == rand_int or idx == rand_int2:
            new_binary_str += "0"
        else:
            new_binary_str += "1"

    int_10 = int(new_binary_str, 2)
    print("int_10 is", int_10, "is prime???")
    if isprime(int_10) == False:
        print("FALSE")
    else:
        print("True lol", int_10)
        sys.exit()

for _ in range(1000):
    #thread_crap(crap_list) # no lock on reused new_binary_str etc.
    from_list_of_crap(crap_list)

#thread_crap(crap_list)

#print(f"The binary representation of {new_base10} \n \nis: \n{binary_representation}")

def utf8_to_binary(text):
    binary_representation = ''
    # Encode the text to UTF-8
    utf8_encoded_text = text.encode('utf-8')
    
    # Convert each byte to its binary representation
    for byte in utf8_encoded_text:
        binary_representation += format(byte, '08b') + ' ' # 08b for 8-bit binary

    return binary_representation.strip()

cyndaquils = ["SimpForSam", "SimpforSam", "Samantha Briasco-Stewart", "Cyndaquil", "weewow", "Samantha"]
#cyndaquil = "Samantha Briasco-Stewart"
for cyndaquil in cyndaquils:
    binary_cyndaquil = utf8_to_binary(cyndaquil)
    print(f"\nThe length of {cyndaquil} is {len(cyndaquil)} and {cyndaquil} in UTF-8 in binary is", binary_cyndaquil)

print("\n")

def view_binary_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            while True:
                byte = file.read(1)
                if not byte:
                    break
                print("WTH is this", byte, end='  🤔 🤔 🤔 😘   ')
                print("This encoding on this line in hex is", byte.hex(), end='\n')
                
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def write_binary_file(file_path):
    pass

def inject_binary_file(file_path):
    pass

view_binary_file("test.bin")

len_of_M82589933 = len("商博")
# print(len("商博")) # this is so basic

print(f"\nThe length of M82589933 is {len_of_M82589933} and M82589933 is not able to encrypt this any futher unless you provide M82589933 with a public key 😘")
GhidraM82589933 = utf8_to_binary("商博")
print(f"\nwith love,\n{GhidraM82589933}")

#M82589933 = ["1"*82589933]
#print(f"with love,\n{M82589933}")
