from pysrphard import SRPGroup, SRP_GROUP_PARAMETERS
from decimal import Decimal, localcontext
import unittest

def compute_pi(digits, ctx):
    '''Chudnovsky algorithm'''
    ctx.prec = digits + 10  # guard digits
    C = 426880 * Decimal(10005).sqrt()
    K = Decimal(6)
    M = Decimal(1)
    X = Decimal(1)
    L = Decimal(13591409)
    S = L
    for i in range(1, digits // 14 + 2):   # ~14 correct digits per term
        M = M * (K**3 - 16*K) / Decimal(i)**3
        L += 545140134
        X *= -262537412640768000
        S += M * L / X
        K += 12
    return C / S

class GroupTests(unittest.TestCase):
    def test_group_bit_lengths(self):
        for bit_size, srp_group in SRP_GROUP_PARAMETERS.items():
            self.assertEqual(bit_size, srp_group.N.bit_length())

    def test_2048_bit_group(self):
        srp_group = SRP_GROUP_PARAMETERS[2048]

        correct_2048_group = SRPGroup(
            bits=2048,
            N=0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73,
            g=2,
            byte_length=256
        )

        self.assertEqual(srp_group.bits, correct_2048_group.bits)
        self.assertEqual(srp_group.N, correct_2048_group.N)
        self.assertEqual(srp_group.g, correct_2048_group.g)
        self.assertEqual(srp_group.byte_length, correct_2048_group.byte_length)

    def test_3072_bit_group(self):
        srp_group = SRP_GROUP_PARAMETERS[3072]
        digits_needed = 1000

        with localcontext() as ctx:
            pi_val = compute_pi(digits_needed, ctx)
            pi_term = int((Decimal(2)**2942 * pi_val).to_integral_value(rounding='ROUND_FLOOR'))

        correct_3072_group = SRPGroup(
            bits=3072,
            N=2**3072 - 2**3008 - 1 + 2**64 * (pi_term + 1690314),
            g=5,
            byte_length=384
        )

        self.assertEqual(srp_group.bits, correct_3072_group.bits)
        self.assertEqual(srp_group.N, correct_3072_group.N)
        self.assertEqual(srp_group.g, correct_3072_group.g)
        self.assertEqual(srp_group.byte_length, correct_3072_group.byte_length)

    def test_4096_bit_group(self):
        srp_group = SRP_GROUP_PARAMETERS[4096]
        digits_needed = 2000

        with localcontext() as ctx:
            pi_val = compute_pi(digits_needed, ctx)
            pi_term = int((Decimal(2)**3966 * pi_val).to_integral_value(rounding='ROUND_FLOOR'))

        correct_4096_group = SRPGroup(
            bits=4096,
            N=2**4096 - 2**4032 - 1 + 2**64 * (pi_term + 240904),
            g=5,
            byte_length=512
        )

        self.assertEqual(srp_group.bits, correct_4096_group.bits)
        self.assertEqual(srp_group.N, correct_4096_group.N)
        self.assertEqual(srp_group.g, correct_4096_group.g)
        self.assertEqual(srp_group.byte_length, correct_4096_group.byte_length)

    def test_6144_bit_group(self):
        srp_group = SRP_GROUP_PARAMETERS[6144]
        digits_needed = 2000

        with localcontext() as ctx:
            pi_val = compute_pi(digits_needed, ctx)
            pi_term = int((Decimal(2)**6014 * pi_val).to_integral_value(rounding='ROUND_FLOOR'))

        correct_6144_group = SRPGroup(
            bits=6144,
            N=2**6144 - 2**6080 - 1 + 2**64 * (pi_term + 929484),
            g=5,
            byte_length=768
        )

        self.assertEqual(srp_group.bits, correct_6144_group.bits)
        self.assertEqual(srp_group.N, correct_6144_group.N)
        self.assertEqual(srp_group.g, correct_6144_group.g)
        self.assertEqual(srp_group.byte_length, correct_6144_group.byte_length)

    def test_8192_bit_group(self):
        srp_group = SRP_GROUP_PARAMETERS[8192]
        digits_needed = 3000

        with localcontext() as ctx:
            pi_val = compute_pi(digits_needed, ctx)
            pi_term = int((Decimal(2)**8062 * pi_val).to_integral_value(rounding='ROUND_FLOOR'))

        correct_8192_group = SRPGroup(
            bits=8192,
            N=2**8192 - 2**8128 - 1 + 2**64 * (pi_term + 4743158),
            g=19,
            byte_length=1024
        )

        self.assertEqual(srp_group.bits, correct_8192_group.bits)
        self.assertEqual(srp_group.N, correct_8192_group.N)
        self.assertEqual(srp_group.g, correct_8192_group.g)
        self.assertEqual(srp_group.byte_length, correct_8192_group.byte_length)
