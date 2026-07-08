# PySRPHard is an implementation of SRP 6a from RFC 5054 with hardened parameters and hashing

from typing import Tuple, Protocol, Any, Self
from collections.abc import Buffer
import hashlib
import hmac
import math
import secrets

MODULE_NAME = 'PySRPHard'
DEFAULT_GROUP_BITS = 4096
MIN_SALT_LENGTH = 16
DEFAULT_HASH_FUNCTION = hashlib.sha256

# 1024/1536-bit groups intentionally excluded
# 2048 bit is currently the minimum acceptable for DH

SRP_GROUPS = {
    2048: ('''\
AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294\
3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D\
CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB\
D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74\
7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A\
436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D\
5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73\
03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6\
94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F\
9E4AFF73''', 2),
    3072: ('''\
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08\
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B\
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9\
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6\
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8\
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D\
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C\
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718\
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D\
04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D\
B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226\
1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C\
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC\
E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF''', 5),
    4096: ('''\
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08\
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B\
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9\
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6\
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8\
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D\
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C\
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718\
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D\
04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D\
B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226\
1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C\
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC\
E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26\
99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB\
04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2\
233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127\
D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199\
FFFFFFFF FFFFFFFF''', 5),
    6144: ('''\
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08\
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B\
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9\
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6\
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8\
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D\
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C\
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718\
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D\
04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D\
B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226\
1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C\
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC\
E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26\
99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB\
04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2\
233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127\
D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492\
36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406\
AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918\
DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151\
2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03\
F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F\
BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA\
CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B\
B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632\
387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E\
6DCC4024 FFFFFFFF FFFFFFFF''', 5),
    8192: ('''\
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08\
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B\
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9\
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6\
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8\
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D\
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C\
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718\
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D\
04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D\
B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226\
1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C\
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC\
E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26\
99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB\
04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2\
233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127\
D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492\
36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406\
AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918\
DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151\
2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03\
F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F\
BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA\
CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B\
B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632\
387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E\
6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA\
3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C\
5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9\
22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886\
2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6\
6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5\
0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268\
359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6\
FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71\
60C980DD 98EDD3DF FFFFFFFF FFFFFFFF''', 19)
}

class SRPGroup:
    def __init__(self, bits: int, N: int, g: int, byte_length: int):
        self.bits = bits
        self.N = N
        self.g = g
        self.byte_length = byte_length
    
    def __repr__(self):
        return f'SRPGroup({self.bits}-bit)'

SRP_GROUP_PARAMETERS = {
    bits: SRPGroup(bits, int(N.replace(' ', ''), 16), g, bits // 8) for bits, (N, g) in SRP_GROUPS.items()
}

if not all(v.N.bit_length() == k for k,v in SRP_GROUP_PARAMETERS.items()):
    raise ValueError('The bit length of one of the SRP group parameters is incorrect')

class KDF(Protocol):
    def __call__(self, password: bytes, salt: bytes, **params: Any) -> bytes: ...

class BadRecordMAC(Exception):
    pass

class UnknownPSKIdentity(Exception):
    pass

class InsufficientSecurity(Exception):
    pass

class IllegalParameter(Exception):
    pass

"""
HKDF implementation from RFC 5869
"""
class HashObject(Protocol):
    @property
    def digest_size(self) -> int: ...
    @property
    def block_size(self) -> int: ...
    @property
    def name(self) -> str: ...
    def copy(self) -> Self: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def update(self, obj: Buffer, /) -> None: ...

class HashConstructor(Protocol):
    def __call__(self, data: bytes = b'', /) -> HashObject: ...

def hkdf_extract(
    salt: bytes,
    key_material: bytes,
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    return hmac.digest(salt, key_material, hash_function)

def hkdf_expand(
    prk: bytes,
    info: bytes,
    length: int,
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    hash_len = hash_function().digest_size

    if length > 255 * hash_len:
        raise ValueError('length must be <= 255 * hash_len')

    N = math.ceil(length / hash_len)
    T = b''
    OKM = b''
    for i in range(N):
        T = hmac.digest(prk, T + info + bytes([i + 1]), hash_function)
        OKM += T

    return OKM[:length]

def hkdf(
    key_material: bytes, 
    length: int, 
    salt: bytes = b"", 
    info: bytes = b"", 
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    prk = hkdf_extract(salt, key_material, hash_function)
    return hkdf_expand(prk, info, length, hash_function)

def generate_salt(salt_length: int = 16):
    if salt_length < MIN_SALT_LENGTH:
        raise ValueError(f'salt_length must be >= {MIN_SALT_LENGTH}')

    return secrets.token_bytes(salt_length)

def pad_int(n: int, byte_length: int) -> bytes:
    return n.to_bytes(byte_length, byteorder='big')

def pad_bytes(b: bytes, byte_length: int) -> bytes:
    return pad_int(int.from_bytes(b, byteorder='big'), byte_length)

def compute_x_int(
    user_identity: bytes, 
    password: bytes,
    salt: bytes,
    kdf: KDF,
    kdf_parameters: dict
) -> int:
    user_cat_password = user_identity + b':' + password
    x = kdf(user_cat_password, salt, **kdf_parameters)

    return int.from_bytes(x, byteorder='big')

def validate_verifier(verifier: bytes, srp_group_bits: int = DEFAULT_GROUP_BITS) -> None:
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
    v_int = int.from_bytes(verifier, byteorder='big')

    if v_int <= 1 or v_int >= srp_group.N:
        raise IllegalParameter('verifier must be greater than 1 and less than N')
    
def create_verifier(
    user_identity: bytes, 
    password: bytes,
    kdf: KDF,
    kdf_parameters: dict,
    srp_group_bits: int = DEFAULT_GROUP_BITS,
    salt_length: int = 16
) -> Tuple[bytes, bytes]:
    salt = generate_salt(salt_length)
    x_int = compute_x_int(user_identity, password, salt, kdf, kdf_parameters)
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

    verifier_int = pow(srp_group.g, x_int, srp_group.N)
    verifier = pad_int(verifier_int, srp_group.byte_length)

    validate_verifier(verifier, srp_group_bits)

    return verifier, salt

def calculate_M(
    user_identity: bytes,
    salt: bytes,
    padded_A: bytes,
    padded_B: bytes,
    K: bytes,
    srp_group_bits: int = DEFAULT_GROUP_BITS,
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
    
    if len(padded_A) != srp_group.byte_length:
        raise IllegalParameter('padded_A has incorrect length')
    if len(padded_B) != srp_group.byte_length:
        raise IllegalParameter('padded_B has incorrect length')

    hn = hash_function(pad_int(srp_group.N, srp_group.byte_length)).digest()
    hg = hash_function(pad_int(srp_group.g, srp_group.byte_length)).digest()
    nxg = bytes(b1 ^ b2 for b1, b2 in zip(hn, hg))

    hu = hash_function(user_identity).digest()
    M = hash_function(nxg)
    M.update(hu)
    M.update(salt)
    M.update(padded_A)
    M.update(padded_B)
    M.update(K)

    return M.digest()

def calculate_HAMK(
    padded_A: bytes,
    M: bytes,
    K: bytes,
    srp_group_bits: int = DEFAULT_GROUP_BITS,
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
    
    if len(padded_A) != srp_group.byte_length:
        raise IllegalParameter('padded_A has incorrect length')
    
    HAMK = hash_function(padded_A)
    HAMK.update(M)
    HAMK.update(K)
    return HAMK.digest()

class SRPClient:
    @staticmethod
    def generate_client_values(srp_group_bits: int = DEFAULT_GROUP_BITS) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        a = secrets.randbelow(srp_group.N - 1) + 1
        A = pow(srp_group.g, a, srp_group.N)

        return pad_int(A, srp_group.byte_length), pad_int(a, srp_group.byte_length)

    @staticmethod
    def calculate_client_secret(
        user_identity: bytes, 
        password: bytes,
        salt: bytes,
        a: bytes,
        padded_A: bytes,
        padded_B: bytes,
        kdf: KDF,
        kdf_parameters: dict,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> bytes:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        if len(padded_A) != srp_group.byte_length:
            raise IllegalParameter('padded_A has incorrect length')
        if len(padded_B) != srp_group.byte_length:
            raise IllegalParameter('padded_B has incorrect length')

        k = hash_function(
            pad_int(srp_group.N, srp_group.byte_length) + pad_int(srp_group.g, srp_group.byte_length)
        ).digest()
        k_int = int.from_bytes(k, byteorder='big')
        x_int = compute_x_int(user_identity, password, salt, kdf, kdf_parameters)
        a_int = int.from_bytes(a, byteorder='big')
        B_int = int.from_bytes(padded_B, byteorder='big')

        if B_int % srp_group.N == 0:
            raise IllegalParameter('B % N cannot be equal to 0')
        
        u = hash_function(padded_A + padded_B).digest()
        u_int = int.from_bytes(u, byteorder='big')

        if u_int == 0:
            raise IllegalParameter('u cannot be equal to 0')

        base = (B_int - k_int * pow(srp_group.g, x_int, srp_group.N)) % srp_group.N
        premaster_secret = pow(base, a_int + u_int * x_int, srp_group.N)

        return pad_int(premaster_secret, srp_group.byte_length)

    @staticmethod
    def start_key_exchange(srp_group_bits: int = DEFAULT_GROUP_BITS) -> Tuple[bytes, bytes]:
        return SRPClient.generate_client_values(srp_group_bits)

    @staticmethod
    def finish_key_exchange(
        user_identity: bytes, 
        password: bytes,
        salt: bytes,
        A: bytes,
        a: bytes,
        B: bytes,
        kdf: KDF,
        kdf_parameters: dict,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        padded_A = pad_bytes(A, srp_group.byte_length)
        padded_B = pad_bytes(B, srp_group.byte_length)
        S = SRPClient.calculate_client_secret(
            user_identity, 
            password, 
            salt, 
            a, 
            padded_A, 
            padded_B, 
            kdf, 
            kdf_parameters, 
            srp_group_bits, 
            hash_function
        )
        hkdf_info = MODULE_NAME.encode('utf-8') + padded_A + padded_B
        K = hkdf(S, 32, info=hkdf_info, hash_function=hash_function)
        client_M = calculate_M(user_identity, salt, padded_A, padded_B, K, srp_group_bits, hash_function)

        return client_M, K

    @staticmethod
    def authenticate_server(
        A: bytes,
        client_M: bytes,
        server_HAMK: bytes,
        K: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ):
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        padded_A = pad_bytes(A, srp_group.byte_length)
        client_HAMK = calculate_HAMK(padded_A, client_M, K, srp_group_bits, hash_function)

        if not hmac.compare_digest(client_HAMK, server_HAMK):
            raise BadRecordMAC('Client failed to authenticate server')

class SRPServer:
    @staticmethod
    def generate_server_values(
        verifier: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        validate_verifier(verifier, srp_group_bits)

        k = hash_function(
            pad_int(srp_group.N, srp_group.byte_length) + pad_int(srp_group.g, srp_group.byte_length)
        ).digest()

        k_int = int.from_bytes(k, byteorder='big')
        v_int = int.from_bytes(verifier, byteorder='big')
        b_int = secrets.randbelow(srp_group.N - 1) + 1
        B_int = (k_int * v_int + pow(srp_group.g, b_int, srp_group.N)) % srp_group.N

        return pad_int(B_int, srp_group.byte_length), pad_int(b_int, srp_group.byte_length)

    @staticmethod
    def calculate_server_secret(
        verifier: bytes,
        b: bytes,
        padded_B: bytes,
        padded_A: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> bytes:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        validate_verifier(verifier, srp_group_bits)

        if len(padded_A) != srp_group.byte_length:
            raise IllegalParameter('padded_A has incorrect length')
        if len(padded_B) != srp_group.byte_length:
            raise IllegalParameter('padded_B has incorrect length')

        u = hash_function(padded_A + padded_B).digest()

        b_int = int.from_bytes(b, byteorder='big')
        u_int = int.from_bytes(u, byteorder='big')
        v_int = int.from_bytes(verifier, byteorder='big')
        A_int = int.from_bytes(padded_A, byteorder='big')

        if A_int % srp_group.N == 0:
            raise IllegalParameter('A % N cannot be equal to 0')
        
        if u_int == 0:
            raise IllegalParameter('u cannot be equal to 0')

        base = (A_int * pow(v_int, u_int, srp_group.N)) % srp_group.N
        premaster_secret = pow(base, b_int, srp_group.N)

        return pad_int(premaster_secret, srp_group.byte_length)

    @staticmethod
    def key_exchange(
        verifier: bytes,
        A: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        validate_verifier(verifier, srp_group_bits)

        B, b = SRPServer.generate_server_values(verifier, srp_group_bits, hash_function)

        padded_A = pad_bytes(A, srp_group.byte_length)
        padded_B = pad_bytes(B, srp_group.byte_length)

        S = SRPServer.calculate_server_secret(verifier, b, padded_B, padded_A, srp_group_bits, hash_function)

        hkdf_info = MODULE_NAME.encode('utf-8') + padded_A + padded_B
        K = hkdf(S, 32, info=hkdf_info, hash_function=hash_function)

        return padded_B, K

    @staticmethod
    def authenticate_client(
        user_identity: bytes,
        salt: bytes,
        A: bytes,
        B: bytes,
        client_M: bytes,
        K: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS, 
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> bytes:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        padded_A = pad_bytes(A, srp_group.byte_length)
        padded_B = pad_bytes(B, srp_group.byte_length)
        server_M = calculate_M(user_identity, salt, padded_A, padded_B, K, srp_group_bits, hash_function)

        if not hmac.compare_digest(client_M, server_M):
            raise BadRecordMAC(f'Server failed to authenticate client {user_identity}')

        return calculate_HAMK(padded_A, client_M, K, srp_group_bits, hash_function)
