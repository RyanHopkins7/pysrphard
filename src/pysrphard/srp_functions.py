from .groups import SRP_GROUP_PARAMETERS
from .constants import DEFAULT_GROUP_BITS, DEFAULT_HASH_FUNCTION, DEFAULT_SALT_LENGTH
from .exceptions import IllegalParameter
from .hkdf import HashConstructor
from typing import Protocol, Tuple, Any, Optional
import secrets

class KDF(Protocol):
    def __call__(self, password: bytes, salt: bytes, **params: Any) -> bytes: ...

def pad_int(n: int, byte_length: int) -> bytes:
    return n.to_bytes(byte_length, byteorder='big')

def pad_bytes(b: bytes, byte_length: int) -> bytes:
    if len(b) > byte_length:
        raise IllegalParameter('byte_length is too short')
    return pad_int(int.from_bytes(b, byteorder='big'), byte_length)

def compute_x_int(
    user_identity: bytes, 
    password: bytes,
    salt: bytes,
    kdf: KDF,
    kdf_parameters: dict
) -> int:
    user_cat_password = user_identity + b':' + password
    x = kdf(password=user_cat_password, salt=salt, **kdf_parameters)

    return int.from_bytes(x, byteorder='big')

def validate_pub(pub: bytes, pub_name: str, srp_group_bits: int = DEFAULT_GROUP_BITS):
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
    pub_int = int.from_bytes(pub, byteorder='big')

    if pub_int % srp_group.N == 0:
        raise IllegalParameter(f'{pub_name} % N cannot be equal to 0')
    if pub_int <= 1 or pub_int >= srp_group.N - 1:
        raise IllegalParameter(f'{pub_name} must be in [2, N-2]')
    if len(pub) != srp_group.byte_length:
        raise IllegalParameter(f'{pub_name} padding is incorrect')

def validate_AB(A: bytes = None, B: bytes = None, srp_group_bits: int = DEFAULT_GROUP_BITS):
    if A is None and B is None:
        raise IllegalParameter('validate_AB was called without A or B')

    if A is not None:
        validate_pub(A, 'A', srp_group_bits)
    if B is not None:
        validate_pub(B, 'B', srp_group_bits)

def validate_verifier(verifier: bytes, srp_group_bits: int = DEFAULT_GROUP_BITS) -> None:
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
    v_int = int.from_bytes(verifier, byteorder='big')

    if v_int <= 1 or v_int >= srp_group.N-1:
        raise IllegalParameter('verifier must be in [2, N-2]')
    if len(verifier) != srp_group.byte_length:
        raise IllegalParameter('verifier padding is incorrect')
    
def create_verifier(
    user_identity: bytes, 
    password: bytes,
    kdf: KDF,
    kdf_parameters: dict,
    srp_group_bits: int = DEFAULT_GROUP_BITS,
    salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(DEFAULT_SALT_LENGTH)

    x_int = compute_x_int(user_identity, password, salt, kdf, kdf_parameters)
    srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

    verifier_int = pow(srp_group.g, x_int, srp_group.N)
    verifier = pad_int(verifier_int, srp_group.byte_length)

    validate_verifier(verifier, srp_group_bits)

    return verifier, salt

def calculate_u(
    padded_A: bytes,
    padded_B: bytes,
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> int:
    u = hash_function(padded_A + padded_B).digest()
    return int.from_bytes(u, byteorder='big')

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