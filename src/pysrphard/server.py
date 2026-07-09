from .groups import SRP_GROUP_PARAMETERS
from .constants import DEFAULT_GROUP_BITS, DEFAULT_HASH_FUNCTION, DEFAULT_KEY_LENGTH, MIN_KEY_LENGTH, MODULE_NAME
from .hkdf import HashConstructor, hkdf
from .srp_functions import validate_verifier, pad_int, pad_bytes, calculate_M, calculate_HAMK
from .exceptions import IllegalParameter, BadRecordMAC
from typing import Tuple
import hmac
import secrets

class SRPServer:
    @staticmethod
    def generate_server_values(
        verifier: bytes,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        # validate_verifier here is defensive programming in case this function is ever called independently
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

        # validate_verifier here is defensive programming in case this function is ever called independently
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
        key_length: int = DEFAULT_KEY_LENGTH,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]

        validate_verifier(verifier, srp_group_bits)

        B, b = SRPServer.generate_server_values(verifier, srp_group_bits, hash_function)

        padded_A = pad_bytes(A, srp_group.byte_length)
        padded_B = pad_bytes(B, srp_group.byte_length)

        S = SRPServer.calculate_server_secret(verifier, b, padded_B, padded_A, srp_group_bits, hash_function)

        if key_length < MIN_KEY_LENGTH:
            raise ValueError(f'key_length must be >= {MIN_KEY_LENGTH}')

        hkdf_info = MODULE_NAME.encode('utf-8') + padded_A + padded_B
        K = hkdf(S, key_length, info=hkdf_info, hash_function=hash_function)

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
