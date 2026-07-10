from .groups import SRP_GROUP_PARAMETERS
from .srp_functions import pad_int, KDF, compute_x_int, pad_bytes, calculate_M, calculate_HAMK, validate_AB, calculate_u
from .hkdf import HashConstructor, hkdf
from .exceptions import IllegalParameter, BadRecordMAC
from .constants import MODULE_NAME, DEFAULT_HASH_FUNCTION, DEFAULT_GROUP_BITS, DEFAULT_KEY_LENGTH, MIN_KEY_LENGTH
from typing import Tuple
import hmac
import secrets

class SRPClient:
    @staticmethod
    def calculate_A(a: int, srp_group_bits: int = DEFAULT_GROUP_BITS) -> int:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        A = pow(srp_group.g, a, srp_group.N)

        return A

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

        # defensive programming in case this function is ever called independently
        validate_AB(padded_A, padded_B, srp_group_bits)

        k = hash_function(
            pad_int(srp_group.N, srp_group.byte_length) + pad_int(srp_group.g, srp_group.byte_length)
        ).digest()
        k_int = int.from_bytes(k, byteorder='big')
        x_int = compute_x_int(user_identity, password, salt, kdf, kdf_parameters)
        a_int = int.from_bytes(a, byteorder='big')
        B_int = int.from_bytes(padded_B, byteorder='big')

        u_int = calculate_u(padded_A, padded_B, hash_function)

        if u_int == 0:
            raise IllegalParameter('u cannot be equal to 0')

        base = (B_int - k_int * pow(srp_group.g, x_int, srp_group.N)) % srp_group.N
        premaster_secret = pow(base, a_int + u_int * x_int, srp_group.N)

        return pad_int(premaster_secret, srp_group.byte_length)

    @staticmethod
    def start_key_exchange(srp_group_bits: int = DEFAULT_GROUP_BITS) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        a = secrets.randbelow(srp_group.N - 1) + 1
        A = SRPClient.calculate_A(a, srp_group_bits)
        padded_A = pad_int(A, srp_group.byte_length)

        validate_AB(padded_A, srp_group_bits=srp_group_bits)

        return padded_A, pad_int(a, srp_group.byte_length)

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
        key_length: int = DEFAULT_KEY_LENGTH,
        srp_group_bits: int = DEFAULT_GROUP_BITS,
        hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
    ) -> Tuple[bytes, bytes]:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        padded_A = pad_bytes(A, srp_group.byte_length)
        padded_B = pad_bytes(B, srp_group.byte_length)

        validate_AB(padded_A, padded_B, srp_group_bits)

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

        if key_length < MIN_KEY_LENGTH:
            raise IllegalParameter(f'key_length must be >= {MIN_KEY_LENGTH}')

        hkdf_info = MODULE_NAME.encode('utf-8') + padded_A + padded_B
        K = hkdf(S, key_length, info=hkdf_info, hash_function=hash_function)
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
    ) -> None:
        srp_group = SRP_GROUP_PARAMETERS[srp_group_bits]
        padded_A = pad_bytes(A, srp_group.byte_length)

        validate_AB(padded_A, srp_group_bits=srp_group_bits)

        client_HAMK = calculate_HAMK(padded_A, client_M, K, srp_group_bits, hash_function)

        if not hmac.compare_digest(client_HAMK, server_HAMK):
            raise BadRecordMAC('Client failed to authenticate server')
