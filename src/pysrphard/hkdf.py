from typing import Protocol, Self
from collections.abc import Buffer
import hashlib
import math
import hmac

'''
HKDF implementation from RFC 5869
'''

DEFAULT_HASH_FUNCTION = hashlib.sha256

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
    salt: bytes = b'', 
    info: bytes = b'', 
    hash_function: HashConstructor = DEFAULT_HASH_FUNCTION
) -> bytes:
    prk = hkdf_extract(salt, key_material, hash_function)
    return hkdf_expand(prk, info, length, hash_function)
