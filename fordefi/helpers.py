import base64
import hashlib
from typing import cast

import ecdsa
import ecdsa.util


def generate_private_key() -> ecdsa.SigningKey:
    return ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)


def public_key_of(private_key: ecdsa.SigningKey) -> str:
    _public_key = private_key.get_verifying_key()
    assert isinstance(_public_key, ecdsa.VerifyingKey)
    pem = cast(bytes, _public_key.to_pem())
    return pem.decode()


def sign(data: bytes, private_key: ecdsa.SigningKey) -> str:
    signature = private_key.sign(
        data,
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der,
    )
    return base64.b64encode(signature).decode()
