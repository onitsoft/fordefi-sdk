from typing import cast

from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.der import base64


def generate_private_key() -> SigningKey:
    private_key = SigningKey.generate(curve=NIST256p)
    return private_key


def get_public_key(private_key: SigningKey) -> VerifyingKey:
    public_key = private_key.get_verifying_key()
    return cast(VerifyingKey, public_key)


def encode_private_key(private_key: SigningKey) -> str:
    private_key_bytes = private_key.to_string()
    base64_private_key = base64.b64encode(private_key_bytes).decode("utf-8")
    return base64_private_key


def decode_private_key(encoded_private_key: str) -> SigningKey:
    private_key_bytes = base64.b64decode(encoded_private_key)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    return private_key


def encode_public_key_as_striped_pem(public_key: VerifyingKey) -> str:
    # https://docs.fordefi.com/developers/getting-started/pair-an-api-client-with-the-api-signer#pair-an-api-client-with-the-api-signer
    pem = public_key.to_pem().decode("utf-8")
    return _strip_pem(pem)


def _strip_pem(pem: str) -> str:
    result = pem.replace("-----BEGIN PUBLIC KEY-----", "")
    result = result.replace("-----END PUBLIC KEY-----", "")
    result = result.replace(" ", "")
    result = result.replace("\n", "")
    return result
