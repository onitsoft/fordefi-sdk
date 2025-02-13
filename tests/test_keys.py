import base64

from ecdsa import SigningKey, VerifyingKey

from fordefi.keys import (
    decode_private_key,
    encode_private_key,
    encode_public_key_as_pem,
    generate_private_key,
    get_public_key,
)


def test_generate_private_key():
    private_key = generate_private_key()
    assert isinstance(private_key, SigningKey)


def test_get_public_key():
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    assert isinstance(public_key, VerifyingKey)


def test_encode_private_key():
    private_key = generate_private_key()
    encoded_key = encode_private_key(private_key)
    assert isinstance(encoded_key, str)

    decoded_key = base64.b64decode(encoded_key)
    assert len(decoded_key) == private_key.to_string().__len__()


def test_decode_private_key():
    private_key = generate_private_key()
    encoded_key = encode_private_key(private_key)

    decoded_key = decode_private_key(encoded_key)

    assert decoded_key.to_string() == private_key.to_string()


def test_encode_public_key_as_pem():
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    pem_key = encode_public_key_as_pem(public_key)

    assert isinstance(pem_key, str)

    assert pem_key.startswith("-----BEGIN PUBLIC KEY-----")
    assert pem_key.endswith("-----END PUBLIC KEY-----\n")
