from abc import ABC, abstractmethod

import ecdsa
import ecdsa.util
import pydantic
import pytest

from fordefi.helpers import generate_private_key, public_key_of, sign
from fordefi.schemas import Direction, Event, Webhook
from fordefi.webhooks import (
    FordefiWebhooksParser,
    FordefiWebooksSignatureValidator,
    InvalidSignatureError,
)
from tests.helpers import raises


class FakeFordefiWebooksSignatureValidator(FordefiWebooksSignatureValidator):
    def __init__(self, public_key: str) -> None:
        self.returns_valid = False

    def is_valid(self, data: bytes, signature: str | None) -> bool:
        return self.returns_valid


@pytest.fixture
def private_key() -> ecdsa.SigningKey:
    return generate_private_key()


@pytest.fixture
def public_key(private_key: ecdsa.SigningKey) -> str:
    return public_key_of(private_key)


@pytest.fixture
def fordefi_webooks_signature_validator(
    public_key: str,
) -> FordefiWebooksSignatureValidator:
    return FordefiWebooksSignatureValidator(public_key=public_key)


@pytest.fixture
def fake_fordefi_webooks_signature_validator() -> FakeFordefiWebooksSignatureValidator:
    return FakeFordefiWebooksSignatureValidator("")


@pytest.fixture
def fordefi_webooks_parser(
    fake_fordefi_webooks_signature_validator: FakeFordefiWebooksSignatureValidator,
) -> FordefiWebhooksParser:
    return FordefiWebhooksParser(fake_fordefi_webooks_signature_validator)


class Signer(ABC):
    @abstractmethod
    def __call__(self, data: bytes, private_key: ecdsa.SigningKey) -> str | None: ...

    def _sign(self, data: bytes, private_key: ecdsa.SigningKey) -> str:
        return sign(data, private_key)


class MissingSignature(Signer):
    def __call__(self, data: bytes, private_key: ecdsa.SigningKey) -> str | None:
        return None


class MalformedSignature(Signer):
    def __call__(self, data: bytes, private_key: ecdsa.SigningKey) -> str | None:
        return data.decode()


class InvalidSignature(Signer):
    def __call__(self, data: bytes, private_key: ecdsa.SigningKey) -> str | None:
        return self._sign(data, generate_private_key())


class ValidSignature(Signer):
    def __call__(self, data: bytes, private_key: ecdsa.SigningKey) -> str | None:
        return self._sign(data, private_key)


@pytest.mark.parametrize(
    argnames=("signer", "is_valid"),
    argvalues=[
        (MissingSignature, False),
        (MalformedSignature, False),
        (InvalidSignature, False),
        (ValidSignature, True),
    ],
)
def test_fordefi_webooks_signature_validator(
    fordefi_webooks_signature_validator: FordefiWebooksSignatureValidator,
    signer: type[Signer],
    is_valid: bool,
    private_key: ecdsa.SigningKey,
) -> None:
    data = b'{"key": 1}'
    signature = signer()(data, private_key)
    assert fordefi_webooks_signature_validator.is_valid(data, signature) == is_valid


@pytest.mark.parametrize(
    argnames=("data", "valid_signature", "parsed_webhook", "error"),
    argvalues=[
        (
            b'{"event_id": "8c690c58-e6c7-44d6-bbdb-5cfabc2da05b", '
            b'"event": {"transaction_id": "1", "direction": "incoming"}}',
            True,
            Webhook(
                event_id="8c690c58-e6c7-44d6-bbdb-5cfabc2da05b",
                event=Event(transaction_id="1", direction=Direction.incoming),
            ),
            None,
        ),
        (
            b'{"event": {"transaction_id": False}}',
            True,
            None,
            pydantic.ValidationError,
        ),
        (
            b'{"event": {"transaction_id": "1"}}',
            False,
            None,
            InvalidSignatureError,
        ),
    ],
    ids=[
        "valid",
        "invalid-schema",
        "invalid-signature",
    ],
)
def test_fordefi_webooks_parser(
    fake_fordefi_webooks_signature_validator: FakeFordefiWebooksSignatureValidator,
    fordefi_webooks_parser: FordefiWebhooksParser,
    data: bytes,
    valid_signature: bool,
    parsed_webhook: Webhook,
    error: type[Exception],
) -> None:
    fake_fordefi_webooks_signature_validator.returns_valid = valid_signature

    with raises(error):
        assert fordefi_webooks_parser.parse_webhook(data, "") == parsed_webhook
