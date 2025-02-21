import base64
from decimal import Decimal
from pathlib import Path

import ecdsa
import ecdsa.curves
import pytest
from openapi_core import Config, OpenAPI, V31RequestValidator
from openapi_core.contrib.requests import RequestsOpenAPIRequest

from fordefi.requests_factory import (
    BlockchainType,
    RequestFactory,
)

VAULD_ID = "ce26562d-ca59-4e85-af01-f86c111939fb"
APTOS_ADDRESS = "0x3300c18e7b931bdfc73dccf3e2d043ad1c9d120c777fff5aeeb9956224e5247a"
EVM_ADDRESS = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
FAKE_PRIVATE_KEY = "piWvYG3xNCU3cXvNJXnLsRZlG6Ae9O1V4aYJiyNXt7M="

BASE_URL = "https://api.fordefi.com/api/v1"
JWT = "ejw.eya"

OPENAPI_PATH = Path(__file__).parent / "openapi.json"


@pytest.fixture(name="openapi", scope="module")
def openapi_fixture() -> OpenAPI:
    config = Config(
        request_validator_cls=V31RequestValidator,
    )
    return OpenAPI.from_file_path(OPENAPI_PATH.as_posix(), config=config)


@pytest.fixture(name="request_factory")
def request_factory_fixture() -> RequestFactory:
    signing_key = ecdsa.SigningKey.from_string(
        base64.b64decode(FAKE_PRIVATE_KEY),
        curve=ecdsa.curves.NIST256p,
    )

    return RequestFactory(base_url=BASE_URL, auth_token=JWT, signing_key=signing_key)


@pytest.mark.parametrize(
    argnames=("vault_id", "blockchain_type", "amount", "destination_address"),
    argvalues=[
        (VAULD_ID, BlockchainType.APTOS, Decimal(1), APTOS_ADDRESS),
        (VAULD_ID, BlockchainType.EVM, Decimal(1), EVM_ADDRESS),
    ],
    ids=[
        "APT",
        "ETH",
    ],
)
def test_create_transfer_request_body(
    request_factory: RequestFactory,
    vault_id: str,
    blockchain_type: BlockchainType,
    amount: Decimal,
    destination_address: str,
) -> None:
    request = request_factory.create_transfer_request(
        blockchain_type=blockchain_type,
        vault_id=vault_id,
        amount=amount,
        destination_address=destination_address,
    )

    body = request.json
    assert body.get("vault_id") == vault_id
    assert (
        body.get("details", {}).get("to") == destination_address
        or body.get("details", {}).get("to", {}).get("address") == destination_address
    )
    assert body.get("details", {}).get("value", {}).get("value") == str(amount)


def test_create_transfer_request_schema(
    openapi: OpenAPI,
    request_factory: RequestFactory,
) -> None:
    request = request_factory.create_transfer_request(
        blockchain_type=BlockchainType.APTOS,
        vault_id=VAULD_ID,
        amount=Decimal(1),
        destination_address=APTOS_ADDRESS,
    )
    openapi_request = RequestsOpenAPIRequest(request)
    openapi.validate_request(openapi_request)
