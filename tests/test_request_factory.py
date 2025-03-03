import base64
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

import ecdsa
import ecdsa.curves
import pytest
from glom import glom
from httpretty.core import json
from openapi_core import Config, OpenAPI, V31RequestValidator
from openapi_core.contrib.requests import RequestsOpenAPIRequest

from fordefi.requests_factory import (
    Asset,
    Blockchain,
    BlockchainNotImplementedError,
    EvmTokenType,
    RequestFactory,
    Token,
    TokenNotImplementedError,
    _EvmSignatureRequest,
)
from tests.factories import EIP712TypedDataFactory

if TYPE_CHECKING:
    from fordefi.httptypes import Json


ARBITRUM_TOKEN_CONTRACT = "0x912CE59144191C1204E64559FE8253a0e49E6548"  # noqa: S105

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

    return RequestFactory(
        base_url=BASE_URL,
        auth_token=JWT,
        signing_key=signing_key,
        timeout=15,
    )


@pytest.mark.parametrize(
    argnames=("vault_id", "amount", "asset", "destination_address"),
    argvalues=[
        (VAULD_ID, Decimal(1), Asset(blockchain=Blockchain.APTOS), APTOS_ADDRESS),
        (VAULD_ID, Decimal(1), Asset(blockchain=Blockchain.ETHEREUM), EVM_ADDRESS),
    ],
    ids=[
        "APT",
        "ETH",
    ],
)
def test_create_transfer_request_body(
    request_factory: RequestFactory,
    vault_id: str,
    amount: Decimal,
    asset: Asset,
    destination_address: str,
) -> None:
    request = request_factory.create_transfer_request(
        vault_id=vault_id,
        amount=amount,
        asset=asset,
        destination_address=destination_address,
    )

    body = request.json
    assert body.get("vault_id") == vault_id
    assert (
        body.get("details", {}).get("to") == destination_address
        or body.get("details", {}).get("to", {}).get("address") == destination_address
    )
    assert body.get("details", {}).get("value", {}).get("value") == str(amount)


@pytest.mark.parametrize(
    argnames=("vault_id", "asset", "destination_address"),
    argvalues=[
        (VAULD_ID, Asset(blockchain=Blockchain.APTOS), APTOS_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.ARBITRUM), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.ETHEREUM), EVM_ADDRESS),
        (
            VAULD_ID,
            Asset(
                blockchain=Blockchain.ETHEREUM,
                token=Token(
                    token_type=EvmTokenType.ERC20,
                    token_id=ARBITRUM_TOKEN_CONTRACT,
                ),
            ),
            EVM_ADDRESS,
        ),
    ],
    ids=["Aptos", "Arbitrum", "Ethereum", "Arbitrum-Ether"],
)
def test_create_transfer_request_schema(
    vault_id: str,
    asset: Asset,
    destination_address: str,
    openapi: OpenAPI,
    request_factory: RequestFactory,
) -> None:
    request = request_factory.create_transfer_request(
        vault_id=vault_id,
        amount=Decimal(1),
        asset=asset,
        destination_address=destination_address,
    )
    openapi_request = RequestsOpenAPIRequest(request)
    openapi.validate_request(openapi_request)


def test_not_implemented_token(request_factory: RequestFactory) -> None:
    with pytest.raises(TokenNotImplementedError):
        request_factory.create_transfer_request(
            vault_id=VAULD_ID,
            amount=Decimal(1),
            asset=Asset(
                blockchain=Blockchain.APTOS,
                token=Token(
                    token_type=EvmTokenType.ERC20,
                    token_id=ARBITRUM_TOKEN_CONTRACT,
                ),
            ),
            destination_address=EVM_ADDRESS,
        )


def test_create_signature_request(
    openapi: OpenAPI,
    request_factory: RequestFactory,
) -> None:
    message = EIP712TypedDataFactory.build()
    request = request_factory.create_signature_request(
        message=message,
        vault_id=VAULD_ID,
        blockchain=Blockchain.ETHEREUM,
    )
    openapi_request = RequestsOpenAPIRequest(request)
    openapi.validate_request(openapi_request)
    body = request.json
    request_raw_data = glom(body, "details.raw_data", default="{}")
    request_data = json.loads(request_raw_data)
    expected_data: Json = message.model_dump(by_alias=True)
    assert request_data == expected_data
    assert body.get("vault_id") == VAULD_ID
    assert Blockchain.ETHEREUM.value in body.get("details", {}).get("chain", "")
    assert "mainnet" in body.get("details", {}).get("chain", "")


def test_serialize_json_field() -> None:
    message = EIP712TypedDataFactory.build()
    result = _EvmSignatureRequest._serialize_eip712message(message)

    meta_obj = {"j": result}
    assert json.loads(json.dumps(meta_obj)) == meta_obj


def test_create_signature_request__blockchain_not_implemented_error(
    request_factory: RequestFactory,
) -> None:
    message = EIP712TypedDataFactory.build()
    with pytest.raises(BlockchainNotImplementedError):
        request_factory.create_signature_request(
            message=message,
            vault_id=VAULD_ID,
            blockchain=Blockchain.APTOS,
        )
