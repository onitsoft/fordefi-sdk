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
    InvalidBlockchainIdError,
    RequestFactory,
    Token,
    TokenNotImplementedError,
    _EvmRawTransactionRequest,
    _EvmSignatureRequest,
)
from tests.factories import EIP712DomainFactory, EIP712TypedDataFactory

if TYPE_CHECKING:
    from fordefi.httptypes import Json


ARBITRUM_TOKEN_CONTRACT = "0x912CE59144191C1204E64559FE8253a0e49E6548"  # noqa: S105

VAULD_ID = "ce26562d-ca59-4e85-af01-f86c111939fb"
APTOS_ADDRESS = "0x3300c18e7b931bdfc73dccf3e2d043ad1c9d120c777fff5aeeb9956224e5247a"
EVM_ADDRESS = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
BTC_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
TRX_ADDRESS = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH"
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
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.APTOS),
            APTOS_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.ETHEREUM),
            EVM_ADDRESS,
        ),
        (VAULD_ID, Decimal(1), Asset(blockchain=Blockchain.BASE), EVM_ADDRESS),
        (VAULD_ID, Decimal(1), Asset(blockchain=Blockchain.BSC), EVM_ADDRESS),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.POLYGON),
            EVM_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.AVALANCHE),
            EVM_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.ARBITRUM),
            EVM_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.SONIC),
            EVM_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.OPTIMISM),
            EVM_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.BITCOIN),
            BTC_ADDRESS,
        ),
        (
            VAULD_ID,
            Decimal(1),
            Asset(blockchain=Blockchain.TRON),
            TRX_ADDRESS,
        ),
    ],
    ids=[
        "APT",
        "ETH",
        "BASE",
        "BNB",
        "MATIC",
        "AVAX",
        "ARB",
        "S",
        "OP",
        "BTC",
        "TRX",
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
    assert body is not None
    assert body.get("vault_id") == vault_id

    details = body.get("details", {})
    _validate_blockchain_specific_fields(asset, details, destination_address, amount)


def _validate_bitcoin_fields(
    details: dict,
    destination_address: str,
    amount: Decimal,
) -> None:
    """Validate Bitcoin-specific request fields."""
    assert details.get("send_max_to", {}).get("address") == destination_address
    assert (
        details.get("outputs", [{}])[0].get("to", {}).get("address")
        == destination_address
    )
    expected_value = str(int(amount * 100000000))
    assert details.get("outputs", [{}])[0].get("value") == expected_value


def _validate_tron_fields(
    details: dict,
    destination_address: str,
    amount: Decimal,
) -> None:
    """Validate Tron-specific request fields."""
    assert details.get("to", {}).get("address") == destination_address
    expected_value = str(int(amount * 1000000))
    assert details.get("value", {}).get("value") == expected_value


def _validate_standard_fields(
    details: dict,
    destination_address: str,
    amount: Decimal,
) -> None:
    """Validate standard blockchain request fields."""
    assert (
        details.get("to") == destination_address
        or details.get("to", {}).get("address") == destination_address
    )
    assert details.get("value", {}).get("value") == str(amount)


def _validate_blockchain_specific_fields(
    asset: Asset,
    details: dict,
    destination_address: str,
    amount: Decimal,
) -> None:
    """Validate blockchain-specific request fields based on asset type."""
    if asset.blockchain == Blockchain.BITCOIN:
        _validate_bitcoin_fields(details, destination_address, amount)
    elif asset.blockchain == Blockchain.TRON:
        _validate_tron_fields(details, destination_address, amount)
    else:
        _validate_standard_fields(details, destination_address, amount)


@pytest.mark.parametrize(
    argnames=("vault_id", "asset", "destination_address"),
    argvalues=[
        (VAULD_ID, Asset(blockchain=Blockchain.APTOS), APTOS_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.ARBITRUM), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.ETHEREUM), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.BASE), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.BSC), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.POLYGON), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.AVALANCHE), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.SONIC), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.OPTIMISM), EVM_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.BITCOIN), BTC_ADDRESS),
        (VAULD_ID, Asset(blockchain=Blockchain.TRON), TRX_ADDRESS),
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
    ids=[
        "Aptos",
        "Arbitrum",
        "Ethereum",
        "Base",
        "BSC",
        "Polygon",
        "Avalanche",
        "Sonic",
        "Optimism",
        "Bitcoin",
        "Tron",
        "Arbitrum-Ether",
    ],
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


def test_not_implemented_token_bitcoin(request_factory: RequestFactory) -> None:
    """Test that Bitcoin with token raises TokenNotImplementedError."""
    with pytest.raises(TokenNotImplementedError):
        request_factory.create_transfer_request(
            vault_id=VAULD_ID,
            amount=Decimal(1),
            asset=Asset(
                blockchain=Blockchain.BITCOIN,
                token=Token(
                    token_type=EvmTokenType.ERC20,
                    token_id=ARBITRUM_TOKEN_CONTRACT,
                ),
            ),
            destination_address=BTC_ADDRESS,
        )


def test_not_implemented_token_tron(request_factory: RequestFactory) -> None:
    """Test that Tron with token raises TokenNotImplementedError."""
    with pytest.raises(TokenNotImplementedError):
        request_factory.create_transfer_request(
            vault_id=VAULD_ID,
            amount=Decimal(1),
            asset=Asset(
                blockchain=Blockchain.TRON,
                token=Token(
                    token_type=EvmTokenType.ERC20,
                    token_id=ARBITRUM_TOKEN_CONTRACT,
                ),
            ),
            destination_address=TRX_ADDRESS,
        )


def test_create_signature_request(
    openapi: OpenAPI,
    request_factory: RequestFactory,
) -> None:
    domain = EIP712DomainFactory.build(chain_id=1)
    message = EIP712TypedDataFactory.build(domain=domain)
    request = request_factory.create_signature_request(
        message=message,
        vault_id=VAULD_ID,
        blockchain=Blockchain.ETHEREUM,
    )
    openapi_request = RequestsOpenAPIRequest(request)
    openapi.validate_request(openapi_request)
    body = request.json
    assert body is not None
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


def test_create_signature_request__invalid_blockchain_id(
    request_factory: RequestFactory,
) -> None:
    invalid_blockchain_id = 1
    domain = EIP712DomainFactory.build(chain_id=invalid_blockchain_id)
    message = EIP712TypedDataFactory.build(domain=domain)
    with pytest.raises(InvalidBlockchainIdError):
        request_factory.create_signature_request(
            message=message,
            vault_id=VAULD_ID,
            blockchain=Blockchain.ARBITRUM,
        )


@pytest.mark.parametrize(
    argnames=("blockchain", "chain_id"),
    argvalues=[
        (Blockchain.ETHEREUM, 1),
        (Blockchain.BASE, 8453),
        (Blockchain.BSC, 56),
        (Blockchain.POLYGON, 137),
        (Blockchain.AVALANCHE, 43114),
        (Blockchain.ARBITRUM, 42161),
        (Blockchain.SONIC, 146),
        (Blockchain.OPTIMISM, 10),
    ],
    ids=[
        "Ethereum",
        "Base",
        "BSC",
        "Polygon",
        "Avalanche",
        "Arbitrum",
        "Sonic",
        "Optimism",
    ],
)
def test_create_signature_request_all_evm_blockchains(
    request_factory: RequestFactory,
    blockchain: Blockchain,
    chain_id: int,
) -> None:
    """Test signature request creation for all EVM blockchains."""
    domain = EIP712DomainFactory.build(chain_id=chain_id)
    message = EIP712TypedDataFactory.build(domain=domain)
    request = request_factory.create_signature_request(
        message=message,
        vault_id=VAULD_ID,
        blockchain=blockchain,
    )

    body = request.json
    assert body is not None
    assert body.get("vault_id") == VAULD_ID
    details = body.get("details", {})
    chain = details.get("chain", "")
    assert blockchain.value in chain
    assert "mainnet" in chain


@pytest.mark.parametrize(
    argnames=("blockchain", "chain_id"),
    argvalues=[
        (Blockchain.ETHEREUM, 1),
        (Blockchain.BASE, 8453),
        (Blockchain.BSC, 56),
        (Blockchain.POLYGON, 137),
        (Blockchain.AVALANCHE, 43114),
        (Blockchain.ARBITRUM, 42161),
        (Blockchain.SONIC, 146),
        (Blockchain.OPTIMISM, 10),
    ],
    ids=[
        "Ethereum",
        "Base",
        "BSC",
        "Polygon",
        "Avalanche",
        "Arbitrum",
        "Sonic",
        "Optimism",
    ],
)
def test_create_evm_raw_transaction_request_all_blockchains(
    request_factory: RequestFactory,
    blockchain: Blockchain,
    chain_id: int,  # noqa: ARG001
) -> None:
    """Test raw transaction request creation for all EVM blockchains."""
    destination_address = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    raw_data = "SGVsbG8="
    request = request_factory.create_evm_raw_transaction_request(
        destination_address=destination_address,
        raw_data=raw_data,
        vault_id=VAULD_ID,
        blockchain=blockchain,
    )

    body = request.json
    assert body is not None
    assert body.get("vault_id") == VAULD_ID
    details = body.get("details", {})
    data = details.get("data", {})
    assert data.get("raw_data") == raw_data
    chain = details.get("chain", "")
    assert blockchain.value in chain


def test_create_evm_raw_transaction_request(
    request_factory: RequestFactory,
    openapi: OpenAPI,
) -> None:
    destination_address = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    raw_data = "SGVsbG8="
    request = request_factory.create_evm_raw_transaction_request(
        destination_address=destination_address,
        raw_data=raw_data,
        vault_id=VAULD_ID,
        blockchain=Blockchain.ARBITRUM,
    )

    openapi_request = RequestsOpenAPIRequest(request)
    openapi.validate_request(openapi_request)

    body = request.json
    assert body is not None
    assert body.get("vault_id") == VAULD_ID
    assert body.get("details", {}).get("data", {}).get("raw_data") == raw_data
    assert Blockchain.ARBITRUM.value in body.get("details", {}).get("chain", "")


def test_create_evm_raw_transaction_request_invalid_blockchain(
    request_factory: RequestFactory,
) -> None:
    destination_address = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    raw_data = "SGVsbG8="
    with pytest.raises(BlockchainNotImplementedError):
        request_factory.create_evm_raw_transaction_request(
            destination_address=destination_address,
            raw_data=raw_data,
            vault_id=VAULD_ID,
            blockchain=Blockchain.APTOS,
        )


def test_evm_raw_transaction_request_serialization() -> None:
    destination_address = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    raw_data = "SGVsbG8="
    request = _EvmRawTransactionRequest(
        destination_address=destination_address,
        vault_id=VAULD_ID,
        blockchain=Blockchain.ETHEREUM,
        network="mainnet",
        raw_data=raw_data,
        timeout=15,
    )

    body = request._get_body()

    assert isinstance(body, dict)

    assert body.get("vault_id") == VAULD_ID
    assert body.get("details", {}).get("data", {}).get("raw_data") == raw_data  # type: ignore[attr-defined]
    assert Blockchain.ETHEREUM.value in body.get("details", {}).get("chain", "")  # type: ignore[attr-defined]


def test_evm_raw_transaction_request_construction(
    request_factory: RequestFactory,
) -> None:
    destination_address = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
    raw_data = "SGVsbG8="
    request = _EvmRawTransactionRequest(
        destination_address=destination_address,
        vault_id=VAULD_ID,
        blockchain=Blockchain.ETHEREUM,
        network="mainnet",
        raw_data=raw_data,
        timeout=15,
    )

    built_request = request.build(
        base_url=BASE_URL,
        auth_token=JWT,
        idempotence_id=None,
        signing_key=request_factory._signing_key,
    )

    assert built_request.method == "POST"
    assert built_request.url == f"{BASE_URL}/transactions"
    assert "Authorization" in built_request.headers
    assert "Content-Type" in built_request.headers
