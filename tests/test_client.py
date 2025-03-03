import base64
from decimal import Decimal
from typing import TYPE_CHECKING, Any, NamedTuple
from uuid import UUID

import httpretty
import pytest
from httpretty.core import re
from pytest_httpserver import HTTPServer, httpserver

from fordefi.client import ClientError, Fordefi
from fordefi.requests_factory import Asset, Blockchain, EvmTokenType, Token
from tests import fordefienv
from tests.factories import EIP712DomainFactory, EIP712TypedDataFactory
from tests.helpers import cases

if TYPE_CHECKING:
    from fordefi.httptypes import JsonDict

FAKE_PRIVATE_KEY = "piWvYG3xNCU3cXvNJXnLsRZlG6Ae9O1V4aYJiyNXt7M="
ARBITRUM_TOKEN_CONTRACT = "0x912CE59144191C1204E64559FE8253a0e49E6548"  # noqa: S105


def all_items_have(items: list[dict[str, Any]], required_properties: set[str]) -> bool:
    return all(required_properties <= set(item.keys()) for item in items)


@pytest.mark.vcr
def test_get_assets(fordefi: Fordefi) -> None:
    assets_iterable = fordefi.get_assets(vault_id=fordefienv.APTOS_DEPOSITS_VAULT_ID)
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/get_vault_assets_api_v1_vaults__id__assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr
def test_list_assets(fordefi: Fordefi) -> None:
    assets_iterable = fordefi.list_assets(
        vault_ids=[
            fordefienv.APTOS_RELEASES_VAULT_ID,
            fordefienv.APTOS_DEPOSITS_VAULT_ID,
        ],
    )
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/list_owned_assets_api_v1_assets_owned_assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr
def test_list_assets__no_vault_id(
    fordefi: Fordefi,
) -> None:
    assets_iterable = fordefi.list_assets()
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/list_owned_assets_api_v1_assets_owned_assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr
def test_create_vault(fordefi: Fordefi) -> None:
    vault_request: JsonDict = {
        "name": "creation-test-vault",
        "type": "evm",
    }
    created_vault = fordefi.create_vault(vault_request)
    assert created_vault
    assert "id" in created_vault
    assert created_vault.get("name") == vault_request["name"]


@pytest.mark.vcr
def test_get_vault(fordefi: Fordefi) -> None:
    response = fordefi.get_vault(vault_id=fordefienv.APTOS_RELEASES_VAULT_ID)
    assert isinstance(response, dict)
    assert len(response) > 0


@pytest.mark.vcr
def test_list_vaults(fordefi: Fordefi) -> None:
    vaults = list(fordefi.list_vaults())
    assert len(vaults) > 0
    assert all({"id", "name"}.intersection(set(vault.keys())) for vault in vaults)


@pytest.mark.vcr
def test_get_transaction(fordefi: Fordefi) -> None:
    transaction = fordefi.get_transaction(fordefienv.TEST_TRANSACTION_ID)
    assert transaction
    assert transaction.get("id") == fordefienv.TEST_TRANSACTION_ID


class CreateTransferBySymbolTestCase(NamedTuple):
    vault_id: str
    asset_symbol: str
    amount: Decimal
    destination_address: str
    idepotence_client_id: UUID


@pytest.mark.vcr
@cases(
    1,
    CreateTransferBySymbolTestCase(
        fordefienv.APTOS_RELEASES_VAULT_ID,
        "APT",
        Decimal(1),
        fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
        UUID("87dcf0b9-50f1-4841-9a3a-f928e6bff8c7"),
    ),
    CreateTransferBySymbolTestCase(
        fordefienv.EVM_RELEASES_VAULT_ID,
        "ETH",
        Decimal(1),
        fordefienv.EVM_DEPOSITS_VAULT_ID,
        UUID("bc0ba65a-3c99-4f0c-918b-febf76b0e287"),
    ),
)
def test_create_transfer(
    fordefi: Fordefi,
    case: CreateTransferBySymbolTestCase,
) -> None:
    created_transfer = fordefi.create_transfer(
        vault_id=case.vault_id,
        amount=case.amount,
        destination_address=case.destination_address,
        idempotence_client_id=case.idepotence_client_id,
        asset_symbol=case.asset_symbol,  # pyright: ignore[reportArgumentType]
    )

    assert created_transfer
    assert "id" in created_transfer
    state = created_transfer.get("state")
    assert state


class CreateTransferByAssetTestCase(NamedTuple):
    name: str
    vault_id: str
    amount: Decimal
    asset: Asset
    destination_address: str
    idepotence_client_id: UUID


@pytest.mark.vcr
@cases(
    0,
    CreateTransferByAssetTestCase(
        "APT",
        fordefienv.APTOS_RELEASES_VAULT_ID,
        Decimal(1),
        Asset(blockchain=Blockchain.APTOS),
        fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
        UUID("87dcf0b9-50f1-4841-9a3a-f928e6bff8c7"),
    ),
    CreateTransferByAssetTestCase(
        "ETH",
        fordefienv.EVM_RELEASES_VAULT_ID,
        Decimal(1),
        Asset(blockchain=Blockchain.ETHEREUM),
        fordefienv.EVM_DEPOSITS_VAULT_ADDRESS,
        UUID("bc0ba65a-3c99-4f0c-918b-febf76b0e287"),
    ),
    CreateTransferByAssetTestCase(
        "Arbitrum-ETH",
        fordefienv.EVM_RELEASES_VAULT_ID,
        Decimal(1),
        Asset(blockchain=Blockchain.ARBITRUM),
        fordefienv.EVM_DEPOSITS_VAULT_ADDRESS,
        UUID("aa4e3c61-2408-44dd-afea-1d4f93bf6e31"),
    ),
    CreateTransferByAssetTestCase(
        "Arbitrum-ARB",
        fordefienv.EVM_RELEASES_VAULT_ID,
        Decimal(1),
        Asset(
            blockchain=Blockchain.ARBITRUM,
            token=Token(
                token_type=EvmTokenType.ERC20,
                token_id=ARBITRUM_TOKEN_CONTRACT,
            ),
        ),
        fordefienv.EVM_DEPOSITS_VAULT_ADDRESS,
        UUID("0775e4a0-201a-430c-aa74-5f20e60b96c0"),
    ),
)
def test_create_transfer_by_blockchain(
    fordefi: Fordefi,
    case: CreateTransferByAssetTestCase,
) -> None:
    created_transfer = fordefi.create_transfer(
        vault_id=case.vault_id,
        amount=case.amount,
        asset=case.asset,
        destination_address=case.destination_address,
        idempotence_client_id=case.idepotence_client_id,
    )

    assert created_transfer
    assert "id" in created_transfer
    state = created_transfer.get("state")
    assert state


def test_create_transfer__missing_asset(
    fordefi: Fordefi,
) -> None:
    with pytest.raises(
        ValueError,
        match=r".*asset_symbol or blockchain must be provided.*",
    ):
        fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            amount=Decimal(1),
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("5c7bc082-b197-43c8-877d-f4cb890dd15a"),
        )


def test_create_transfer__invalid_asset_symbol(
    fordefi: Fordefi,
) -> None:
    with pytest.raises(
        ValueError,
        match=re.compile(r".*asset_symbol.*argument only supports:.*", re.DOTALL),
    ):
        fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            amount=Decimal(1),
            asset_symbol="ARB",  # pyright: ignore[reportArgumentType]
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("5c7bc082-b197-43c8-877d-f4cb890dd15a"),
        )


def test_create_transfer__bad_request(
    httpserver_fordefi: Fordefi,
    httpserver: httpserver.HTTPServer,
) -> None:
    error_detail = "Invalid prediction result: move abort in 0x1::coin:"
    "einsufficient_balance(0x10006): not enough coins to complete transaction"
    httpserver.expect_oneshot_request(
        method="POST",
        uri="/transactions",
    ).respond_with_json(
        {"detail": error_detail},
        status=400,
    )

    with pytest.raises(ClientError) as error:
        httpserver_fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            asset_symbol="APT",
            amount=Decimal(1),
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("87dcf0b9-50f1-4841-9a3a-f928e6bff8c7"),
        )

    assert error_detail in str(error)


def test_create_transfer_by_asset__bad_request(
    httpserver_fordefi: Fordefi,
    httpserver: httpserver.HTTPServer,
) -> None:
    error_detail = r".*Invalid prediction result: move abort in 0x1::coin: "
    "einsufficient_balance(0x10006): not enough coins to complete transaction.*"
    httpserver.expect_oneshot_request(
        method="POST",
        uri="/transactions",
    ).respond_with_json(
        {"detail": error_detail},
        status=400,
    )

    with pytest.raises(ClientError, match=error_detail):
        httpserver_fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            asset=Asset(blockchain=Blockchain.APTOS),
            amount=Decimal(1),
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("2b23019c-6c11-4f35-931e-b396a92f4155"),
        )


def test_create_transfer__non_interger_amount(fordefi: Fordefi) -> None:
    with pytest.raises(
        ValueError,
        match=r"Amount must be an integer representing the amount in smallest unit.",
    ):
        fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            asset=Asset(blockchain=Blockchain.APTOS),
            amount=Decimal("0.1"),
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("bc0ba65a-3c99-4f0c-918b-febf76b0e287"),
        )


@pytest.mark.vcr
def test_create_transaction(
    fordefi: Fordefi,
) -> None:
    transaction_request = {
        "vault_id": fordefienv.BLACKBOX_VAULT_ID,
        "note": "string",
        "sign_mode": "auto",
        "type": "black_box_signature",
        "details": {"format": "hash_binary", "hash_binary": "SGVsbG8="},
    }
    created_transaction = fordefi.create_transaction(
        transaction_request,
        idempotence_client_id=UUID("56493cf2-36d9-4f37-b310-db1247941bbd"),
    )
    assert created_transaction
    assert "id" in created_transaction
    state = created_transaction.get("state")
    assert state


@pytest.mark.vcr
def test_create_transaction_idempotence(
    fordefi: Fordefi,
) -> None:
    transaction_request = {
        "vault_id": "e1e88d12-7f78-440e-a12c-c7e3904daeed",
        "note": "string",
        "sign_mode": "auto",
        "type": "black_box_signature",
        "details": {"format": "hash_binary", "hash_binary": "SGVsbG8="},
    }
    created_transaction1 = fordefi.create_transaction(
        transaction_request,
        idempotence_client_id=UUID("7ce3ecd6-ad3a-4563-a094-81973e3f1247"),
    )
    created_transaction2 = fordefi.create_transaction(
        transaction_request,
        idempotence_client_id=UUID("dbfde74f-c753-4f90-aca9-a788cd5ec88e"),
    )
    assert created_transaction2.get("id") != created_transaction1.get("id")

    common_id = UUID("4a178661-340a-42bf-b0e7-8d68959d205d")
    created_transaction3 = fordefi.create_transaction(
        transaction_request,
        idempotence_client_id=common_id,
    )
    created_transaction4 = fordefi.create_transaction(
        transaction_request,
        idempotence_client_id=common_id,
    )
    assert created_transaction4.get("id") == created_transaction3.get("id")


def test_create_invalid_signature_type_transaction(fordefi: Fordefi) -> None:
    transaction_request = {
        "vault_id": fordefienv.APTOS_RELEASES_VAULT_ID,
        "signer_type": "initiator",
        "type": "black_box_signature",
        "details": {"format": "hash_binary", "hash_binary": "SGVsbG8="},
    }
    with pytest.raises(ValueError, match="signer_type must be 'api_signer'"):
        fordefi.create_transaction(
            transaction_request,
            idempotence_client_id=UUID("34a525c3-61a2-46f4-80ec-2142320fe5b8"),
        )


@httpretty.activate
def test_failed_create_transaction(fordefi: Fordefi) -> None:
    transaction_request = {
        "vault_id": fordefienv.APTOS_RELEASES_VAULT_ID,
        "note": "string",
        "sign_mode": "auto",
        "type": "black_box_signature",
        "details": {"format": "hash_binary", "hash_binary": "SGVsbG8="},
    }
    httpretty.register_uri(
        httpretty.POST,
        f"{fordefi._base_url}/transactions",
        status=422,
    )
    with pytest.raises(ClientError):
        fordefi.create_transaction(
            transaction_request,
            idempotence_client_id=UUID("c9fe423a-4f2c-423c-83a0-c8c5b8389dc9"),
        )


@pytest.mark.vcr
def test_list_transactions(
    fordefi: Fordefi,
) -> None:
    transactions_iterable = fordefi.list_transactions(
        vault_ids=[
            fordefienv.APTOS_RELEASES_VAULT_ID,
            fordefienv.SOLANA_DEPOSITS_VAULT_ID,
        ],
    )
    transactions = list(transactions_iterable)

    assert len(transactions) > 0
    assert all_items_have(transactions, {"id", "type", "state"})


@pytest.mark.vcr
def test_list_transactions__with_direction_parameter(
    fordefi: Fordefi,
) -> None:
    vault_ids = [
        fordefienv.APTOS_DEPOSITS_VAULT_ID,
        fordefienv.APTOS_RELEASES_VAULT_ID,
    ]

    transactions_iterable = fordefi.list_transactions(
        vault_ids=vault_ids,
    )
    transactions = list(transactions_iterable)

    incoming_transactions_iterable = fordefi.list_transactions(
        vault_ids=vault_ids,
        direction="incoming",
    )
    incoming_transactions = list(incoming_transactions_iterable)

    assert 0 < len(incoming_transactions) < len(transactions)
    assert all_items_have(incoming_transactions, {"id", "type", "state"})


def test_get_pages(httpserver: HTTPServer) -> None:
    base_url = httpserver.url_for("")

    fordefi = Fordefi(
        base_url=base_url,
        page_size=2,
        api_key="",
        private_key=FAKE_PRIVATE_KEY,
    )

    httpserver.expect_request(
        "/items",
        query_string={"page": "1", "size": "2"},
    ).respond_with_json({"items": ["a", "b"], "total": 5, "page": 1})
    httpserver.expect_request(
        "/items",
        query_string={"page": "2", "size": "2"},
    ).respond_with_json({"items": ["c", "d"], "total": 5, "page": 2})
    httpserver.expect_request(
        "/items",
        query_string={"page": "3", "size": "2"},
    ).respond_with_json({"items": ["f"], "total": 5, "page": 3})

    items = fordefi._get_pages("items", "items")

    assert list(items) == ["a", "b", "c", "d", "f"]


def test_get_pages_empty(httpserver: HTTPServer) -> None:
    base_url = httpserver.url_for("")

    fordefi = Fordefi(
        base_url=base_url,
        page_size=2,
        api_key="",
        private_key=FAKE_PRIVATE_KEY,
    )

    httpserver.expect_request(
        "/items",
        query_string={"page": "1", "size": "2"},
    ).respond_with_json({"items": [], "total": 0, "page": 1})

    items = fordefi._get_pages("items", "items")

    assert list(items) == []


@pytest.mark.vcr
def test_create_signature(fordefi: Fordefi) -> None:
    domain = EIP712DomainFactory.build(chain_id=1)
    message = EIP712TypedDataFactory.build(domain=domain)
    response = fordefi.create_signature(
        message=message,
        vault_id=fordefienv.EVM_RELEASES_VAULT_ID,
        blockchain=Blockchain.ETHEREUM,
    )
    signatures = response.get("signatures")

    assert isinstance(signatures, list)
    assert len(signatures) == 1
    assert isinstance(signatures[0], str)
    assert base64.b64decode(signatures[0])
