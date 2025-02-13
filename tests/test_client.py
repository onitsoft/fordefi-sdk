from decimal import Decimal
from typing import Any
from uuid import UUID

import httpretty
import pytest
from pytest_httpserver import HTTPServer, httpserver

from fordefi.client import ClientError, Fordefi
from tests import fordefienv

FAKE_PRIVATE_KEY = "piWvYG3xNCU3cXvNJXnLsRZlG6Ae9O1V4aYJiyNXt7M="


def all_items_have(items: list[dict[str, Any]], required_properties: set[str]) -> bool:
    return all(required_properties <= set(item.keys()) for item in items)


@pytest.mark.vcr()
def test_get_assets(fordefi: Fordefi) -> None:
    assets_iterable = fordefi.get_assets(vault_id=fordefienv.APTOS_DEPOSITS_VAULT_ID)
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/get_vault_assets_api_v1_vaults__id__assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr()
def test_list_assets(fordefi: Fordefi) -> None:
    assets_iterable = fordefi.list_assets(
        vault_ids=[
            fordefienv.APTOS_RELEASES_VAULT_ID,
            fordefienv.APTOS_DEPOSITS_VAULT_ID,
        ]
    )
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/list_owned_assets_api_v1_assets_owned_assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr()
def test_list_assets__no_vault_id(
    fordefi: Fordefi,
) -> None:
    assets_iterable = fordefi.list_assets()
    assets = list(assets_iterable)
    assert len(assets) > 0
    # https://documentation.fordefi.com/redoc/#operation/list_owned_assets_api_v1_assets_owned_assets_get
    assert all_items_have(assets, {"priced_asset", "balance", "balances"})


@pytest.mark.vcr()
def test_create_vault(fordefi: Fordefi) -> None:
    vault_request = dict(
        name="creation-test-vault",
        type="evm",
    )
    created_vault = fordefi.create_vault(vault_request)
    assert created_vault
    assert "id" in created_vault
    assert created_vault.get("name") == vault_request["name"]


@pytest.mark.vcr()
def test_get_vault(fordefi: Fordefi) -> None:
    response = fordefi.get_vault(vault_id=fordefienv.APTOS_RELEASES_VAULT_ID)
    assert isinstance(response, dict)
    assert len(response) > 0


@pytest.mark.vcr()
def test_list_vaults(fordefi: Fordefi) -> None:
    vaults = list(fordefi.list_vaults())
    assert len(vaults) > 0
    assert all({"id", "name"}.intersection(set(vault.keys())) for vault in vaults)


@pytest.mark.vcr()
def test_get_transaction(fordefi: Fordefi) -> None:
    transaction = fordefi.get_transaction(fordefienv.TEST_TRANSACTION_ID)
    assert transaction
    assert transaction.get("id") == fordefienv.TEST_TRANSACTION_ID


@pytest.mark.vcr
@pytest.mark.parametrize(
    argnames="vault_id,asset_symbol,amount,destination_address",
    argvalues=[
        (
            fordefienv.APTOS_RELEASES_VAULT_ID,
            "APT",
            Decimal("1"),
            fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
        ),
    ],
    ids=["APT"],
)
def test_create_transfer(
    fordefi: Fordefi,
    vault_id: str,
    asset_symbol: str,
    amount: Decimal,
    destination_address: str,
):
    created_transfer = fordefi.create_transfer(
        vault_id=vault_id,
        asset_symbol=asset_symbol,
        amount=amount,
        destination_address=destination_address,
        idempotence_client_id=UUID("87dcf0b9-50f1-4841-9a3a-f928e6bff8c7"),
    )

    assert created_transfer
    assert "id" in created_transfer
    state = created_transfer.get("state")
    assert state


def test_create_transfer__bad_request(
    httpserver_fordefi: Fordefi,
    httpserver: httpserver.HTTPServer,
):
    error_detail = "Invalid prediction result: move abort in 0x1::coin: einsufficient_balance(0x10006): not enough coins to complete transaction"
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

        assert str(error) == error_detail


def test_create_transfer__non_interger_amount(fordefi: Fordefi):
    with pytest.raises(ValueError):
        fordefi.create_transfer(
            vault_id=fordefienv.APTOS_RELEASES_VAULT_ID,
            asset_symbol="DSOL",
            amount=Decimal("0.1"),
            destination_address=fordefienv.APTOS_DEPOSITS_VAULT_ADDRESS,
            idempotence_client_id=UUID("bc0ba65a-3c99-4f0c-918b-febf76b0e287"),
        )


@pytest.mark.vcr()
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


@pytest.mark.vcr()
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
        transaction_request, idempotence_client_id=common_id
    )
    created_transaction4 = fordefi.create_transaction(
        transaction_request, idempotence_client_id=common_id
    )
    assert created_transaction4.get("id") == created_transaction3.get("id")


def test_create_invalid_signature_type_transaction(fordefi: Fordefi) -> None:
    transaction_request = {
        "vault_id": fordefienv.APTOS_RELEASES_VAULT_ID,
        "signer_type": "initiator",
        "type": "black_box_signature",
        "details": {"format": "hash_binary", "hash_binary": "SGVsbG8="},
    }
    with pytest.raises(ValueError):
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
        httpretty.POST, f"{fordefi._base_url}/transactions", status=422
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
        ]
    )
    transactions = list(transactions_iterable)

    assert len(transactions) > 0
    assert all_items_have(transactions, {"id", "type", "state"})


def test_get_pages(httpserver: HTTPServer) -> None:
    base_url = httpserver.url_for("")

    fordefi = Fordefi(
        base_url=base_url,
        page_size=2,
        api_key="",
        private_key=FAKE_PRIVATE_KEY,
    )

    httpserver.expect_request(
        "/items", query_string={"page": "1", "size": "2"}
    ).respond_with_json({"items": ["a", "b"], "total": 5, "page": 1})
    httpserver.expect_request(
        "/items", query_string={"page": "2", "size": "2"}
    ).respond_with_json({"items": ["c", "d"], "total": 5, "page": 2})
    httpserver.expect_request(
        "/items", query_string={"page": "3", "size": "2"}
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
        "/items", query_string={"page": "1", "size": "2"}
    ).respond_with_json({"items": [], "total": 0, "page": 1})

    items = fordefi._get_pages("items", "items")

    assert list(items) == []
