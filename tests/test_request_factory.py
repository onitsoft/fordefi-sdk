from decimal import Decimal

import pytest

from fordefi import requests_factory
from fordefi.types import Json

VAULD_ID = "ce26562d-ca59-4e85-af01-f86c111939fb"
APTOS_ADDRESS = "0x3300c18e7b931bdfc73dccf3e2d043ad1c9d120c777fff5aeeb9956224e5247a"
EVM_ADDRESS = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"


@pytest.mark.parametrize(
    argnames=(
        "vault_id",
        "blockchain",
        "amount",
        "destination_address",
        "expected_request",
    ),
    argvalues=[
        (
            VAULD_ID,
            "aptos",
            Decimal(1),
            APTOS_ADDRESS,
            {
                "vault_id": VAULD_ID,
                "type": "aptos_transaction",
                "details": {
                    "type": "aptos_transfer",
                    "gas_config": {
                        "price": {
                            "type": "priority",
                            "priority": "medium",
                        },
                    },
                    "to": {
                        "type": "hex",
                        "address": APTOS_ADDRESS,
                    },
                    "value": {"type": "value", "value": "1"},
                    "asset_identifier": {
                        "type": "aptos",
                        "details": {
                            "type": "native",
                            "chain": "aptos_mainnet",
                        },
                    },
                },
            },
        ),
        (
            VAULD_ID,
            "ethereum",
            Decimal(1),
            EVM_ADDRESS,
            {
                "vault_id": VAULD_ID,
                "type": "evm_transaction",
                "details": {
                    "type": "evm_transfer",
                    "gas": {
                        "type": "priority",
                        "priority_level": "medium",
                    },
                    "asset_identifier": {
                        "type": "evm",
                        "details": {
                            "type": "native",
                            "chain": "evm_ethereum_mainnet",
                        },
                    },
                    "to": EVM_ADDRESS,
                    "value": {
                        "type": "value",
                        "value": "1",
                    },
                },
            },
        ),
    ],
    ids=["APT", "ETH"],
)
def test_create_transfer_request(
    vault_id: str,
    blockchain: str,
    amount: Decimal,
    destination_address: str,
    expected_request: Json,
) -> None:
    request = requests_factory.create_transfer_request(
        vault_id=vault_id,
        amount=amount,
        destination_address=destination_address,
        blockchain=blockchain,
    )

    assert request == expected_request
