from collections.abc import Callable
from dataclasses import dataclass

from pydantic import Json


@dataclass()
class AssetIdentifier:
    type: str
    subtype: str
    chain: str
    default_gas: Json | None = None
    default_gas_config: Json | None = None
    default_destination_serializer: Callable[[str], str | Json] = (
        lambda address: address
    )


@dataclass(frozen=True)
class TransactionType:
    type: str
    subtype: str
    chain_unique_id: str


class UnknownTransactionType(Exception):
    def __init__(self, transfer_type: TransactionType, transaction_id: str) -> None:
        super().__init__(
            f"Transaction {transaction_id} has an unknown type {transfer_type}",
        )


ASSET_IDENTIFIER_BY_SYMBOL = {
    "DSOL": AssetIdentifier(
        type="solana",
        subtype="native",
        chain="solana_devnet",
    ),
    "APT": AssetIdentifier(
        type="aptos",
        subtype="native",
        chain="aptos_mainnet",
        default_gas_config={
            "price": {
                "type": "priority",
                "priority": "medium",
            },
        },
        default_destination_serializer=lambda address: {
            "type": "hex",
            "address": address,
        },
    ),
    "ETH": AssetIdentifier(
        type="evm",
        subtype="native",
        chain="evm_ethereum_mainnet",
        default_gas={
            "type": "priority",
            "priority_level": "medium",
        },
    ),
}


ASSET_SYMBOL_BY_TRANSACTION_TYPE: dict[TransactionType, str] = {
    TransactionType(
        type="aptos_transaction",
        subtype="native_transfer",
        chain_unique_id="aptos_mainnet",
    ): "APT",
    TransactionType(
        type="evm_transaction",
        subtype="native_transfer",
        chain_unique_id="evm_ethereum_sepolia",
    ): "SETH",
    TransactionType(
        type="solana_transaction",
        subtype="native_transfer",
        chain_unique_id="solana_devnet",
    ): "DSOL",
    TransactionType(
        type="solana_transaction",
        subtype="raw_transaction",
        chain_unique_id="solana_devnet",
    ): "DSOL",
}


def get_transfer_asset_identifier(asset_symbol: str) -> AssetIdentifier:
    return ASSET_IDENTIFIER_BY_SYMBOL[asset_symbol]


def get_asset_symbol(transfer: Json) -> str:
    id: str = transfer["id"]
    type: str = transfer["type"]
    subtype: str = transfer[f"{type}_type_details"]["type"]
    chain_id: str = transfer["chain"]["unique_id"]
    transaction_type = TransactionType(
        type=type,
        subtype=subtype,
        chain_unique_id=chain_id,
    )

    try:
        return ASSET_SYMBOL_BY_TRANSACTION_TYPE[transaction_type]

    except KeyError as error:
        raise UnknownTransactionType(
            transfer_type=transaction_type,
            transaction_id=id,
        ) from error
