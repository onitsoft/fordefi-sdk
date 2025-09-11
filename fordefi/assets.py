from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(Enum):
    """Supported asset types."""

    EVM = "evm"
    APTOS = "aptos"
    SOLANA = "solana"
    UTXO = "utxo"


class AssetSubtype(Enum):
    """Supported asset subtypes."""

    NATIVE = "native"
    ERC20 = "erc20"
    SPL = "spl"  # Solana Program Library tokens


class TransactionType(Enum):
    """Supported transaction types."""

    APTOS_TRANSACTION = "aptos_transaction"
    EVM_TRANSACTION = "evm_transaction"
    SOLANA_TRANSACTION = "solana_transaction"
    UTXO_TRANSACTION = "utxo_transaction"


class TransactionSubtype(Enum):
    """Supported transaction subtypes."""

    NATIVE_TRANSFER = "native_transfer"
    COIN_TRANSFER = "coin_transfer"
    RAW_TRANSACTION = "raw_transaction"
    UTXO_TRANSFER = "utxo_transfer"


@dataclass(frozen=True)
class GasConfig:
    """Gas configuration for transactions."""

    type: str
    priority: str
    priority_level: str | None = None


@dataclass(frozen=True)
class DestinationSerializer:
    """Destination address serializer configuration."""

    type: str
    address: str


class AssetIdentifier(BaseModel):
    """Asset identifier with proper validation and type safety."""

    type: AssetType
    subtype: AssetSubtype
    chain: str
    default_gas: GasConfig | None = None
    default_gas_config: dict[str, Any] | None = None
    default_destination_serializer: Callable[
        [str],
        str | dict[str, Any],
    ] = Field(default_factory=lambda: lambda address: address)

    class Config:
        arbitrary_types_allowed = True


@dataclass(frozen=True)
class TransactionTypeKey:
    """Key for transaction type mapping."""

    type: TransactionType
    subtype: TransactionSubtype
    chain_unique_id: str


class UnknownTransactionTypeError(Exception):
    """Raised when a transaction type is not recognized."""

    def __init__(
        self,
        transfer_type: TransactionTypeKey,
        transaction_id: str,
    ) -> None:
        super().__init__(
            f"Transaction {transaction_id} has an unknown type {transfer_type}",
        )
        self.transfer_type = transfer_type
        self.transaction_id = transaction_id


class AssetRegistry:
    """Registry for managing asset configurations."""

    def __init__(self) -> None:
        self._assets: dict[str, AssetIdentifier] = {}
        self._transaction_mappings: dict[TransactionTypeKey, str] = {}
        self._initialize_assets()
        self._initialize_transaction_mappings()

    def _initialize_assets(self) -> None:
        """Initialize asset configurations."""
        # EVM chains
        evm_chains = {
            "ETH": ("ethereum", "mainnet"),
            "BASE": ("base", "mainnet"),
            "BNB": ("bsc", "mainnet"),
            "MATIC": ("polygon", "mainnet"),
            "AVAX": ("avalanche", "chain"),  # edge case 'chain'
            "ARB": ("arbitrum", "mainnet"),
            "OP": ("optimism", "mainnet"),
            "S": ("sonic", "mainnet"),
            "SETH": ("ethereum", "sepolia"),
        }

        # evm native mappings
        for symbol, (blockchain, network) in evm_chains.items():
            chain_id = f"evm_{blockchain}_{network}"
            self._assets[symbol] = AssetIdentifier(
                type=AssetType.EVM,
                subtype=AssetSubtype.NATIVE,
                chain=chain_id,
                default_gas=GasConfig(
                    type="priority",
                    priority="medium",
                    priority_level="medium",
                ),
            )

        # Custom mappings
        # Solana
        self._assets["DSOL"] = AssetIdentifier(
            type=AssetType.SOLANA,
            subtype=AssetSubtype.NATIVE,
            chain="solana_devnet",
        )

        # Aptos
        self._assets["APT"] = AssetIdentifier(
            type=AssetType.APTOS,
            subtype=AssetSubtype.NATIVE,
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
        )

        # Bitcoin
        self._assets["BTC"] = AssetIdentifier(
            type=AssetType.UTXO,
            subtype=AssetSubtype.NATIVE,
            chain="bitcoin_mainnet",
            default_destination_serializer=lambda address: {
                "type": "address",
                "address": address,
            },
        )

    def _initialize_transaction_mappings(self) -> None:
        """Initialize transaction type to asset symbol mappings."""
        # Non-EVM chains
        non_evm_mappings = [
            (
                TransactionType.APTOS_TRANSACTION,
                TransactionSubtype.NATIVE_TRANSFER,
                "aptos_mainnet",
                "APT",
            ),
            (
                TransactionType.APTOS_TRANSACTION,
                TransactionSubtype.COIN_TRANSFER,
                "aptos_mainnet",
                "APT",
            ),
            (
                TransactionType.SOLANA_TRANSACTION,
                TransactionSubtype.NATIVE_TRANSFER,
                "solana_devnet",
                "DSOL",
            ),
            (
                TransactionType.SOLANA_TRANSACTION,
                TransactionSubtype.RAW_TRANSACTION,
                "solana_devnet",
                "DSOL",
            ),
            (
                TransactionType.UTXO_TRANSACTION,
                TransactionSubtype.UTXO_TRANSFER,
                "bitcoin_mainnet",
                "BTC",
            ),
        ]

        for tx_type, tx_subtype, chain_id, symbol in non_evm_mappings:
            key = TransactionTypeKey(
                type=tx_type,
                subtype=tx_subtype,
                chain_unique_id=chain_id,
            )
            self._transaction_mappings[key] = symbol

        # EVM chains
        evm_symbols = [
            "ETH",
            "BASE",
            "BNB",
            "MATIC",
            "AVAX",
            "ARB",
            "OP",
            "S",
            "SETH",
        ]
        for symbol in evm_symbols:
            if symbol in self._assets:
                asset = self._assets[symbol]
                key = TransactionTypeKey(
                    type=TransactionType.EVM_TRANSACTION,
                    subtype=TransactionSubtype.NATIVE_TRANSFER,
                    chain_unique_id=asset.chain,
                )
                self._transaction_mappings[key] = symbol

    def get_asset_identifier(self, symbol: str) -> AssetIdentifier:
        """Get asset identifier by symbol."""
        if symbol not in self._assets:
            msg = f"Unknown asset symbol: {symbol}"
            raise ValueError(msg)
        return self._assets[symbol]

    def get_asset_symbol(self, transfer: dict[str, Any]) -> str:
        """Get asset symbol from transfer data."""
        transfer_id = transfer["id"]
        transfer_type_str = transfer["type"]
        subtype_str = transfer[f"{transfer_type_str}_type_details"]["type"]
        chain_id = transfer["chain"]["unique_id"]

        try:
            tx_type = TransactionType(transfer_type_str)
            tx_subtype = TransactionSubtype(subtype_str)
        except ValueError as e:
            # Create a fallback key for error reporting
            fallback_key = TransactionTypeKey(
                type=TransactionType.EVM_TRANSACTION,  # Default fallback
                subtype=TransactionSubtype.NATIVE_TRANSFER,  # Default fallback
                chain_unique_id=chain_id,
            )
            raise UnknownTransactionTypeError(fallback_key, transfer_id) from e

        key = TransactionTypeKey(
            type=tx_type,
            subtype=tx_subtype,
            chain_unique_id=chain_id,
        )

        if key not in self._transaction_mappings:
            raise UnknownTransactionTypeError(key, transfer_id)

        return self._transaction_mappings[key]

    def list_available_assets(self) -> list[str]:
        """List all available asset symbols."""
        return list(self._assets.keys())

    def list_assets_by_type(self, asset_type: AssetType) -> list[str]:
        """List asset symbols by type."""
        return [
            symbol for symbol, asset in self._assets.items() if asset.type == asset_type
        ]


# Global registry instance
asset_registry = AssetRegistry()


# Convenience functions for backward compatibility
def get_transfer_asset_identifier(asset_symbol: str) -> AssetIdentifier:
    """Get asset identifier by symbol (backward compatibility)."""
    return asset_registry.get_asset_identifier(asset_symbol)


def get_asset_symbol(transfer: dict[str, Any]) -> str:
    """Get asset symbol from transfer data (backward compatibility)."""
    return asset_registry.get_asset_symbol(transfer)
