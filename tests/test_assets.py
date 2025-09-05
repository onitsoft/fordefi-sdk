from typing import Any

import pytest

from fordefi.assets import (
    AssetSubtype,
    AssetType,
    TransactionSubtype,
    TransactionType,
    UnknownTransactionTypeError,
    asset_registry,
    get_asset_symbol,
    get_transfer_asset_identifier,
)
from tests.helpers import raises


def _create_test_transaction(
    chain_unique_id: str,
    sub_type: str,
) -> dict[str, Any]:
    """Create a test transaction with proper structure based on chain type."""
    # Map chain patterns to their types
    chain_mapping = {
        "aptos": ("aptos", "aptos_transaction"),
        "evm": ("evm", "evm_transaction"),
        "solana": ("solana", "solana_transaction"),
    }

    # Find the matching chain type
    chain_type, transaction_type = "unknown", "unknown_transaction"
    for pattern, (ct, tt) in chain_mapping.items():
        if pattern in chain_unique_id:
            chain_type, transaction_type = ct, tt
            break

    return {
        "id": "b085757b-5c2d-43ed-8a32-5cbb5c3c84f2",
        "type": transaction_type,
        f"{chain_type}_transaction_type_details": {
            "type": sub_type,
        },
        "chain": {
            "chain_type": chain_type,
            "unique_id": chain_unique_id,
        },
    }


@pytest.mark.parametrize(
    argnames=(
        "chain_unique_id",
        "expected_symbol",
        "sub_type",
        "expected_exception",
    ),
    argvalues=[
        ("aptos_mainnet", "APT", "native_transfer", None),
        ("aptos_mainnet", "APT", "coin_transfer", None),
        ("evm_ethereum_mainnet", "ETH", "native_transfer", None),
        ("evm_base_mainnet", "BASE", "native_transfer", None),
        ("evm_bsc_mainnet", "BNB", "native_transfer", None),
        ("evm_polygon_mainnet", "MATIC", "native_transfer", None),
        ("evm_avalanche_chain", "AVAX", "native_transfer", None),
        ("evm_arbitrum_mainnet", "ARB", "native_transfer", None),
        ("evm_optimism_mainnet", "OP", "native_transfer", None),
        ("evm_sonic_mainnet", "S", "native_transfer", None),
        ("evm_ethereum_sepolia", "SETH", "native_transfer", None),
        ("solana_devnet", "DSOL", "native_transfer", None),
        ("solana_devnet", "DSOL", "raw_transaction", None),
        ("unknown_chain", None, "native_transfer", UnknownTransactionTypeError),
    ],
    ids=[
        "aptos_native_transfer",
        "aptos_coin_transfer",
        "ethereum_native_transfer",
        "base_native_transfer",
        "bsc_native_transfer",
        "polygon_native_transfer",
        "avalanche_native_transfer",
        "arbitrum_native_transfer",
        "optimism_native_transfer",
        "sonic_native_transfer",
        "ethereum_sepolia_native_transfer",
        "solana_native_transfer",
        "solana_raw_transaction",
        "unknown_chain",
    ],
)
def test_get_asset_symbol(
    chain_unique_id: str,
    expected_symbol: str,
    sub_type: str,
    expected_exception: type[Exception],
) -> None:
    """Test getting asset symbol from transaction data."""
    tx = _create_test_transaction(chain_unique_id, sub_type)

    with raises(expected_exception):
        assert get_asset_symbol(tx) == expected_symbol


def test_asset_registry_get_asset_identifier() -> None:
    """Test getting asset identifiers from the registry."""
    # Test known assets
    apt_asset = asset_registry.get_asset_identifier("APT")
    assert apt_asset.type == AssetType.APTOS
    assert apt_asset.subtype.value == "native"
    assert apt_asset.chain == "aptos_mainnet"

    eth_asset = asset_registry.get_asset_identifier("ETH")
    assert eth_asset.type == AssetType.EVM
    assert eth_asset.subtype.value == "native"
    assert eth_asset.chain == "evm_ethereum_mainnet"

    # Test unknown asset
    with pytest.raises(ValueError, match="Unknown asset symbol: UNKNOWN"):
        asset_registry.get_asset_identifier("UNKNOWN")


def test_asset_registry_list_available_assets() -> None:
    """Test listing available assets."""
    assets = asset_registry.list_available_assets()

    # Check that all expected assets are present
    expected_assets = {
        "DSOL",
        "APT",
        "ETH",
        "BASE",
        "BNB",
        "MATIC",
        "AVAX",
        "ARB",
        "OP",
        "S",
        "SETH",
    }
    assert set(assets) == expected_assets


def test_asset_registry_list_assets_by_type() -> None:
    """Test listing assets by type."""
    # Test EVM assets
    evm_assets = asset_registry.list_assets_by_type(AssetType.EVM)
    expected_evm = {
        "ETH",
        "BASE",
        "BNB",
        "MATIC",
        "AVAX",
        "ARB",
        "OP",
        "S",
        "SETH",
    }
    assert set(evm_assets) == expected_evm

    # Test Aptos assets
    aptos_assets = asset_registry.list_assets_by_type(AssetType.APTOS)
    assert set(aptos_assets) == {"APT"}

    # Test Solana assets
    solana_assets = asset_registry.list_assets_by_type(AssetType.SOLANA)
    assert set(solana_assets) == {"DSOL"}


def test_get_transfer_asset_identifier_backward_compatibility() -> None:
    """Test backward compatibility function."""
    asset = get_transfer_asset_identifier("ETH")
    assert asset.type == AssetType.EVM
    assert asset.chain == "evm_ethereum_mainnet"


def test_asset_identifier_validation() -> None:
    """Test asset identifier validation."""
    from fordefi.assets import AssetIdentifier, GasConfig

    # Test valid asset identifier
    asset = AssetIdentifier(
        type=AssetType.EVM,
        subtype=AssetSubtype.NATIVE,
        chain="evm_test_mainnet",
        default_gas=GasConfig(type="priority", priority="high"),
    )
    assert asset.type == AssetType.EVM
    assert asset.subtype == AssetSubtype.NATIVE
    assert asset.chain == "evm_test_mainnet"


def test_unknown_transaction_type_error() -> None:
    """Test UnknownTransactionType error details."""
    from fordefi.assets import TransactionTypeKey

    key = TransactionTypeKey(
        type=TransactionType.EVM_TRANSACTION,
        subtype=TransactionSubtype.NATIVE_TRANSFER,
        chain_unique_id="unknown_chain",
    )

    error = UnknownTransactionTypeError(key, "test_id")
    assert error.transfer_type == key
    assert error.transaction_id == "test_id"
    assert "test_id" in str(error)
    assert "unknown_chain" in str(error)
