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
        "bitcoin": ("utxo", "utxo_transaction"),
        "tron": ("tron", "tron_transaction"),
        "cosmos": ("cosmos", "cosmos_transaction"),
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
        ("bitcoin_mainnet", "BTC", "utxo_transfer", None),
        ("tron_mainnet", "TRX", "tron_transfer", None),
        ("cosmos_mainnet", "ATOM", "raw_transaction", None),
        (
            "unknown_chain",
            None,
            "native_transfer",
            UnknownTransactionTypeError,
        ),
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
        "bitcoin_utxo_transfer",
        "tron_tron_transfer",
        "cosmos_raw_transaction",
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
        "BTC",
        "TRX",
        "ATOM",
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


def _test_evm_assets_by_type() -> None:
    """Test EVM assets by type."""
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


def _test_non_evm_assets_by_type() -> None:
    """Test non-EVM assets by type."""
    # Test Aptos assets
    aptos_assets = asset_registry.list_assets_by_type(AssetType.APTOS)
    assert set(aptos_assets) == {"APT"}

    # Test Solana assets
    solana_assets = asset_registry.list_assets_by_type(AssetType.SOLANA)
    assert set(solana_assets) == {"DSOL"}

    # Test UTXO/Bitcoin assets
    utxo_assets = asset_registry.list_assets_by_type(AssetType.UTXO)
    assert set(utxo_assets) == {"BTC"}

    # Test Tron assets
    tron_assets = asset_registry.list_assets_by_type(AssetType.TRON)
    assert set(tron_assets) == {"TRX"}

    # Test Cosmos assets
    cosmos_assets = asset_registry.list_assets_by_type(AssetType.COSMOS)
    assert set(cosmos_assets) == {"ATOM"}


def test_asset_registry_list_assets_by_type() -> None:
    """Test listing assets by type."""
    _test_evm_assets_by_type()
    _test_non_evm_assets_by_type()


def test_get_transfer_asset_identifier_backward_compatibility() -> None:
    """Test backward compatibility function."""
    asset = get_transfer_asset_identifier("ETH")
    assert asset.type == AssetType.EVM
    assert asset.chain == "evm_ethereum_mainnet"


def test_btc_asset_identifier() -> None:
    """Test BTC asset identifier."""
    btc_asset = get_transfer_asset_identifier("BTC")
    assert btc_asset.type == AssetType.UTXO
    assert btc_asset.subtype == AssetSubtype.NATIVE
    assert btc_asset.chain == "bitcoin_mainnet"
    assert btc_asset.default_destination_serializer is not None

    # Test the default destination serializer
    result = btc_asset.default_destination_serializer(
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    )
    expected = {
        "type": "address",
        "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    }
    assert result == expected


def test_trx_asset_identifier() -> None:
    """Test TRX asset identifier."""
    trx_asset = get_transfer_asset_identifier("TRX")
    assert trx_asset.type == AssetType.TRON
    assert trx_asset.subtype == AssetSubtype.NATIVE
    assert trx_asset.chain == "tron_mainnet"
    assert trx_asset.default_destination_serializer is not None

    # Test the default destination serializer
    result = trx_asset.default_destination_serializer(
        "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH",
    )
    expected = {
        "type": "address",
        "address": "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH",
    }
    assert result == expected


def test_atom_asset_identifier() -> None:
    """Test ATOM asset identifier."""
    atom_asset = get_transfer_asset_identifier("ATOM")
    assert atom_asset.type == AssetType.COSMOS
    assert atom_asset.subtype == AssetSubtype.NATIVE
    assert atom_asset.chain == "cosmos_mainnet"
    assert atom_asset.default_destination_serializer is not None

    # Test the default destination serializer
    result = atom_asset.default_destination_serializer(
        "cosmos1huydeevpz37sd9snkgul6070mjukukqfc0p8n0",
    )
    expected = {
        "type": "address",
        "address": "cosmos1huydeevpz37sd9snkgul6070mjukukqfc0p8n0",
    }
    assert result == expected


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


def test_utxo_asset_identifier() -> None:
    """Test UTXO asset identifier creation and details."""
    from fordefi.requests_factory import _UtxoAssetIdentifier

    # Test UTXO asset identifier
    utxo_asset = _UtxoAssetIdentifier(network="mainnet")
    assert utxo_asset.type == "utxo"
    assert utxo_asset.subtype == "native"
    assert utxo_asset.network == "mainnet"
    assert utxo_asset.chain == "utxo_mainnet"

    # Test details method
    details = utxo_asset._get_details()
    assert details == {
        "type": "native",
        "chain": "utxo_mainnet",
    }


def test_cosmos_asset_identifier() -> None:
    """Test Cosmos asset identifier creation and details."""
    from fordefi.requests_factory import _CosmosAssetIdentifier

    # Test Cosmos asset identifier
    cosmos_asset = _CosmosAssetIdentifier(network="mainnet")
    assert cosmos_asset.type == "cosmos"
    assert cosmos_asset.subtype == "native"
    assert cosmos_asset.network == "mainnet"
    assert cosmos_asset.chain == "cosmos_mainnet"

    # Test details method
    details = cosmos_asset._get_details()
    assert details == {
        "type": "native",
        "chain": "cosmos_mainnet",
    }


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


def test_destination_serializer() -> None:
    """Test DestinationSerializer dataclass."""
    from fordefi.assets import DestinationSerializer

    serializer = DestinationSerializer(type="hex", address="0x123")
    assert serializer.type == "hex"
    assert serializer.address == "0x123"


def test_gas_config() -> None:
    """Test GasConfig dataclass."""
    from fordefi.assets import GasConfig

    # Test with all fields
    gas_config = GasConfig(
        type="priority",
        priority="high",
        priority_level="high",
    )
    assert gas_config.type == "priority"
    assert gas_config.priority == "high"
    assert gas_config.priority_level == "high"

    # Test with optional field
    gas_config_minimal = GasConfig(type="priority", priority="medium")
    assert gas_config_minimal.type == "priority"
    assert gas_config_minimal.priority == "medium"
    assert gas_config_minimal.priority_level is None


def test_transaction_type_key() -> None:
    """Test TransactionTypeKey dataclass."""
    from fordefi.assets import TransactionTypeKey

    key = TransactionTypeKey(
        type=TransactionType.APTOS_TRANSACTION,
        subtype=TransactionSubtype.COIN_TRANSFER,
        chain_unique_id="aptos_mainnet",
    )
    assert key.type == TransactionType.APTOS_TRANSACTION
    assert key.subtype == TransactionSubtype.COIN_TRANSFER
    assert key.chain_unique_id == "aptos_mainnet"


def test_asset_identifier_with_all_fields() -> None:
    """Test AssetIdentifier with all possible fields."""
    from fordefi.assets import AssetIdentifier, GasConfig

    def custom_serializer(address: str) -> dict[str, str]:
        return {"type": "custom", "address": address}

    asset = AssetIdentifier(
        type=AssetType.EVM,
        subtype=AssetSubtype.ERC20,
        chain="evm_test_mainnet",
        default_gas=GasConfig(
            type="priority",
            priority="high",
            priority_level="high",
        ),
        default_gas_config={"price": {"type": "priority", "priority": "high"}},
        default_destination_serializer=custom_serializer,
    )

    assert asset.type == AssetType.EVM
    assert asset.subtype == AssetSubtype.ERC20
    assert asset.chain == "evm_test_mainnet"
    assert asset.default_gas is not None
    assert asset.default_gas_config is not None
    assert asset.default_destination_serializer is not None

    # Test the custom serializer
    result = asset.default_destination_serializer("0x123")
    assert result == {"type": "custom", "address": "0x123"}


def test_asset_identifier_with_defaults() -> None:
    """Test AssetIdentifier with default values."""
    from fordefi.assets import AssetIdentifier

    asset = AssetIdentifier(
        type=AssetType.SOLANA,
        subtype=AssetSubtype.SPL,
        chain="solana_testnet",
    )

    assert asset.type == AssetType.SOLANA
    assert asset.subtype == AssetSubtype.SPL
    assert asset.chain == "solana_testnet"
    assert asset.default_gas is None
    assert asset.default_gas_config is None
    assert asset.default_destination_serializer is not None

    # Test default serializer (should return address as-is)
    result = asset.default_destination_serializer("test_address")
    assert result == "test_address"


def test_get_asset_symbol_invalid_transaction_type() -> None:
    """Test get_asset_symbol with invalid transaction type."""
    from fordefi.assets import UnknownTransactionTypeError, get_asset_symbol

    # Test with invalid transaction type
    tx = {
        "id": "test_id",
        "type": "invalid_transaction_type",
        "invalid_transaction_type_type_details": {
            "type": "native_transfer",
        },
        "chain": {
            "unique_id": "evm_ethereum_mainnet",
        },
    }

    with pytest.raises(UnknownTransactionTypeError) as exc_info:
        get_asset_symbol(tx)

    # Check that the fallback key is used
    assert exc_info.value.transfer_type.type == TransactionType.EVM_TRANSACTION
    assert exc_info.value.transfer_type.subtype == TransactionSubtype.NATIVE_TRANSFER
    assert exc_info.value.transfer_type.chain_unique_id == "evm_ethereum_mainnet"


def test_get_asset_symbol_invalid_subtype() -> None:
    """Test get_asset_symbol with invalid subtype."""
    from fordefi.assets import UnknownTransactionTypeError, get_asset_symbol

    # Test with invalid subtype
    tx = {
        "id": "test_id",
        "type": "evm_transaction",
        "evm_transaction_type_details": {
            "type": "invalid_subtype",
        },
        "chain": {
            "unique_id": "evm_ethereum_mainnet",
        },
    }

    with pytest.raises(UnknownTransactionTypeError) as exc_info:
        get_asset_symbol(tx)

    # Check that the fallback key is used
    assert exc_info.value.transfer_type.type == TransactionType.EVM_TRANSACTION
    assert exc_info.value.transfer_type.subtype == TransactionSubtype.NATIVE_TRANSFER


def test_get_asset_symbol_unknown_transaction_mapping() -> None:
    """Test get_asset_symbol with unknown transaction mapping."""
    from fordefi.assets import UnknownTransactionTypeError, get_asset_symbol

    # Test with valid transaction type and subtype but unknown chain
    tx = {
        "id": "test_id",
        "type": "evm_transaction",
        "evm_transaction_type_details": {
            "type": "native_transfer",
        },
        "chain": {
            "unique_id": "evm_unknown_chain",
        },
    }

    with pytest.raises(UnknownTransactionTypeError) as exc_info:
        get_asset_symbol(tx)

    # Check that the correct key is used
    assert exc_info.value.transfer_type.type == TransactionType.EVM_TRANSACTION
    assert exc_info.value.transfer_type.subtype == TransactionSubtype.NATIVE_TRANSFER
    assert exc_info.value.transfer_type.chain_unique_id == "evm_unknown_chain"


def test_asset_registry_initialization() -> None:
    """Test AssetRegistry initialization."""
    from fordefi.assets import AssetRegistry

    registry = AssetRegistry()

    # Test that assets are properly initialized
    assert "ETH" in registry._assets
    assert "APT" in registry._assets
    assert "DSOL" in registry._assets

    # Test that transaction mappings are properly initialized
    assert len(registry._transaction_mappings) > 0


def test_asset_registry_eth_configuration() -> None:
    """Test ETH asset configuration."""
    from fordefi.assets import AssetRegistry, AssetSubtype, AssetType, GasConfig

    registry = AssetRegistry()
    eth_asset = registry._assets["ETH"]

    assert eth_asset.type == AssetType.EVM
    assert eth_asset.subtype == AssetSubtype.NATIVE
    assert eth_asset.chain == "evm_ethereum_mainnet"
    assert eth_asset.default_gas is not None
    assert isinstance(eth_asset.default_gas, GasConfig)


def test_asset_registry_apt_configuration() -> None:
    """Test APT asset configuration."""
    from fordefi.assets import AssetRegistry, AssetSubtype, AssetType

    registry = AssetRegistry()
    apt_asset = registry._assets["APT"]

    assert apt_asset.type == AssetType.APTOS
    assert apt_asset.subtype == AssetSubtype.NATIVE
    assert apt_asset.chain == "aptos_mainnet"
    assert apt_asset.default_gas_config is not None
    assert apt_asset.default_destination_serializer is not None


def test_asset_registry_edge_cases() -> None:
    """Test edge cases in AssetRegistry."""
    from fordefi.assets import AssetRegistry, AssetType

    registry = AssetRegistry()

    # Test listing assets by type that has no assets
    # This tests the list comprehension in list_assets_by_type
    # We need to create a scenario where an asset type has no matches
    # Since all our current assets are EVM, APTOS, or SOLANA, test the logic

    # Test that the method works correctly even with no matches
    # (This is more of a structural test since we don't have empty asset types)
    evm_assets = registry.list_assets_by_type(AssetType.EVM)
    assert len(evm_assets) > 0
    assert all(registry._assets[symbol].type == AssetType.EVM for symbol in evm_assets)


def test_asset_type_enum_values() -> None:
    """Test AssetType enum values."""
    assert AssetType.EVM.value == "evm"
    assert AssetType.APTOS.value == "aptos"
    assert AssetType.SOLANA.value == "solana"
    assert AssetType.UTXO.value == "utxo"
    assert AssetType.TRON.value == "tron"
    assert AssetType.COSMOS.value == "cosmos"


def test_asset_subtype_enum_values() -> None:
    """Test AssetSubtype enum values."""
    assert AssetSubtype.NATIVE.value == "native"
    assert AssetSubtype.ERC20.value == "erc20"
    assert AssetSubtype.SPL.value == "spl"


def test_transaction_type_enum_values() -> None:
    """Test TransactionType enum values."""
    assert TransactionType.APTOS_TRANSACTION.value == "aptos_transaction"
    assert TransactionType.EVM_TRANSACTION.value == "evm_transaction"
    assert TransactionType.SOLANA_TRANSACTION.value == "solana_transaction"
    assert TransactionType.UTXO_TRANSACTION.value == "utxo_transaction"
    assert TransactionType.TRON_TRANSACTION.value == "tron_transaction"
    assert TransactionType.COSMOS_TRANSACTION.value == "cosmos_transaction"


def test_transaction_subtype_enum_values() -> None:
    """Test TransactionSubtype enum values."""
    assert TransactionSubtype.NATIVE_TRANSFER.value == "native_transfer"
    assert TransactionSubtype.COIN_TRANSFER.value == "coin_transfer"
    assert TransactionSubtype.RAW_TRANSACTION.value == "raw_transaction"
    assert TransactionSubtype.UTXO_TRANSFER.value == "utxo_transfer"
    assert TransactionSubtype.TRON_TRANSFER.value == "tron_transfer"
