import pytest

from fordefi.assets import UnknownTransactionType, get_asset_symbol
from tests.helpers import raises


@pytest.mark.parametrize(
    argnames=("chain__unique_id", "expected_symbol", "expected_exception"),
    argvalues=[
        ("aptos_mainnet", "APT", None),
        ("evm_ethereum_sepolia", None, UnknownTransactionType),
    ],
    ids=[
        "known",
        "unknown",
    ],
)
def test_get_asset_symbol(
    chain__unique_id: str,
    expected_symbol: str,
    expected_exception: type[Exception],
) -> None:
    tx = {
        "id": "b085757b-5c2d-43ed-8a32-5cbb5c3c84f2",
        "type": "aptos_transaction",
        "aptos_transaction_type_details": {
            "type": "native_transfer",
        },
        "chain": {
            "chain_type": "aptos",
            "unique_id": chain__unique_id,
        },
    }

    with raises(expected_exception):
        assert get_asset_symbol(tx) == expected_symbol
