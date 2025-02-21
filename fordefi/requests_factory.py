from abc import abstractmethod
from dataclasses import dataclass
from decimal import Decimal

import requests
from requests import Request

from fordefi.types import Json


class UnsupportedBlockchainError(Exception):
    def __init__(self, blockchain: str) -> None:
        msg = f"blockchain {blockchain} is not supported"
        super().__init__(msg)
        self.blockchain = blockchain


def _get_transaction_type(blockchain: str) -> str:
    if blockchain == "aptos":
        return "aptos_transaction"

    if blockchain == "ethereum":
        return "evm_transaction"

    raise UnsupportedBlockchainError(blockchain)


def _create_aptos_transfer_details(
    destination_address: str,
    amount: Decimal,
    blockchain: str,
) -> Json:
    if blockchain != "aptos":
        raise UnsupportedBlockchainError(blockchain)

    return {
        "type": "aptos_transfer",
        "gas_config": {
            "price": {
                "type": "priority",
                "priority": "medium",
            },
        },
        "to": {
            "type": "hex",
            "address": destination_address,
        },
        "value": {"type": "value", "value": str(amount)},
        "asset_identifier": {
            "type": "aptos",
            "details": {
                "type": "native",
                "chain": "aptos_mainnet",
            },
        },
    }


def _create_evm_transfer_details(
    destination_address: str,
    amount: Decimal,
    blockchain: str,
) -> Json:
    if blockchain != "ethereum":
        raise UnsupportedBlockchainError(blockchain)

    return {
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
        "to": destination_address,
        "value": {
            "type": "value",
            "value": str(amount),
        },
    }


def _create_transfer_details(
    destination_address: str,
    amount: Decimal,
    blockchain: str,
) -> Json:
    if blockchain == "aptos":
        return _create_aptos_transfer_details(
            destination_address=destination_address,
            amount=amount,
            blockchain=blockchain,
        )

    if blockchain == "ethereum":
        return _create_evm_transfer_details(
            destination_address=destination_address,
            amount=amount,
            blockchain=blockchain,
        )

    raise UnsupportedBlockchainError(blockchain)


class RequestFactory:
    path_prefix = "/api/v1"
    path: str
    method: str

    @property
    def full_path(self) -> str:
        return f"{self.path_prefix}{self.path}"

    @abstractmethod
    def _get_body(self) -> Json: ...

    def build(self, base_url: str, auth_token: str) -> Request:
        return requests.Request(
            method=self.method,
            headers={"Authorization": f"Bearer {auth_token}"},
            url=f"{base_url}{self.full_path}",
            json=self._get_body(),
        )


@dataclass()
class TranferRequestFactory(RequestFactory):
    method = "POST"
    path = "/transactions"
    vault_id: str
    destination_address: str
    amount: Decimal
    blockchain: str

    def _get_body(self) -> Json:
        return {
            "vault_id": self.vault_id,
            "type": _get_transaction_type(self.blockchain),
            "details": _create_transfer_details(
                destination_address=self.destination_address,
                amount=self.amount,
                blockchain=self.blockchain,
            ),
        }
