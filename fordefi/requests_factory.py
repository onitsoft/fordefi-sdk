from abc import abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import ClassVar

import requests
from requests import Request

from fordefi.types import Json


class _RequestFactory:
    path_prefix: ClassVar[str] = "/api/v1"
    path: ClassVar[str]
    method: ClassVar[str]

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


@dataclass(frozen=True)
class _TranferRequestFactory(_RequestFactory):
    method: ClassVar[str] = "POST"
    path: ClassVar[str] = "/transactions"
    transaction_type: ClassVar[str]
    vault_id: str
    destination_address: str
    amount: Decimal

    @abstractmethod
    def _get_transfer_details(
        self,
        destination_address: str,
        amount: Decimal,
    ) -> Json: ...

    def _get_body(self) -> Json:
        return {
            "vault_id": self.vault_id,
            "type": self.transaction_type,
            "details": self._get_transfer_details(
                destination_address=self.destination_address,
                amount=self.amount,
            ),
        }


class _AptosTransferRequestFactory(_TranferRequestFactory):
    transaction_type = "aptos_transaction"

    def _get_transfer_details(
        self,
        destination_address: str,
        amount: Decimal,
    ) -> Json:
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


class _EvmTransferRequestFactory(_TranferRequestFactory):
    transaction_type = "evm_transaction"

    def _get_transfer_details(
        self,
        destination_address: str,
        amount: Decimal,
    ) -> Json:
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


class BlockchainType(Enum):
    APTOS = _AptosTransferRequestFactory
    EVM = _EvmTransferRequestFactory


class RequestFactory:
    def __init__(self, base_url: str, auth_token: str) -> None:
        self.base_url = base_url
        self.auth_token = auth_token

    def create_transfer_request(
        self,
        blockchain_type: BlockchainType,
        vault_id: str,
        amount: Decimal,
        destination_address: str,
    ) -> Request:
        factory_class = blockchain_type.value
        factory = factory_class(
            vault_id=vault_id,
            amount=amount,
            destination_address=destination_address,
        )
        return factory.build(base_url=self.base_url, auth_token=self.auth_token)
