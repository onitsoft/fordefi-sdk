import base64
import datetime
import hashlib
import json
import time
from abc import abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import ClassVar
from uuid import UUID

import ecdsa.util
import requests
from requests import Request

from fordefi.types import Json


class _RequestFactory:
    path: ClassVar[str]
    method: ClassVar[str]

    @staticmethod
    def _signature(
        path: str,
        request_json: Json,
        signing_key: ecdsa.SigningKey,
    ) -> dict[str, bytes | str]:
        request_body = json.dumps(request_json)
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%s")
        timestamp = str(int(time.time()))
        payload = f"/api/v1{path}|{timestamp}|{request_body}"
        signature = signing_key.sign(
            data=payload.encode(),
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_der,
        )
        return {
            "x-signature": base64.b64encode(signature),
            "x-timestamp": timestamp,
        }

    @abstractmethod
    def _get_body(self) -> Json: ...

    def _get_headers(
        self,
        data: Json,
        auth_token: str,
        idempotence_id: UUID | None,
        signing_key: ecdsa.SigningKey,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }
        if idempotence_id:
            headers["x-idempotence-id"] = str(idempotence_id)

        if signing_key:
            headers = {
                **headers,
                **self._signature(self.path, data, signing_key),
            }

        return headers

    def build(
        self,
        base_url: str,
        auth_token: str,
        idempotence_id: UUID | None,
        signing_key: ecdsa.SigningKey,
    ) -> Request:
        body = self._get_body()
        return requests.Request(
            method=self.method,
            headers=self._get_headers(
                auth_token=auth_token,
                data=body,
                idempotence_id=idempotence_id,
                signing_key=signing_key,
            ),
            url=f"{base_url}{self.path}",
            json=body,
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
    transaction_type: ClassVar[str] = "evm_transaction"
    chain: ClassVar[str]

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
                    "chain": self.chain,
                },
            },
            "to": destination_address,
            "value": {
                "type": "value",
                "value": str(amount),
            },
        }


class _EthereumTransferRequestFactory(_EvmTransferRequestFactory):
    transaction_type = "evm_transaction"
    chain = "evm_ethereum_mainnet"


class Blockchain(Enum):
    APTOS = _AptosTransferRequestFactory
    ETHEREUM = _EthereumTransferRequestFactory


class RequestFactory:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        signing_key: ecdsa.SigningKey,
    ) -> None:
        self.base_url = base_url
        self.auth_token = auth_token
        self._signing_key = signing_key

    def create_transfer_request(
        self,
        blockchain: Blockchain,
        vault_id: str,
        amount: Decimal,
        destination_address: str,
        idempotence_id: UUID | None = None,
    ) -> Request:
        factory_class = blockchain.value
        factory = factory_class(
            vault_id=vault_id,
            amount=amount,
            destination_address=destination_address,
        )
        return factory.build(
            base_url=self.base_url,
            auth_token=self.auth_token,
            idempotence_id=idempotence_id,
            signing_key=self._signing_key,
        )
