import base64
import dataclasses
import datetime
import hashlib
import json
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import ClassVar
from uuid import UUID

import ecdsa.util
import requests
from requests import Request

from .httptypes import Json


class Blockchain(Enum):
    APTOS = "aptos"
    ARBITRUM = "arbitrum"
    ETHEREUM = "ethereum"


EVM_BLOCKCHAINS = {Blockchain.ARBITRUM, Blockchain.ETHEREUM}


class TokenType(Enum): ...


class EvmTokenType(TokenType):
    ERC20 = "erc20"


@dataclass(frozen=True)
class Token:
    token_type: TokenType
    token_id: str


@dataclass(frozen=True)
class Asset:
    blockchain: Blockchain
    token: Token | None = None


class TokenNotImplementedError(NotImplementedError):
    def __init__(self, asset: Asset) -> None:
        super().__init__(f"Token type not implemented: {dataclasses.asdict(asset)}")
        self.asset = asset


class BlockchainNotImplementedError(NotImplementedError):
    def __init__(self, blockchain: Blockchain) -> None:
        super().__init__(f"Blockchain not implemented: {blockchain}")


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
class _AssetIdentifier(ABC):
    type: ClassVar[str]
    subtype: ClassVar[str]
    network: str

    @property
    def chain(self) -> str:
        return f"{self.type}_{self.network}"

    @abstractmethod
    def _get_details(self) -> Json: ...

    def as_dict(self) -> Json:
        return {
            "type": self.type,
            "details": self._get_details(),
        }


@dataclass(frozen=True)
class _AptosAssetIdentifier(_AssetIdentifier):
    type: ClassVar[str] = "aptos"

    def _get_details(self) -> Json:
        return {
            "type": self.subtype,
            "chain": self.chain,
        }


@dataclass(frozen=True)
class _AptosNativeAssetIdentifier(_AptosAssetIdentifier):
    subtype: ClassVar[str] = "native"


@dataclass(frozen=True)
class _EvmAssetIdentifier(_AssetIdentifier):
    type: ClassVar[str] = "evm"
    blockchain: str

    @property
    def chain(self) -> str:
        return f"{self.type}_{self.blockchain}_{self.network}"


@dataclass(frozen=True)
class _EvmNativeAssetIdentifier(_EvmAssetIdentifier):
    subtype: ClassVar[str] = "native"

    def _get_details(self) -> Json:
        return {
            "type": self.subtype,
            "chain": self.chain,
        }


@dataclass(frozen=True)
class _EvmErc20AssetIdentifier(_EvmAssetIdentifier):
    subtype: ClassVar[str] = "erc20"
    contract_address: str

    def _get_details(self) -> Json:
        return {
            "type": self.subtype,
            "token": {
                "chain": self.chain,
                "hex_repr": self.contract_address,
            },
        }


@dataclass(frozen=True)
class _TranferRequestFactory(_RequestFactory):
    method: ClassVar[str] = "POST"
    path: ClassVar[str] = "/transactions"
    transaction_type: ClassVar[str]
    asset_identifier: _AssetIdentifier
    vault_id: str
    destination_address: str
    amount: Decimal

    @abstractmethod
    def _get_transfer_details(self) -> Json: ...

    def _get_body(self) -> Json:
        return {
            "signer_type": "api_signer",
            "vault_id": self.vault_id,
            "type": self.transaction_type,
            "details": self._get_transfer_details(),
        }


@dataclass(frozen=True)
class _AptosTransferRequestFactory(_TranferRequestFactory):
    transaction_type = "aptos_transaction"

    def _get_transfer_details(self) -> Json:
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
                "address": self.destination_address,
            },
            "value": {"type": "value", "value": str(self.amount)},
            "asset_identifier": self.asset_identifier.as_dict(),
        }


class _EvmTransferRequestFactory(_TranferRequestFactory):
    transaction_type: ClassVar[str] = "evm_transaction"
    chain: ClassVar[str]

    def _get_transfer_details(self) -> Json:
        return {
            "type": "evm_transfer",
            "gas": {
                "type": "priority",
                "priority_level": "medium",
            },
            "asset_identifier": self.asset_identifier.as_dict(),
            "to": self.destination_address,
            "value": {
                "type": "value",
                "value": str(self.amount),
            },
        }


_REQUEST_FACTORY_BY_BLOCKCHAIN = {
    Blockchain.APTOS: _AptosTransferRequestFactory,
    Blockchain.ARBITRUM: _EvmTransferRequestFactory,
    Blockchain.ETHEREUM: _EvmTransferRequestFactory,
}


def _create_aptos_asset_identifier(asset: Asset) -> _AssetIdentifier:
    if asset.token:
        raise TokenNotImplementedError(asset)

    return _AptosNativeAssetIdentifier(
        network="mainnet",
    )


def _create_evm_asset_identifier(asset: Asset) -> _AssetIdentifier:
    if asset.token and asset.token.token_type is EvmTokenType.ERC20:
        return _EvmErc20AssetIdentifier(
            blockchain=asset.blockchain.value,
            network="mainnet",
            contract_address=asset.token.token_id,
        )

    return _EvmNativeAssetIdentifier(
        blockchain=asset.blockchain.value,
        network="mainnet",
    )


_ASSET_IDENTIFIER_FACTORY_BY_BLOCKCHAIN: dict[
    Blockchain,
    Callable[[Asset], _AssetIdentifier],
] = {
    Blockchain.APTOS: _create_aptos_asset_identifier,
    Blockchain.ARBITRUM: _create_evm_asset_identifier,
    Blockchain.ETHEREUM: _create_evm_asset_identifier,
}


@dataclass(frozen=True)
class _EvmSignatureRequest(_RequestFactory):
    path: ClassVar[str] = "/transactions"
    method: ClassVar[str] = "POST"
    vault_id: str
    blockchain: Blockchain
    network: str
    message: str

    def _get_body(self) -> Json:
        return {
            "vault_id": self.vault_id,
            "type": "evm_message",
            "details": {
                "type": "typed_message_type",
                "chain": f"{self.blockchain.value}_{self.network}",
                "raw_data": self.message,
            },
        }


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
        vault_id: str,
        amount: Decimal,
        destination_address: str,
        asset: Asset,
        idempotence_id: UUID | None = None,
    ) -> Request:
        factory_class = _REQUEST_FACTORY_BY_BLOCKCHAIN[asset.blockchain]
        asset_identifier = self._create_asset_identifier(asset)
        factory = factory_class(
            asset_identifier=asset_identifier,
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

    def _create_asset_identifier(self, asset: Asset) -> _AssetIdentifier:
        factory = _ASSET_IDENTIFIER_FACTORY_BY_BLOCKCHAIN[asset.blockchain]
        return factory(asset)

    def create_signature_request(
        self,
        message: str,
        vault_id: str,
        blockchain: Blockchain,
        network: str = "mainnet",
    ) -> Request:
        if blockchain not in EVM_BLOCKCHAINS:
            raise BlockchainNotImplementedError(blockchain)

        return _EvmSignatureRequest(
            message=message,
            vault_id=vault_id,
            blockchain=blockchain,
            network=network,
        ).build(
            base_url=self.base_url,
            auth_token=self.auth_token,
            idempotence_id=None,
            signing_key=self._signing_key,
        )
