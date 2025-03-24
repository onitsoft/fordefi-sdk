import base64
import datetime
import hashlib
import json
import logging
from collections.abc import Iterable
from decimal import Decimal
from http import HTTPStatus
from typing import Literal, TypedDict, cast, overload

import ecdsa
import ecdsa.util
import requests
from pydantic import UUID4
from typing_extensions import deprecated

from fordefi.evmtypes import EIP712TypedData, SignedMessage

from .assets import (
    ASSET_IDENTIFIER_BY_SYMBOL,
    AssetIdentifier,
    get_transfer_asset_identifier,
)
from .httptypes import Json, JsonDict, QueryParams
from .logs import request_repr
from .requests_factory import Asset, Blockchain, RequestFactory

logger = logging.getLogger(__name__)

PAGE_SIZE = 50  # must be <= 100


class Page(TypedDict):
    total: int
    page: int
    size: int


class ClientError(Exception):
    def __init__(self, status_code: int, content: str) -> None:
        self.status_code = status_code
        self.content = content
        super().__init__(f"Client error: {status_code} {content}")


class Fordefi:
    def __init__(
        self,
        api_key: str,
        private_key: str,
        base_url: str = "https://api.fordefi.com/api/v1",
        page_size: int = PAGE_SIZE,
        timeout: int = 30,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._signing_key = ecdsa.SigningKey.from_string(
            base64.b64decode(private_key),
            curve=ecdsa.curves.NIST256p,
        )
        self._request_factory = RequestFactory(
            base_url=base_url,
            auth_token=api_key,
            signing_key=self._signing_key,
            timeout=timeout,
        )
        self.page_size = page_size
        self.timeout = timeout

    def create_vault(self, vault: Json) -> JsonDict:
        endpoint = "/vaults"
        return self._request("POST", endpoint, data=vault)

    def list_vaults(self) -> Iterable[JsonDict]:
        endpoint = "/vaults"
        return self._get_pages(endpoint, "vaults")

    def get_vault(self, vault_id: str) -> Json:
        endpoint = f"/vaults/{vault_id}"
        return self._request("GET", endpoint)

    def get_assets(self, vault_id: str) -> Iterable[JsonDict]:
        endpoint = f"/vaults/{vault_id}/assets"
        return self._get_pages(endpoint, "owned_assets")

    def list_assets(self, vault_ids: list[str] | None = None) -> Iterable[JsonDict]:
        endpoint = "/assets/owned-assets"
        params: QueryParams | None = None

        if vault_ids:
            params = {"vault_ids": vault_ids}

        return self._get_pages(endpoint, "owned_assets", params=params)

    def get_transaction(self, transaction_id: str) -> JsonDict:
        endpoint = f"/transactions/{transaction_id}"
        return self._request("GET", endpoint)

    def list_transactions(
        self,
        vault_ids: list[str] | None = None,
        direction: Literal["incoming", "outgoing"] | None = None,
    ) -> Iterable[JsonDict]:
        path = "/transactions"

        params: QueryParams = {}

        if vault_ids:
            params["vault_ids"] = vault_ids

        if direction:
            params["direction"] = direction

        return self._get_pages(
            endpoint=path,
            items_property="transactions",
            params=params,
        )

    @deprecated("Use asset (Asset) argument instead of asset_symbol (str).")
    @overload
    def create_transfer(
        self,
        vault_id: str,
        destination_address: str,
        amount: Decimal,
        idempotence_client_id: UUID4,
        asset: None = None,
        asset_symbol: Literal["APT", "ETH", "DSOL"] = "APT",
    ) -> JsonDict: ...

    @overload
    def create_transfer(
        self,
        vault_id: str,
        destination_address: str,
        amount: Decimal,
        idempotence_client_id: UUID4,
        asset: Asset,
        asset_symbol: None = None,
    ) -> JsonDict: ...

    def create_transfer(  # noqa: PLR0913
        self,
        vault_id: str,
        destination_address: str,
        amount: Decimal,
        idempotence_client_id: UUID4,
        asset: Asset | None = None,
        asset_symbol: str | None = None,
    ) -> JsonDict:
        if amount % 1 != 0:
            msg = "Amount must be an integer representing the amount in smallest unit."
            raise ValueError(msg)

        if asset_symbol is not None and asset_symbol not in ASSET_IDENTIFIER_BY_SYMBOL:
            supported_assets = ", ".join(ASSET_IDENTIFIER_BY_SYMBOL.keys())
            msg = f"""Deprecated asset_symbol (str) argument only supports:
                      {supported_assets}."""
            raise ValueError(msg)

        if asset_symbol is not None:
            return self._create_transfer_by_asset_symbol(
                vault_id,
                destination_address,
                amount,
                idempotence_client_id,
                asset_symbol,
            )

        if asset is not None:
            return self._create_transfer_by_blockchain_type(
                vault_id,
                destination_address,
                amount,
                asset,
                idempotence_client_id,
            )

        msg = "Either asset_symbol or blockchain must be provided."
        raise ValueError(msg)

    def _create_transfer_by_blockchain_type(
        self,
        vault_id: str,
        destination_address: str,
        amount: Decimal,
        asset: Asset,
        idempotence_client_id: UUID4,
    ) -> JsonDict:
        request = self._request_factory.create_transfer_request(
            vault_id=vault_id,
            destination_address=destination_address,
            amount=amount,
            asset=asset,
            idempotence_id=idempotence_client_id,
        )
        return cast("JsonDict", self._send_request(request))

    @staticmethod
    def _send_request(request: requests.Request) -> JsonDict:
        prepared_request = request.prepare()

        with requests.Session() as session:
            response = session.send(prepared_request)

            logger.info(
                "Requested to Fordefi: %s",
                request_repr(
                    method=request.method,
                    path=request.url,
                    query_params=request.params,
                    headers=request.headers,
                    body=request.json,
                    sensitive_headers={"Authorization", "x-signature"},
                ),
            )
            logger.info(
                "Fordefi responded: HTTP %s %s",
                response.status_code,
                response.content,
            )

            if (
                response.status_code >= HTTPStatus.BAD_REQUEST
                and response.status_code < HTTPStatus.INTERNAL_SERVER_ERROR
            ):
                raise ClientError(response.status_code, response.content.decode())

            response.raise_for_status()

            return response.json()

    def _create_transfer_by_asset_symbol(
        self,
        vault_id: str,
        destination_address: str,
        amount: Decimal,
        idempotence_client_id: UUID4,
        asset_symbol: str,
    ) -> JsonDict:
        asset_identifier = get_transfer_asset_identifier(asset_symbol)
        transaction = {
            "vault_id": vault_id,
            "type": f"{asset_identifier.type}_transaction",
            "details": self._serialize_transfer_transaction_details(
                asset_identifier,
                destination_address,
                amount,
            ),
        }
        return cast(
            "JsonDict",
            self.create_transaction(
                transaction,
                idempotence_client_id=idempotence_client_id,
            ),
        )

    @staticmethod
    def _serialize_transfer_transaction_details(
        asset_identifier: AssetIdentifier,
        destination_address: str,
        amount: Decimal,
    ) -> Json:
        details = {
            "type": f"{asset_identifier.type}_transfer",
            "to": asset_identifier.default_destination_serializer(destination_address),
            "value": {
                "type": "value",
                "value": str(amount),
            },
            "asset_identifier": Fordefi._serialize_asset_identifier(asset_identifier),
        }

        if asset_identifier.default_gas is not None:
            details["gas"] = asset_identifier.default_gas

        if asset_identifier.default_gas_config is not None:
            details["gas_config"] = asset_identifier.default_gas_config

        return details

    @staticmethod
    def _serialize_asset_identifier(
        asset_identifier: AssetIdentifier,
    ) -> Json:
        return {
            "type": asset_identifier.type,
            "details": {
                "type": asset_identifier.subtype,
                "chain": asset_identifier.chain,
            },
        }

    def create_transaction(
        self,
        transaction: JsonDict,
        idempotence_client_id: UUID4,
    ) -> JsonDict:
        endpoint = "/transactions"
        signer_type = transaction.get("signer_type")

        if not signer_type:
            transaction["signer_type"] = "api_signer"

        if transaction["signer_type"] != "api_signer":
            msg = "signer_type must be 'api_signer'"
            raise ValueError(msg)

        return self._request(
            "POST",
            endpoint,
            sign=True,
            data=transaction,
            idempotence_id=idempotence_client_id,
        )

    def set_contract_allowance(
        self,
        vault_id,
        call_data,
        asset_symbol,
        spender,
        idempotence_client_id: UUID4,
    ):
        asset_identifier = get_transfer_asset_identifier(asset_symbol)
        transaction = {
            "vault_id": vault_id,
            "signer_type": "api_signer",
            "type": "evm_transaction",
            "details": self._serialize_token_approve_details(
                asset_identifier, call_data, spender
            ),
        }

        return cast(
            "JsonDict",
            self.create_transaction(
                transaction,
                idempotence_client_id=idempotence_client_id,
            ),
        )


    @staticmethod
    def _serialize_token_approve_details(
        asset_identifier: AssetIdentifier,
            call_data: JsonDict,
            spender: str,
    ) -> Json:
        return {
            "type": f"{asset_identifier.type}_raw_transaction",
            "chain": asset_identifier.chain,
            "gas": asset_identifier.default_gas,
            "to": spender,
            "value": "0",
            "data": {"type": "hex", "hex_data": call_data},
        }

    def _get_pages(
        self,
        endpoint: str,
        items_property: str,
        params: QueryParams | None = None,
    ) -> Iterable[JsonDict]:
        if not params:
            params = {}

        page = 1
        last_page = False

        while not last_page:
            params["page"] = page
            params["size"] = self.page_size
            content = self._request(
                method="GET",
                endpoint=endpoint,
                params=params,
            )
            page_content = cast("Page", content)
            total_items = page_content["total"]
            last_page = page * self.page_size >= total_items
            yield from page_content[items_property]
            page += 1

    def _request(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        params: QueryParams | None = None,
        data: Json | None = None,
        sign: bool = False,  # noqa: FBT001 FBT002
        idempotence_id: UUID4 | None = None,
    ) -> JsonDict:
        if data is None:
            data = {}

        url = f"{self._base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        if idempotence_id:
            headers["x-idempotence-id"] = str(idempotence_id)

        if sign:
            headers = {
                **headers,
                **self._signature(endpoint, data),
            }

        kwargs = {}

        if data:
            kwargs = {"json": data}

        request = requests.Request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            **kwargs,
        )
        return self._send_request(request)

    def _signature(self, path: str, request_json: Json) -> dict[str, bytes]:
        request_body = json.dumps(request_json)
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%s")
        payload = f"/api/v1{path}|{timestamp}|{request_body}"
        signature = self._signing_key.sign(
            data=payload.encode(),
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_der,
        )
        return {
            "x-signature": base64.b64encode(signature),
            "x-timestamp": timestamp.encode(),
        }

    def create_signature(
        self,
        message: EIP712TypedData,
        blockchain: Blockchain,
        vault_id: str,
    ) -> JsonDict:
        request = self._request_factory.create_signature_request(
            message=message,
            blockchain=blockchain,
            vault_id=vault_id,
        )
        return cast("JsonDict", self._send_request(request))

    def sign_message(
        self,
        message: EIP712TypedData,
        blockchain: Blockchain,
        vault_id: str,
    ) -> SignedMessage:
        response = self.create_signature(
            message=message,
            blockchain=blockchain,
            vault_id=vault_id,
        )
        return self._parse_signature(response)

    @staticmethod
    def _parse_signature(response: JsonDict) -> SignedMessage:
        signatures = cast("str", response["signatures"])
        raw_signature = base64.b64decode(signatures[0])
        r = int.from_bytes(raw_signature[0:32], byteorder="big")
        s = int.from_bytes(raw_signature[32:64], byteorder="big")
        v = int(raw_signature[-1])  # 27 or 28
        return SignedMessage(r=r, s=s, v=v)
