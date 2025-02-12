import base64
import datetime
import gzip
import hashlib
import json
import logging
from decimal import Decimal
from typing import Any, Iterable, Literal, Optional

import ecdsa
import ecdsa.util
import requests
from pydantic import UUID4, Json

from .assets import AssetIdentifier, get_transfer_asset_identifier
from .logs import request_repr

logger = logging.getLogger(__name__)

PAGE_SIZE = 50  # must be <= 100


class BadRequestError(Exception):
    def __init__(self, response_json: dict[str, str]) -> None:
        detail = response_json["detail"]
        super().__init__(detail)


class Fordefi:
    def __init__(
        self,
        api_key: str,
        private_key: str,
        base_url: str = "https://api.fordefi.com/api/v1",
        page_size: int = PAGE_SIZE,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._signing_key = ecdsa.SigningKey.from_string(
            base64.b64decode(private_key),
            curve=ecdsa.curves.NIST256p,
        )
        self.page_size = page_size

    def create_vault(self, vault: Json) -> Json:
        endpoint = "/vaults"
        vault_data = self._request("POST", endpoint, data=vault)
        return vault_data

    def list_vaults(self) -> Iterable[Json]:
        endpoint = "/vaults"
        return self._get_pages(endpoint, "vaults")

    def get_vault(self, vault_id: str) -> Json:
        endpoint = f"/vaults/{vault_id}"
        vault = self._request("GET", endpoint)
        return vault

    def get_assets(self, vault_id: str) -> Iterable[Json]:
        endpoint = f"/vaults/{vault_id}/assets"
        return self._get_pages(endpoint, "owned_assets")

    def list_assets(self, vault_ids: Optional[list[str]] = None) -> Iterable[Json]:
        endpoint = "/assets/owned-assets"
        params = {"vault_ids": vault_ids}
        return self._get_pages(endpoint, "owned_assets", params=params)

    def get_transaction(self, transaction_id: str) -> Json:
        endpoint = f"/transactions/{transaction_id}"
        transaction_data = self._request("GET", endpoint)
        return transaction_data

    def list_transactions(
        self,
        vault_ids: Optional[list[str]] = None,
        direction: Literal["incoming"] | Literal["outgoing"] | None = None,
    ) -> Iterable[Json]:
        path = "/transactions"

        params: dict[str, str | list[str]] = {}

        if vault_ids:
            params["vault_ids"] = vault_ids

        if direction:
            params["direction"] = direction

        return self._get_pages(
            endpoint=path,
            items_property="transactions",
            params=params,
        )

    def create_transfer(
        self,
        vault_id: str,
        asset_symbol: str,
        destination_address: str,
        amount: Decimal,
        idempotence_client_id: UUID4,
    ) -> Json:
        if amount % 1 != 0:
            raise ValueError(
                "Amount must be an integer representing the amount in smallest unit."
            )

        asset_identifier = get_transfer_asset_identifier(asset_symbol)
        transaction = {
            "vault_id": vault_id,
            "type": f"{asset_identifier.type}_transaction",
            "details": self._serialize_transfer_transaction_details(
                asset_identifier, destination_address, amount
            ),
        }
        return self.create_transaction(
            transaction, idempotence_client_id=idempotence_client_id
        )

    @staticmethod
    def _serialize_transfer_transaction_details(
        asset_identifier: AssetIdentifier, destination_address: str, amount: Decimal
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
        transaction: Json,
        idempotence_client_id: UUID4,
    ) -> Json:
        endpoint = "/transactions"
        signer_type = transaction.get("signer_type")

        if not signer_type:
            transaction["signer_type"] = "api_signer"

        if transaction["signer_type"] != "api_signer":
            raise ValueError("signer_type must be 'api_signer'")

        transaction_data = self._request(
            "POST",
            endpoint,
            sign=True,
            data=transaction,
            idempotence_id=idempotence_client_id,
        )
        return transaction_data

    def _get_pages(
        self,
        endpoint: str,
        items_property: str,
        params: Optional[dict[str, Any]] = None,
    ) -> Iterable[Json]:
        if not params:
            params = {}

        page = 1
        last_page = False

        while not last_page:
            params["page"] = page
            params["size"] = self.page_size
            page_content = self._request(
                method="GET",
                endpoint=endpoint,
                params=params,
            )
            total_items = page_content["total"]
            last_page = page * self.page_size >= total_items
            yield from page_content[items_property]
            page += 1

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        sign: bool = False,
        idempotence_id: Optional[UUID4] = None,
    ) -> Any:
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

        response = requests.request(
            method, url, headers=headers, params=params, json=data
        )
        logger.info(
            "Requested to Fordefi: %s",
            request_repr(
                method=method,
                path=endpoint,
                query_params=params,
                headers=headers,
                body=data,
                sensitive_headers={"Authorization", "x-signature"},
            ),
        )
        logger.info(
            "Fordefi responded: HTTP %s %s", response.status_code, response.content
        )

        if response.headers.get("Content-Encoding") == "gzip":
            json_content = json.loads(gzip.decompress(response.content).decode("utf-8"))

        else:
            json_content = response.json()

        if response.status_code == 400:
            raise BadRequestError(json_content)

        response.raise_for_status()
        return json_content

    def _signature(self, path: str, request_json: Json) -> dict[str, bytes]:
        request_body = json.dumps(request_json)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%s")
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
