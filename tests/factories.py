import random
from typing import Any

from eth_pydantic_types import HexBytes
from hexbytes.main import HexBytes as BaseHexBytes
from polyfactory.factories.pydantic_factory import ModelFactory

from fordefi.evmtypes import EIP712Domain, EIP712TypedData, TypeField
from fordefi.httptypes import JsonValue


def _hexbytes_provider() -> BaseHexBytes:
    random_bytes = bytes(
        random.getrandbits(8) for _ in range(32)
    )  # Example: 32 random bytes
    return HexBytes(random_bytes)


class EIP712DomainFactory(ModelFactory[EIP712Domain]):
    __model__ = EIP712Domain

    @classmethod
    def get_provider_map(cls) -> dict[type, Any]:
        providers_map = super().get_provider_map()

        return {
            HexBytes: _hexbytes_provider,
            **providers_map,
        }


class EIP712TypedDataFactory(ModelFactory[EIP712TypedData]):
    __model__ = EIP712TypedData

    @classmethod
    def types(cls) -> dict[str, list[TypeField]]:
        return {
            "Message": [
                TypeField.model_validate({"name": "from", "type": "string"}),
                TypeField.model_validate({"name": "to", "type": "string"}),
                TypeField.model_validate({"name": "contents", "type": "string"}),
            ],
        }

    @classmethod
    def message(cls) -> dict[str, JsonValue]:
        return {
            "from": "0x5409ed021d9299bf6814279a6a1411a7e866a631",
            "to": "0x6ecbe1db9ef729cbe972c83fb886247691f41e9e",
            "contents": "Hello, Bob!",
        }

    @classmethod
    def primary_type(cls) -> str:
        return "Message"

    @classmethod
    def get_provider_map(cls) -> dict[type, Any]:
        providers_map = super().get_provider_map()

        return {
            HexBytes: _hexbytes_provider,
            **providers_map,
        }
