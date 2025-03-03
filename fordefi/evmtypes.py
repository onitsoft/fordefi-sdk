from typing import NamedTuple

from eth_pydantic_types import Address, HexBytes
from pydantic import BaseModel, ConfigDict, JsonValue, ValidationInfo, field_validator
from pydantic.alias_generators import to_camel


class EIP712Domain(BaseModel):
    """Represents the EIP-712 domain separator parameters"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    version: str
    chain_id: int
    verifying_contract: Address
    salt: HexBytes | None = None


class TypeField(BaseModel):
    """Represents a single field in a type definition"""

    name: str
    type: str


class EIP712TypedData(BaseModel):
    """Represents the complete EIP-712 TypedData structure"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    types: dict[str, list[TypeField]]  # Maps type names to their field definitions
    domain: EIP712Domain  # Domain separator parameters
    primary_type: str  # The primary type being signed
    message: dict[str, JsonValue]  # The actual message to be signed

    @field_validator("types")
    @classmethod
    def validate_types(
        cls,
        v: dict[str, list[TypeField]],
    ) -> dict[str, list[TypeField]]:
        if "EIP712Domain" not in set(v.keys()):
            return {
                **v,
                "EIP712Domain": [
                    TypeField(name="name", type="string"),
                    TypeField(name="version", type="string"),
                    TypeField(name="chainId", type="uint256"),
                    TypeField(name="verifyingContract", type="address"),
                ],
            }

        return v

    @field_validator("primary_type")
    @classmethod
    def validate_primary_type(cls, v: str, info: ValidationInfo) -> str:
        msg = f"primaryType '{v}' must be defined in types"

        if v not in info.data.get("types", {}):
            raise ValueError(msg)

        return v


class SignedMessage(NamedTuple):
    r: int
    s: int
    v: int
