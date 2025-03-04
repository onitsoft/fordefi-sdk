import base64
import hashlib

import ecdsa
from ecdsa.util import sigdecode_der

from .schemas import Webhook


class InvalidSignatureError(Exception):
    pass


class FordefiWebooksSignatureValidator:
    def __init__(self, public_key: str) -> None:
        self.public_key = ecdsa.VerifyingKey.from_pem(public_key)

    def is_valid(self, data: bytes, signature: str | None) -> bool:
        if signature is None:
            return False

        try:
            # https://docs.fordefi.com/reference/webhooks#validate-a-webhook
            self.public_key.verify(
                signature=base64.b64decode(signature),
                data=data,
                hashfunc=hashlib.sha256,
                sigdecode=sigdecode_der,
            )

        except ecdsa.keys.BadSignatureError:
            return False

        else:
            return True


class FordefiWebhooksParser:
    SIGNATURE_HEADER = "X-Signature"

    def __init__(self, signature_validator: FordefiWebooksSignatureValidator) -> None:
        self._signature_validator = signature_validator

    def parse_webhook(self, data: bytes, signature: str | None) -> Webhook:
        if not self._signature_validator.is_valid(data, signature):
            raise InvalidSignatureError

        return Webhook.model_validate_json(data)
