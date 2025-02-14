from enum import StrEnum

import pydantic


class Direction(StrEnum):
    incoming = "incoming"
    outgoing = "outgoing"


class Event(pydantic.BaseModel):
    transaction_id: str
    direction: Direction


class Webhook(pydantic.BaseModel):
    event: Event
    event_id: str
