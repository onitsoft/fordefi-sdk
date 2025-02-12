import json
import os

import typer
from pydantic import Json

from .client import Fordefi

app = typer.Typer()


def get_client() -> Fordefi:
    return Fordefi(
        api_key=os.environ["FORDEFI_API_KEY"],
        private_key=os.environ["FORDEFI_PRIVATE_KEY"],
    )


def echo_response(data: Json) -> None:
    typer.echo(json.dumps(data, indent=4))


@app.command()
def get_transaction(transaction_id: str):
    response = get_client().get_transaction(transaction_id)
    echo_response(response)


if __name__ == "__main__":
    typer.run(get_transaction)
