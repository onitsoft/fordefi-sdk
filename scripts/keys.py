#!/usr/bin/env python
from pathlib import Path

import pyperclip
import typer
from ecdsa.keys import os

from fordefi.keys import (
    decode_private_key,
    encode_private_key,
    encode_public_key_as_striped_pem,
    generate_private_key,
    get_public_key,
)

FORDEFI_PRIVATE_KEY_ENV_VAR = "FORDEFI_PRIVATE_KEY"


app = typer.Typer()


@app.command()
def gen_keys(env_file: Path = Path(".env")) -> None:
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    base64_private_key = encode_private_key(private_key)
    public_key_pem = encode_public_key_as_striped_pem(public_key)

    with env_file.open("a") as file:
        file.write(f'\n{FORDEFI_PRIVATE_KEY_ENV_VAR}="{base64_private_key}"\n')

    typer.echo(f"Appended {FORDEFI_PRIVATE_KEY_ENV_VAR} to {env_file}")

    typer.echo(f"Public key:\n {public_key_pem}")

    try:  # pragma: no cover
        pyperclip.copy(public_key_pem)
        typer.echo("Copied public key to clipboard")

    except pyperclip.PyperclipException:  # pragma: no cover
        typer.echo("Could not copy public key to clipboard", err=True)


@app.command()
def get_pk() -> None:
    encoded_private_key = os.environ.get(FORDEFI_PRIVATE_KEY_ENV_VAR)

    if not encoded_private_key:
        typer.echo(f"Environment variable {FORDEFI_PRIVATE_KEY_ENV_VAR} not set")
        raise typer.Exit(code=1)

    private_key = decode_private_key(encoded_private_key)
    public_key = get_public_key(private_key)
    public_key_pem = encode_public_key_as_striped_pem(public_key)
    typer.echo(public_key_pem)

    try:  # pragma: no cover
        pyperclip.copy(public_key_pem)
        typer.echo("Copied public key to clipboard")

    except pyperclip.PyperclipException:  # pragma: no cover
        typer.echo("Could not copy public key to clipboard", err=True)


if __name__ == "__main__":
    app()
