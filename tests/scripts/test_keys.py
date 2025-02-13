from pathlib import Path

import pytest
from typer.testing import CliRunner

from fordefi.keys import encode_private_key, generate_private_key
from scripts.keys import FORDEFI_PRIVATE_KEY_ENV_VAR, app

runner = CliRunner()


def test_gen_keys(tmp_path: Path):
    env_file_path = tmp_path / ".env"
    result = runner.invoke(app, ["gen-keys", "--env-file", str(env_file_path)])

    assert result.exit_code == 0, result.output
    assert FORDEFI_PRIVATE_KEY_ENV_VAR in env_file_path.read_text()


def test_get_pk__mising_env_ver(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(FORDEFI_PRIVATE_KEY_ENV_VAR, raising=False)

    result = runner.invoke(app, ["get-pk"])

    assert result.exit_code == 1, result.output
    assert (
        f"Environment variable {FORDEFI_PRIVATE_KEY_ENV_VAR} not set" in result.output
    )


def test_get_pk_succeeds_when_env_var_is_set(monkeypatch: pytest.MonkeyPatch):
    private_key = generate_private_key()
    encoded_private_key = encode_private_key(private_key)
    monkeypatch.setenv(FORDEFI_PRIVATE_KEY_ENV_VAR, encoded_private_key)

    result = runner.invoke(app, ["get-pk"])

    assert result.exit_code == 0, result.output
    assert "-----BEGIN PUBLIC KEY-----" in result.output
