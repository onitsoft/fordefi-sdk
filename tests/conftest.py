import os
from pathlib import Path

import pytest
import pytest_httpserver

from fordefi import Fordefi
from tests import helpers

FAKE_FORDEFI_PRIVATE_KEY = helpers.generate_private_key()


def load_env_vars(env_file: str = ".env") -> None:
    with Path(env_file).open() as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                key, value = line.strip().split("=", 1)
                os.environ[key] = value


load_env_vars()


@pytest.fixture(scope="module")
def vcr_config() -> dict[str, bool | list[str]]:
    return {
        "filter_headers": [
            "authorization",
            "x-signature",
            "x-timestamp",
            "X-API-Key",
        ],
        "ignore_localhost": True,
    }


@pytest.fixture(name="is_live_vcr_session")
def is_live_vcr_session_fixture(request: pytest.FixtureRequest) -> bool:
    recording_disabled = request.config.getoption("--disable-recording")
    record_mode = request.config.getoption("--record-mode")

    if recording_disabled:
        return True

    return record_mode in {"rewrite", "new_episodes", "all", "once"}


def _get_config(env_var: str, default: str | None = None) -> str:
    value = os.getenv(env_var, default)

    if not value:
        pytest.skip(f"{env_var} not defined")

    return value


@pytest.fixture(name="fordefi_api_key")
def fordefi_api_key_fixture(is_live_vcr_session: bool) -> str:
    default = None

    if not is_live_vcr_session:
        default = "fake-api-key"

    return _get_config("FORDEFI_API_KEY", default)


@pytest.fixture(name="fordefi_private_key")
def fordefi_private_key_fixture(is_live_vcr_session: bool) -> str:
    default = None

    if not is_live_vcr_session:
        default = FAKE_FORDEFI_PRIVATE_KEY

    return _get_config("FORDEFI_PRIVATE_KEY", default)


@pytest.fixture(name="fordefi")
def fordefi_fixture(fordefi_api_key: str, fordefi_private_key: str) -> Fordefi:
    return Fordefi(
        api_key=fordefi_api_key,
        private_key=fordefi_private_key,
    )


@pytest.fixture
def httpserver_fordefi(
    httpserver: pytest_httpserver.HTTPServer,
    fordefi_api_key: str,
    fordefi_private_key: str,
) -> Fordefi:
    return Fordefi(
        api_key=fordefi_api_key,
        private_key=fordefi_private_key,
        base_url=httpserver.url_for(""),
    )
