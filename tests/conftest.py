import os

import pytest
import pytest_httpserver

from fordefi import Fordefi
from tests import helpers

FAKE_FORDEFI_PRIVATE_KEY = helpers.generate_private_key()


@pytest.fixture(name="is_live_vcr_session")
def is_live_vcr_session_fixture(request: pytest.FixtureRequest) -> bool:
    recording_disabled = request.config.getoption("--disable-recording")
    record_mode = request.config.getoption("--record-mode")

    if recording_disabled:
        return True

    return record_mode in {"rewrite", "new_episodes", "all"}


def _get_config(env_var: str, default: str | None = None) -> str:
    value = os.getenv(env_var, default)

    if not value:
        pytest.skip(f"{env_var} not defined")

    return value


@pytest.fixture(name="fordefi")
def fordefi_fixture() -> Fordefi:
    return Fordefi(
        api_key=_get_config("FORDEFI_API_KEY", "fake-api-key"),
        private_key=_get_config("FORDEFI_PRIVATE_KEY", FAKE_FORDEFI_PRIVATE_KEY),
    )


@pytest.fixture
def httpserver_fordefi(httpserver: pytest_httpserver.HTTPServer) -> Fordefi:
    return Fordefi(
        api_key=_get_config("FORDEFI_API_KEY", "fake-api-key"),
        private_key=_get_config("FORDEFI_PRIVATE_KEY", FAKE_FORDEFI_PRIVATE_KEY),
        base_url=httpserver.url_for(""),
    )
