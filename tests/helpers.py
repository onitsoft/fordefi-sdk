import base64
import os
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from typing import TypeVar

import pytest
from _pytest.python_api import RaisesContext

E = TypeVar("E", bound=BaseException)


@contextmanager
def _noop_context_manager() -> Generator[None, None, None]:
    yield


def raises(
    error: type[E] | None,
) -> RaisesContext[E] | AbstractContextManager[None]:
    if error is None:
        return _noop_context_manager()

    return pytest.raises(error)


def generate_private_key() -> str:
    private_key_bytes = os.urandom(32)
    return base64.b64encode(private_key_bytes).decode("utf-8")
