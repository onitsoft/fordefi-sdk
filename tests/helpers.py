import base64
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import ContextManager, TypeVar

import pytest
from _pytest.python_api import RaisesContext

E = TypeVar("E", bound=BaseException)


@contextmanager
def _noop_context_manager() -> Generator[None, None, None]:
    yield


def raises(
    error: type[E] | None,
) -> RaisesContext[E] | ContextManager[None]:
    if error is None:
        return _noop_context_manager()

    return pytest.raises(error)


def generate_private_key():
    private_key_bytes = os.urandom(32)
    private_key_base64 = base64.b64encode(private_key_bytes).decode("utf-8")
    return private_key_base64
