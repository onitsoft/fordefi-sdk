import base64
import operator
import os
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from typing import NamedTuple, TypeVar

import pytest
from _pytest.python_api import RaisesContext

E = TypeVar("E", bound=BaseException)


TestFunction = Callable[..., None]


class BaseTestCase(NamedTuple):
    name: str


def cases(
    name_position: int,
    *cases: NamedTuple,
) -> Callable[[TestFunction], TestFunction]:
    def wrapper(test_function: TestFunction) -> TestFunction:
        return pytest.mark.parametrize(
            argnames="case",
            argvalues=list(cases),
            ids=operator.itemgetter(name_position),
        )(test_function)

    return wrapper


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
