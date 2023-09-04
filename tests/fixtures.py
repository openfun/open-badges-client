"""Pytest fixtures."""

import pytest

from obc.providers.obf import OBFAPIClient


@pytest.fixture
def anyio_backend():
    """Select asyncio backend for pytest anyio."""
    return "asyncio"


@pytest.fixture
def mocked_responses(httpx_mock):
    """Use the responses module to mock Open Badge provider API responses."""
    yield httpx_mock
    # pylint: disable=protected-access
    OBFAPIClient._access_token.cache_clear()
