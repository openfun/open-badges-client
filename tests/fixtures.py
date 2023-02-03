"""Pytest fixtures."""

import pytest
import responses

from obc.providers.obf import OBFAPIClient


@pytest.fixture
def mocked_responses():
    """Use the responses module to mock Open Badge provider API responses."""
    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        yield rsps
    # pylint: disable=protected-access
    OBFAPIClient._access_token.cache_clear()
