"""Badge provider interface."""

from abc import ABC, abstractmethod


class BaseAssertion(ABC):
    """Base assertion class."""

    @abstractmethod
    def __init__(self, api_client):
        """Initialize the assertion class."""

    @abstractmethod
    async def read(self, event_id, query=None):
        """Read an assertion."""


class BaseBadge(ABC):
    """Base badge class."""

    @abstractmethod
    def __init__(self, api_client):
        """Initialize the badge class."""

    @abstractmethod
    async def create(self, badge):
        """Create a badge."""

    @abstractmethod
    async def read(self, badge_id=None, query=None):
        """Read a badge."""

    @abstractmethod
    async def update(self, badge):
        """Update a badge."""

    @abstractmethod
    async def delete(self, badge_id=None):
        """Delete a badge."""

    @abstractmethod
    async def issue(self, badge_id, issue):
        """Issue a badge."""

    @abstractmethod
    async def revoke(self, revocation):
        """Revoke one or more badges."""


class BaseProvider(ABC):
    """Base provider class."""

    code: str = "BPC"
    name: str = "Base provider"

    @abstractmethod
    def __init__(self, *args, **kwargs):
        """Initialize the API client, the badge and the assertion classes."""
