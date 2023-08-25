"""Badge provider interface."""

from abc import ABC, abstractmethod


class BaseAssertion(ABC):
    """Base assertion class."""

    @abstractmethod
    def __init__(self, api_client):
        """Initialize the assertion class."""

    @abstractmethod
    def read(self, assertion, query=None):
        """Read an assertion."""


class BaseBadge(ABC):
    """Base badge class."""

    @abstractmethod
    def __init__(self, api_client):
        """Initialize the badge class."""

    @abstractmethod
    def create(self, badge):
        """Create a badge."""

    @abstractmethod
    def read(self, badge=None, query=None):
        """Read a badge."""

    @abstractmethod
    def update(self, badge):
        """Update a badge."""

    @abstractmethod
    def delete(self, badge=None):
        """Delete a badge."""

    @abstractmethod
    def issue(self, badge, issue):
        """Issue a badge."""

    @abstractmethod
    def revoke(self, revokation):
        """Revoke one or more badges."""


class BaseProvider(ABC):
    """Base provider class."""

    code: str = "BPC"
    name: str = "Base provider"

    @abstractmethod
    def __init__(self, *args, **kwargs):
        """Initialize the API client, the badge and the assertion classes."""
