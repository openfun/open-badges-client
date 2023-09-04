"""OpenBadgeFactory provider."""

import json
import logging
import re
from collections.abc import Iterable
from datetime import datetime
from functools import cache
from json import JSONDecodeError
from typing import Literal, Optional
from urllib.parse import urljoin

import httpx
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
    ValidationError,
    field_serializer,
    model_validator,
)

from ..exceptions import AuthenticationError, BadgeProviderError
from .base import BaseAssertion, BaseBadge, BaseProvider

logger = logging.getLogger(__name__)


class OAuth2AccessToken(httpx.Auth):
    """Add OAuth2 access token to HTTP API requests header."""

    def __init__(self, access_token):
        """Instantiate requests Auth object with generated access_token."""
        self.access_token = access_token

    def auth_flow(self, request):
        """Modify and return the request."""
        request.headers["Authorization"] = f"Bearer {self.access_token}"
        yield request


class OBFAPIClient(httpx.AsyncClient):
    """Open Badge Factory API Client."""

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *args,
        raise_for_status: bool = False,
        **kwargs,
    ):
        """Override default httpx.AsyncClient instantiation to handle authentication."""
        super().__init__(*args, **kwargs)

        self.api_root_url: str = "https://openbadgefactory.com"
        self.api_version_prefix: str = "v1"
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.event_hooks = {"response": [self.raise_status]} if raise_for_status else {}
        self.headers = {"Content-Type": "application/json"}
        self.base_url = f"{self.api_root_url}/{self.api_version_prefix}"
        self.auth = self._get_auth

    @staticmethod
    @cache
    def _access_token(
        client_id: str, client_secret: str, api_version_prefix: str, api_root_url: str
    ):
        """Request OAuth2 access token from the API backend.

        We cache this function to avoid regenerating an access token at each
        API request. This access token has a limited validity (e.g. 10h) so we
        try to regenerate it when the API response code is 403 (see the
        `request` overridden method).

        """
        url = f"{api_version_prefix}/client/oauth2/token"
        response = httpx.post(
            urljoin(api_root_url, url),
            json={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=10,
        )
        try:
            json_response = response.json()
        except JSONDecodeError as exc:
            raise AuthenticationError(
                "Invalid response from the OBF server with provided credentials"
            ) from exc

        if "access_token" not in json_response:
            raise AuthenticationError(
                (
                    "Cannot get an access token from the OBF server with provided "
                    "credentials"
                )
            )

        return json_response.get("access_token")

    @property
    def _get_auth(self):
        """Make access token generation dynamic."""
        return OAuth2AccessToken(
            self._access_token(
                self.client_id,
                self.client_secret,
                self.api_version_prefix,
                self.api_root_url,
            )
        )

    async def check_auth(self):
        """Check OBF API credentials using the dedicated endpoint."""
        url = f"/ping/{self.client_id}"
        response = await self.get(url)
        if response.status_code != httpx.codes.OK:
            raise AuthenticationError("Invalid access token for OBF")
        return response

    @classmethod
    def iter_json(cls, response: httpx.Response) -> Iterable:
        """Iterate over JSON lines serialization in API responses.

        When multiple objects are returned by the API, they are streamed as
        JSON lines instead of a JSON list, leading the response.json() method
        to fail as it is expected a valid JSON list instead. We mitigate this
        issue by forcing JSON serialization of each non-empty item in the response.
        """
        try:
            json_response = response.json()
            if isinstance(json_response, list):
                yield from json_response
            else:
                yield json_response
        except JSONDecodeError:
            for line in response.iter_lines():
                if not line:
                    continue
                yield json.loads(line)

    @staticmethod
    async def raise_status(response):
        """Event hook to raise for status if chosen."""
        await response.raise_for_status()

    # pylint: disable=arguments-differ
    async def request(self, method, url, **kwargs):
        """Make OBF API usage more developer-friendly.

        - Automatically add the API root URL so that we can focus on the endpoints
        - Automatically renew access token when expired
        """
        url = urljoin(self.api_root_url, f"{self.api_version_prefix}/{url}")
        response = await super().request(method, url, **kwargs)

        # Try to regenerate the access token in case of 403 response
        if response.status_code == httpx.codes.FORBIDDEN:
            # Clear cached property and force access token update
            self._access_token.cache_clear()
            self.auth = self._get_auth
            # Give it another try
            return await super().request(method, url, **kwargs)

        return response


class Badge(BaseModel):
    """Open Badge Factory Badge Model."""

    id: Optional[str] = None
    name: str
    description: str
    draft: bool = False
    image: Optional[str] = None
    css: Optional[str] = None
    criteria_html: Optional[str] = None
    email_subject: Optional[str] = None
    email_body: Optional[str] = None
    email_link_text: Optional[str] = None
    email_footer: Optional[str] = None
    expires: Optional[int] = None
    tags: Optional[list[str]] = None
    metadata: Optional[dict] = None
    is_created: bool = False

    @model_validator(mode="after")
    def check_id(self) -> "Badge":
        """Created badges (fetched from the API) should have an identifier."""
        id_ = self.id
        is_created = self.is_created

        if is_created and id_ is None:
            raise AssertionError("Created badges should have an `id` field.")

        return self


class BadgeQuery(BaseModel):
    """Open Badge Factory badge query filters."""

    draft: Optional[Literal[0, 1]] = None
    category: Optional[list[str]] = None
    id: Optional[list[str]] = None
    query: Optional[str] = None
    meta: Optional[dict] = None
    external: Optional[Literal[0, 1]] = None

    def params(self):
        """Convert model to OBF badge query parameters."""
        query = self.model_dump(exclude_unset=True)
        if query.get("category", None) is not None:
            query["category"] = "|".join(query.get("category"))
        if query.get("id", None) is not None:
            query["id"] = "|".join(query.get("id"))
        if query.get("meta", None) is not None:
            for key in query["meta"]:
                query[f"meta:{key}"] = query["meta"][key]
            del query["meta"]

        return query


class IssueBadgeOverride(BaseModel):
    """Open Badge Factory issue badge override model."""

    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    criteria: Optional[str] = None
    criteria_add: Optional[str] = None


class BadgeIssue(BaseModel):
    """Open Badge Factory badge issue Model."""

    id: Optional[str] = None
    recipient: list[EmailStr | str]
    expires: Optional[int] = None
    issued_on: Optional[int] = None
    email_subject: Optional[str] = None
    email_body: Optional[str] = None
    email_link_text: Optional[str] = None
    email_footer: Optional[str] = None
    badge_override: Optional[IssueBadgeOverride] = None
    log_entry: Optional[dict] = None
    send_email: Literal[0, 1] = 1
    badge_id: Optional[str] = None
    revoked: Optional[dict] = None
    is_created: bool = False

    @model_validator(mode="after")
    def check_ids(self) -> "BadgeIssue":
        """Badge issues (fetched from the API) should have an id and badge_id."""
        id_ = self.id
        badge_id_ = self.badge_id
        is_created = self.is_created

        if is_created and (id_ is None or badge_id_ is None):
            raise AssertionError(
                "Badge issues should have both an `id` and `badge_id` field."
            )

        return self


class IssueQuery(BaseModel):
    """Open Badge Factory issue event query filters."""

    api_consumer_id: Optional[str] = None
    badge_id: Optional[str] = None
    recipient: Optional[list[EmailStr | str]] = None
    begin: Optional[datetime] = None
    end: Optional[datetime] = None
    order_by: Literal["asc", "desc"] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    count_only: Optional[Literal[0, 1]] = None

    @field_serializer("begin")
    def serialize_begin(
        self, begin: datetime | None, _info
    ):  # pylint:disable =no-self-use
        """Convert begin attribute to timestamp."""
        return int(begin.timestamp()) if begin else None

    @field_serializer("end")
    def serialize_end(self, end: datetime, _info):  # pylint:disable =no-self-use
        """Convert begin attribute to timestamp."""
        return int(end.timestamp()) if end else None

    def params(self):
        """Convert model to OBF badge query parameters."""
        query = self.model_dump(exclude_unset=True)

        if query.get("recipient", None) is not None:
            query["recipient"] = "|".join(query.get("recipient"))
        return query


class BadgeAssertion(BaseModel):
    """Open Badge Factory badge assertion Model."""

    id: Optional[str] = None
    event_id: Optional[str] = None
    image: Optional[HttpUrl] = None
    url: Optional[HttpUrl] = Field(alias="json", default=None)
    pdf: Optional[dict] = None
    recipient: Optional[EmailStr | str] = None
    status: Optional[str] = None


class AssertionQuery(BaseModel):
    """Open Badge Factory assertion query filters."""

    email: Optional[list[str]] = None

    def params(self):
        """Convert model to OBF assertion query parameters."""
        query = self.model_dump(exclude_unset=True)
        if query.get("email", None) is not None:
            query["email"] = "|".join(query.get("email"))

        return query


class BadgeRevokation(BaseModel):
    """Open Badge Factory badge revokation model."""

    event_id: str
    recipient: list[EmailStr]

    def params(self):
        """Convert recipient list to a pipe-separated list."""
        return {"email": "|".join(self.recipient)}


class OBFAssertion(BaseAssertion):
    """Open Badge Factory assertion."""

    def __init__(self, api_client: OBFAPIClient):
        """Initialize with the API client."""
        self.api_client = api_client

    async def read(
        self,
        assertion: BadgeAssertion,
        query: AssertionQuery | None = None,
    ) -> Iterable[BadgeAssertion]:
        """Fetch selected or all assertions from an issuing event.

        Args:
            assertion: the assertion to get (using the event_id)
            query: select assertions and yield them

        If no `query` argument is provided, it yields all assertions from issue.
        """
        if assertion.event_id is None:
            raise BadgeProviderError(
                "We expect an existing issue (the event_id field is required)"
            )

        # Get a selected assertion or assertion list
        params = None
        if query is not None:
            params = query.params()
        response = await self.api_client.get(
            f"/event/{self.api_client.client_id}/{assertion.event_id}/assertion",
            params=params,
        )
        logger.info("Successfully listed assertions with query %s", query)

        for item in self.api_client.iter_json(response):
            try:
                yield BadgeAssertion(**item, event_id=assertion.event_id)
            except ValidationError as err:
                logger.warning(
                    "Cannot yield BadgeAssertion for event_id %s: %s",
                    assertion.event_id,
                    err,
                )
                continue


class OBFEvent:
    """Open Badge Factory event."""

    def __init__(self, api_client: OBFAPIClient):
        """Initialize with the API client."""
        self.api_client = api_client

    async def read(
        self, issue: BadgeIssue | None = None, query: IssueQuery | None = None
    ) -> BadgeIssue:
        """Fetch one, selected or all issuing events.

        Args:
            issue: if provided will only yield selected issue (using the issue id)
            query: select events and yield them

        If no `issue` or `query` argument is provided, it yields all issues.
        """
        # Get a single badge or issue event
        issue_url = f"/event/{self.api_client.client_id}"
        params = None
        if issue is not None:
            if issue.id is None:
                raise BadgeProviderError(
                    "We expect an existing instance (the ID field is required)"
                )
            issue_url += f"/{issue.id}"
        # Get a selected badge or issue event list
        if query is not None:
            params = query.params()

        response = await self.api_client.get(issue_url, params=params)
        logger.info("Successfully listed events for issue %s params %s", issue, params)

        for item in self.api_client.iter_json(response):
            try:
                yield BadgeIssue(**item, is_created=True)
            except ValidationError as err:
                logger.warning(
                    "Cannot yield BadgeIssue with id %s: %s", item["id"], err
                )
                continue


class OBFBadge(BaseBadge):
    """Open Badge Factory badge."""

    def __init__(self, api_client: OBFAPIClient):
        """Initialize the API client."""
        self.api_client = api_client

    async def create(self, badge: Badge) -> Badge:
        """Create a badge."""
        response = await self.api_client.post(
            f"/badge/{self.api_client.client_id}", json=badge.model_dump()
        )
        if not response.status_code == httpx.codes.CREATED:
            raise BadgeProviderError(f"Cannot create badge: {badge}")

        # Get badge ID
        badge_url = response.headers.get("Location")
        badge.id = re.match(
            f"/v1/badge/{self.api_client.client_id}/(.*)", badge_url  # type: ignore
        ).groups()[0]

        # Get created badge
        fetched = await anext(self.read(badge=badge))  # type: ignore
        fetched.is_created = True
        logger.info("Successfully created badge '%s' with ID: %s", badge.name, badge.id)

        return Badge(**fetched.model_dump())

    async def read(
        self, badge: Badge | None = None, query: BadgeQuery | None = None
    ) -> Iterable[Badge]:
        """Read one, selected or all badges.

        Args:
            badge: if provided will only yield selected badge (using the badge id)
            query: select badges and yield them

        If no `badge` or `query` argument is provided, it yields all badges.
        """
        # Get a single badge
        if badge is not None:
            if badge.id is None:
                raise BadgeProviderError(
                    "We expect an existing badge instance (the ID field is required)"
                )
            response = await self.api_client.get(
                f"/badge/{self.api_client.client_id}/{badge.id}"
            )
            logger.info("Successfully get badge with ID: %s", badge.id)

        # Get a selected badge list
        elif query is not None:
            response = await self.api_client.get(
                f"/badge/{self.api_client.client_id}",
                params=query.params(),
            )
            logger.info("Successfully filtered badges from query")

        # Get all badges list
        else:
            response = await self.api_client.get(
                f"/badge/{self.api_client.client_id}",
            )
            logger.info("Successfully listed badges")

        for item in self.api_client.iter_json(response):
            try:
                yield Badge(**item, is_created=True)
            except ValidationError as err:
                logger.warning("Cannot yield Badge with id %s: %s", item["id"], err)
                continue

    async def update(self, badge: Badge) -> Badge:
        """Update a badge."""
        if badge.id is None:
            raise BadgeProviderError(
                "We expect an existing badge instance (the ID field is required)"
            )

        response = await self.api_client.put(
            f"/badge/{self.api_client.client_id}/{badge.id}", json=badge.model_dump()
        )
        if not response.status_code == httpx.codes.NO_CONTENT:
            raise BadgeProviderError(f"Cannot update badge with ID: {badge.id}")
        logger.info("Successfully updated badge '%s' with ID: %s", badge.name, badge.id)

        return badge

    async def delete(self, badge: Badge | None = None) -> None:
        """Delete a badge."""
        # Delete all client badges
        if badge is None:
            logger.critical("Will delete all client badges!")
            response = await self.api_client.delete(
                f"/badge/{self.api_client.client_id}"
            )
            if not response.status_code == httpx.codes.NO_CONTENT:
                raise BadgeProviderError(
                    (
                        "Cannot delete badges for client with ID: "
                        f"{self.api_client.client_id}"
                    )
                )
            logger.info(
                "All badges have been deleted for the '%s' client",
                self.api_client.client_id,
            )
            return

        if badge.id is None:
            raise BadgeProviderError(
                "We expect an existing badge instance (the ID field is required)"
            )

        # Delete a single badge
        logger.critical("Will delete badge '%s' with ID: %s", badge.name, badge.id)
        response = await self.api_client.delete(
            f"/badge/{self.api_client.client_id}/{badge.id}"
        )
        if not response.status_code == httpx.codes.NO_CONTENT:
            raise BadgeProviderError(f"Cannot delete badge with ID: {badge.id}")
        logger.critical("Deleted badge '%s' with ID: %s", badge.name, badge.id)

    async def issue(self, badge: Badge, issue: BadgeIssue) -> BadgeIssue:
        """Issue a badge.

        Note that you cannot issue a badge with a draft status.
        """
        if badge.id is None:
            raise BadgeProviderError(
                "We expect an existing badge instance (the ID field is required)"
            )
        if badge.draft:
            raise BadgeProviderError(
                f"You cannot issue a badge with a draft status (ID: {badge.id})"
            )

        response = await self.api_client.post(
            f"/badge/{self.api_client.client_id}/{badge.id}", json=issue.model_dump()
        )
        if not response.status_code == httpx.codes.CREATED:
            raise BadgeProviderError(f"Cannot issue badge with ID: {badge.id}")

        event_url = response.headers.get("Location")
        issue.id = re.match(
            f"/v1/event/{self.api_client.client_id}/(.*)", event_url  # type: ignore
        ).groups()[0]

        # Get issued badge event
        response = await self.api_client.get(
            f"/event/{self.api_client.client_id}/{issue.id}"
        )
        fetched = BadgeIssue(**response.json())
        fetched.is_created = True
        logger.info(
            "Successfully issued %d badges for badge ID: %s",
            len(issue.recipient),
            badge.id,
        )

        # Return BadgeIssue with added fields
        return badge.model_copy(update=fetched.model_dump())

    async def revoke(self, revokation: BadgeRevokation) -> None:
        """Revoke one or more issued badges."""
        logger.warning("Will revoke event: %s", revokation)
        response = await self.api_client.delete(
            f"/event/{self.api_client.client_id}/{revokation.event_id}",
            params=revokation.params(),
        )
        if not response.status_code == httpx.codes.NO_CONTENT:
            raise BadgeProviderError(f"Cannot revoke event: {revokation}")
        logger.info("Revoked event: %s", revokation)


class OBF(BaseProvider):
    """Open Badge Factory provider.

    API documentation:
    https://openbadgefactory.com/static/doc/obf-api-v1.pdf
    """

    code: str = "OBF"
    name: str = "Open Badge Factory"

    def __init__(
        self, client_id: str, client_secret: str, raise_for_status: bool = False
    ):
        """Initialize the API client and the badge and assertion classes."""
        super().__init__()
        self.api_client = OBFAPIClient(
            client_id, client_secret, raise_for_status=raise_for_status
        )
        self.badges = OBFBadge(self.api_client)
        self.assertions = OBFAssertion(self.api_client)
        self.events = OBFEvent(self.api_client)
