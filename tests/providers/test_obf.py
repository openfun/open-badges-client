"""Test suite for the OBF badge provider."""  # pylint: disable = too-many-lines

import logging
import re

import pytest
import requests
import responses
from pydantic import ValidationError

from obc.exceptions import AuthenticationError, BadgeProviderError
from obc.providers.obf import (
    OBF,
    AssertionQuery,
    Badge,
    BadgeAssertion,
    BadgeIssue,
    BadgeQuery,
    BadgeRevokation,
    IssueQuery,
    OAuth2AccessToken,
    OBFAPIClient,
)


def test_client_init(mocked_responses):
    """Test the OBF client class instantiation."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    client_id = "real_client"
    client_secret = "super_duper"
    api_client = OBFAPIClient(client_id=client_id, client_secret=client_secret)
    assert api_client.api_root_url == "https://openbadgefactory.com"
    assert api_client.client_id == client_id
    assert api_client.client_secret == client_secret
    assert api_client.raise_for_status is False
    assert "Content-Type" in api_client.headers
    assert api_client.headers["Content-Type"] == "application/json"
    assert isinstance(api_client.auth, OAuth2AccessToken) is True
    assert api_client.auth.access_token == "accesstoken123"

    api_client = OBFAPIClient(
        client_id=client_id, client_secret=client_secret, raise_for_status=True
    )
    assert api_client.raise_for_status is True


def test_client_access_token(mocked_responses):
    """Test the OBF Client access_token private method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    api_client = OBFAPIClient(client_id="real_client", client_secret="super_duper")
    # pylint: disable=protected-access
    assert (
        OBFAPIClient._access_token(
            api_client.client_id,
            api_client.client_secret,
            api_client.api_version_prefix,
            api_client.api_root_url,
        )
        == "accesstoken123"
    )
    # Ensure _access_token property has been cached
    assert len(mocked_responses.calls) == 1

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "Error": "invalid credentials",
        },
        status=403,
    )
    with pytest.raises(
        AuthenticationError,
        match=(
            "Cannot get an access token from the OBF server with provided "
            "credentials"
        ),
    ):
        api_client = OBFAPIClient(
            client_id="fake_id",
            client_secret="fake_secret",
        )

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        body="invalid credentials",
        status=403,
    )
    with pytest.raises(
        AuthenticationError,
        match="Invalid response from the OBF server with provided credentials",
    ):
        api_client = OBFAPIClient(
            client_id="fake_id",
            client_secret="fake_secret",
        )


def test_client_request(mocked_responses):
    """Test the OBF client request method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    api_client = OBFAPIClient(client_id="real_client", client_secret="super_duper")

    mocked_responses.get("https://openbadgefactory.com/v1/foo")
    response = api_client.get("/foo")
    assert response.request.url == "https://openbadgefactory.com/v1/foo"
    assert response.status_code == 200


def test_client_request_raise_for_status(mocked_responses):
    """Test the OBF client request method when the response status is not ok."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    api_client = OBFAPIClient(
        client_id="real_client", client_secret="super_duper", raise_for_status=True
    )

    mocked_responses.get("https://openbadgefactory.com/v1/foo", status=404)
    with pytest.raises(
        requests.HTTPError,
        match=(
            "404 Client Error: Not Found for url: "
            "https://openbadgefactory.com/v1/foo"
        ),
    ):
        api_client.get("/foo")


def test_client_request_access_token_regeneration(mocked_responses):
    """Test the OBF client request method when access token expired."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    api_client = OBFAPIClient(client_id="real_client", client_secret="super_duper")
    assert api_client.auth.access_token == "accesstoken123"

    mocked_responses.add(
        responses.GET, "https://openbadgefactory.com/v1/foo", status=403
    )
    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken456",
        },
        status=200,
    )
    mocked_responses.add(
        responses.GET, "https://openbadgefactory.com/v1/foo", status=200
    )
    response = api_client.get("/foo")
    assert response.request.url == "https://openbadgefactory.com/v1/foo"
    assert response.status_code == 200
    assert api_client.auth.access_token == "accesstoken456"


def test_client_check_auth(mocked_responses):
    """Test the OBF client check_auth method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    client_id = "real_client"
    api_client = OBFAPIClient(client_id=client_id, client_secret="super_duper")

    mocked_responses.get(
        f"https://openbadgefactory.com/v1/ping/{client_id}",
        status=200,
        body=f"{client_id}",
    )
    response = api_client.check_auth()
    assert response.status_code == 200
    assert response.text == "real_client"

    with pytest.raises(
        AuthenticationError,
        match="Invalid access token for OBF",
    ):
        mocked_responses.get(
            f"https://openbadgefactory.com/v1/ping/{client_id}",
            status=403,
        )
        api_client.check_auth()


# pylint: disable=protected-access
def test_iter_json():
    """Test the OBF provider iter_json method."""

    response = requests.Response()
    response._content = b'{"id": "1"}'
    assert list(OBFAPIClient.iter_json(response)) == [{"id": "1"}]

    response = requests.Response()
    response._content = b'[{"id": "1"},{"id": "2"}]'
    assert list(OBFAPIClient.iter_json(response)) == [{"id": "1"}, {"id": "2"}]

    response = requests.Response()
    response._content = b'[\n{"id": "1"},\n{"id": "2"}\n]'
    assert list(OBFAPIClient.iter_json(response)) == [{"id": "1"}, {"id": "2"}]

    response = requests.Response()
    response._content = b"[]"
    assert not list(OBFAPIClient.iter_json(response))

    response = requests.Response()
    response._content = b'{"id": "1"}\n{"id": "2"}\n{"id": "3"}\n'
    with pytest.raises(requests.JSONDecodeError):
        response.json()
    assert list(OBFAPIClient.iter_json(response)) == [
        {"id": "1"},
        {"id": "2"},
        {"id": "3"},
    ]

    response = requests.Response()
    response._content = b'{"id": "1"}\n\n{"id": "3"}\n'
    assert list(OBFAPIClient.iter_json(response)) == [{"id": "1"}, {"id": "3"}]


def test_badge_query_params():
    """Test the BadgeQuery model params method."""

    query = BadgeQuery(category=["one", "two"])
    assert query.params().get("category") == "one|two"

    query = BadgeQuery(id=["1", "2"])
    assert query.params().get("id") == "1|2"

    query = BadgeQuery(meta={"foo": 1, "bar": 2})
    params = query.params()
    assert params.get("meta:foo") == 1
    assert params.get("meta:bar") == 2
    assert params.get("meta") is None


def test_badge_check_id():
    """Test the Badge check_id method."""

    items = {
        "name": "toto",
        "description": "lorem ipsum",
        "is_created": True,
        "id": None,
    }
    with pytest.raises(
        ValidationError,
        match="Created badges should have an `id` field.",
    ):
        Badge(**items)


def test_badgeissue_check_ids():
    """Test the BadgeIssue check_ids method."""

    items = {
        "recipient": ["toto@bar.com"],
        "is_created": True,
        "id": None,
        "badge_id": "1234",
    }
    with pytest.raises(
        ValidationError,
        match="Badge issues should have both an `id` and `badge_id` field.",
    ):
        BadgeIssue(**items)

    items = {
        "recipient": ["toto@bar.com"],
        "is_created": True,
        "id": "1234",
        "badge_id": None,
    }
    with pytest.raises(
        ValidationError,
        match="Badge issues should have both an `id` and `badge_id` field.",
    ):
        BadgeIssue(**items)


def test_provider_init(mocked_responses):
    """Test the OBF class instantiation."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    assert isinstance(obf.api_client, OBFAPIClient)
    assert obf.api_client.client_id == "real_client"
    assert obf.api_client.client_secret == "super_duper"
    assert obf.api_client.raise_for_status is False


def test_provider_raise_for_status(mocked_responses):
    """Test that the provider raises an exception on HTTP request error."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(
        client_id="real_client", client_secret="super_duper", raise_for_status=True
    )

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        status=404,
    )
    with pytest.raises(
        requests.HTTPError,
        match=(
            "404 Client Error: Not Found for url: "
            "https://openbadgefactory.com/v1/badge/real_client"
        ),
    ):
        next(obf.badges.read())


def test_provider_badge_read_all(mocked_responses):
    """Test the OBF read method without argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[],
        status=200,
    )
    assert len(list(obf.badges.read())) == 0

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[
            {"id": "1", "name": "foo", "description": "lorem ipsum"},
            {"id": "2", "name": "bar", "description": "lorem ipsum"},
            {"id": "3", "name": "lol", "description": "lorem ipsum"},
        ],
        status=200,
    )
    badges = list(obf.badges.read())
    for badge in badges:
        assert isinstance(badge, Badge)
    assert badges[0].id == "1"
    assert badges[0].name == "foo"
    assert badges[0].description == "lorem ipsum"
    assert badges[1].id == "2"
    assert badges[1].name == "bar"
    assert badges[1].description == "lorem ipsum"
    assert badges[2].id == "3"
    assert badges[2].name == "lol"
    assert badges[2].description == "lorem ipsum"


def test_provider_badge_read_one(mocked_responses):
    """Test the OBF read method with a given badge argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client/1",
        json=[
            {
                "id": "1",
                "name": "foo",
                "description": "lorem ipsum",
                "metadata": {"life": 42},
            }
        ],
        status=200,
    )
    target_badge = Badge(id="1", name="foo", description="lorem ipsum")
    badge = next(obf.badges.read(badge=target_badge))
    assert badge.id == "1"
    assert "life" in badge.metadata
    assert badge.metadata.get("life") == 42

    target_badge = Badge(name="foo", description="lorem ipsum")
    with pytest.raises(
        BadgeProviderError,
        match="the ID field is required",
    ):
        next(obf.badges.read(badge=target_badge))


def test_provider_badge_read_selected(mocked_responses):
    """Test the OBF read method with a badge query."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[],
        status=200,
    )
    query = BadgeQuery(draft=0)
    assert len(list(obf.badges.read(query=query))) == 0

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[
            {"id": "1", "name": "foo", "description": "lorem ipsum"},
            {"id": "2", "name": "bar", "description": "lorem ipsum"},
            {"id": "3", "name": "lol", "description": "lorem ipsum"},
        ],
        status=200,
    )
    query = BadgeQuery(query="lorem ipsum")
    assert len(list(obf.badges.read(query=query))) == 3


def test_provider_badge_read_with_validationerror(mocked_responses, caplog):
    """Test the OBF read method with a validation error."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[],
        status=200,
    )
    query = BadgeQuery(draft=0)
    assert len(list(obf.badges.read(query=query))) == 0

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client",
        json=[
            {"id": "1", "name": 1, "description": "lorem ipsum"},
            {"id": "2", "name": "bar", "description": "lorem ipsum"},
        ],
        status=200,
    )

    with caplog.at_level(logging.WARNING):
        assert len(list(obf.badges.read())) == 1

    assert ("obc.providers.obf", logging.WARNING) in [
        (class_, level) for (class_, level, _) in caplog.record_tuples
    ]


def test_provider_badge_create(mocked_responses):
    """Test the OBF create method with a given badge argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    submitted = Badge(name="foo", description="lorem ipsum")
    mocked = submitted.model_copy()
    mocked.id = "abcd1234"
    del mocked.is_created
    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client",
        status=201,
        headers={"Location": "/v1/badge/real_client/abcd1234"},
    )
    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        json=mocked.model_dump(),
        status=200,
    )
    created = obf.badges.create(badge=submitted)

    assert created.name == "foo"
    assert created.description == "lorem ipsum"
    assert created.id == "abcd1234"

    # An error occurred while creating the badge
    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client",
        status=500,
    )
    with pytest.raises(BadgeProviderError, match="Cannot create badge"):
        obf.badges.create(badge=submitted)


def test_provider_badge_update(mocked_responses):
    """Test the OBF update method with a given badge argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    with pytest.raises(
        BadgeProviderError, match="We expect an existing badge instance"
    ):
        obf.badges.update(Badge(name="foo", description="lorem ipsum"))

    badge = Badge(id="abcd1234", name="foo", description="lorem ipsum")
    mocked_responses.add(
        responses.PUT,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=204,
    )
    updated = obf.badges.update(badge)
    assert updated == badge

    # An error occurred while updating the badge
    mocked_responses.add(
        responses.PUT,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError, match="Cannot update badge with ID: abcd1234"
    ):
        obf.badges.update(badge=badge)


def test_provider_badge_delete_one(mocked_responses):
    """Test the OBF delete method with a given badge argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    with pytest.raises(
        BadgeProviderError, match="We expect an existing badge instance"
    ):
        obf.badges.delete(Badge(name="foo", description="lorem ipsum"))

    badge = Badge(id="abcd1234", name="foo", description="lorem ipsum")
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=204,
    )
    assert obf.badges.delete(badge) is None

    # An error occurred while deleting the badge
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError, match="Cannot delete badge with ID: abcd1234"
    ):
        obf.badges.delete(badge=badge)


def test_provider_badge_delete_all(mocked_responses):
    """Test the OBF delete method without badge argument (delete all badges)."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client",
        status=204,
    )
    assert obf.badges.delete() is None

    # An error occurred while updating the badge
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError,
        match="Cannot delete badges for client with ID: real_client",
    ):
        obf.badges.delete()


def test_provider_badge_issue_non_existing(mocked_responses):
    """Trying to issue a badge for a non-existing instance should fail."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    badge = Badge(name="test", description="lorem ipsum")
    issue = BadgeIssue(
        recipient=[
            "foo@example.org",
        ]
    )
    with pytest.raises(
        BadgeProviderError,
        match="We expect an existing badge instance",
    ):
        obf.badges.issue(badge, issue)


def test_provider_badge_issue_draft(mocked_responses):
    """Trying to issue a badge for a draft instance should fail."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    badge = Badge(id="abcd1234", name="test", description="lorem ipsum", draft=True)
    issue = BadgeIssue(
        recipient=[
            "foo@example.org",
        ]
    )
    with pytest.raises(
        BadgeProviderError,
        match="You cannot issue a badge with a draft status",
    ):
        obf.badges.issue(badge, issue)


def test_provider_badge_issue_success(mocked_responses):
    """Test the OBF issue method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    badge = Badge(id="badgeId1234", name="test", description="lorem ipsum", draft=False)
    submitted_issue = BadgeIssue(
        recipient=[
            "foo@example.org",
        ],
        email_subject="Subject of the email",
    )
    mocked = submitted_issue.model_copy()
    mocked.id = "issueId1234"
    mocked.badge_id = "badgeId1234"
    del mocked.is_created
    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client/badgeId1234",
        status=201,
        headers={"Location": "/v1/event/real_client/issueId1234"},
    )
    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client/issueId1234",
        json=mocked.model_dump(),
        status=200,
    )
    created_issue = obf.badges.issue(badge, submitted_issue)
    assert created_issue.email_subject == submitted_issue.email_subject
    assert created_issue.badge_id == badge.id
    assert not created_issue.revoked
    assert created_issue.is_created
    assert created_issue.id == "issueId1234"

    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client/badgeId1234",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError,
        match="Cannot issue badge with ID: badgeId1234",
    ):
        obf.badges.issue(badge, submitted_issue)


def test_provider_badge_revoke(mocked_responses):
    """Test the OBF revoke method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/event/real_client/foo_event",
        status=204,
        match=[
            responses.matchers.query_string_matcher(
                "email=foo@example.org|bar@example.org"
            )
        ],
    )
    assert (
        obf.badges.revoke(
            BadgeRevokation(
                event_id="foo_event",
                recipient=["foo@example.org", "bar@example.org"],
            )
        )
        is None
    )

    # An error occurred while updating the badge
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/event/real_client/foo_event",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError,
        match=re.escape(
            (
                "Cannot revoke event: event_id='foo_event' "
                "recipient=['foo@example.org']"
            )
        ),
    ):
        obf.badges.revoke(
            BadgeRevokation(
                event_id="foo_event",
                recipient=[
                    "foo@example.org",
                ],
            )
        )


def test_provider_event_read_all(mocked_responses):
    """Test the OBF event read method without argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client",
        json=[],
        status=200,
    )
    assert len(list(obf.events.read())) == 0

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client",
        json=[
            {
                "id": "1",
                "badge_id": "1234",
                "recipient": ["foo@bar.com", "bar@foo.com"],
                "expires": 1670832081,
                "issued_on": 1670822080,
                "revoked": {},
                "log_entry": {"issuer": "luc"},
            },
            {
                "id": "2",
                "badge_id": "5678",
                "recipient": ["toto@bar.com", "tata@foo.com"],
                "expires": 9876543211,
                "issued_on": 9876543210,
                "revoked": {"an_id1234": 9876543212},
                "log_entry": {"issuer": "anonymous"},
            },
        ],
        status=200,
    )
    issues = list(obf.events.read())
    for issue in issues:
        assert isinstance(issue, BadgeIssue)
    assert issues[0].id == "1"
    assert issues[0].badge_id == "1234"
    assert issues[0].recipient == ["foo@bar.com", "bar@foo.com"]
    assert issues[0].expires == 1670832081
    assert issues[0].issued_on == 1670822080
    assert issues[0].revoked == {}
    assert issues[0].log_entry == {"issuer": "luc"}
    assert issues[0].is_created
    assert issues[1].id == "2"
    assert issues[1].badge_id == "5678"
    assert issues[1].recipient == ["toto@bar.com", "tata@foo.com"]
    assert issues[1].expires == 9876543211
    assert issues[1].issued_on == 9876543210
    assert issues[1].revoked == {"an_id1234": 9876543212}
    assert issues[1].log_entry == {"issuer": "anonymous"}
    assert issues[1].is_created


def test_provider_event_read_one(mocked_responses):
    """Test the OBF event read method with a given issue argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client/1",
        json={
            "id": "1",
            "badge_id": "1234",
            "recipient": ["foo@bar.com", "bar@foo.com"],
            "expires": 1670832081,
            "issued_on": 1670822080,
            "revoked": {},
            "log_entry": {"issuer": "luc"},
        },
        status=200,
    )
    target_issue = BadgeIssue(id="1", recipient=["foo@bar.com"])
    issue = next(obf.events.read(issue=target_issue))
    assert issue == BadgeIssue(
        id="1",
        badge_id="1234",
        recipient=["foo@bar.com", "bar@foo.com"],
        expires=1670832081,
        issued_on=1670822080,
        revoked={},
        log_entry={"issuer": "luc"},
        is_created=True,
    )

    target_issue = BadgeIssue(recipient=["foo@bar.com"])
    with pytest.raises(
        BadgeProviderError,
        match="the ID field is required",
    ):
        next(obf.events.read(issue=target_issue))


def test_provider_event_read_selected(mocked_responses):
    """Test the OBF event read method with a issue query."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client",
        json=[],
        status=200,
    )
    query = IssueQuery()
    assert len(list(obf.events.read(query=query))) == 0

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client",
        json=[
            {
                "id": "1",
                "badge_id": "1234",
                "recipient": ["foo@bar.com", "bar@foo.com"],
                "expires": 1670832081,
                "issued_on": 1670822080,
                "revoked": {},
                "log_entry": {"issuer": "luc"},
            },
            {
                "id": "2",
                "badge_id": "1234",
                "recipient": ["toto@bar.com", "tata@foo.com"],
                "expires": 1670832083,
                "issued_on": 1670822082,
                "revoked": {},
                "log_entry": {"issuer": "toto"},
            },
            {
                "id": "3",
                "badge_id": "2345",
                "recipient": ["toto@bar.com", "tata@foo.com"],
                "expires": 1670832085,
                "issued_on": 1670822084,
                "revoked": {},
                "log_entry": {"issuer": "tata"},
            },
        ],
        status=200,
    )
    query = IssueQuery(recipient=["toto@bar.com", "tata@foo.com"])
    assert len(list(obf.events.read(query=query))) == 3


def test_provider_event_read_with_validationerror(mocked_responses, caplog):
    """Test the OBF event read method with a validation error."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client",
        json=[
            {
                "id": "1",
                "badge_id": "1234",
                "recipient": "bad_formatted_list",
                "expires": 1670832081,
                "issued_on": 1670822080,
                "revoked": {},
                "log_entry": {"issuer": "luc"},
            },
            {
                "id": "2",
                "badge_id": "1234",
                "recipient": ["toto@bar.com", "tata@foo.com"],
                "expires": 1670832083,
                "issued_on": 1670822082,
                "revoked": {},
                "log_entry": {"issuer": "toto"},
            },
        ],
        status=200,
    )
    with caplog.at_level(logging.WARNING):
        assert len(list(obf.events.read())) == 1

    assert ("obc.providers.obf", logging.WARNING) in [
        (class_, level) for (class_, level, _) in caplog.record_tuples
    ]


def test_provider_assertion_read_all(mocked_responses):
    """Test the OBF assertion read method without argument."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client/1/assertion",
        json=[
            {
                "id": "1234",
                "image": "http://obf.com/image",
                "json": "http://obf.com/json",
                "pdf": {"default": "http://obf.com/pdf"},
                "recipient": "toto@bar.com",
                "status": "accepted",
            },
            {
                "id": "5678",
                "image": "http://obf.com/image2",
                "json": "http://obf.com/json2",
                "pdf": {
                    "default": "http://obf.com/pdf2",
                    "fr": "http://obf.com/pdf_fr",
                },
                "recipient": "foo@bar.com",
                "status": "accepted",
            },
        ],
        status=200,
    )
    assertion = BadgeAssertion(event_id="1")
    assertions = list(obf.assertions.read(assertion=assertion))
    for assertion in assertions:
        assert isinstance(assertion, BadgeAssertion)
    assert assertions[0].id == "1234"
    assert str(assertions[0].image) == "http://obf.com/image"
    assert str(assertions[0].url) == "http://obf.com/json"
    assert assertions[0].pdf == {"default": "http://obf.com/pdf"}
    assert assertions[0].recipient == "toto@bar.com"
    assert assertions[0].status == "accepted"
    assert assertions[1].id == "5678"
    assert str(assertions[1].image) == "http://obf.com/image2"
    assert str(assertions[1].url) == "http://obf.com/json2"
    assert assertions[1].pdf == {
        "default": "http://obf.com/pdf2",
        "fr": "http://obf.com/pdf_fr",
    }
    assert assertions[1].recipient == "foo@bar.com"
    assert assertions[1].status == "accepted"


def test_provider_assertion_read_selected(mocked_responses):
    """Test the OBF event assertion read method with an assertion query."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client/4321/assertion",
        json=[
            {
                "id": "1234",
                "image": "http://obf.com/image",
                "json": "http://obf.com/json",
                "pdf": {"default": "http://obf.com/pdf"},
                "recipient": "foo@bar.com",
                "status": "accepted",
            },
            {
                "id": "5678",
                "image": "http://obf.com/image2",
                "json": "http://obf.com/json2",
                "pdf": {
                    "default": "http://obf.com/pdf2",
                    "fr": "http://obf.com/pdf_fr",
                },
                "recipient": "foo@bar.com",
                "status": "accepted",
            },
        ],
        status=200,
    )
    assertion = BadgeAssertion(event_id="4321")
    query = AssertionQuery(email=["foo@bar.com"])
    assert len(list(obf.assertions.read(assertion=assertion, query=query))) == 2


def test_provider_assertion_read_with_validationerror(mocked_responses, caplog):
    """Test the OBF event assertion read method with a validation error."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    mocked_responses.add(
        responses.GET,
        "https://openbadgefactory.com/v1/event/real_client/4321/assertion",
        json=[
            {
                "id": "1234",
                "image": "bad_formatted_url",
                "json": None,
                "pdf": {},
                "recipient": None,
                "status": None,
            },
            {
                "id": "5678",
                "image": None,
                "json": None,
                "pdf": {},
                "recipient": None,
                "status": None,
            },
        ],
        status=200,
    )

    assertion = BadgeAssertion(event_id="4321")
    with caplog.at_level(logging.WARNING):
        assert len(list(obf.assertions.read(assertion=assertion))) == 1

    assert ("obc.providers.obf", logging.WARNING) in [
        (class_, level) for (class_, level, _) in caplog.record_tuples
    ]

    assertion.event_id = None
    with pytest.raises(
        BadgeProviderError,
        match="We expect an existing issue",
    ):
        list(obf.assertions.read(assertion=assertion))
