"""Test suite for the OBF badge provider."""

import re

import pytest
import requests
import responses

from obc.exceptions import AuthenticationError, BadgeProviderError
from obc.providers.obf import (
    OBF,
    Badge,
    BadgeIssue,
    BadgeQuery,
    BadgeRevokation,
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
        next(obf.read())


def test_provider_read_all(mocked_responses):
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
    assert len(list(obf.read())) == 0

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
    badges = list(obf.read())
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


def test_provider_read_one(mocked_responses):
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
    badge = next(obf.read(badge=target_badge))
    assert badge.id == "1"
    assert "life" in badge.metadata
    assert badge.metadata.get("life") == 42

    target_badge = Badge(name="foo", description="lorem ipsum")
    with pytest.raises(
        BadgeProviderError,
        match="the ID field is required",
    ):
        next(obf.read(badge=target_badge))


def test_provider_read_selected(mocked_responses):
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
    assert len(list(obf.read(query=query))) == 0

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
    assert len(list(obf.read(query=query))) == 3


def test_provider_create(mocked_responses):
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
    created = obf.create(badge=submitted)

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
        obf.create(badge=submitted)


def test_provider_update(mocked_responses):
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
        obf.update(Badge(name="foo", description="lorem ipsum"))

    badge = Badge(id="abcd1234", name="foo", description="lorem ipsum")
    mocked_responses.add(
        responses.PUT,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=204,
    )
    updated = obf.update(badge)
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
        obf.update(badge=badge)


def test_provider_delete_one(mocked_responses):
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
        obf.delete(Badge(name="foo", description="lorem ipsum"))

    badge = Badge(id="abcd1234", name="foo", description="lorem ipsum")
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=204,
    )
    assert obf.delete(badge) is None

    # An error occurred while deleting the badge
    mocked_responses.add(
        responses.DELETE,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError, match="Cannot delete badge with ID: abcd1234"
    ):
        obf.delete(badge=badge)


def test_provider_delete_all(mocked_responses):
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
    assert obf.delete() is None

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
        obf.delete()


def test_provider_issue_non_existing(mocked_responses):
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
        obf.issue(badge, issue)


def test_provider_issue_draft(mocked_responses):
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
        obf.issue(badge, issue)


def test_provider_issue_success(mocked_responses):
    """Test the OBF issue method."""

    mocked_responses.post(
        "https://openbadgefactory.com/v1/client/oauth2/token",
        json={
            "access_token": "accesstoken123",
        },
        status=200,
    )
    obf = OBF(client_id="real_client", client_secret="super_duper")

    badge = Badge(id="abcd1234", name="test", description="lorem ipsum", draft=False)
    issue = BadgeIssue(
        recipient=[
            "foo@example.org",
        ]
    )

    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=201,
        headers={"Location": "/v1/event/real_client/foo_event"},
    )
    event_url, event_id = obf.issue(badge, issue)
    assert event_url == "/v1/event/real_client/foo_event"
    assert event_id == "foo_event"

    mocked_responses.add(
        responses.POST,
        "https://openbadgefactory.com/v1/badge/real_client/abcd1234",
        status=500,
    )
    with pytest.raises(
        BadgeProviderError,
        match="Cannot issue badge with ID: abcd1234",
    ):
        obf.issue(badge, issue)


def test_provider_revoke(mocked_responses):
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
        obf.revoke(
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
        obf.revoke(
            BadgeRevokation(
                event_id="foo_event",
                recipient=[
                    "foo@example.org",
                ],
            )
        )
