"""Graph client tests, using a fake HTTP session so nothing touches the network."""

import pytest

from ca_gap_analyzer.graph import BASE_URL, GraphClient, GraphError


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.text = str(self._body)

    def json(self):
        return self._body


class FakeSession:
    """Returns queued responses in order and records every request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def get(self, url, headers=None, timeout=None):
        self.requests.append({"method": "GET", "url": url, "headers": headers})
        return self.responses.pop(0)

    def post(self, url, headers=None, json=None, timeout=None):
        self.requests.append({"method": "POST", "url": url, "headers": headers, "json": json})
        return self.responses.pop(0)


def test_sends_bearer_token():
    session = FakeSession([FakeResponse(body={"value": []})])
    GraphClient("token-123", session=session).get_all("/things")
    assert session.requests[0]["headers"]["Authorization"] == "Bearer token-123"
    assert session.requests[0]["url"] == BASE_URL + "/things"


def test_follows_next_links():
    page2_url = BASE_URL + "/things?$skiptoken=abc"
    session = FakeSession([
        FakeResponse(body={"value": [{"id": 1}, {"id": 2}], "@odata.nextLink": page2_url}),
        FakeResponse(body={"value": [{"id": 3}]}),
    ])
    items = GraphClient("t", session=session).get_all("/things")
    assert [i["id"] for i in items] == [1, 2, 3]
    assert session.requests[1]["url"] == page2_url


def test_retries_after_throttling():
    waits = []
    session = FakeSession([
        FakeResponse(429, headers={"Retry-After": "7"}),
        FakeResponse(body={"value": [{"id": 1}]}),
    ])
    items = GraphClient("t", session=session, sleep=waits.append).get_all("/things")
    assert items == [{"id": 1}]
    assert waits == [7.0]


def test_gives_up_after_max_retries():
    session = FakeSession([FakeResponse(429)] * 3)
    with pytest.raises(GraphError, match="429"):
        GraphClient("t", session=session, sleep=lambda s: None, max_retries=2).get_all("/things")


def test_get_by_ids_posts_in_chunks(monkeypatch):
    monkeypatch.setattr("ca_gap_analyzer.graph.GET_BY_IDS_LIMIT", 2)
    session = FakeSession([
        FakeResponse(body={"value": [{"id": "a"}, {"id": "b"}]}),
        FakeResponse(body={"value": [{"id": "c"}]}),
    ])
    found = GraphClient("t", session=session).get_by_ids(["a", "b", "c"], ["user"])
    assert [o["id"] for o in found] == ["a", "b", "c"]
    assert [r["json"]["ids"] for r in session.requests] == [["a", "b"], ["c"]]
    assert session.requests[0]["url"].endswith("/directoryObjects/getByIds")


def test_errors_carry_status_code():
    session = FakeSession([FakeResponse(400, body={"error": {"message": "bad"}})])
    with pytest.raises(GraphError) as excinfo:
        GraphClient("t", session=session).get_all("/things")
    assert excinfo.value.status == 400


def test_403_explains_permissions():
    body = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
    session = FakeSession([FakeResponse(403, body=body)])
    with pytest.raises(GraphError) as excinfo:
        GraphClient("t", session=session).get_all("/things")
    message = str(excinfo.value)
    assert "Insufficient privileges" in message
    assert "admin consent" in message
