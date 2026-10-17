"""A minimal, read-only Microsoft Graph client.

Handles the two things every Graph caller has to deal with:
  * Paging: Graph returns results in pages and puts the next page's URL in "@odata.nextLink".
  * Throttling: Graph answers 429 "Too Many Requests" with a Retry-After header saying how
    many seconds to wait.

The one POST it makes (directoryObjects/getByIds) is a read: it looks up many objects at once.
"""

import time

import requests

BASE_URL = "https://graph.microsoft.com/v1.0"
RETRY_STATUSES = {429, 503, 504}
GET_BY_IDS_LIMIT = 1000  # Graph's maximum IDs per getByIds call


class GraphError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def describe_error(response, url: str) -> str:
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = response.text[:200] or "no details"

    text = f"Graph returned {response.status_code} for {url}: {message}"
    if response.status_code == 403:
        text += (
            "\nThe app or the signed-in account isn't allowed to read this. Check that admin "
            "consent was granted for the app's API permissions, and that you signed in as an "
            "account with Global Reader or Security Reader (ca-auditor)."
        )
    elif response.status_code == 401:
        text += "\nThe sign-in token was rejected. Try running the command again."
    return text


class GraphClient:
    def __init__(self, access_token: str, session=None, sleep=time.sleep, max_retries: int = 3):
        self._headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        self._session = session or requests.Session()
        self._sleep = sleep          # swappable so tests don't actually wait
        self._max_retries = max_retries

    def get_all(self, path: str) -> list[dict]:
        """GET a collection and follow every nextLink, returning all items."""
        url = BASE_URL + path
        items = []
        while url:
            data = self._request("GET", url)
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return items

    def get_by_ids(self, ids: list[str], types: list[str]) -> list[dict]:
        """Look up many directory objects (users, groups, service principals) by ID."""
        found = []
        for start in range(0, len(ids), GET_BY_IDS_LIMIT):
            body = {"ids": ids[start:start + GET_BY_IDS_LIMIT], "types": types}
            data = self._request("POST", BASE_URL + "/directoryObjects/getByIds", body)
            found.extend(data.get("value", []))
        return found

    def count(self, path: str) -> int:
        """GET a $count endpoint, e.g. /users/$count. Graph requires an extra header for these."""
        response = self._send("GET", BASE_URL + path, extra_headers={"ConsistencyLevel": "eventual"})
        return int(response.text.strip().lstrip("﻿"))

    def _request(self, method: str, url: str, body: dict | None = None) -> dict:
        return self._send(method, url, body).json()

    def _send(self, method: str, url: str, body: dict | None = None, extra_headers: dict | None = None):
        headers = {**self._headers, **(extra_headers or {})}
        for attempt in range(self._max_retries + 1):
            if method == "POST":
                response = self._session.post(url, headers=headers, json=body, timeout=30)
            else:
                response = self._session.get(url, headers=headers, timeout=30)

            if response.status_code in RETRY_STATUSES and attempt < self._max_retries:
                self._sleep(self._retry_delay(response, attempt))
                continue
            if response.status_code >= 400:
                raise GraphError(describe_error(response, url), status=response.status_code)
            return response

        raise GraphError(f"Gave up on {url} after {self._max_retries} retries")  # pragma: no cover

    @staticmethod
    def _retry_delay(response, attempt: int) -> float:
        try:
            return float(response.headers.get("Retry-After", ""))
        except ValueError:
            return 2 ** attempt  # 1s, 2s, 4s... if Graph didn't say
