"""A minimal, read-only Microsoft Graph client.

Handles the two things every Graph caller has to deal with:
  * Paging: Graph returns results in pages and puts the next page's URL in "@odata.nextLink".
  * Throttling: Graph answers 429 "Too Many Requests" with a Retry-After header saying how
    many seconds to wait.
"""

import time

import requests

BASE_URL = "https://graph.microsoft.com/v1.0"
RETRY_STATUSES = {429, 503, 504}


class GraphError(Exception):
    pass


def describe_error(response, url: str) -> str:
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = response.text[:200] or "no details"

    text = f"Graph returned {response.status_code} for {url}: {message}"
    if response.status_code == 403:
        text += (
            "\nThe app or the signed-in account isn't allowed to read this. Check that admin "
            "consent was granted for Policy.Read.All, and that you signed in as an account with "
            "Global Reader or Security Reader (ca-auditor)."
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
            data = self._get(url)
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return items

    def _get(self, url: str) -> dict:
        for attempt in range(self._max_retries + 1):
            response = self._session.get(url, headers=self._headers, timeout=30)

            if response.status_code in RETRY_STATUSES and attempt < self._max_retries:
                self._sleep(self._retry_delay(response, attempt))
                continue
            if response.status_code >= 400:
                raise GraphError(describe_error(response, url))
            return response.json()

        raise GraphError(f"Gave up on {url} after {self._max_retries} retries")  # pragma: no cover

    @staticmethod
    def _retry_delay(response, attempt: int) -> float:
        try:
            return float(response.headers.get("Retry-After", ""))
        except ValueError:
            return 2 ** attempt  # 1s, 2s, 4s... if Graph didn't say
