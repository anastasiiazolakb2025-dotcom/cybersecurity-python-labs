"""Клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервер повернув статус, відмінний від 200, але не HTTP-помилку"""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"неочікуваний HTTP-статус {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту; додає apiKey, якщо NVD_API_KEY непорожній."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> object:
    """Виконує один GET-запит до NVD і повертає декодований JSON.
    Піднімає винятки Requests (Timeout, ConnectionError, HTTPError,
    JSONDecodeError) та UnexpectedStatusError для статусу, відмінного від 200.
    """
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
