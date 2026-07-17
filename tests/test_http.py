import httpx

from cf_ip_blacklist.http import request_with_retry


def test_retry_after_is_honored() -> None:
    calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429 if not calls else 200, headers={"Retry-After": "3"})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, trust_env=False) as client:
        response = request_with_retry(client, "GET", "https://example.test", 1, calls.append)
    assert response.status_code == 200
    assert calls == [3.0]
