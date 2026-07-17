from datetime import UTC, datetime

import httpx
import respx

from cf_ip_blacklist.analytics import AnalyticsClient


@respx.mock
def test_collect_uses_supported_analytics_arguments() -> None:
    route = respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "viewer": {
                        "zones": [
                            {
                                "series": [
                                    {
                                        "dimensions": {
                                            "clientIP": "192.0.2.1",
                                            "edgeResponseStatus": 404,
                                        },
                                        "count": 3,
                                    }
                                ]
                            }
                        ]
                    }
                }
            },
        )
    )

    with httpx.Client(trust_env=False) as client:
        observations = AnalyticsClient(client, "https://example.test/graphql").collect(
            "zone", datetime(2026, 7, 18, tzinfo=UTC), datetime(2026, 7, 18, 1, tzinfo=UTC)
        )

    assert route.called
    assert "cursor" not in route.calls[0].request.content.decode()
    assert observations[0].observed_requests == 3
    assert observations[0].error_requests == 3
