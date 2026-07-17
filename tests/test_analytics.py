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
                                            "clientRequestPath": "/.env?x=redacted",
                                        },
                                        "avg": {"sampleInterval": 10},
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
        observations = AnalyticsClient(
            client,
            "https://example.test/graphql",
            suspicious_path_patterns=(r"(^|/)\.env($|/)",),
        ).collect("zone", datetime(2026, 7, 18, tzinfo=UTC), datetime(2026, 7, 18, 1, tzinfo=UTC))

    assert route.called
    request_body = route.calls[0].request.content.decode()
    assert "cursor" not in request_body
    assert "clientRequestPath" in request_body
    assert "sampleInterval" in request_body
    assert observations[0].observed_requests == 3
    assert observations[0].weighted_requests == 30
    assert observations[0].paths == ["/.env"]
    assert observations[0].suspicious_paths == 1
    assert observations[0].sampled is True
    assert observations[0].sample_interval == 10
    assert observations[0].error_requests == 3
