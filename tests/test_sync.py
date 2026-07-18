import httpx
import respx

from cf_ip_blacklist.models import CloudflareItem, DesiredList
from cf_ip_blacklist.sync import ListsClient, diff_lists


def test_diff_is_deterministic() -> None:
    desired = DesiredList(items=[CloudflareItem(ip="192.0.2.1", comment="new")])
    actual = [CloudflareItem(ip="192.0.2.2", comment="old")]
    diff = diff_lists(desired, actual)
    assert [item.ip for item in diff.additions] == ["192.0.2.1"]
    assert diff.removals == ("192.0.2.2",)


@respx.mock
def test_empty_list_fuse() -> None:
    client = httpx.Client(trust_env=False)
    lists = ListsClient(client, "https://api.example", "account", "list")
    try:
        import pytest

        with pytest.raises(Exception, match="non-empty"):
            lists.replace(DesiredList(items=[]), actual_count=1)
    finally:
        client.close()


@respx.mock
def test_get_items_discards_cloudflare_metadata() -> None:
    respx.get("https://api.example/accounts/account/rules/lists/list/items").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {
                        "id": "item-id",
                        "created_on": "2026-07-18T00:00:00Z",
                        "ip": "192.0.2.1",
                        "comment": "scanner",
                    }
                ]
            },
        )
    )
    with httpx.Client(trust_env=False) as client:
        items = ListsClient(client, "https://api.example", "account", "list").get_items()

    assert items == [CloudflareItem(ip="192.0.2.1", comment="scanner")]


@respx.mock
def test_get_items_reads_all_pages() -> None:
    items_url = "https://api.example/accounts/account/rules/lists/list/items"
    response = respx.get(items_url).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "result": [{"ip": "192.0.2.1", "comment": "first"}],
                    "result_info": {"cursors": {"after": "next-page"}},
                },
            ),
            httpx.Response(
                200,
                json={"result": [{"ip": "192.0.2.2", "comment": "second"}]},
            ),
        ]
    )

    with httpx.Client(trust_env=False) as client:
        items = ListsClient(client, "https://api.example", "account", "list").get_items()

    assert items == [
        CloudflareItem(ip="192.0.2.1", comment="first"),
        CloudflareItem(ip="192.0.2.2", comment="second"),
    ]
    assert response.calls[0].request.url.params["per_page"] == "500"
    assert response.calls[1].request.url.params["cursor"] == "next-page"


@respx.mock
def test_replace_retries_eventually_consistent_verification(monkeypatch) -> None:
    items_url = "https://api.example/accounts/account/rules/lists/list/items"
    respx.put(items_url).mock(
        return_value=httpx.Response(200, json={"result": {"operation_id": "op-1"}})
    )
    respx.get("https://api.example/accounts/account/rules/lists/bulk_operations/op-1").mock(
        return_value=httpx.Response(200, json={"result": {"status": "completed"}})
    )
    response = respx.get(items_url).mock(
        side_effect=[
            httpx.Response(200, json={"result": []}),
            httpx.Response(
                200,
                json={"result": [{"ip": "192.0.2.1", "comment": "scanner"}]},
            ),
        ]
    )
    monkeypatch.setattr("cf_ip_blacklist.sync.time.sleep", lambda _: None)
    desired = DesiredList(items=[CloudflareItem(ip="192.0.2.1", comment="scanner")])

    with httpx.Client(trust_env=False) as client:
        lists = ListsClient(client, "https://api.example", "account", "list")
        lists.replace(desired)

    assert response.call_count == 2
