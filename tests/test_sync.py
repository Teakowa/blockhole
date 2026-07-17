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
