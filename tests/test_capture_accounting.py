"""Platform-specific shutdown delivery accounting."""

import pytest

from packet_audit.supervisor import _capture_delivery_issue


@pytest.mark.parametrize("received,dropped,queued,captured,expected", [
    # Npcap ps_recv includes these 96 filtered-out frames.
    (100, 0, 4, 4, None),
    # An accepted but unread post-filter frame cannot be called complete.
    (100, 0, 5, 4, "Npcap capture accounting mismatch"),
    (100, 0, None, 4, "post-filter capture count unavailable"),
    (None, None, None, 4, "drop statistics unavailable"),
    (100, 0, 0, 2**32, "counter wrapped"),
])
def test_npcap_final_delivery_requires_post_filter_count(
    received, dropped, queued, captured, expected,
):
    issue = _capture_delivery_issue(
        platform="nt", offline=False, received=received, dropped=dropped,
        queued=queued, captured=captured,
    )
    assert (issue is None) if expected is None else expected in issue


def test_linux_and_offline_accounting_remain_distinct():
    options = dict(received=10, dropped=1, queued=None, captured=9)
    assert _capture_delivery_issue(platform="posix", offline=False, **options) is None
    assert "mismatch" in _capture_delivery_issue(
        platform="posix", offline=False, **(options | {"captured": 8})
    )
    assert _capture_delivery_issue(
        platform="nt", offline=True, received=None, dropped=None,
        queued=None, captured=9,
    ) is None
