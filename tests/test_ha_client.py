import httpx
import pytest

from app import ha_client


@pytest.fixture
async def mock_http_client(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(
        base_url="http://homeassistant.local:8123",
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(ha_client, "_client", client)
    yield requests
    await client.aclose()


async def test_fire_event_posts_to_home_assistant_event_endpoint(mock_http_client):
    result = await ha_client.fire_event("ha_pass_activity", {"activity": "command"})

    assert result == {"ok": True}
    assert len(mock_http_client) == 1
    request = mock_http_client[0]
    assert request.method == "POST"
    assert request.url.path == "/api/events/ha_pass_activity"
    assert request.read() == b'{"activity":"command"}'


async def test_fire_event_does_not_retry_failed_posts(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500, request=request)

    client = httpx.AsyncClient(
        base_url="http://homeassistant.local:8123",
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(ha_client, "_client", client)

    with pytest.raises(httpx.HTTPStatusError):
        await ha_client.fire_event("ha_pass_activity", {"activity": "command"})

    assert len(requests) == 1
    await client.aclose()


async def test_logbook_log_posts_to_home_assistant_service_endpoint(mock_http_client):
    result = await ha_client.logbook_log({
        "name": "HAPass",
        "message": "Guest used light.turn_on",
    })

    assert result == {"ok": True}
    assert len(mock_http_client) == 1
    request = mock_http_client[0]
    assert request.method == "POST"
    assert request.url.path == "/api/services/logbook/log"
    assert request.read() == b'{"name":"HAPass","message":"Guest used light.turn_on"}'
