from unittest.mock import MagicMock

import pytest
import websockets
from galaxy.unittest.mock import AsyncMock
from .pytest_asyncio_helpers import resolve_async_fixture
from websockets.protocol import State

from steam_network.protocol.protobuf_client import ProtobufClient


ACCOUNT_NAME = "john"
PASSWORD = "testing123"
TWO_FACTOR = "AbCdEf"
TOKEN = "TOKEN"
USED_SERVER_CELL_ID = 0
MACHINE_ID = bytes('machine_id', 'utf-8')
OS_VALUE = 1
SENTRY = None
PRIVATE_IP = 1
HOST_NAME = "john pc"
PROTOCOL_VERSION = ProtobufClient._MSG_PROTOCOL_VERSION
CLIENT_PACKAGE_VERSION = ProtobufClient._MSG_CLIENT_PACKAGE_VERSION
CLIENT_LANGUAGE = "english"
TWO_FACTOR_TYPE = 'email'


@pytest.fixture
def websocket():
    websocket_ = MagicMock()
    websocket_.send = AsyncMock()
    return websocket_


@pytest.fixture
async def client(websocket, mocker):
    protobuf_client = ProtobufClient(websocket)
    mocker.patch(
        "socket.gethostname", return_value=HOST_NAME
    )
    return protobuf_client


@pytest.mark.asyncio
async def test_log_on_token_message(client, websocket):
    client_instance = await resolve_async_fixture(client)
    client_instance._get_obfuscated_private_ip = AsyncMock(return_value=PRIVATE_IP)
    await client_instance.send_log_on_token_message(ACCOUNT_NAME, 12345, TOKEN, USED_SERVER_CELL_ID, MACHINE_ID, OS_VALUE)
    msg_to_send = str(websocket.send.call_args[0][0])
    assert ACCOUNT_NAME in msg_to_send
    assert TOKEN in msg_to_send
    assert str(USED_SERVER_CELL_ID) in msg_to_send
    assert MACHINE_ID.decode('utf-8') in msg_to_send
    assert str(OS_VALUE) in msg_to_send
    assert str(PRIVATE_IP) in msg_to_send
    assert HOST_NAME in msg_to_send
    assert CLIENT_LANGUAGE in msg_to_send


@pytest.mark.asyncio
async def test_log_on_password_message(client, websocket):
    client_instance = await resolve_async_fixture(client)
    client_instance._get_obfuscated_private_ip = AsyncMock(return_value=PRIVATE_IP)
    await client_instance.log_on_password(ACCOUNT_NAME, PASSWORD.encode('utf-8'), 1234567890, OS_VALUE)
    msg_to_send = str(websocket.send.call_args[0][0])
    # Check for values that are actually used in the log_on_password method
    assert ACCOUNT_NAME in msg_to_send
    assert HOST_NAME in msg_to_send  # device_friendly_name
    assert "dGVzdGluZzEyMw==" in msg_to_send  # base64 encoded password
    assert str(OS_VALUE) in msg_to_send  # device_details.os_type
    assert "Client" in msg_to_send  # website_id
    assert "GOG Galaxy" in msg_to_send  # device_friendly_name suffix
    # The method uses the new authentication workflow, not the old logon message


@pytest.mark.asyncio
@pytest.mark.parametrize("socket_state", [State.CLOSED, State.CONNECTING, State.CLOSING])
async def test_ensure_open_exception(client, socket_state, monkeypatch, mocker):
    client_instance = await resolve_async_fixture(client)

    mocker.patch('asyncio.shield', AsyncMock(return_value=MagicMock()))
    # Create a mock websocket instead of using WebSocketCommonProtocol directly
    mock_websocket = MagicMock()
    mock_websocket.close_code = 1
    mock_websocket.close_reason = "Close reason"
    mock_websocket.close_connection_task = MagicMock()
    mock_websocket.state = socket_state
    # Make ensure_open an AsyncMock that raises the appropriate exception
    mock_websocket.ensure_open = AsyncMock(side_effect=websockets.ConnectionClosedError(1, "Close reason"))
    
    client = ProtobufClient(mock_websocket)

    with pytest.raises((websockets.ConnectionClosedError, websockets.InvalidState)):
        await client._get_obfuscated_private_ip()
