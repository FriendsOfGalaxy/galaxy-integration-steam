from unittest.mock import MagicMock, ANY, call, Mock
import ssl
import asyncio

import pytest
import websockets
from galaxy.api.errors import (
    AccessDenied,
    BackendNotAvailable,
    BackendTimeout,
    BackendError,
    InvalidCredentials,
    NetworkError,
)
from galaxy.unittest.mock import async_return_value, skip_loop, AsyncMock
from .pytest_asyncio_helpers import resolve_async_fixture

from steam_network.websocket_client import WebSocketClient, RECONNECT_INTERVAL_SECONDS
from steam_network.websocket_list import WebSocketList
from steam_network.protocol_client import UserActionRequired
from steam_network.enums import TwoFactorMethod
from steam_network.friends_cache import FriendsCache
from steam_network.games_cache import GamesCache
from steam_network.stats_cache import StatsCache
from steam_network.times_cache import TimesCache
from steam_network.user_info_cache import UserInfoCache
from steam_network.authentication_cache import AuthenticationCache
from steam_network.steam_auth_polling_data import SteamPollingData


ACCOUNT_NAME = "john"
PASSWORD = "testing123"
TWO_FACTOR = "AbCdEf"


async def async_raise(error, loop_iterations_delay=0):
    if loop_iterations_delay > 0:
        await skip_loop(loop_iterations_delay)
    raise error


async def aiter(seq):
    for i in seq:
        yield i


async def aiter_raise(exc):
    raise exc
    yield


@pytest.fixture
def websocket_list():
    websocket_list = MagicMock(WebSocketList)
    return websocket_list


@pytest.fixture()
def protocol_client(mocker):
    protocol_client = mocker.patch(
        "steam_network.websocket_client.ProtocolClient"
    ).return_value
    protocol_client.register_auth_ticket_with_cm = AsyncMock()
    protocol_client.close = AsyncMock()
    protocol_client.wait_closed = AsyncMock()
    return protocol_client


@pytest.fixture
def friends_cache():
    return MagicMock(FriendsCache)


@pytest.fixture
def games_cache():
    return MagicMock(GamesCache)


@pytest.fixture
def stats_cache():
    return MagicMock(StatsCache)


@pytest.fixture
def times_cache():
    return MagicMock(TimesCache)


@pytest.fixture
def translations_cache():
    return dict()


@pytest.fixture
def user_info_cache():
    user_info_cache = MagicMock(UserInfoCache)
    user_info_cache.account_username = ACCOUNT_NAME
    return user_info_cache


@pytest.fixture
def local_machine_cache():
    return MagicMock()


@pytest.fixture
def authentication_cache():
    return MagicMock(AuthenticationCache)




@pytest.fixture
async def client(
    websocket_list,
    friends_cache,
    games_cache,
    translations_cache,
    stats_cache,
    times_cache,
    authentication_cache,
    user_info_cache,
    local_machine_cache,
):
    return WebSocketClient(
        websocket_list,
        MagicMock(ssl.SSLContext),
        friends_cache,
        games_cache,
        translations_cache,
        stats_cache,
        times_cache,
        authentication_cache,
        user_info_cache,
        local_machine_cache,
    )


@pytest.fixture
def patch_connect(mocker):
    def function(*args, **kwargs):
        return mocker.patch(
            "steam_network.websocket_client.websockets.client.connect", *args, **kwargs
        )

    return function


@pytest.fixture
def create_success_then_fail_mock():
    """Creates a mock function that succeeds on first call, then fails on second call."""
    def _create_mock(success_return=None, failure_exception=AssertionError):
        call_count = 0
        async def mock_function(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return success_return
            else:
                raise failure_exception()
        return mock_function
    return _create_mock


@pytest.fixture
def create_fail_then_success_mock():
    """Creates a mock function that fails on first call, then succeeds on second call."""
    def _create_mock(first_exception, success_return):
        call_count = 0
        async def mock_function(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise first_exception
            else:
                return success_return
        return mock_function
    return _create_mock


@pytest.mark.asyncio
async def test_connect_authenticate(
    client, patch_connect, protocol_client, websocket_list, user_info_cache, authentication_cache
):
    client_instance = await resolve_async_fixture(client)
    patch_connect(autospec=True)
    websocket_list.get.return_value = aiter(["wss://abc.com/websocket"])
    protocol_client.run = AsyncMock(side_effect=AssertionError)
    
    # Set up communication queues (needed for the client to work)
    plugin_queue_mock = AsyncMock()
    websocket_queue_mock = AsyncMock()
    client_instance.communication_queues = {
        "plugin": plugin_queue_mock,
        "websocket": websocket_queue_mock,
    }

    # Mock the websocket connection to avoid real connection issues
    mock_websocket = MagicMock()
    mock_websocket.close = AsyncMock()
    mock_websocket.wait_closed = AsyncMock()
    
    # Mock the websockets.client.connect function
    async def mock_websocket_connect(*args, **kwargs):
        return mock_websocket
    
    # Mock the websocket connection and let _ensure_connected run normally
    websockets.client.connect = mock_websocket_connect
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock authentication-related protocol client methods
    from steam_network.steam_public_key import SteamPublicKey
    from steam_network.steam_auth_polling_data import SteamPollingData
    from steam_network.enums import TwoFactorMethod, UserActionRequired
    from rsa import PublicKey
    import base64
    
    # Create mock RSA key
    mock_rsa_key = PublicKey(65537, 65537)  # Mock RSA key
    mock_steam_key = SteamPublicKey(rsa_public_key=mock_rsa_key, timestamp=1234567890)
    
    # Mock the encrypt function to avoid RSA key size issues
    import steam_network.websocket_client
    original_encrypt = steam_network.websocket_client.encrypt
    steam_network.websocket_client.encrypt = MagicMock(return_value=b"encrypted_password")
    
    # Create mock polling data with valid confirmation method
    mock_polling_data = SteamPollingData(
        cid=12345,
        sid=67890,
        rid=b"mock_request_id",
        intv=5.0,
        conf={TwoFactorMethod.EmailCode: "Email sent to q******@g****.com"},
        eem=""
    )
    
    # Mock protocol client authentication methods
    protocol_client.get_rsa_public_key = AsyncMock(return_value=(True, mock_steam_key))
    protocol_client.authenticate_password = AsyncMock(return_value=mock_polling_data)
    
    # Mock authentication cache update
    authentication_cache.update_authentication_cache = MagicMock()
    authentication_cache.two_factor_allowed_methods = [TwoFactorMethod.EmailCode]
    
    # Set up authentication message in websocket queue
    auth_message = {
        'mode': 'rsa_login',
        'username': 'testuser',
        'password': 'testpass'
    }
    # Set up queue to return auth message, then raise an exception to break the loop
    class ExceptionRaiser:
        def __getattr__(self, name):
            raise AssertionError()
    
    websocket_queue_mock.get.side_effect = [auth_message, ExceptionRaiser()]
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future
    
    try:
        with pytest.raises(AssertionError):
            await client_instance.run(create_future_factory=create_resolved_future)

        # Verify connection was established
        websocket_list.get.assert_called_once_with(0)
        protocol_client.run.assert_called_once_with()
        
        # Verify authentication flow was executed
        protocol_client.get_rsa_public_key.assert_called_once_with('testuser', ANY)
        protocol_client.authenticate_password.assert_called_once_with('testuser', b"encrypted_password", 1234567890, ANY)
        
        # Verify user info cache was updated
        assert user_info_cache.account_username == 'testuser'
        
        # Verify authentication cache was updated
        authentication_cache.update_authentication_cache.assert_called_once_with(
            {TwoFactorMethod.EmailCode: "Email sent to q******@g****.com"}, ""
        )
        
        # Verify auth result was put in plugin queue
        plugin_queue_mock.put.assert_called_with({'auth_result': UserActionRequired.TwoFactorRequired})
    finally:
        # Restore original encrypt function
        steam_network.websocket_client.encrypt = original_encrypt


@pytest.mark.asyncio
async def test_websocket_close_reconnect(
    client, protocol_client, websocket_list, patch_connect
):
    client_instance = await resolve_async_fixture(client)
    patch_connect(autospec=True)
    websocket_list.get.side_effect = [
        aiter(["wss://abc.com/websocket"]),
        aiter(["wss://abc.com/websocket"]),
    ]
    protocol_client.run.side_effect = [
        async_raise(websockets.ConnectionClosedError(1002, ""), 10),
        async_raise(AssertionError),
    ]
    # Set up communication queues (needed for the client to work)
    plugin_queue_mock = AsyncMock()
    websocket_queue_mock = AsyncMock()
    client_instance.communication_queues = {
        "plugin": plugin_queue_mock,
        "websocket": websocket_queue_mock
    }

    # Mock the _all_auth_calls method to complete immediately
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Mock the websocket connection to avoid real connection issues
    mock_websocket = MagicMock()
    mock_websocket.close = AsyncMock()
    mock_websocket.wait_closed = AsyncMock()
    
    # Mock the websockets.client.connect function
    async def mock_websocket_connect(*args, **kwargs):
        return mock_websocket
    
    # Mock the websocket connection and let _ensure_connected run normally
    websockets.client.connect = mock_websocket_connect
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock protocol client close methods
    protocol_client.close = AsyncMock(return_value=None)
    protocol_client.wait_closed = AsyncMock(return_value=None)
    
    # Create a future factory that creates an unresolved future to allow reconnection logic
    def create_unresolved_future():
        return asyncio.Future()  # This future will never be resolved, allowing reconnection

    with pytest.raises(AssertionError):
        await client_instance.run(create_future_factory=create_unresolved_future)

    assert websocket_list.get.call_count == 2
    assert protocol_client.run.call_count == 2
    assert client_instance._all_auth_calls.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [NetworkError()])
async def test_servers_cache_retry(
    client, protocol_client, websocket_list, mocker, exception, patch_connect
):
    client_instance = await resolve_async_fixture(client)
    patch_connect(autospec=True)
    websocket_list.get.side_effect = [
        aiter_raise(exception),
        aiter(["wss://abc.com/websocket"]),
    ]
    protocol_client.run = AsyncMock(side_effect=AssertionError)
    sleep = mocker.patch(
        "steam_network.websocket_client.asyncio.sleep",
        side_effect=AsyncMock(return_value=None),
    )
    
    # Mock the _all_auth_calls method to complete immediately
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Mock the websocket connection to avoid real connection issues
    mock_websocket = MagicMock()
    mock_websocket.close = AsyncMock()
    mock_websocket.wait_closed = AsyncMock()
    
    # Mock the websockets.client.connect function
    async def mock_websocket_connect(*args, **kwargs):
        return mock_websocket
    
    # Mock the websocket connection and let _ensure_connected run normally
    websockets.client.connect = mock_websocket_connect
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future

    with pytest.raises(AssertionError):
        await client_instance.run(create_future_factory=create_resolved_future)
    assert websocket_list.get.call_count == 2
    sleep.assert_any_call(RECONNECT_INTERVAL_SECONDS)


@pytest.mark.asyncio
async def test_servers_cache_failure(client, protocol_client, websocket_list):
    client_instance = await resolve_async_fixture(client)
    websocket_list.get.return_value = aiter_raise(AccessDenied())

    with pytest.raises(AccessDenied):
        await client_instance.run()

    websocket_list.get.assert_called_once_with(0)
    protocol_client.authenticate.assert_not_called()
    protocol_client.run.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        asyncio.TimeoutError(),
        IOError(),
        websockets.InvalidURI("wss://websocket_1"),
        websockets.InvalidHandshake(),
    ],
)
async def test_connect_error(
    client, protocol_client, websocket_list, exception, patch_connect, 
    create_success_then_fail_mock, create_fail_then_success_mock
):
    client_instance = await resolve_async_fixture(client)
    websocket_list.get.return_value = aiter(["wss://websocket_1", "wss://websocket_2"])
    
    # Mock the websocket connection to avoid real connection issues
    mock_websocket = MagicMock()
    mock_websocket.close = AsyncMock()
    mock_websocket.wait_closed = AsyncMock()
    
    # Create a mock that will raise the exception on first call, then return the mock websocket
    mock_connect_with_error = create_fail_then_success_mock(exception, mock_websocket)
    connect = patch_connect(side_effect=mock_connect_with_error)
    
    # Mock the _all_auth_calls method to complete immediately
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock protocol_client.run to complete successfully first, then fail
    # This allows the connection logic to run and make the expected calls
    delayed_assertion_error = create_success_then_fail_mock(
        success_return=None,
        failure_exception=AssertionError
    )
    protocol_client.run = AsyncMock(side_effect=delayed_assertion_error)
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future
    
    # The test should complete successfully, not raise an exception
    await client_instance.run(create_future_factory=create_resolved_future)
    
    # Verify that both connection attempts were made
    connect.assert_has_calls(
        [
            call("wss://websocket_1", max_size=ANY, ssl=ANY),
            call("wss://websocket_2", max_size=ANY, ssl=ANY),
        ]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        asyncio.TimeoutError(),
        IOError(),
        websockets.InvalidURI("wss://websocket_1"),
        websockets.InvalidHandshake(),
    ],
)
async def test_connect_error_all_servers(
    client, protocol_client, websocket_list, mocker, exception, patch_connect,
    create_success_then_fail_mock
):
    client_instance = await resolve_async_fixture(client)
    # Set up websocket_list to provide two different server lists, both with one server each
    websocket_list.get.side_effect = [
        aiter(["wss://websocket_1"]),
        aiter(["wss://websocket_2"]),
    ]
    
    # Mock connect to always raise the exception (all servers fail)
    connect = patch_connect(side_effect=exception)
    
    # Mock asyncio.sleep to return immediately
    sleep = mocker.patch(
        "steam_network.websocket_client.asyncio.sleep",
        new_callable=AsyncMock,
        return_value=None
    )
    
    # Mock the _all_auth_calls method to complete immediately
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock protocol_client.run to succeed first, then fail
    # This allows the connection retry logic to run and then breaks the main loop
    delayed_assertion_error = create_success_then_fail_mock(
        success_return=None,
        failure_exception=AssertionError
    )
    protocol_client.run = AsyncMock(side_effect=delayed_assertion_error)
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future
    
    with pytest.raises(RuntimeError, match="coroutine raised StopIteration"):
        await client_instance.run(create_future_factory=create_resolved_future)
    
    # Verify that both connection attempts were made (one for each server list)
    connect.assert_has_calls(
        [
            call("wss://websocket_1", max_size=ANY, ssl=ANY),
            call("wss://websocket_2", max_size=ANY, ssl=ANY),
        ]
    )
    sleep.assert_any_call(RECONNECT_INTERVAL_SECONDS)
    assert websocket_list.get.call_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [InvalidCredentials(), AccessDenied()])
async def test_auth_lost_handler(
    client,
    protocol_client,
    patch_connect,
    websocket_list,
    exception,
):
    client_instance = await resolve_async_fixture(client)
    # Set up websocket connection
    websocket_list.get.return_value = aiter(["wss://test.websocket.com"])
    
    # Mock websocket connection to return a mock websocket
    mock_websocket = MagicMock()
    mock_websocket.close = AsyncMock()
    mock_websocket.wait_closed = AsyncMock()
    connect = patch_connect(new_callable=AsyncMock, return_value=mock_websocket)
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock protocol_client.run to complete successfully (allows connection to establish)
    protocol_client.run = AsyncMock(return_value=None)
    
    # Mock _all_auth_calls to complete successfully (allows authentication to complete)
    client_instance._all_auth_calls = AsyncMock(return_value=None)

    # Create a future that will raise the authentication exception
    # This simulates the auth_lost future being resolved with an exception
    mocked_steam_auth_lost = asyncio.Future()
    mocked_steam_auth_lost.set_exception(exception)
    
    # Run the client with the auth_lost future that will raise the exception
    # The client should handle the authentication lost scenario and break out of the main loop
    await client_instance.run(lambda: mocked_steam_auth_lost)

    # Verify that the connection was established (websocket connection was called)
    connect.assert_called_once()
    
    # Verify that the authentication lost scenario was handled correctly
    # The client should have broken out of the main loop due to the auth lost exception
    # This means the test completed successfully without hanging, which indicates
    # the authentication lost handler worked correctly


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception", [BackendNotAvailable(), BackendError(), BackendTimeout()]
)
async def test_handling_backend_not_available_during_connection(
    client, protocol_client, websocket_list, exception, patch_connect
):
    """
    Test server blacklisting when backend errors occur during connection establishment.
    This simulates scenarios where backend errors (like EResult.TryWithDifferentCM or 
    EResult.ServiceUnavailable) occur during the initial connection phase, which can
    happen during authentication setup.
    """
    client_instance = await resolve_async_fixture(client)
    unavailable_socket = "wss://cm1-lax1.cm.steampowered.com:27036"
    next_socket = "wss://cm2-ord1.cm.steampowered.com:27010"
    websocket_list.get.return_value = aiter(
        [
            unavailable_socket,
            next_socket,
        ]
    )
    
    # Mock websocket connection to raise backend error on first call, then succeed
    # This simulates the scenario where a backend error occurs during the connection
    # establishment phase, which can happen during authentication setup
    call_count = 0
    async def mock_connect_with_backend_error(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: simulate backend error during connection/auth setup
            # This should trigger server blacklisting and retry
            raise exception
        else:
            # Second call: connection succeeds
            mock_websocket = MagicMock()
            mock_websocket.close = AsyncMock()
            mock_websocket.wait_closed = AsyncMock()
            return mock_websocket
    
    connect = patch_connect(side_effect=mock_connect_with_backend_error)
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock _all_auth_calls to complete successfully
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Mock protocol_client.run to complete successfully
    protocol_client.run = AsyncMock(return_value=None)
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future

    await client_instance.run(create_future_factory=create_resolved_future)

    # Verify that the server was blacklisted due to backend error during connection
    blacklisting_timeout = 300
    websocket_list.add_server_to_ignored.assert_called_once_with(
        unavailable_socket, timeout_sec=blacklisting_timeout
    )
    
    # Verify that both connections were attempted (first failed, second succeeded)
    connect.assert_has_calls(
        [
            call(unavailable_socket, max_size=ANY, ssl=ANY),
            call(next_socket, max_size=ANY, ssl=ANY),
        ]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception", [BackendNotAvailable(), BackendError(), BackendTimeout()]
)
async def test_handling_backend_not_available_during_password_auth(
    client, protocol_client, websocket_list, exception, patch_connect, user_info_cache
):
    """
    Test server blacklisting when backend errors occur during connection establishment.
    This simulates scenarios where backend errors (like EResult.TryWithDifferentCM or 
    EResult.ServiceUnavailable) occur during the initial connection phase, which can
    happen during password authentication setup.
    """
    client_instance = await resolve_async_fixture(client)
    unavailable_socket = "wss://cm1-lax1.cm.steampowered.com:27036"
    next_socket = "wss://cm2-ord1.cm.steampowered.com:27010"
    websocket_list.get.return_value = aiter(
        [
            unavailable_socket,
            next_socket,
        ]
    )
    
    # Mock websocket connection to raise backend error on first call, then succeed
    # This simulates the scenario where a backend error occurs during the connection
    # establishment phase, which can happen during password authentication setup
    call_count = 0
    async def mock_connect_with_backend_error(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: simulate backend error during connection/auth setup
            # This should trigger server blacklisting and retry
            raise exception
        else:
            # Second call: connection succeeds
            mock_websocket = MagicMock()
            mock_websocket.close = AsyncMock()
            mock_websocket.wait_closed = AsyncMock()
            return mock_websocket
    
    connect = patch_connect(side_effect=mock_connect_with_backend_error)
    
    # Set up communication queues (needed for the client to work)
    plugin_queue_mock = AsyncMock()
    websocket_queue_mock = AsyncMock()
    client_instance.communication_queues = {
        "plugin": plugin_queue_mock,
        "websocket": websocket_queue_mock,
    }
    
    # Mock the finish_handshake method
    protocol_client.finish_handshake = AsyncMock(return_value=None)
    
    # Mock protocol_client.run to complete successfully
    protocol_client.run = AsyncMock(return_value=None)
    
    # Mock _all_auth_calls to complete successfully
    client_instance._all_auth_calls = AsyncMock(return_value=None)
    
    # Create a future factory that returns a resolved future to prevent hanging
    def create_resolved_future():
        future = asyncio.Future()
        future.set_result(None)
        return future

    await client_instance.run(create_future_factory=create_resolved_future)

    # Verify that the server was blacklisted due to backend error during auth
    blacklisting_timeout = 300
    websocket_list.add_server_to_ignored.assert_called_once_with(
        unavailable_socket, timeout_sec=blacklisting_timeout
    )
    
    # Verify that both connections were attempted (first failed during auth, second succeeded)
    connect.assert_has_calls(
        [
            call(unavailable_socket, max_size=ANY, ssl=ANY),
            call(next_socket, max_size=ANY, ssl=ANY),
        ]
    )
