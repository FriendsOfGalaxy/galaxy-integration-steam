from unittest.mock import Mock
import pytest

from async_mock import AsyncMock


FIRST_SETUP_VERSION_CACHE = "auth_setup_on_version"


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("initial_version", [
    "0.53",
    "1.53",
    "2.2.10",
])
async def test_ensure_version_is_cached_on_pass_login_credentials(
    create_plugin_with_backend,
    initial_version,
    mocker,
):
    current_plugin_version = "2.2.10"
    mocker.patch("plugin.__version__", current_plugin_version)
    
    # Mock the backend's pass_login_credentials method
    mocker.patch('backend_steam_network.SteamNetworkBackend.pass_login_credentials', 
                 new_callable=AsyncMock)
    
    plugin = create_plugin_with_backend(connected_on_version=initial_version)

    await plugin.pass_login_credentials(
        Mock(str, name="step"),
        Mock(dict, name="credentials"),
        Mock(dict, name="cookies")
    )
    
    assert plugin.persistent_cache[FIRST_SETUP_VERSION_CACHE] == current_plugin_version


async def test_do_not_cache_version_on_authenticate(
    create_plugin_with_backend,
    mocker
):
    current_plugin_version = "2.2.10"
    initial_version = "1.2.9"
    mocker.patch("plugin.__version__", current_plugin_version)
    
    # Mock the websocket client to prevent actual authentication
    websocket_client_mock = mocker.MagicMock()
    websocket_client_mock.communication_queues = {
        'plugin': AsyncMock(),
        'websocket': AsyncMock()
    }
    websocket_client_mock.run = AsyncMock()
    websocket_client_mock.close = AsyncMock()
    websocket_client_mock.wait_closed = AsyncMock()
    mocker.patch('backend_steam_network.WebSocketClient', return_value=websocket_client_mock)
    
    plugin = create_plugin_with_backend(connected_on_version=initial_version)

    # Mock stored_credentials as a proper dictionary with base64 encoded values
    import base64
    stored_credentials = {
        'steam_id': base64.b64encode('123456789'.encode('utf-8')).decode('utf-8'),
        'persona_name': base64.b64encode('test_user'.encode('utf-8')).decode('utf-8'),
        'refresh_token': base64.b64encode('test_token'.encode('utf-8')).decode('utf-8'),
        'account_username': base64.b64encode('test_account'.encode('utf-8')).decode('utf-8')
    }
    
    # Mock the authentication to return a successful result
    websocket_client_mock.communication_queues['plugin'].get.return_value = {
        'auth_result': 'NoActionRequired'
    }
    
    await plugin.authenticate(stored_credentials=stored_credentials)
    
    # Verify that the cached version remains the initial version, not the current version
    assert plugin.persistent_cache[FIRST_SETUP_VERSION_CACHE] == initial_version
