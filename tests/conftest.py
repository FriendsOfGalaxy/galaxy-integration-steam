import pathlib
import pytest

from unittest.mock import MagicMock, Mock, PropertyMock
from galaxy.unittest.mock import AsyncMock, async_return_value

from os import path
BASE_DIR = path.abspath(path.curdir)

import sys
sys.path.append(path.join(BASE_DIR, "src"))

from plugin import SteamPlugin, AUTH_SETUP_ON_VERSION__CACHE_KEY
from backend_interface import BackendInterface
from version import __version__


@pytest.fixture
def plugin_root_dir():
    import plugin as module
    return pathlib.Path(module.__file__).parent


@pytest.fixture()
def steam_id():
    return "123"


@pytest.fixture()
def login():
    return "tester"


@pytest.fixture()
def miniprofile():
    return 123


@pytest.fixture
def http_response_mock():
    mock = MagicMock(spec=(), name=http_response_mock.__name__)
    mock.text = AsyncMock()
    mock.json = AsyncMock()
    return mock


@pytest.fixture
def http_client_mock(http_response_mock):
    mock = MagicMock(spec=(), name=http_client_mock.__name__)
    mock.close = AsyncMock()
    mock.get = AsyncMock(return_value=http_response_mock)
    return mock




@pytest.fixture()
def create_plugin(mocker, http_client_mock):
    created_plugins = []

    def function(cache=MagicMock()):
        writer = MagicMock(name="stream_writer")
        writer.drain.side_effect = lambda: async_return_value(None)

        # Mock asyncio operations to avoid event loop issues
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        mock_task.done = MagicMock(return_value=True)
        mocker.patch('asyncio.create_task', return_value=mock_task)
        mocker.patch('asyncio.sleep', return_value=async_return_value(None))

        mocker.patch('plugin.HttpClient', return_value=http_client_mock)
        mocker.patch("plugin.local_games_list", return_value=[])
        plugin = SteamPlugin(MagicMock(), writer, None)
        plugin.lost_authentication = Mock(return_value=None)
        type(plugin).persistent_cache = PropertyMock(return_value=cache)
        created_plugins.append(plugin)
        return plugin

    yield function

    # Cleanup will be handled by the plugin.close() calls
    for plugin in created_plugins:
        try:
            plugin.close()
        except:
            pass


@pytest.fixture()
def plugin(create_plugin):
    return create_plugin()


@pytest.fixture
def create_plugin_with_backend(create_plugin):
    def fn(connected_on_version: str = __version__, **kwargs):
        """
        :param connected_on_version     Version on which plugin was connected for the first time.
                                        Required to emulate stored state.
        """
        cache = kwargs.setdefault("cache", {})
        if connected_on_version and not connected_on_version.startswith('0'):
            cache.setdefault(AUTH_SETUP_ON_VERSION__CACHE_KEY, connected_on_version)

        plugin = create_plugin(**kwargs)
        plugin.handshake_complete()  # loads backend
        return plugin
    return fn


@pytest.fixture
def create_authenticated_plugin_with_backend(create_plugin_with_backend):
    async def fn(*args, **kwargs):
        plugin = create_plugin_with_backend(*args, **kwargs)
        await plugin.authenticate(Mock(dict, name='stored_credentials'))
        return plugin
    return fn






# load nested conftest files
# fixtures and hooks are applied in the relevant package scope only
# pytest_plugins = ('tests.tests_steam_network.conftest',)
