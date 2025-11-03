from galaxy.api.types import GameTime
from galaxy.api.errors import AuthenticationRequired
import pytest
from .pytest_asyncio_helpers import resolve_async_fixture


@pytest.mark.asyncio
async def test_not_authenticated(plugin):
    plugin_instance = await resolve_async_fixture(plugin)
    with pytest.raises(AuthenticationRequired):
        await plugin_instance.prepare_game_times_context(["13", "23"])


@pytest.mark.asyncio
async def test_import(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    plugin_instance._backend._times_cache = {"281990": {'time_played': 78, 'last_played': 123},
                                         "236850": {'time_played': 86820, 'last_played':321}}
    assert await plugin_instance.get_game_time("236850", None) == GameTime("236850", 86820, 321)
    assert await plugin_instance.get_game_time("281990", None) == GameTime("281990", 78, 123)


@pytest.mark.asyncio
async def test_missing_game_time(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    plugin_instance._backend._times_cache = {}
    game_time = await plugin_instance.get_game_time("281990", None)
    assert game_time == GameTime("281990", None, None)
