import pytest
from galaxy.api.types import Achievement
from galaxy.api.errors import AuthenticationRequired
from .pytest_asyncio_helpers import resolve_async_fixture


@pytest.mark.asyncio
async def test_not_authenticated(plugin):
    plugin_instance = await resolve_async_fixture(plugin)
    with pytest.raises(AuthenticationRequired):
        await plugin_instance.prepare_achievements_context(["12", "13"])


@pytest.mark.asyncio
async def test_get_achievements_success(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    plugin_instance._backend._stats_cache = {"236850": {'achievements': [{'unlock_time': 1551887210, 'name': 'name 1'},
                                                                     {'unlock_time': 1551887134, 'name': 'name 2'}]}}
    achievements = await plugin_instance.get_unlocked_achievements("236850", None)
    assert achievements == [
        Achievement(1551887210, None, "name 1"),
        Achievement(1551887134, None, "name 2")
    ]


@pytest.mark.asyncio
async def test_initialize_cache(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    plugin_instance._backend._stats_cache = {"17923": {'achievements': [{'unlock_time': 123,'name':'name'}]}}
    achievements = await plugin_instance.get_unlocked_achievements("17923", None)
    assert achievements == [
        Achievement(123, None , "name")
    ]


@pytest.mark.asyncio
async def test_no_game_time(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    assert await plugin_instance.get_unlocked_achievements("17923", None) == []


@pytest.mark.asyncio
async def test_trailing_whitespace(authenticated_plugin):
    plugin_instance = await resolve_async_fixture(authenticated_plugin)
    plugin_instance._backend._stats_cache = {"236850": {'achievements': [{'unlock_time': 1551887210, 'name': 'name 1 '},
                                                                     {'unlock_time': 1551887134, 'name': 'name 2    '}]}}
    achievements = await plugin_instance.get_unlocked_achievements("236850", None)
    assert achievements == [
        Achievement(1551887210, None, "name 1"),
        Achievement(1551887134, None, "name 2")
    ]
