from galaxy.api.consts import Feature
import pytest



pytestmark = pytest.mark.asyncio


@pytest.fixture
def local_features():
    return {
        Feature.ImportInstalledGames,
        Feature.InstallGame,
        Feature.LaunchGame,
        Feature.UninstallGame,
        Feature.ShutdownPlatformClient,
        Feature.ImportLocalSize,
    }




@pytest.fixture
def steam_network_features():
    return {
        Feature.ImportOwnedGames,
        Feature.ImportSubscriptionGames,
        Feature.ImportSubscriptions,
        Feature.ImportAchievements,
        Feature.ImportGameTime,
        Feature.ImportFriends,
        Feature.ImportUserPresence,
        Feature.ImportGameLibrarySettings,
    }


async def test_features_default(
    create_plugin, local_features, steam_network_features
):
    plugin = create_plugin()
    assert isinstance(plugin.features, list)
    assert set(plugin.features) == local_features | steam_network_features


async def test_features_steam_network(
    create_plugin_with_backend, local_features, steam_network_features
):
    plugin = create_plugin_with_backend()
    assert set(plugin.features) == local_features | steam_network_features


