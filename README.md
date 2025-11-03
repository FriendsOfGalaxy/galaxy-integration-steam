# Steam Integration

GOG Galaxy 2.0 Community integration for Steam.

## Installation

*The latest release should be available for download via the "Connect" button in Galaxy*

### To install a custom build:

* make sure Galaxy is closed
* remove the currently installed plugin directory (if present), usually<br>
`%localappdata%\GOG.com\Galaxy\plugins\installed\steam_ca27391f-2675-49b1-92c0-896d43afa4f8`
* create a new folder under a name of your choice (the name doesn't matter) at the following path:<br>
`%localappdata%\GOG.com\Galaxy\plugins\installed\`
* copy the custom build files to the newly created folder

If the latest version available on Github is newer than the version specified in the `manifest.json` file in the custom build, Galaxy will download the newer version and replace the files. To prevent this from happening, you can manually set the version in `manifest.json` to a significantly higher value (e.g. `9.9`).


## Credits

The new Authorization flow implementation was done by ABaumer [ABaumer](https://github.com/ABaumher) (big thanks!) in [#171](https://github.com/gogcom/galaxy-integrations-steam/pull/171). The pull request was improved (dependency upgrade, restore unit tests) before the merge.

The new Authorization flow implementation is heavily influenced by [SteamKit](https://github.com/SteamRE/SteamKit).<br>
While we have not utilized their source code, they have implemented the new authentication workflow before we did, and we used their knowledge of how to do so in order to implement it ourselves. If you are doing anything steam related in C#, you should check them out; their project has far more features than our own.

Some work was influenced by [ValvePython](https://github.com/ValvePython/steam).<br>
Our projects do the same thing, but use different methods (we use asyncio, they use gevent, for example). Both projects were working on the new Auth Flow simultaneously, with little collaboration between us. That said, their scope is much larger than our own and lets you do a lot more things. If you are looking for a python means of implementing a steam network authentication, you should use their work instead.

Based on work and research done by others:
* https://github.com/prncc/steam-scraper
* https://github.com/rhaarm/steam-scraper
* https://github.com/mulhod/steam_reviews
* https://github.com/summersb92/aeolipile
* https://github.com/rcpoison/steam-scraper
* https://github.com/chmccc/steam-scraper
