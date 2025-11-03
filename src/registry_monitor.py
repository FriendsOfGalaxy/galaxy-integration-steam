import platform

if platform.system().lower() == "windows":
    from galaxy.registry_monitor import RegistryMonitor

    HKEY_CURRENT_USER = 0x80000001

    def get_steam_registry_monitor():
        return RegistryMonitor(HKEY_CURRENT_USER, r"Software\Valve\Steam\Apps")

else:

    import os

    class FileRegistryMonitor:

        def __init__(self, filename):
            self._filename = filename
            self._stat = self._get_stat()

        def _get_stat(self):
            try:
                st = os.stat(self._filename)
            except OSError:
                return (0, 0)
            return (st.st_size, st.st_mtime_ns)

        def is_updated(self):
            current_stat = self._get_stat()
            changed = self._stat != current_stat
            self._stat = current_stat
            return changed

        def close(self):
            pass

    def get_steam_registry_monitor():
        return FileRegistryMonitor(os.path.expanduser("~/Library/Application Support/Steam/registry.vdf"))
