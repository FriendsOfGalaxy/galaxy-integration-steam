from pathlib import Path
from typing import Any, Optional, Union

_VERSION_FILENAME = "version.py"  # keep version.py for backward compatibility
_metadata_cache: dict[str, Any] = {}


def _metadata_file_path(repo_root: Path) -> Path:
    return repo_root.joinpath("src", _VERSION_FILENAME)


def _read_metadata_file(metadata_file: Path) -> dict[str, Any]:
    if _metadata_cache:
        return _metadata_cache
    exec(metadata_file.read_text(encoding="utf-8"), _metadata_cache)
    return _metadata_cache


def load_metadata(repo_root: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Load plugin metadata from src/version.py.

    repo_root: repository root (directory containing src/). Defaults to the
    parent of this package directory.
    """
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parent.parent
    metadata_file = _metadata_file_path(root)
    if not metadata_file.is_file():
        raise FileNotFoundError(metadata_file)
    return _read_metadata_file(metadata_file)
