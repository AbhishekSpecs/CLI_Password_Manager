"""JSON vault storage with atomic file replacement."""
import json
import os
import tempfile
from pathlib import Path

from .exceptions import VaultError

DEFAULT_VAULT = Path("vault.json")
DEFAULT_LOCK_FILE = Path(".password_manager_lock.json")


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise VaultError(f"{path} must contain a JSON object.")
        return value
    except FileNotFoundError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError(f"{path} is not valid JSON.") from exc
    except OSError as exc:
        raise VaultError(f"Could not read {path}: {exc}") from exc


def atomic_write_json(path: Path, data: dict) -> None:
    """Write to a temporary file in the same directory, then replace atomically."""
    path = Path(path)
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                try:
                    os.remove(temp_name)
                except OSError:
                    pass
    except OSError as exc:
        raise VaultError(f"Could not safely write {path}: {exc}") from exc
