"""Persistent, basic brute-force delay for failed master-password attempts."""
import time
from pathlib import Path

from .exceptions import LockoutError, VaultError
from .storage import DEFAULT_LOCK_FILE, atomic_write_json, load_json

MAX_FAILURES = 5
LOCK_SECONDS = 60


def _read(path: Path) -> dict:
    try:
        data = load_json(path)
        return {
            "failures": int(data.get("failures", 0)),
            "locked_until": float(data.get("locked_until", 0)),
        }
    except FileNotFoundError:
        return {"failures": 0, "locked_until": 0}
    except (ValueError, TypeError):
        raise VaultError(f"Lockout file {path} is malformed.")


def check_lockout(path: Path = DEFAULT_LOCK_FILE) -> None:
    state = _read(path)
    remaining = int(state["locked_until"] - time.time())
    if remaining > 0:
        raise LockoutError(
            f"Vault temporarily locked. Try again in about {remaining} seconds."
        )


def record_failure(path: Path = DEFAULT_LOCK_FILE) -> None:
    state = _read(path)
    failures = state["failures"] + 1
    locked_until = time.time() + LOCK_SECONDS if failures >= MAX_FAILURES else 0
    if failures >= MAX_FAILURES:
        failures = 0
    atomic_write_json(path, {"failures": failures, "locked_until": locked_until})


def clear_failures(path: Path = DEFAULT_LOCK_FILE) -> None:
    atomic_write_json(path, {"failures": 0, "locked_until": 0})
