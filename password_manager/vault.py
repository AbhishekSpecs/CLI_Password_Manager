"""Vault operations. All credential fields are encrypted, including site names."""
import json
import re
from urllib.parse import urlparse

from .crypto_utils import (
    SALT_BYTES, b64decode, b64encode, decrypt_bytes, derive_key,
    encrypt_bytes, make_verifier, verify_key,
)
from .exceptions import AuthenticationError, DecryptionError, VaultError
from .storage import atomic_write_json, load_json

FORMAT_VERSION = 1


def normalize_site(site: str) -> str:
    site = site.strip()
    if not site:
        raise ValueError("Website cannot be empty.")
    candidate = site if "://" in site else "https://" + site
    parsed = urlparse(candidate)
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Enter a valid website such as example.com.")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// website URLs are accepted.")
    if any(ch.isspace() for ch in site):
        raise ValueError("Website URL must not contain spaces.")
    # Keep the user's display form, but normalize hostname case for matching.
    if "://" not in site:
        return parsed.hostname.lower() + (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    return site


def _validate_vault(data: dict) -> None:
    if data.get("version") != FORMAT_VERSION:
        raise VaultError("Unsupported vault format version.")
    for field in ("salt", "verifier", "entries"):
        if field not in data:
            raise VaultError(f"Vault is missing required field: {field}.")
    if not isinstance(data["entries"], list):
        raise VaultError("Vault entries must be a list.")


def create_vault(path, master_password: str) -> dict:
    import os
    if path.exists():
        raise VaultError(f"{path} already exists. Refusing to overwrite it.")
    if len(master_password) < 12:
        raise ValueError("Use a master password with at least 12 characters.")
    salt = os.urandom(SALT_BYTES)
    key = derive_key(master_password, salt)
    data = {
        "version": FORMAT_VERSION,
        "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": 600000},
        "cipher": "AES-256-GCM",
        "salt": b64encode(salt),
        "verifier": make_verifier(key),
        "entries": [],
    }
    atomic_write_json(path, data)
    return data


def unlock_vault(path, master_password: str):
    try:
        data = load_json(path)
    except FileNotFoundError as exc:
        raise VaultError(f"Vault not found at {path}. Run 'init' first.") from exc
    _validate_vault(data)
    salt = b64decode(data["salt"])
    key = derive_key(master_password, salt)
    if not verify_key(key, data["verifier"]):
        raise AuthenticationError("Incorrect master password.")
    return data, key


def _decrypt_entry(key: bytes, record: dict) -> dict:
    try:
        plaintext = decrypt_bytes(key, record)
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Entry is not an object.")
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DecryptionError("An entry could not be decoded; vault may be damaged.") from exc


def all_entries(data: dict, key: bytes) -> list:
    return [_decrypt_entry(key, record) for record in data["entries"]]


def save_entry(path, data: dict, key: bytes, site: str, username: str, password: str) -> None:
    site = normalize_site(site)
    if not username.strip():
        raise ValueError("Username cannot be empty.")
    existing = all_entries(data, key)
    if any(item["site"].casefold() == site.casefold() for item in existing):
        raise ValueError("That website already exists. Delete it first or use another site URL.")
    payload = json.dumps(
        {"site": site, "username": username.strip(), "password": password},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    data["entries"].append(encrypt_bytes(key, payload))
    atomic_write_json(path, data)


def find_entry(data: dict, key: bytes, site: str) -> dict:
    wanted = normalize_site(site).casefold()
    for item in all_entries(data, key):
        if item.get("site", "").casefold() == wanted:
            return item
    # Also permit matching by hostname for convenient lookup.
    wanted_host = urlparse(wanted if "://" in wanted else "https://" + wanted).hostname
    for item in all_entries(data, key):
        stored = item.get("site", "")
        host = urlparse(stored if "://" in stored else "https://" + stored).hostname
        if wanted_host and host and wanted_host.casefold() == host.casefold():
            return item
    raise ValueError(f"No credentials found for {site!r}.")


def delete_entry(path, data: dict, key: bytes, site: str) -> None:
    wanted = normalize_site(site).casefold()
    kept = []
    found = False
    for record in data["entries"]:
        item = _decrypt_entry(key, record)
        if item.get("site", "").casefold() == wanted:
            found = True
        else:
            kept.append(record)
    if not found:
        wanted_host = urlparse(wanted if "://" in wanted else "https://" + wanted).hostname
        for record in data["entries"]:
            item = _decrypt_entry(key, record)
            host = urlparse(item.get("site", "") if "://" in item.get("site", "") else "https://" + item.get("site", "")).hostname
            if wanted_host and host and wanted_host.casefold() == host.casefold():
                found = True
                kept = [r for r in data["entries"] if r is not record]
                break
    if not found:
        raise ValueError(f"No credentials found for {site!r}.")
    data["entries"] = kept
    atomic_write_json(path, data)


def change_master_password(path, data: dict, old_key: bytes, new_password: str) -> dict:
    if len(new_password) < 12:
        raise ValueError("Use a new master password with at least 12 characters.")
    entries = all_entries(data, old_key)  # Verify/decrypt everything before changing anything.
    import os
    from .crypto_utils import PBKDF2_ITERATIONS
    salt = os.urandom(SALT_BYTES)
    new_key = derive_key(new_password, salt)
    data["salt"] = b64encode(salt)
    data["kdf"] = {"name": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ITERATIONS}
    data["verifier"] = make_verifier(new_key)
    data["entries"] = [
        encrypt_bytes(
            new_key,
            json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )
        for entry in entries
    ]
    atomic_write_json(path, data)
    return data
