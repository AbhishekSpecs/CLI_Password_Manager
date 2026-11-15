"""Command-line interface for the encrypted password manager."""
import argparse
import getpass
import sys
from pathlib import Path

from password_manager.exceptions import (
    AuthenticationError, DecryptionError, LockoutError, PasswordManagerError,
)
from password_manager.lockout import check_lockout, clear_failures, record_failure
from password_manager.storage import DEFAULT_LOCK_FILE, DEFAULT_VAULT
from password_manager.vault import (
    all_entries, change_master_password, create_vault, delete_entry,
    find_entry, save_entry, unlock_vault,
)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="password-manager",
        description="A local encrypted CLI password manager.",
    )
    parser.add_argument("--vault", default=str(DEFAULT_VAULT), help="Vault JSON path (default: vault.json)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create a new encrypted vault")
    sub.add_parser("add", help="Add credentials interactively")
    get_p = sub.add_parser("get", help="Retrieve credentials for a website")
    get_p.add_argument("site", help="Website URL or hostname")
    sub.add_parser("list", help="List saved websites")
    del_p = sub.add_parser("delete", help="Delete credentials for a website")
    del_p.add_argument("site", help="Website URL or hostname")
    sub.add_parser("change-master", help="Change the master password")
    return parser


def prompt_master(confirm=False, label="Master password: "):
    password = getpass.getpass(label)
    if confirm:
        second = getpass.getpass("Confirm master password: ")
        if password != second:
            raise ValueError("Passwords do not match.")
    return password


def do_init(path):
    if path.exists():
        raise ValueError(f"{path} already exists. Choose another --vault path or back it up first.")
    password = prompt_master(confirm=True, label="Create master password (12+ characters): ")
    create_vault(path, password)
    print(f"Vault created: {path}")
    print("Keep a secure backup of the vault. If you lose the master password, credentials cannot be recovered.")


def unlock_with_attempts(path):
    lock_path = path.with_name(path.name + ".lock.json")
    check_lockout(lock_path)
    password = prompt_master()
    try:
        data, key = unlock_vault(path, password)
    except AuthenticationError:
        record_failure(lock_path)
        raise
    clear_failures(lock_path)
    return data, key, lock_path


def run(args):
    path = Path(args.vault).expanduser().resolve()
    if args.command == "init":
        do_init(path)
        return

    data, key, lock_path = unlock_with_attempts(path)

    if args.command == "add":
        site = input("Website URL (e.g. https://example.com): ").strip()
        username = input("Username/email: ").strip()
        password = getpass.getpass("Account password (input hidden): ")
        if not password:
            raise ValueError("Account password cannot be empty.")
        save_entry(path, data, key, site, username, password)
        print("Credentials encrypted and saved.")
    elif args.command == "get":
        item = find_entry(data, key, args.site)
        print(f"Website : {item['site']}")
        print(f"Username: {item['username']}")
        print(f"Password: {item['password']}")
        print("Warning: the retrieved password is now visible on your screen.")
    elif args.command == "list":
        entries = all_entries(data, key)
        if not entries:
            print("Vault is empty.")
        else:
            print(f"Saved websites ({len(entries)}):")
            for item in sorted(entries, key=lambda x: x.get("site", "").casefold()):
                print(f"- {item['site']}")
    elif args.command == "delete":
        confirmation = input(f"Delete credentials for {args.site!r}? Type 'yes' to confirm: ").strip().lower()
        if confirmation != "yes":
            print("Cancelled.")
            return
        delete_entry(path, data, key, args.site)
        print("Entry deleted.")
    elif args.command == "change-master":
        new_password = prompt_master(confirm=True, label="New master password (12+ characters): ")
        change_master_password(path, data, key, new_password)
        clear_failures(lock_path)
        print("Master password changed and all entries re-encrypted.")


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except LockoutError as exc:
        print(f"LOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except (PasswordManagerError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()





# python main.py --vault new_vault.json init

python main.py --vault vault3.json init