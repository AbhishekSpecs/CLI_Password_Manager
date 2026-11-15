class PasswordManagerError(Exception):
    """Base class for expected application errors."""


class VaultError(PasswordManagerError):
    """Vault file is missing, malformed, or unsupported."""


class AuthenticationError(PasswordManagerError):
    """Master password was not accepted."""


class DecryptionError(PasswordManagerError):
    """Encrypted data failed authentication or could not be decrypted."""


class LockoutError(PasswordManagerError):
    """Too many failed unlock attempts."""
