import os

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.CryptoUtils.CryptoPaladinExceptions import (
    InvalidPasswordException,
    InvalidVaultConfigurationException,
    KeyFileNotFoundException,
    VaultCreationException,
)


class AuthService:
    MIN_MASTER_PASSWORD_LENGTH = 8

    def authenticate(self, master_password: str, key_file_path: str) -> tuple[bytes, str]:
        if not os.path.exists(key_file_path):
            raise KeyFileNotFoundException(f"Key file not found at: {key_file_path}")

        loaded_key_data, salt = cp.load_key(key_file_path)
        if not cp.verify_key(input=master_password, key=loaded_key_data, salt=salt):
            raise InvalidPasswordException("Master password verification failed.")

        derived_key, _ = cp.derive_key(input=master_password, salt=salt)
        return derived_key, key_file_path

    def create_vault(self, master_password: str, key_file_path: str) -> tuple[bytes, str]:
        self._validate_master_password(master_password)
        if not key_file_path or not key_file_path.strip():
            raise InvalidVaultConfigurationException("Key file path is required.")

        resolved_key_path = os.path.abspath(key_file_path)
        key_dir = os.path.dirname(resolved_key_path)
        if key_dir:
            os.makedirs(key_dir, exist_ok=True)

        try:
            key_hash, salt = cp.generate_key(master_password)
            cp.save_key(key_hash, salt, resolved_key_path)
            derived_key, _ = cp.derive_key(input=master_password, salt=salt)
        except Exception as ex:
            raise VaultCreationException(f"Vault key creation failed: {str(ex)}") from ex

        return derived_key, resolved_key_path

    def _validate_master_password(self, master_password: str) -> None:
        if not master_password:
            raise InvalidPasswordException("Master password is required.")
        if len(master_password) < self.MIN_MASTER_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                f"Master password must be at least {self.MIN_MASTER_PASSWORD_LENGTH} characters long."
            )
