import os

import psutil

from Backend.CryptoUtils.CryptoPaladinExceptions import InvalidUSBPathException, VaultAlreadyExistsException
from Backend.Entities.Password import Password
from Backend.Repository.SQLiteRepository import SQLiteRepository
from PaladinVaultLogic.Services.AuthService import AuthService
from PaladinVaultLogic.Services.VaultService import VaultService


class PaladinVaultController:
    def __init__(self):
        self.auth_service = AuthService()
        self.vault_service: VaultService | None = None
        self.derived_key: bytes | None = None
        self.db_repository: SQLiteRepository | None = None
        self.key_file_path: str | None = None
        self.db_path: str | None = None

    def login(self, master_password: str, key_file_path: str, db_path: str | None = None) -> bool:
        derived_key, resolved_key_path = self.auth_service.authenticate(master_password, key_file_path)
        self.derived_key = derived_key
        self.key_file_path = resolved_key_path
        self.initialize_repository(db_path=db_path)
        return True

    def create_new_vault(
        self,
        master_password: str,
        key_file_path: str,
        db_path: str | None = None,
        use_usb_key: bool = False,
        overwrite_existing: bool = False,
    ) -> bool:
        if use_usb_key and not self._is_path_on_removable(key_file_path):
            raise InvalidUSBPathException("USB key path must be located on removable media.")

        resolved_db_path = self._resolve_db_path(db_path)

        if os.path.exists(key_file_path) and not overwrite_existing:
            raise VaultAlreadyExistsException(f"Key file already exists at: {os.path.abspath(key_file_path)}")
        if os.path.exists(resolved_db_path) and not overwrite_existing:
            raise VaultAlreadyExistsException(f"Database already exists at: {resolved_db_path}")

        if overwrite_existing and os.path.exists(resolved_db_path):
            os.remove(resolved_db_path)

        derived_key, resolved_key_path = self.auth_service.create_vault(master_password, key_file_path)
        self.derived_key = derived_key
        self.key_file_path = resolved_key_path
        self.initialize_repository(db_path=resolved_db_path)
        return True

    def initialize_repository(self, db_path: str | None = None):
        if not self.derived_key:
            raise Exception("Derived key is not available. Login must be successful first.")

        self.db_path = self._resolve_db_path(db_path)
        self.db_repository = SQLiteRepository(key=self.derived_key, maindb_path=self.db_path)
        self.vault_service = VaultService(
            repository=self.db_repository,
            derived_key=self.derived_key,
            key_file_path=self.key_file_path or "",
        )

    def _resolve_db_path(self, db_path: str | None) -> str:
        if db_path and db_path.strip():
            return os.path.abspath(db_path)
        return SQLiteRepository.resolve_default_db_path()

    def _is_path_on_removable(self, path: str) -> bool:
        abs_path = os.path.abspath(path)
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                if "removable" not in part.opts.lower():
                    continue
            elif not (part.mountpoint.startswith("/media") or part.mountpoint.startswith("/run/media")):
                continue

            mountpoint = os.path.abspath(part.mountpoint)
            if os.name == "nt":
                if abs_path.lower().startswith(mountpoint.lower()):
                    return True
            elif abs_path.startswith(mountpoint):
                return True
        return False

    def _require_vault(self) -> VaultService:
        if not self.vault_service:
            raise Exception("Database repository not initialized.")
        return self.vault_service

    def get_repository(self) -> SQLiteRepository | None:
        return self.db_repository

    def add_password_entry_controller(
        self,
        service: str,
        username: str,
        email: str | None,
        password: str,
        link: str | None,
        category: str | None,
        note: str | None,
    ) -> Password:
        return self._require_vault().add_password_entry(
            service=service,
            username=username,
            email=email,
            password=password,
            link=link,
            category=category,
            note=note,
        )

    def get_passwords(
        self,
        page: int | None = None,
        size: int | None = None,
        sort_by: str = "pid",
        sort_dir: str = "desc",
        service: str | None = None,
        category: str | None = None,
    ) -> list[Password]:
        return self._require_vault().list_passwords(
            page=page,
            size=size,
            sort_by=sort_by,
            sort_dir=sort_dir,
            service=service,
            category=category,
        )

    def get_passwords_paginated(
        self,
        page: int,
        size: int,
        sort_by: str = "pid",
        sort_dir: str = "desc",
        service: str | None = None,
        category: str | None = None,
    ) -> tuple[list[Password], int]:
        vault = self._require_vault()
        items = vault.list_passwords(
            page=page,
            size=size,
            sort_by=sort_by,
            sort_dir=sort_dir,
            service=service,
            category=category,
        )
        total = vault.count_passwords(service=service, category=category)
        return items, total

    def get_password_by_id(self, pid: int) -> Password | None:
        return self._require_vault().get_password_by_id(pid)

    def get_passwords_by_service(self, service: str) -> list[Password]:
        return self._require_vault().get_passwords_by_service(service)

    def decrypt_password(self, password_entity: Password) -> str:
        return self._require_vault().decrypt_password(password_entity)

    def update_password_entry_controller(
        self,
        pid: int,
        service: str | None = None,
        username: str | None = None,
        email: str | None = None,
        password: str | None = None,
        link: str | None = None,
        category: str | None = None,
        note: str | None = None,
    ) -> Password | None:
        return self._require_vault().update_password_entry(
            pid=pid,
            service=service,
            username=username,
            email=email,
            password=password,
            link=link,
            category=category,
            note=note,
        )

    def delete_password_entry_controller(self, pid: int) -> bool:
        return self._require_vault().delete_password_entry(pid)

    def backup_vault(self, backup_path: str | None = None):
        self._require_vault().backup_vault(backup_path)

    def restore_vault(self, backup_path: str):
        self._require_vault().restore_vault(backup_path)

    def logout(self) -> None:
        if self.vault_service:
            try:
                self.vault_service.close()
            except Exception:
                pass

        self.vault_service = None
        self.db_repository = None
        self.derived_key = None
        self.key_file_path = None
        self.db_path = None
