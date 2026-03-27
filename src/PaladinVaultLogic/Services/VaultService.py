from pathlib import Path

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.Entities.Password import Password
from Backend.Repository.SQLiteRepository import SQLiteRepository


class VaultService:
    def __init__(self, repository: SQLiteRepository, derived_key: bytes, key_file_path: str):
        self.repository = repository
        self.derived_key = derived_key
        self.key_file_path = key_file_path

    def add_password_entry(
        self,
        service: str,
        username: str,
        email: str | None,
        password: str,
        link: str | None,
        category: str | None,
        note: str | None,
    ) -> Password:
        nonce, ciphertext, tag = cp.encrypt(password.encode("utf-8"), self.derived_key)
        return self.repository.create_password_entry(
            password_entity=Password(
                service=service,
                username=username,
                email=email,
                password=ciphertext,
                nonce=nonce,
                tag=tag,
                link=link,
                category=category,
                note=note,
            )
        )

    def list_passwords(
        self,
        page: int | None = None,
        size: int | None = None,
        sort_by: str = "pid",
        sort_dir: str = "desc",
        service: str | None = None,
        category: str | None = None,
    ) -> list[Password]:
        return self.repository.get_all_passwords(
            page=page,
            size=size,
            sort_by=sort_by,
            sort_dir=sort_dir,
            service=service,
            category=category,
        )

    def count_passwords(self, service: str | None = None, category: str | None = None) -> int:
        return self.repository.count_passwords(service=service, category=category)

    def get_password_by_id(self, pid: int) -> Password | None:
        return self.repository.get_password_by_id(pid)

    def get_passwords_by_service(self, service: str) -> list[Password]:
        return self.repository.get_passwords_by_service(service)

    def decrypt_password(self, password_entity: Password) -> str:
        plaintext = cp.decrypt(
            key=self.derived_key,
            nonce=password_entity.nonce,
            ciphertext=password_entity.password,
            tag=password_entity.tag,
        )
        return plaintext.decode("utf-8")

    def update_password_entry(
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
        updates = {
            "service": service,
            "username": username,
            "email": email,
            "link": link,
            "category": category,
            "note": note,
        }

        if password is not None:
            nonce, ciphertext, tag = cp.encrypt(password.encode("utf-8"), self.derived_key)
            updates["password"] = ciphertext
            updates["nonce"] = nonce
            updates["tag"] = tag

        return self.repository.update_password_entry(pid, **updates)

    def delete_password_entry(self, pid: int) -> bool:
        return self.repository.delete_password_by_id(pid)

    def backup_vault(self, backup_path: str | None = None):
        target = backup_path
        if not target:
            kf = Path(self.key_file_path)
            if kf.is_file():
                target = str(kf.parent / "PaladinVault_Backup.bin")

        if not target:
            raise Exception("Unable to resolve backup path.")

        self.repository.backup(backup_path=target)

    def restore_vault(self, backup_path: str):
        self.repository.load_backup(backup_path)

    def close(self) -> None:
        self.repository.close()
