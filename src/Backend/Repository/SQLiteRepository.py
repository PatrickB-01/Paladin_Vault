import os
import pathlib
from contextlib import contextmanager
from datetime import datetime, timezone
import logging
from typing import Iterator, Optional

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.Entities.Password import BaseModel, Password


class SQLiteRepository:
    DB_PATH_DIR = "PaladinVault"
    DB_FILE_NAME = "PaladinVault.db"

    def __init__(self,key:bytes, maindb_path:str|None=None) -> None:
        if maindb_path:
            self.maindb_path = os.path.abspath(maindb_path)
        else:
            self.maindb_path = self.get_db_path()

        db_parent = os.path.dirname(self.maindb_path)
        if db_parent:
            pathlib.Path(db_parent).mkdir(parents=True, exist_ok=True)

        self.key = key
        self.engine = create_engine(f"sqlite:///{self.maindb_path}", future=True)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False, class_=Session)
        self.initializeDB()

    @contextmanager
    def _session_scope(self) -> Iterator[Session]:
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_db_path(self)->str:
        return self.resolve_default_db_path()

    @classmethod
    def resolve_default_db_path(cls) -> str:
        if os.name == "nt":  # Windows
            base_dir = os.getenv('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        else:
            base_dir = os.path.expanduser(f'~/.{cls.DB_PATH_DIR.lower()}')
        
        

        # Path to your password DB
        db_path_dir = os.path.join(base_dir, cls.DB_PATH_DIR)

        # Ensure the directory exists
        pathlib.Path(db_path_dir).mkdir(parents=True, exist_ok=True)

        db_path_file = os.path.join(db_path_dir, cls.DB_FILE_NAME)
        return db_path_file

    def initializeDB(self) -> None:
        BaseModel.metadata.create_all(self.engine)
            
    def load_backup(self, backup_path:str):
        try:
            self._load_decrypt(backup_path=backup_path)
            self.engine.dispose()
            self.engine = create_engine(f"sqlite:///{self.maindb_path}", future=True)
            self.SessionLocal.configure(bind=self.engine)
            self.initializeDB()
        except Exception as ex:
            logging.error(str(ex))

    def _load_decrypt(self, backup_path:str)->None:
        try:
            with open(backup_path,"rb") as db_file:
                encrypted_db_file = db_file.read()
                nonce = encrypted_db_file[:16]
                tag = encrypted_db_file[16:32]
                data = encrypted_db_file[32:]
            decryptedDB:bytes = cp.decrypt(self.key,nonce=nonce,tag=tag,ciphertext=data)
            with open(self.maindb_path,"wb") as local_db_file:
                local_db_file.write(decryptedDB)
        except Exception as ex:
            logging.error(str(ex))


    def backup(self, backup_path:str, cleanup:bool = False):
        # Perform Encryption in memory then write to file
        backup_path_str = str(backup_path)
        with open(self.maindb_path,"rb") as local_db_file:
            plain_db_bytes = local_db_file.read()
        
        nonce,encrypted_db_bytes,tag = cp.encrypt(plain_db_bytes,self.key)
        with open(backup_path_str,"wb") as edb:
            edb.write(nonce+tag+encrypted_db_bytes)

        if cleanup:
            self.engine.dispose()

    def create_password_entry(self, password_entity:Password) -> Password:
        entry = Password(
            service=password_entity.service,
            username=password_entity.username,
            email=password_entity.email,
            password=password_entity.password,
            tag=password_entity.tag,
            nonce=password_entity.nonce,
            link=password_entity.link,
            note=password_entity.note,
            category=password_entity.category,
        )
        with self._session_scope() as session:
            session.add(entry)
            session.flush()
            session.refresh(entry)
            return entry

    def get_password_by_id(self,pid: int) -> Optional[Password]:
        with self._session_scope() as session:
            return session.get(Password, pid)

    def get_passwords_by_service(self,service: str) -> list[Password]:
        with self._session_scope() as session:
            stmt = select(Password).where(Password.service.like(f"%{service}%"))
            return list(session.scalars(stmt).all())

    def get_all_passwords(
        self,
        page: int | None = None,
        size: int | None = None,
        sort_by: str = "pid",
        sort_dir: str = "desc",
        service: str | None = None,
        category: str | None = None,
    ) -> list[Password]:
        sort_column_map = {
            "pid": Password.pid,
            "service": Password.service,
            "username": Password.username,
            "category": Password.category,
            "pcreated": Password.pcreated,
            "pupdated": Password.pupdated,
        }
        sort_column = sort_column_map.get(sort_by, Password.pid)
        sort_expr = sort_column.desc() if sort_dir.lower() == "desc" else sort_column.asc()

        with self._session_scope() as session:
            stmt = select(Password).order_by(sort_expr)
            if service:
                stmt = stmt.where(Password.service.ilike(f"%{service}%"))
            if category:
                stmt = stmt.where(Password.category.ilike(category))
            if page is not None and size is not None:
                offset = max(page - 1, 0) * max(size, 1)
                stmt = stmt.offset(offset).limit(max(size, 1))
            return list(session.scalars(stmt).all())

    def update_password_entry(self, pid: int, **updates) -> Optional[Password]:
        with self._session_scope() as session:
            entry = session.get(Password, pid)
            if not entry:
                return None

            for key, value in updates.items():
                if hasattr(entry, key) and value is not None:
                    setattr(entry, key, value)

            entry.pupdated = datetime.now(timezone.utc)
            session.flush()
            session.refresh(entry)
            return entry

    def delete_password_by_id(self, pid: int) -> bool:
        with self._session_scope() as session:
            entry = session.get(Password, pid)
            if not entry:
                return False

            session.delete(entry)
            return True

    def close(self) -> None:
        self.engine.dispose()

    def count_passwords(self, service: str | None = None, category: str | None = None) -> int:
        with self._session_scope() as session:
            stmt = select(func.count(Password.pid))
            if service:
                stmt = stmt.where(Password.service.ilike(f"%{service}%"))
            if category:
                stmt = stmt.where(Password.category.ilike(category))
            return int(session.scalar(stmt) or 0)