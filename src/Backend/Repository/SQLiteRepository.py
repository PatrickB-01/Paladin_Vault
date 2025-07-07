import sqlite3
from peewee import *
from peewee import SqliteDatabase
from playhouse.sqlite_ext import SqliteExtDatabase
import os
import pathlib
from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.Entities.Password import Password,PasswordDB
import logging
from typing import Any,Optional
import tempfile


class SQLiteRepository:

    MODELS = [Password]

    DB_PATH_DIR = "PaladinVault"
    DB_FILE_NAME = "PaladinVault.db"

    def __init__(self,key:bytes, maindb_path:str|None=None) -> None:

        if not maindb_path:
            self.maindb_path = self.get_db_path()

        self.key = key
        self.database = SqliteExtDatabase(None)
        self.initializeDB()

    def __del__(self):
        if self.database:
            self._flush_encrypt(cleanup=True)

    def get_db_path(self)->str:
        if os.name == "nt":  # Windows
            base_dir = os.getenv('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        else:
            base_dir = os.path.expanduser(f'~/.{self.DB_PATH_DIR.lower()}')
        
        

        # Path to your password DB
        db_path_dir = os.path.join(base_dir, self.DB_PATH_DIR)

        # Ensure the directory exists
        pathlib.Path(db_path_dir).mkdir(parents=True, exist_ok=True)

        db_path_file = os.path.join(db_path_dir, self.DB_FILE_NAME)
        return db_path_file

    def initializeDB(self) -> None:
        if pathlib.Path(self.maindb_path).exists():
            self.database.init(self.maindb_path)
            PasswordDB.init(self.maindb_path)
        else:
            self.database.init(self.maindb_path)
            PasswordDB.init(self.maindb_path)
            self.database.create_tables(self.MODELS)

    def _transfer_db_to_memory(self, db:bytes, temp_file_name:str=None) -> None:
        with tempfile.NamedTemporaryFile() as temp_file:
            pass
            
    def load_backup(self, backup_path:str):
        try:
            self._load_decrypt(backup_path=backup_path)
            self.database.init(self.maindb_path)
            PasswordDB.init(self.maindb_path)
        except Exception as ex:
            logging.error(str(ex))

    def _load_decrypt(self, backup_path:str)->None:
        try:
            with open(backup_path,"rb") as db_file:
                encrypted_db_file = db_file.read()
                nonce = encrypted_db_file[:16]
                tag = encrypted_db_file[16:32]
                print(nonce)
                print(tag)
                data = encrypted_db_file[32:]
            decryptedDB:bytes = cp.decrypt(self.key,nonce=nonce,tag=tag,ciphertext=data)
            with open(self.maindb_path,"wb") as local_db_file:
                local_db_file.write(decryptedDB)
        except Exception as ex:
            logging.error(str(ex))


    def backup(self, backup_path:str, cleanup:bool = False):
        # Perform Encryption in memory then write to file
        with open(self.maindb_path,"rb") as local_db_file:
            plain_db_bytes = local_db_file.read()
        
        nonce,encrypted_db_bytes,tag = cp.encrypt(plain_db_bytes,self.key)
        print(nonce)
        print(tag)
        with open(backup_path,"wb") as edb:
            edb.write(nonce+tag+encrypted_db_bytes)

        if cleanup:
            self.database.close()

    def create_password_entry(self, service: str, username: str, password: bytes, tag: bytes, nonce: bytes, 
                              link: str | None = None, 
                              note: str | None = None, 
                              category:str|None = None) -> Password:
        return Password.create(
            service=service,
            username=username,
            password=password,
            tag=tag,
            nonce=nonce,
            link=link,
            note=note,
            category=category
        )
    
    def create_password_entry(self, password_entity:Password) -> Password:
        return Password.create(
            service=password_entity.service,
            username=password_entity.username,
            password=password_entity.password,
            tag=password_entity.tag,
            nonce=password_entity.nonce,
            link=password_entity.link,
            note=password_entity.note,
            category=password_entity.category
        )

    def get_password_by_id(self,pid: int) -> Optional[Password]:
        try:
            return Password.get(Password.pid == pid)
        except Exception as ex:
            return None

    def get_passwords_by_service(self,service: str) -> list[Password]:
        return list(Password.select().where(Password.service ** service))

    def get_all_passwords(self) -> list[Password]:
        return list(Password.select())