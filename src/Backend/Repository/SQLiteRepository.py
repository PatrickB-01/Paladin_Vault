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

    def __init__(self, maindb_path:str, key:bytes) -> None:
        self.maindb_path = maindb_path
        self.key = key
        self.database = SqliteExtDatabase(None)
        self.initializeDB()

    def __del__(self):
        if self.database:
            self._flush_encrypt(cleanup=True)

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
            PasswordDB.init(self.database)
        except Exception as ex:
            logging.error(str(ex))

    def _load_decrypt(self, backup_path:str)->None:
        try:
            with open(backup_path,"rb") as db_file:
                encrypted_db_file = db_file.read()
                nonce = encrypted_db_file[:15]
                tag = encrypted_db_file[15:31]
                data = encrypted_db_file[31:]
            decryptedDB:bytes = cp.decrypt(self.key,nonce=nonce,tag=tag,ciphertext=data)
            with open(self.maindb_path,"wb") as local_db_file:
                local_db_file.write(decryptedDB)
        except Exception as ex:
            logging.error(str(ex))


    def _backup_encrypt(self, backup_path:str, cleanup:bool = False):
        # Perform Encryption in memory then write to file
        with open(self.maindb_path,"rb") as local_db_file:
            plain_db_bytes = local_db_file.read()
        
        nonce,encrypted_db_bytes,tag = cp.encrypt(plain_db_bytes,self.key)
        with open(backup_path,"wb") as edb:
            edb.write(nonce+tag+encrypted_db_bytes)

        if cleanup:
            self.database.close()

    def create_password_entry(self, service: str, username: str, password: bytes, tag: bytes, nonce: bytes, link: Optional[str] = None, note: Optional[str] = None) -> Password:
        return Password.create(
            service=service,
            username=username,
            password=password,
            tag=tag,
            nonce=nonce,
            link=link,
            note=note
        )

    def get_password_by_id(self,pid: int) -> Optional[Password]:
        try:
            return Password.get(Password.pid == pid)
        except Password.DoesNotExist:
            return None

    def get_passwords_by_service(self,service: str) -> list[Password]:
        return list(Password.select().where(Password.service ** service))

    def get_all_passwords(self) -> list[Password]:
        return list(Password.select())