import sqlite3
from peewee import SqliteDatabase
from playhouse.sqlite_ext import CSqliteExtDatabase
import os
import pathlib
from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.Entities.Password import Password,PasswordDB
import logging
from typing import Any,Optional

class SQLiteRepository:

    MODELS = [Password]

    def __init__(self, maindb_path:str, key:bytes) -> None:
        self.maindb_path = maindb_path
        self.key = key
        #self.database = sqlite3.connect(":memory:")
        self.initializeDB()

    def __del__(self):
        if self.database:
            self._flush_encrypt(cleanup=True)

    def initializeDB(self) -> None:
        if pathlib.Path(self.maindb_path).exists():
            self._load_decrypt()
        else:
            PasswordDB.init(":memory:")
            #t = SqliteDatabase(database=self.database)
            PasswordDB.create_tables([Password])

    def _load_decrypt(self):
        try:
            with open(self.maindb_path,"rb") as db_file:
                encrypted_db_file = db_file.read()
                nonce = encrypted_db_file[:15]
                tag = encrypted_db_file[15:31]
                data = encrypted_db_file[31:]
            decryptedDB:bytes = cp.decrypt(self.key,nonce=nonce,tag=tag,ciphertext=data)
            PasswordDB.backup_to_file(self.maindb_path)
            PasswordDB.
            self.database.deserialize(decryptedDB)
            PasswordDB.init(self.database)
        except Exception as ex:
            logging.error(str(ex))


    def _flush_encrypt(self,cleanup:bool = False):
        # Perform Encryption in memory then write to file
        plain_db_bytes = self.database.serialize()
        encrypted_db_bytes = cp.encrypt(plain_db_bytes,self.key)
        with open(self.maindb_path,"wb") as edb:
            edb.write(encrypted_db_bytes)

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