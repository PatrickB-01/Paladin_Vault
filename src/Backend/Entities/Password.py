import datetime
from peewee import Model,BlobField,CharField,TextField,AutoField,TimestampField,SqliteDatabase
from playhouse.sqlite_ext import SqliteExtDatabase
from enum import Enum


PasswordDB:SqliteExtDatabase = SqliteExtDatabase(None)


# class syntax
class Categories(Enum):
    RED = 1
    GREEN = 2
    BLUE = 3


class BaseModel(Model):
    class Meta:
        database = PasswordDB

class Password(BaseModel):
    pid = AutoField(null = True,unique=True,primary_key = True)
    service = TextField(index = True)
    username = TextField(index = True)
    password = BlobField()
    tag =  BlobField()
    nonce = BlobField()
    link = TextField(null = True,default=None)
    category = TextField(null = True,default=None)
    note = CharField(null = True,max_length=1000)
    pcreated =  TimestampField(default=datetime.datetime.now,null = True)
    pupdated =  TimestampField(null = True)