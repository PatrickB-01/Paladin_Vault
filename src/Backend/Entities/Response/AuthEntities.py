from pydantic import BaseModel
from enum import Enum, IntEnum


class EDescription(str,Enum):
    found = "Key found"
    notfound = "Key not found"

class UsbKeyStatus(BaseModel):
    status:bool = False
    description:EDescription = EDescription.notfound

class jwtObject(BaseModel):
    iss: str|None
    sub: str
    iat: int|None
    exp: int|None