from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta,timezone
import jwt
import os
import hashlib
from Entities.Response.AuthEntities import *


class AuthenticationController:

    SECRET_KEY = "super-secret-key"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    MASTER_PASSWORD_HASH = hashlib.sha256(b"MyStrongPassword123!").hexdigest()

    def __init__(self):
        self.router = APIRouter()
        self.router.post("/token")(self.login)
        self.router.get("/usb/check")(self.check_usb_key)

    async def check_usb_key(self) -> UsbKeyStatus:
        response:UsbKeyStatus = UsbKeyStatus()
        isUsbKeyPresent = False
        if isUsbKeyPresent:
            response.status = True
            response.description = EDescription.found
            return response
        return response
    
    def create_access_token(self, data: jwtObject, expires_delta: timedelta = None):
        to_encode = data.model_dump(exclude_none=True,exclude_unset=True)
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def login(self, password: str):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash == self.MASTER_PASSWORD_HASH and self.check_usb_key():
            access_token = self.create_access_token(
                jwtObject(sub="user"), timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            return {"access_token": access_token, "token_type": "bearer"}

        raise HTTPException(status_code=401, detail="Invalid password or USB not detected.")
    

