from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
import jwt

class PasswordController:
    SECRET_KEY = "super-secret-key"  # Same secret as in AuthRouter

    def __init__(self):
        self.router = APIRouter()
        self.router.get("/")(self.get_passwords)
        self.router.post("/")(self.add_password)
        self.router.delete("/{service}")(self.delete_password)

        # In-memory password list (replace with a database later)
        self.passwords_db = []

    def get_current_user(self, token: str):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired.")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token.")

    async def get_passwords(self, token: str):
        self.get_current_user(token)
        return self.passwords_db

    async def add_password(self, password: dict, token: str):
        self.get_current_user(token)
        self.passwords_db.append(password)
        return {"message": "Password added."}

    async def delete_password(self, service: str, token: str):
        self.get_current_user(token)
        self.passwords_db = [pw for pw in self.passwords_db if pw["service"] != service]
        return {"message": "Password deleted."}
