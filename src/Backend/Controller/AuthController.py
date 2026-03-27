import os
import secrets

import psutil
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field

from Backend.CryptoUtils.CryptoPaladinExceptions import (
    InvalidPasswordException,
    InvalidVaultConfigurationException,
    InvalidUSBPathException,
    VaultAlreadyExistsException,
    VaultCreationException,
)
from Backend.Entities.Response.AuthEntities import (
    CreateVaultResponse,
    EDescription,
    UsbKeyStatus,
)
from PaladinVaultLogic.PaladinVaultController import PaladinVaultController


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
ACTIVE_SESSIONS: dict[str, PaladinVaultController] = {}


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "master_password": "your-master-password",
                "key_file_path": "D:/keys/key.bin",
                "db_path": "D:/vaults/PaladinVault.db",
                "require_usb": False,
            }
        }
    )

    master_password: str = Field(description="Master password used to derive the vault encryption key.")
    key_file_path: str = Field(description="Path to the key file containing salt and hash metadata.")
    db_path: str | None = Field(default=None, description="Optional custom SQLite database file path.")
    require_usb: bool = Field(default=False, description="When true, USB key presence is required.")


class RegisterVaultRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "master_password": "my-very-strong-password",
                "key_file_path": "D:/keys/key.bin",
                "db_path": "D:/vaults/PaladinVault.db",
                "use_usb_key": False,
                "overwrite_existing": False,
            }
        }
    )

    master_password: str = Field(description="Master password used to create a new vault key and encryption key.")
    key_file_path: str = Field(description="Output path for generated key file.")
    db_path: str | None = Field(default=None, description="Optional custom SQLite database file path.")
    use_usb_key: bool = Field(default=False, description="When true, key_file_path must be on removable media.")
    overwrite_existing: bool = Field(default=False, description="When true, existing key/db files at target paths are replaced.")


class TokenResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "P8xQ6sY...",
                "token_type": "bearer",
            }
        }
    )

    access_token: str = Field(description="Session token to send as Bearer token in Authorization header.")
    token_type: str = Field(default="bearer", description="Authentication scheme.")


class AuthenticationController:
    def __init__(self):
        self.router = APIRouter(prefix="/auth", tags=["auth"])
        self.router.post(
            "/token",
            response_model=TokenResponse,
            summary="Authenticate and create session token",
            description="Validates master password and key file, then returns a bearer token.",
        )(self.login)
        self.router.post(
            "/register",
            response_model=CreateVaultResponse,
            summary="Create a new vault",
            description="Creates a new key file and vault database, then returns a bearer token.",
        )(self.register)
        self.router.post(
            "/logout",
            summary="Invalidate current session",
            description="Destroys the current bearer-token session and clears server-side key state.",
        )(self.logout)
        self.router.get(
            "/usb/check",
            response_model=UsbKeyStatus,
            summary="Check USB key availability",
            description="Scans removable drives for a key file by name.",
        )(self.check_usb_key)

    def _scan_usb_once(self, filename: str) -> str | None:
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                if "removable" not in part.opts.lower():
                    continue
            else:
                if not (part.mountpoint.startswith("/media") or part.mountpoint.startswith("/run/media")):
                    continue

            candidate = os.path.join(part.mountpoint, filename)
            if os.path.isfile(candidate):
                return candidate
        return None

    async def check_usb_key(self, filename: str = "key.bin") -> UsbKeyStatus:
        found = self._scan_usb_once(filename)
        if found:
            return UsbKeyStatus(status=True, description=EDescription.found)
        return UsbKeyStatus(status=False, description=EDescription.notfound)

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

    async def login(self, request: LoginRequest) -> TokenResponse:
        if request.require_usb:
            key_filename = os.path.basename(request.key_file_path)
            usb_status = await self.check_usb_key(filename=key_filename)
            if not usb_status.status:
                raise HTTPException(status_code=401, detail="USB key is required but was not detected.")

        controller = PaladinVaultController()
        try:
            controller.login(request.master_password, request.key_file_path, db_path=request.db_path)
        except Exception as ex:
            raise HTTPException(status_code=401, detail=f"Login failed: {str(ex)}")

        token = secrets.token_urlsafe(32)
        ACTIVE_SESSIONS[token] = controller
        return TokenResponse(access_token=token)

    async def register(self, request: RegisterVaultRequest) -> CreateVaultResponse:
        if request.use_usb_key and not self._is_path_on_removable(request.key_file_path):
            raise HTTPException(status_code=400, detail="USB key path must be located on removable media.")

        controller = PaladinVaultController()
        try:
            controller.create_new_vault(
                master_password=request.master_password,
                key_file_path=request.key_file_path,
                db_path=request.db_path,
                use_usb_key=request.use_usb_key,
                overwrite_existing=request.overwrite_existing,
            )
        except VaultAlreadyExistsException as ex:
            raise HTTPException(status_code=409, detail=str(ex)) from ex
        except (InvalidUSBPathException, InvalidPasswordException, InvalidVaultConfigurationException) as ex:
            raise HTTPException(status_code=400, detail=str(ex)) from ex
        except VaultCreationException as ex:
            raise HTTPException(status_code=500, detail=str(ex)) from ex
        except Exception as ex:
            raise HTTPException(status_code=500, detail=f"Vault creation failed: {str(ex)}") from ex

        token = secrets.token_urlsafe(32)
        ACTIVE_SESSIONS[token] = controller
        return CreateVaultResponse(
            access_token=token,
            key_file_path=controller.key_file_path or os.path.abspath(request.key_file_path),
            db_path=controller.db_path or "",
        )

    async def logout(self, token: str = Depends(oauth2_scheme)) -> dict:
        controller = ACTIVE_SESSIONS.pop(token, None)
        if controller:
            controller.logout()
        return {"message": "Logged out."}


def get_authenticated_controller(token: str = Depends(oauth2_scheme)) -> PaladinVaultController:
    controller = ACTIVE_SESSIONS.get(token)
    if not controller:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return controller
