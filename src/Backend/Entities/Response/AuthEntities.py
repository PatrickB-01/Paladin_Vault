from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EDescription(str,Enum):
    found = "Key found"
    notfound = "Key not found"

class UsbKeyStatus(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": True,
                "description": "Key found",
            }
        }
    )

    status: bool = Field(default=False, description="True when the requested USB key file is detected.")
    description: EDescription = Field(default=EDescription.notfound, description="Human-readable detection status.")

class jwtObject(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "iss": "paladin-vault",
                "sub": "user",
                "iat": 1742976000,
                "exp": 1742979600,
            }
        }
    )

    iss: str | None = Field(default=None)
    sub: str
    iat: int | None = Field(default=None)
    exp: int | None = Field(default=None)


class CreateVaultRequest(BaseModel):
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
    key_file_path: str = Field(description="Output path for the generated key file.")
    db_path: str | None = Field(default=None, description="Optional custom SQLite database file path.")
    use_usb_key: bool = Field(default=False, description="When true, key_file_path must be on removable media.")
    overwrite_existing: bool = Field(default=False, description="When true, existing key/db files at target paths are replaced.")


class CreateVaultResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "P8xQ6sY...",
                "token_type": "bearer",
                "key_file_path": "D:/keys/key.bin",
                "db_path": "D:/vaults/PaladinVault.db",
                "message": "Vault created successfully.",
            }
        }
    )

    access_token: str = Field(description="Session token to send as Bearer token in Authorization header.")
    token_type: str = Field(default="bearer", description="Authentication scheme.")
    key_file_path: str = Field(description="Resolved key file path used for the new vault.")
    db_path: str = Field(description="Resolved SQLite database path used for the new vault.")
    message: str = Field(default="Vault created successfully.", description="Creation result message.")