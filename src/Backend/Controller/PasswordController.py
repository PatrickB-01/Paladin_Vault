from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from Backend.Controller.AuthController import get_authenticated_controller
from Backend.Entities.Password import Password
from PaladinVaultLogic.PaladinVaultController import PaladinVaultController


class PasswordCreateRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "service": "discord",
                "username": "paladin_user",
                "password": "my-secret-password",
                "email": "user@example.com",
                "link": "https://discord.com",
                "category": "social",
                "note": "primary account",
            }
        }
    )

    service: str = Field(description="Service/app name for this credential.")
    username: str = Field(description="Username or account identifier.")
    password: str = Field(description="Plaintext password. API encrypts this before storage.")
    email: str | None = Field(default=None, description="Optional account email.")
    link: str | None = Field(default=None, description="Optional service URL.")
    category: str | None = Field(default=None, description="Optional category label.")
    note: str | None = Field(default=None, description="Optional freeform note.")


class PasswordUpdateRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "paladin_user_updated",
                "password": "new-secret-password",
                "category": "social",
            }
        }
    )

    service: str | None = Field(default=None, description="Updated service name.")
    username: str | None = Field(default=None, description="Updated username.")
    password: str | None = Field(default=None, description="Updated plaintext password.")
    email: str | None = Field(default=None, description="Updated email value.")
    link: str | None = Field(default=None, description="Updated URL.")
    category: str | None = Field(default=None, description="Updated category.")
    note: str | None = Field(default=None, description="Updated note.")


class PasswordResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "pid": 12,
                "service": "discord",
                "username": "paladin_user",
                "email": "user@example.com",
                "password": "my-secret-password",
                "link": "https://discord.com",
                "category": "social",
                "note": "primary account",
            }
        }
    )

    pid: int = Field(description="Unique password entry ID.")
    service: str = Field(description="Service/app name.")
    username: str = Field(description="Username/account identifier.")
    email: str | None = Field(default=None, description="Account email.")
    password: str = Field(description="Decrypted password value for authenticated session use.")
    link: str | None = Field(default=None, description="Service URL.")
    category: str | None = Field(default=None, description="Category label.")
    note: str | None = Field(default=None, description="Optional note.")


class BackupRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"backup_path": "D:/backups/paladin_backup.bin"}})

    backup_path: str = Field(description="Target path for backup file or source path for restore.")


class PaginatedPasswordResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {
                        "pid": 12,
                        "service": "discord",
                        "username": "paladin_user",
                        "email": "user@example.com",
                        "password": "my-secret-password",
                        "link": "https://discord.com",
                        "category": "social",
                        "note": "primary account",
                    }
                ],
                "page": 1,
                "size": 50,
                "total": 1,
            }
        }
    )

    items: list[PasswordResponse] = Field(description="Page of password entries.")
    page: int = Field(description="Current page number.")
    size: int = Field(description="Requested page size.")
    total: int = Field(description="Total entries matching current filters.")


class PasswordController:
    def __init__(self):
        self.router = APIRouter(prefix="/vault", tags=["vault"])
        self.router.get(
            "/passwords",
            response_model=PaginatedPasswordResponse,
            summary="List vault entries",
            description="Returns paginated, sortable, and filterable password entries.",
        )(self.get_passwords)
        self.router.get(
            "/passwords/search",
            response_model=list[PasswordResponse],
            deprecated=True,
            summary="Legacy service search",
            description="Deprecated. Use /vault/passwords?service=<value> instead.",
        )(self.search_passwords)
        self.router.get(
            "/passwords/{pid}",
            response_model=PasswordResponse,
            summary="Get vault entry by ID",
        )(self.get_password_by_id)
        self.router.post(
            "/passwords",
            response_model=PasswordResponse,
            summary="Create vault entry",
        )(self.add_password)
        self.router.put(
            "/passwords/{pid}",
            response_model=PasswordResponse,
            summary="Update vault entry",
        )(self.update_password)
        self.router.delete(
            "/passwords/{pid}",
            summary="Delete vault entry",
        )(self.delete_password)
        self.router.post(
            "/backup",
            summary="Create encrypted vault backup",
        )(self.backup_vault)
        self.router.post(
            "/restore",
            summary="Restore encrypted vault backup",
        )(self.restore_vault)

    def _to_response(self, controller: PaladinVaultController, entity: Password) -> PasswordResponse:
        return PasswordResponse(
            pid=entity.pid,
            service=entity.service,
            username=entity.username,
            email=entity.email,
            password=controller.decrypt_password(entity),
            link=entity.link,
            category=entity.category,
            note=entity.note,
        )

    async def get_passwords(
        self,
        page: int = Query(1, ge=1, description="1-based page number."),
        size: int = Query(50, ge=1, le=500, description="Number of records per page (max 500)."),
        sort_by: Literal["pid", "service", "username", "category", "pcreated", "pupdated"] = Query(
            "pid", description="Field used for sorting."
        ),
        sort_dir: Literal["asc", "desc"] = Query("desc", description="Sort direction."),
        service: str | None = Query(None, description="Optional case-insensitive partial filter on service."),
        category: str | None = Query(None, description="Optional case-insensitive exact filter on category."),
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> PaginatedPasswordResponse:
        entities, total = controller.get_passwords_paginated(
            page=page,
            size=size,
            sort_by=sort_by,
            sort_dir=sort_dir,
            service=service,
            category=category,
        )
        items = [self._to_response(controller, entity) for entity in entities]
        return PaginatedPasswordResponse(items=items, page=page, size=size, total=total)

    async def get_password_by_id(
        self,
        pid: int,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> PasswordResponse:
        entity = controller.get_password_by_id(pid)
        if not entity:
            raise HTTPException(status_code=404, detail="Password entry not found.")
        return self._to_response(controller, entity)

    async def search_passwords(
        self,
        service: str,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> list[PasswordResponse]:
        entities, _ = controller.get_passwords_paginated(
            page=1,
            size=500,
            sort_by="service",
            sort_dir="asc",
            service=service,
        )
        return [self._to_response(controller, entity) for entity in entities]

    async def add_password(
        self,
        request: PasswordCreateRequest,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> PasswordResponse:
        created = controller.add_password_entry_controller(
            service=request.service,
            username=request.username,
            email=request.email,
            password=request.password,
            link=request.link,
            category=request.category,
            note=request.note,
        )
        return self._to_response(controller, created)

    async def update_password(
        self,
        pid: int,
        request: PasswordUpdateRequest,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> PasswordResponse:
        updated = controller.update_password_entry_controller(
            pid=pid,
            service=request.service,
            username=request.username,
            email=request.email,
            password=request.password,
            link=request.link,
            category=request.category,
            note=request.note,
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Password entry not found.")
        return self._to_response(controller, updated)

    async def delete_password(
        self,
        pid: int,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> dict:
        deleted = controller.delete_password_entry_controller(pid)
        if not deleted:
            raise HTTPException(status_code=404, detail="Password entry not found.")
        return {"message": "Password deleted."}

    async def backup_vault(
        self,
        request: BackupRequest,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> dict:
        controller.backup_vault(request.backup_path)
        return {"message": "Vault backup created.", "path": request.backup_path}

    async def restore_vault(
        self,
        request: BackupRequest,
        controller: PaladinVaultController = Depends(get_authenticated_controller),
    ) -> dict:
        repository = controller.get_repository()
        if not repository:
            raise HTTPException(status_code=500, detail="Repository is not initialized.")
        repository.load_backup(request.backup_path)
        return {"message": "Vault restored.", "path": request.backup_path}
