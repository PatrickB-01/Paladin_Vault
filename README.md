# Paladin_Vault

![logo](./assets/logo.png)

## Features

- Store Passwords securely
- Military grade encryption
- USB Key
- Backup and restore functionality
- SQLAlchemy-backed local vault storage
- FastAPI API for external/testing integrations
- PyQt6 desktop UI with vault CRUD workflow

## How to use

### 1. Install dependencies

```powershell
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

### 2. Run desktop app

```powershell
./.venv/Scripts/python.exe src/main.py --mode qt
```

### First-Time Vault Setup (Qt)

If this is your first time using Paladin Vault:

1. Launch the Qt app.
2. In the first dialog, choose **Create New Vault**.
3. Enter and confirm a new master password.
4. Choose a key file path (for example `D:/keys/key.bin`).
5. Choose a vault DB path (for example `D:/vaults/PaladinVault.db`).
6. Optionally enable USB mode and select a removable-drive key path.
7. Click **Create Vault**.

Notes:

- If key/DB files already exist, you will get an overwrite confirmation prompt.
- After creation, the main vault window opens immediately.
- On later launches, choose **Login to Existing Vault** and use the same key file path and master password.

### 3. Run API server

```powershell
./.venv/Scripts/python.exe src/main.py --mode api --host 127.0.0.1 --port 8000
```

## API Migration Guide

### Canonical base path

- Use `/api/v1` for all new client integrations.
- Example: `/api/v1/auth/token`, `/api/v1/vault/passwords`.

### Compatibility aliases

- Legacy unversioned routes (`/auth/*`, `/vault/*`, `/health`) are still available for compatibility.
- These alias responses include migration headers:
	- `Deprecation: true`
	- `Sunset: Wed, 31 Dec 2026 23:59:59 GMT`
	- `Link: </api/v1>; rel="successor-version"`

### Migration examples

Login (versioned):

```http
POST /api/v1/auth/token
Content-Type: application/json

{
	"master_password": "your-master-password",
	"key_file_path": "D:/keys/key.bin",
	"require_usb": false
}
```

Create new vault (versioned):

```http
POST /api/v1/auth/register
Content-Type: application/json

{
	"master_password": "my-very-strong-password",
	"key_file_path": "D:/keys/key.bin",
	"db_path": "D:/vaults/PaladinVault.db",
	"use_usb_key": false,
	"overwrite_existing": false
}
```

Create password entry (versioned):

```http
POST /api/v1/vault/passwords
Authorization: Bearer <token>
Content-Type: application/json

{
	"service": "discord",
	"username": "paladin_user",
	"password": "my-secret-password",
	"email": "user@example.com",
	"link": "https://discord.com",
	"category": "social",
	"note": "primary account"
}
```

List with paging/filtering/sorting:

```http
GET /api/v1/vault/passwords?page=1&size=20&sort_by=service&sort_dir=asc&service=disc&category=social
Authorization: Bearer <token>
```

Full endpoint reference: [docs/API.md](docs/API.md)
First-time API workflow (register -> create entry -> logout): see **First-Time API Quick Start** in [docs/API.md](docs/API.md)

Qt manual verification checklist for create-vault flow: [docs/QT_CREATE_VAULT_CHECKLIST.md](docs/QT_CREATE_VAULT_CHECKLIST.md)

## Future work

- Add API rate limiting and lockout policies
- Add export/import UI flows
- Add packaged desktop releases

