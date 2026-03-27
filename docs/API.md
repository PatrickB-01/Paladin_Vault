# Paladin Vault API Reference

## Base URL

- Canonical base path: `/api/v1`
- Compatibility aliases: `/auth/*`, `/vault/*`, `/health`

## Versioning and Deprecation

Unversioned compatibility aliases return the following headers:

- `Deprecation: true`
- `Sunset: Wed, 31 Dec 2026 23:59:59 GMT`
- `Link: </api/v1>; rel="successor-version"`

## Authentication

### Token Model

Use bearer token authentication after login:

- Header: `Authorization: Bearer <access_token>`

### First-Time API Quick Start

This flow creates a new vault, uses the returned token to create one password entry, then logs out.

Step 1: Register and create a new vault.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "master_password": "my-very-strong-password",
    "key_file_path": "D:/keys/key.bin",
    "db_path": "D:/vaults/PaladinVault.db",
    "use_usb_key": false,
    "overwrite_existing": false
  }'
```

Example response:

```json
{
  "access_token": "P8xQ6sY...",
  "token_type": "bearer",
  "key_file_path": "D:/keys/key.bin",
  "db_path": "D:/vaults/PaladinVault.db",
  "message": "Vault created successfully."
}
```

Step 2: Create a password entry using the token from step 1.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/vault/passwords" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "service": "discord",
    "username": "paladin_user",
    "password": "my-secret-password",
    "email": "user@example.com",
    "category": "social"
  }'
```

Step 3: Logout.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer <access_token>"
```

Tip:

- For later sessions, use `POST /api/v1/auth/token` with the same `master_password`, `key_file_path`, and optional `db_path`.

### Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| POST | `/api/v1/auth/token` | No | Authenticate with master password + key file and get access token. |
| POST | `/api/v1/auth/register` | No | Create a new vault (key + DB) and get access token. |
| POST | `/api/v1/auth/logout` | Yes | Invalidate active token session and clear server-side key state. |
| GET | `/api/v1/auth/usb/check?filename=key.bin` | No | Check removable drives for key file. |

### Request/Response Schemas

#### POST `/api/v1/auth/token`

Request body:

```json
{
  "master_password": "your-master-password",
  "key_file_path": "D:/keys/key.bin",
  "require_usb": false
}
```

Success response:

```json
{
  "access_token": "P8xQ6sY...",
  "token_type": "bearer"
}
```

Failure response (401):

```json
{
  "detail": "Login failed: ..."
}
```

#### POST `/api/v1/auth/register`

Request body:

```json
{
  "master_password": "my-very-strong-password",
  "key_file_path": "D:/keys/key.bin",
  "db_path": "D:/vaults/PaladinVault.db",
  "use_usb_key": false,
  "overwrite_existing": false
}
```

Field notes:

- `master_password`: required, minimum length is 8.
- `key_file_path`: required output path for new key file.
- `db_path`: optional custom vault DB path. If omitted, app default path is used.
- `use_usb_key`: when true, `key_file_path` must be on removable media.
- `overwrite_existing`: when true, existing key/db targets may be replaced.

Success response:

```json
{
  "access_token": "P8xQ6sY...",
  "token_type": "bearer",
  "key_file_path": "D:/keys/key.bin",
  "db_path": "D:/vaults/PaladinVault.db",
  "message": "Vault created successfully."
}
```

Common failure responses:

- `400`: invalid password/configuration or USB path not removable.
- `409`: key or DB target already exists and overwrite is not enabled.
- `500`: vault creation failed unexpectedly.

#### GET `/api/v1/auth/usb/check`

Success response:

```json
{
  "status": true,
  "description": "Key found"
}
```

## Vault

### Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| GET | `/api/v1/vault/passwords` | Yes | List passwords with pagination, sorting, and filtering. |
| GET | `/api/v1/vault/passwords/{pid}` | Yes | Get one password entry by ID. |
| GET | `/api/v1/vault/passwords/search?service=...` | Yes | Deprecated legacy search endpoint. |
| POST | `/api/v1/vault/passwords` | Yes | Create password entry (API encrypts plaintext password before storage). |
| PUT | `/api/v1/vault/passwords/{pid}` | Yes | Update existing password entry. |
| DELETE | `/api/v1/vault/passwords/{pid}` | Yes | Delete password entry. |
| POST | `/api/v1/vault/backup` | Yes | Create encrypted vault backup file. |
| POST | `/api/v1/vault/restore` | Yes | Restore encrypted vault backup file. |

### GET `/api/v1/vault/passwords` Query Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| page | integer | No | 1 | 1-based page number. |
| size | integer | No | 50 | Page size, max 500. |
| sort_by | string | No | `pid` | One of: `pid`, `service`, `username`, `category`, `pcreated`, `pupdated`. |
| sort_dir | string | No | `desc` | One of: `asc`, `desc`. |
| service | string | No | null | Case-insensitive partial match filter on service. |
| category | string | No | null | Case-insensitive exact match filter on category. |

Success response:

```json
{
  "items": [
    {
      "pid": 12,
      "service": "discord",
      "username": "paladin_user",
      "email": "user@example.com",
      "password": "my-secret-password",
      "link": "https://discord.com",
      "category": "social",
      "note": "primary account"
    }
  ],
  "page": 1,
  "size": 50,
  "total": 1
}
```

### POST `/api/v1/vault/passwords`

Request body:

```json
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

### PUT `/api/v1/vault/passwords/{pid}`

Request body (partial updates allowed):

```json
{
  "username": "paladin_user_updated",
  "password": "new-secret-password",
  "category": "social"
}
```

### POST `/api/v1/vault/backup`

Request body:

```json
{
  "backup_path": "D:/backups/paladin_backup.bin"
}
```

### POST `/api/v1/vault/restore`

Request body:

```json
{
  "backup_path": "D:/backups/paladin_backup.bin"
}
```

## System

| Method | Path | Auth Required | Description |
|---|---|---|---|
| GET | `/api/v1/health` | No | Service health endpoint. |

## Error Model

Most error responses follow:

```json
{
  "detail": "Error message"
}
```
