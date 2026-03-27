from fastapi import FastAPI
from fastapi import Request

from Backend.Controller.AuthController import AuthenticationController
from Backend.Controller.PasswordController import PasswordController


def create_app() -> FastAPI:
    app = FastAPI(title="Paladin Vault API", version="0.1.0")

    alias_prefixes = ("/auth", "/vault", "/health")

    @app.middleware("http")
    async def add_deprecation_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        is_alias = path.startswith(alias_prefixes) and not path.startswith("/api/v1")
        if is_alias:
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = "Wed, 31 Dec 2026 23:59:59 GMT"
            response.headers["Link"] = '</api/v1>; rel="successor-version"'
        return response

    auth_controller = AuthenticationController()
    password_controller = PasswordController()

    # Primary stable versioned surface.
    app.include_router(auth_controller.router, prefix="/api/v1")
    app.include_router(password_controller.router, prefix="/api/v1")

    # Backward-compatible aliases for existing clients.
    app.include_router(auth_controller.router, include_in_schema=False)
    app.include_router(password_controller.router, include_in_schema=False)

    @app.get("/api/v1/health", tags=["system"], summary="Health check")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/health", include_in_schema=False)
    async def health_compat() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
