import argparse


def run_tk() -> None:
    import tkinter as tk

    from Frontend.PaladinVaultUI import LoginWindow

    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()


def run_qt() -> None:
    from Frontend.PaladinVaultQtUI import start_qt_ui

    start_qt_ui()


def run_api(host: str, port: int, reload: bool) -> None:
    import uvicorn

    uvicorn.run("Backend.api:app", host=host, port=port, reload=reload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Paladin Vault launcher")
    parser.add_argument(
        "--mode",
        choices=["qt", "tk", "api"],
        default="qt",
        help="Run desktop UI (qt/tk) or API server.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="API host for --mode api")
    parser.add_argument("--port", type=int, default=8000, help="API port for --mode api")
    parser.add_argument("--reload", action="store_true", help="Enable API auto-reload in api mode")

    args = parser.parse_args()

    if args.mode == "tk":
        run_tk()
    elif args.mode == "api":
        run_api(args.host, args.port, args.reload)
    else:
        run_qt()


if __name__ == "__main__":
    main()
