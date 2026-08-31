"""seclens — composition root and CLI entry point."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from seclens.api.dependencies import initialize_db
from seclens.api.router import router

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await initialize_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="seclens",
        description="Security search engine — scorecard, vulnerabilities, and patch tracking",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(router)

    if _FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=_FRONTEND_DIR / "static"), name="static")

        from fastapi.responses import FileResponse

        @app.get("/")
        async def serve_frontend():
            return FileResponse(_FRONTEND_DIR / "index.html")

    return app


def cli():
    parser = argparse.ArgumentParser(prog="seclens", description="seclens CLI")
    sub = parser.add_subparsers(dest="command")

    serve_parser = sub.add_parser("serve", help="Start the web server")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")

    sync_parser = sub.add_parser("sync", help="Sync vulnerability data")
    sync_parser.add_argument(
        "--max-vulns",
        type=int,
        default=10000,
        help="Maximum vulnerabilities to sync from NVD",
    )
    sync_parser.add_argument("--source", choices=["all", "nvd", "epss", "kev"], default="all")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.command == "serve":
        uvicorn.run(
            "seclens.main:create_app",
            factory=True,
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    elif args.command == "sync":
        asyncio.run(_run_sync(args))
    else:
        parser.print_help()
        sys.exit(1)


async def _run_sync(args):
    from seclens.api.dependencies import get_sync_service

    await initialize_db()
    svc = get_sync_service()

    if args.source == "all":
        results = await svc.sync_all(max_vulns=args.max_vulns)
    elif args.source == "nvd":
        results = {"nvd": await svc.sync_nvd(max_vulns=args.max_vulns)}
    elif args.source == "epss":
        results = {"epss": await svc.sync_epss()}
    elif args.source == "kev":
        results = {"kev": await svc.sync_kev()}

    print(f"\nSync complete: {results}")


if __name__ == "__main__":
    cli()
