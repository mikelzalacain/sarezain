"""API local del panel (solo escucha en 127.0.0.1)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, netinfo, safety, scanner, storage

WEB = Path(__file__).parent / "web"

app = FastAPI(title="Sarezain", version=__version__, docs_url=None, redoc_url=None)

state: dict = {"status": "idle", "phase": None, "label": None, "progress": 0.0, "error": None, "scan_id": None}
_task: asyncio.Task | None = None


class ScanRequest(BaseModel):
    network: str | None = None


@app.get("/api/info")
def info():
    local = netinfo.detect()
    return {"version": __version__, "local": local.to_dict()}


@app.get("/api/state")
def get_state():
    return state


@app.post("/api/scan", status_code=202)
async def start_scan(req: ScanRequest):
    global _task
    if _task and not _task.done():
        raise HTTPException(409, "Ya hay un escaneo en curso.")
    if req.network:
        try:
            safety.validate_network(req.network)
        except safety.UnsafeTargetError as exc:
            raise HTTPException(400, str(exc)) from exc

    def progress(phase, label, value):
        state.update(phase=phase, label=label, progress=round(value, 3))

    async def run():
        state.update(status="running", error=None, progress=0.0, phase="discovery",
                     label="Preparando", scan_id=None)
        try:
            result = await scanner.run_scan(req.network, progress)
            state.update(status="done", scan_id=result["id"])
        except Exception as exc:  # se muestra en el panel
            state.update(status="error", error=str(exc) or type(exc).__name__)

    _task = asyncio.create_task(run())
    return {"ok": True}


@app.get("/api/scans")
def scans():
    return storage.list_scans()


@app.get("/api/scans/latest")
def latest_scan():
    scan = storage.latest()
    if not scan:
        raise HTTPException(404, "Todavía no hay escaneos.")
    return scan


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = storage.load(scan_id)
    if not scan:
        raise HTTPException(404, "Escaneo no encontrado.")
    return scan


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="web")
