from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import db
from cairn.server.routers import claims, export, hints, intents, projects, settings, verification

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(claims.router)
app.include_router(verification.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(export.router)


@app.get("/", include_in_schema=False)
def index():
    """Cairn v2 verification console is the product front page."""
    return FileResponse(STATIC_DIR / "verify.html")


@app.get("/graph", include_in_schema=False)
def graph_console():
    """v1 fact/intent graph view — debug lens over any project's board."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/verify", include_in_schema=False)
def verify_console():
    """Alias of / (kept for bookmarks)."""
    return FileResponse(STATIC_DIR / "verify.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
