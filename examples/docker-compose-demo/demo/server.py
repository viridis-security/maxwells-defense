"""Demo server: Maxwell's Defense in front of FastAPI."""
import os
import secrets

from fastapi import FastAPI

from maxwells_defense.core import StaticDifficultyOracle
from maxwells_defense.middleware import FastAPIMaxwellMiddleware

SECRET = secrets.token_bytes(32)
DIFFICULTY = int(os.environ.get("MAXWELL_DIFFICULTY", "14"))

app = FastAPI(title="Maxwell's Defense demo")
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    difficulty_oracle=StaticDifficultyOracle(difficulty=DIFFICULTY),
    protect_path_prefix="/api/",
)


@app.get("/")
def public():
    return {
        "status": "public",
        "note": "GET /api/hello to see the Maxwell challenge in action.",
    }


@app.get("/api/hello")
def protected():
    return {
        "status": "ok",
        "note": "You solved the challenge. This handler ran.",
    }
