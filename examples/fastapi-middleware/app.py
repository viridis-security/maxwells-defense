"""Minimal FastAPI integration.

Run:

    pip install fastapi uvicorn maxwells-defense
    uvicorn app:app --reload

Then:

    curl -i http://localhost:8000/api/hello       # 401 with challenge
    # solve with the JS client (../express-middleware/client.mjs) or
    # the Python solve_challenge() helper.
"""

import secrets

from fastapi import FastAPI

from maxwells_defense.middleware import FastAPIMaxwellMiddleware
from maxwells_defense.core import StaticDifficultyOracle

# In production: load from secrets manager. Never hardcode.
SECRET = secrets.token_bytes(32)

app = FastAPI()
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    difficulty_oracle=StaticDifficultyOracle(difficulty=14),
    protect_path_prefix="/api/",
    ttl_seconds=300,
)


@app.get("/")
def public():
    return {"status": "public, no challenge required"}


@app.get("/api/hello")
def protected():
    return {"status": "you solved the challenge — welcome"}
