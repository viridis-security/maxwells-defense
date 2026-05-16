# maxwells-defense (Python)

Adaptive proof-of-work defense for AI agents. Asymmetric thermodynamic cost: attackers dissipate energy in `O(2^d)` expected work; defenders verify in `O(1)`.

Reference implementation of **T-IB-09 (Adversarial Dissipation Theorem)** from the Intelligence Bound corpus — Aristotle-verified 2026-05-10.

## Install

```bash
pip install maxwells-defense
```

## Use

```python
from fastapi import FastAPI
from maxwells_defense.middleware import FastAPIMaxwellMiddleware
from maxwells_defense.core import StaticDifficultyOracle
import secrets

app = FastAPI()
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=secrets.token_bytes(32),
    difficulty_oracle=StaticDifficultyOracle(difficulty=18),
    protect_path_prefix="/api/",
)

@app.get("/api/hello")
def hello():
    return {"ok": True}
```

Full documentation, theorems, and the JavaScript client live in the parent reference SDK:

**https://github.com/viridis-security/maxwells-defense**

## License

Apache-2.0. See LICENSE in the parent repository.
