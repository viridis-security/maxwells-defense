# maxwells-defense (Python)

SHA-256 proof-of-work defense for AI agents. Verification work is constant in difficulty for fixed input lengths. Fresh solutions take `2^d` expected classical hash queries under a random-oracle model. See the [implementation](maxwells_defense/core.py), [regression tests](tests/test_invariants.py), and [model assumptions](../THEOREMS.md#cryptographic-guarantees).

**T-IB-09 is a conditional research model**, with one external axiom and explicit dissipation hypotheses in its [source statement](../docs/artifacts/t-ib-09/statement.lean). The [saved checking report](../docs/artifacts/t-ib-09/ARISTOTLE_SUMMARY.md) concerns arithmetic corollaries; it does not establish a physical energy bound. See [THEOREMS.md](../THEOREMS.md#t-ib-09).

## Install

```bash
# Until the 0.2.0 candidate is published, from the repository root:
pip install -e ./python
# After publication:
pip install "maxwells-defense==0.2.0"
```

Use an exact release pin during 0.x; update it deliberately after integration testing. The Python wheel carries a `py.typed` marker for the package's inline annotations. See [version pinning and typing](../docs/integration.md#10-version-pinning-and-typing).

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
