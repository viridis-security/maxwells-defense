"""Demo client: hits the protected endpoint, sees the challenge, solves, retries."""
import json
import time

import httpx

from maxwells_defense.core import Challenge, Solution, solve_challenge


def main() -> None:
    url = "http://localhost:8000/api/hello"
    t0 = time.time()
    with httpx.Client() as c:
        r = c.get(url)
        print(f"first request: {r.status_code}, body={r.json()}")
        body = r.json()
        challenge = Challenge.from_dict(body["challenge"])
        print(f"solving difficulty={challenge.difficulty}...")
        solution = solve_challenge(challenge)
        print(f"solved in {time.time() - t0:.2f}s")
        r2 = c.get(
            url,
            headers={
                "X-Maxwell-Challenge": json.dumps(challenge.to_dict()),
                "X-Maxwell-Solution": json.dumps(solution.to_dict()),
            },
        )
        print(f"second request: {r2.status_code}, body={r2.json()}")


if __name__ == "__main__":
    main()
