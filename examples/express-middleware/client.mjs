// Client for the example server. Hits the protected endpoint, sees the
// challenge in the 401, solves it, retries — all in one fetch wrapper.
//
//   node client.mjs

import { fetchWithMaxwell } from "../../javascript/src/maxwell.mjs";

const url = process.argv[2] || "http://localhost:3000/api/hello";

const t0 = Date.now();
const res = await fetchWithMaxwell(url);
const body = await res.json();
console.log(`[${Date.now() - t0}ms] status=${res.status}`, body);
