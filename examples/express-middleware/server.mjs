// Minimal Express integration.
//
//   npm install express
//   node server.mjs
//
// Then:
//   curl -i http://localhost:3000/api/hello   # 401 with challenge

import express from "express";
import { randomBytes } from "node:crypto";
import { maxwellsDefense } from "../../javascript/src/maxwell-express.mjs";

// In production: load from process.env / secrets manager. Never hardcode.
const SECRET = randomBytes(32);

const app = express();

app.use(
    "/api",
    maxwellsDefense({
        serverSecret: SECRET,
        difficulty: 14,
        ttlSeconds: 300,
    }),
);

app.get("/", (req, res) => {
    res.json({ status: "public, no challenge required" });
});

app.get("/api/hello", (req, res) => {
    res.json({ status: "you solved the challenge — welcome" });
});

app.listen(3000, () => console.log("listening on :3000"));
