# vsoc-api — Rust backend

Backend-only Rust port of the TanStack Start server functions. Runs as a
standalone service alongside the existing React frontend, against the same
Supabase Postgres database.

## Status

| Endpoint | Source (TS) | Auth | Done |
|----------|-------------|------|------|
| `GET  /health` | — | none | ✅ |
| `GET  /api/intel/live` | `intel.functions.ts → getLiveIntel` | none | ✅ |
| `POST /api/intel/osv`  | `intel.functions.ts → queryOsv`   | none | ✅ |
| `GET  /api/intel/nvd`  | `intel.functions.ts → getNvdRecent` | none | ✅ |
| `GET  /api/intel/feed-status` | `intel.functions.ts → getFeedStatus` | none | ✅ |
| JWKS token verification | `auth-middleware.ts` | — | ✅ (not yet applied to a route) |
| `GET  /api/feed-health` | `vsoc.functions.ts → getFeedHealth` | Bearer | ⬜ needs DB |
| `GET  /api/workspace`   | `vsoc.functions.ts → getWorkspace`  | Bearer | ⬜ needs DB |
| `POST /api/feeds/run`   | `vsoc.functions.ts → runFeedsNow`   | admin  | ⬜ needs DB |
| `POST /api/cron/feeds`  | `routes/api/public/cron/feeds.ts`   | secret | ⬜ needs DB |

## Run

```sh
cd api
cargo run
# PORT defaults to 8787
curl localhost:8787/health
curl localhost:8787/api/intel/live
curl -X POST localhost:8787/api/intel/osv \
  -H 'content-type: application/json' \
  -d '{"name":"lodash","version":"4.17.20","ecosystem":"npm"}'
curl localhost:8787/api/intel/nvd           # set NVD_API_KEY to raise rate limits
curl localhost:8787/api/intel/feed-status   # live reachability for the feed catalog
```

## Environment

| Var | Needed by | Notes |
|-----|-----------|-------|
| `PORT` | server | default `8787` |
| `NVD_API_KEY` | `/api/intel/nvd` | optional; sent as `apiKey` header to raise NVD rate limits |
| `SUPABASE_URL` | auth | base URL; JWKS is fetched from `/auth/v1/.well-known/jwks.json` |
| `SUPABASE_JWT_SECRET` | auth | only for legacy HS256 tokens |
| `DATABASE_URL` | (future) DB endpoints | Postgres connection string |
