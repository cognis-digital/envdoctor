# Demo 01 -- basic .env validation

This demo shows ENVDOCTOR catching the three failure modes it was built for,
using the files in this directory.

## Files

- `.env.example` -- the documented template committed to the repo.
- `.env` -- a developer's real config, which has drifted and is unhealthy.
- `env.schema.json` -- a typed contract for the required variables.

## What is wrong with `.env`

1. `API_SECRET` is present but still holds the placeholder `changeme`.
2. `DATABASE_URL` (documented in the example) is **missing** entirely.
3. `PORT` is set to `not-a-number`, which violates the schema's `port` type.
4. `LEGACY_FLAG` exists in `.env` but is undocumented (config drift).

## Try it

From the repository root:

```sh
# 1. Structural + secret hygiene
python -m envdoctor lint demos/01-basic/.env

# 2. Drift vs the committed template
python -m envdoctor drift --example demos/01-basic/.env.example --env demos/01-basic/.env

# 3. Typed schema validation, JSON output for CI
python -m envdoctor check --schema demos/01-basic/env.schema.json --env demos/01-basic/.env --format json
```

Each command exits non-zero because at least one ERROR-severity finding is
reported, so it drops straight into a CI pipeline:

```sh
python -m envdoctor lint demos/01-basic/.env || echo "env is unhealthy"
```
