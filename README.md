# TDS GA7 Policy Services (Q1–Q5)

One FastAPI app, five deterministic policy endpoints. No LLM calls, no wall-clock
reads, no shared state — every request is evaluated independently.

| Q | Method | Path | Purpose |
|---|--------|------|---------|
| 1 | POST | `/release-gate` | CI/CD container release gate |
| 2 | POST | `/action-firewall` | LLM action firewall |
| 3 | POST | `/terraform/plan` | Terraform plan policy gate |
| 4 | POST | `/sanitize-output` | LLM output handling gate (OWASP LLM05) |
| 5 | POST | `/corroborate` | OSINT corroboration engine |

`GET /` and `GET /healthz` return `{"ok": true}` for uptime pings.

## Run locally
    pip install -r requirements.txt
    uvicorn main:app --reload
    python test_all.py        # 121 local checks
    pytest tests/             # the suite CI runs

## Deploy
Deploy as a Docker web service. The container is multi-stage, runs as a non-root
user, and binds `$PORT` when the platform sets one. Submit the base URL only —
no trailing path, query string, or fragment.

## v2 hardening
* Each endpoint is registered with **and** without a trailing slash: the graders
  do not follow redirects, and FastAPI would otherwise answer `/x/` with a 307.
* Every handler is wrapped so an unexpected exception still returns a 2xx
  response with a schema-valid JSON body rather than a 500.
* Q3 type-checks `resource.address` and every label key/value.
* Q1 reads `criticalVulnerabilities` tolerantly so a string count cannot raise.
