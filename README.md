# TDS GA7 Policy Services (Q1-Q5)

One FastAPI app, five deterministic policy endpoints:

| Q | Method | Path | Purpose |
|---|--------|------|---------|
| 1 | POST | /release-gate | CI/CD container release gate |
| 2 | POST | /action-firewall | LLM action firewall |
| 3 | POST | /terraform/plan | Terraform plan policy gate |
| 4 | POST | /sanitize-output | LLM output handling gate (OWASP LLM05) |
| 5 | POST | /corroborate | OSINT corroboration engine |

## Run locally
    pip install -r requirements.txt
    uvicorn main:app --reload

## Deploy (Render / any Docker host)
Push to a repo, deploy as a Docker web service. Submit the base URL;
each question's checker hits its own path.

Per-student scope values are already filled into main.py.
