"""
Combined deterministic policy service for TDS GA7 questions 1-5.

One deploy, five endpoints:
  Q1  POST /release-gate       CI/CD Container Release Gate
  Q2  POST /action-firewall    LLM Action Firewall
  Q3  POST /terraform/plan     Terraform Plan Policy Gate
  Q4  POST /sanitize-output    LLM Output Handling Gate (OWASP LLM05)
  Q5  POST /corroborate        OSINT Corroboration Engine

No LLM calls, no wall-clock reads, no external state. Every request is evaluated
independently and deterministically.

--- PER-STUDENT SCOPE VALUES (already filled in from the assignment) ---
  Q2 tenant:            tenant-0zhlu6v
  Q2 email domain:      notify-6pyvlfj.example
  Q3 workspace:         prod-spjo6m
  Q3 labels:            owner=student-mhkes, environment=production, cost_center=cc-dpj8
  Q4 allowed hosts:     cdn-mn1nuwb.example, app-3zhw6j6.example
  Q5 subject:           tzy0sl.example   (informational; logic is subject-agnostic)
"""
import re
import html
import urllib.parse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/")
async def root():
    return {"ok": True, "endpoints": [
        "/release-gate", "/action-firewall", "/terraform/plan",
        "/sanitize-output", "/corroborate"
    ]}


async def _json(request: Request):
    try:
        return await request.json()
    except Exception:
        return None


# ==========================================================================
# Q1 — CI/CD Container Release Gate      POST /release-gate
# ==========================================================================

_SHA40 = re.compile(r"^[0-9a-f]{40}$")

@app.post("/release-gate")
async def release_gate(request: Request):
    body = await _json(request)
    if not isinstance(body, dict):
        return JSONResponse({"decision": "block", "violations": ["EXCESS_PERMISSION"]})

    violations = []
    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    wf = body.get("workflow", {}) or {}
    img = body.get("image", {}) or {}

    # Rule 1: permissions must be EXACTLY least privilege, no extra scopes
    perms = wf.get("permissions", {}) or {}
    expected = {"contents": "read", "packages": "write", "id-token": "none"}
    if perms != expected:
        violations.append("EXCESS_PERMISSION")

    # Rule 2: PR trigger safety + tests/matrix/failFast
    trigger = wf.get("trigger")
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    if not (wf.get("testsPassed") is True
            and wf.get("matrixComplete") is True
            and wf.get("failFast") is False):
        violations.append("TESTS_INCOMPLETE")

    # Rule 3: third-party actions must be full 40-char lowercase hex SHA
    for a in wf.get("actions", []) or []:
        owner = a.get("owner")
        ref_val = str(a.get("ref", ""))
        if owner == "actions":
            continue  # first-party may use a version tag
        if not _SHA40.match(ref_val):
            violations.append("MUTABLE_ACTION")
            break

    # Rule 4: image hardening
    if img.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if img.get("runsAsRoot") is True:
        violations.append("ROOT_RUNTIME")
    secret_mode = img.get("secretMode", "none")
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")
    if (img.get("criticalVulnerabilities") or 0) > 0:
        violations.append("CRITICAL_CVE")
    if img.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Rule 5: production extras
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if wf.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return JSONResponse({"decision": decision, "violations": violations})


# ==========================================================================
# Q2 — LLM Action Firewall      POST /action-firewall
# ==========================================================================

Q2_TENANT = "tenant-0zhlu6v"
Q2_EMAIL_DOMAIN = "notify-6pyvlfj.example"

def _q2_html_unsafe(h: str) -> bool:
    if not isinstance(h, str):
        return True
    low = h.lower()
    if "<script" in low or "<iframe" in low:
        return True
    # inline event handlers: on...=  (onclick=, onerror=, etc.)
    if re.search(r"\bon[a-z]+\s*=", low):
        return True
    # javascript: URLs (optional whitespace before colon)
    if re.search(r"javascript\s*:", low):
        return True
    return False

@app.post("/action-firewall")
async def action_firewall(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({"decision": "allow" if reason == "ALLOW" else "block",
                             "reason": reason})

    # 1. Top-level schema
    if not isinstance(body, dict):
        return out("INVALID_SCHEMA")
    action = body.get("action")
    if not isinstance(action, dict):
        return out("INVALID_SCHEMA")
    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(tool, str) or not isinstance(args, dict):
        return out("INVALID_SCHEMA")

    # 2. Tool allowlist
    allowed_tools = {"search", "lookup_record", "send_email", "render_html"}
    if tool not in allowed_tools:
        return out("TOOL_NOT_ALLOWED")

    # 3. Selected tool's arg schema (exact key sets), then 4-7 scope/approval/safety
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return out("INVALID_SCHEMA")
        q = args["query"]
        if not isinstance(q, str) or not (1 <= len(q) <= 200):
            return out("INVALID_SCHEMA")
        return out("ALLOW")

    if tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return out("INVALID_SCHEMA")
        tid, rid = args["tenantId"], args["recordId"]
        if not isinstance(tid, str) or not isinstance(rid, str) or rid == "":
            return out("INVALID_SCHEMA")
        if tid != Q2_TENANT:
            return out("TENANT_SCOPE")
        return out("ALLOW")

    if tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return out("INVALID_SCHEMA")
        to, subject, bod = args["to"], args["subject"], args["body"]
        if not all(isinstance(x, str) for x in (to, subject, bod)):
            return out("INVALID_SCHEMA")
        # exact recipient domain match
        domain = to.rsplit("@", 1)[-1] if "@" in to else ""
        if domain != Q2_EMAIL_DOMAIN:
            return out("EGRESS_DENIED")
        if body.get("humanApproved") is not True:
            return out("APPROVAL_REQUIRED")
        return out("ALLOW")

    if tool == "render_html":
        if set(args.keys()) != {"html"}:
            return out("INVALID_SCHEMA")
        h = args["html"]
        if not isinstance(h, str):
            return out("INVALID_SCHEMA")
        if _q2_html_unsafe(h):
            return out("UNSAFE_OUTPUT")
        return out("ALLOW")

    return out("TOOL_NOT_ALLOWED")


# ==========================================================================
# Q3 — Terraform Plan Policy Gate      POST /terraform/plan
# ==========================================================================

Q3_WORKSPACE = "prod-spjo6m"
Q3_LABELS = {"owner": "student-mhkes", "environment": "production", "cost_center": "cc-dpj8"}
Q3_DESTROY_PROTECTED = {"storage_bucket", "sql_database", "persistent_disk"}

def _q3_provider_pinned(v):
    if not isinstance(v, str):
        return False
    s = v.strip()
    # exact: "6.2.1" or "= 6.2.1"
    if re.fullmatch(r"=?\s*\d+\.\d+\.\d+", s):
        return True
    # pessimistic: "~> 6.0"
    if re.fullmatch(r"~>\s*\d+\.\d+(\.\d+)?", s):
        return True
    return False

@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({"decision": "approve" if reason == "APPROVE" else "reject",
                             "reason": reason})

    # Rule 1: shape/type validation
    if not isinstance(body, dict):
        return out("INVALID_PLAN")
    env = body.get("environment")
    state = body.get("state")
    provider = body.get("providerVersion")
    destroy_approved = body.get("destroyApproved")
    resource = body.get("resource")
    if not (isinstance(env, str) and isinstance(state, dict)
            and isinstance(provider, str) and isinstance(destroy_approved, bool)
            and isinstance(resource, dict)):
        return out("INVALID_PLAN")
    backend = state.get("backend")
    locked = state.get("locked")
    if not (isinstance(backend, str) and isinstance(locked, bool)):
        return out("INVALID_PLAN")
    rtype = resource.get("type")
    raction = resource.get("action")
    rlabels = resource.get("labels")
    rsecret = resource.get("secret")
    force_destroy = resource.get("forceDestroy")
    if not (isinstance(rtype, str) and isinstance(raction, str)
            and isinstance(rlabels, dict) and isinstance(force_destroy, bool)):
        return out("INVALID_PLAN")
    if not (rsecret is None or isinstance(rsecret, str)):
        return out("INVALID_PLAN")

    # Rule 2: environment match
    if env != Q3_WORKSPACE:
        return out("ENVIRONMENT_MISMATCH")

    # Rule 3: state safety
    if backend not in ("gcs", "s3", "azurerm", "remote") or locked is not True:
        return out("STATE_UNSAFE")

    # Rule 4: provider pin
    if not _q3_provider_pinned(provider):
        return out("UNPINNED_PROVIDER")

    # Rule 5: labels
    for k, v in Q3_LABELS.items():
        if rlabels.get(k) != v:
            return out("MISSING_LABELS")

    # Rule 6: secret null or non-empty secret:// reference
    if rsecret is not None:
        if not (isinstance(rsecret, str) and rsecret.startswith("secret://") and len(rsecret) > len("secret://")):
            return out("PLAINTEXT_SECRET")

    # Rule 7: destroy approval for protected types
    if raction == "delete" and rtype in Q3_DESTROY_PROTECTED and destroy_approved is not True:
        return out("DELETE_NOT_APPROVED")

    # Rule 8: production storage_bucket forceDestroy
    if rtype == "storage_bucket" and force_destroy is True:
        return out("FORCE_DESTROY")

    return out("APPROVE")


# ==========================================================================
# Q4 — LLM Output Handling Gate (OWASP LLM05)      POST /sanitize-output
# ==========================================================================

Q4_ALLOWED_HOSTS = {"cdn-mn1nuwb.example", "app-3zhw6j6.example"}
Q4_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

def _decode_once(s: str) -> str:
    # percent-escapes, then HTML entities (numeric + the named set), then \uXXXX
    out = s
    try:
        out = urllib.parse.unquote(out)
    except Exception:
        pass
    # HTML entities: numeric &#NN; / &#xNN; and named lt gt quot apos amp
    def _ent(m):
        return html.unescape(m.group(0))
    out = re.sub(r"&#x?[0-9a-fA-F]+;|&(?:lt|gt|quot|apos|amp);", _ent, out)
    # \uXXXX escapes
    def _u(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    out = re.sub(r"\\u([0-9a-fA-F]{4})", _u, out)
    return out

def _extract_urls(channel: str, output: str):
    urls = []
    if channel == "html":
        for m in re.finditer(r'(?:src|href)\s*=\s*"([^"]*)"', output, re.IGNORECASE):
            urls.append(m.group(1))
        for m in re.finditer(r"(?:src|href)\s*=\s*'([^']*)'", output, re.IGNORECASE):
            urls.append(m.group(1))
    elif channel == "markdown":
        for m in re.finditer(r"\]\(([^)]*)\)", output):
            urls.append(m.group(1).strip())
    elif channel == "url":
        urls.append(output.strip())
    return urls

def _dangerous_scheme(text: str) -> bool:
    if re.search(r"(javascript|data|vbscript)\s*:", text, re.IGNORECASE):
        return True
    return False

def _url_scheme_bad(u: str) -> bool:
    # an extracted URL uses any scheme other than http/https
    m = re.match(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*):", u)
    if m:
        scheme = m.group(1).lower()
        if scheme not in ("http", "https"):
            return True
    return False

def _hostname_of(u: str):
    s = u.strip()
    if s.startswith("//"):
        s = "https:" + s  # protocol-relative -> absolute
    try:
        parsed = urllib.parse.urlparse(s)
    except Exception:
        return None
    if not parsed.netloc:
        return None  # relative reference like /local/page
    host = parsed.hostname
    return host.lower() if host else None

def _external_exfil(urls):
    for u in urls:
        if _url_scheme_bad(u):
            # dangerous scheme handled separately; here only judge host if absolute http(s)
            pass
        host = _hostname_of(u)
        if host is None:
            continue  # relative -> fine
        if host not in Q4_ALLOWED_HOSTS:
            return True
    return False

def _sql_metachar(text: str) -> bool:
    low = text.lower()
    if "'" in text or '"' in text or ";" in text or "--" in text or "/*" in text:
        return True
    if re.search(r"\bunion\b", low):
        return True
    if re.search(r"\bor\s+1=1\b", low):
        return True
    return False

def _shell_metachar(text: str) -> bool:
    if any(ch in text for ch in [";", "&", "|", "`", "<", ">"]):
        return True
    if "$(" in text or "${" in text:
        return True
    return False

def _channel_reason(channel, output):
    """Return a violation reason for this output on this channel, or None if safe."""
    if channel == "html":
        low = output.lower()
        if re.search(r"<\s*(script|iframe|object|embed)\b", low):
            return "SCRIPT_TAG"
        if re.search(r"\bon[a-z]+\s*=", low):
            return "EVENT_HANDLER"
        if _dangerous_scheme(output) or any(_url_scheme_bad(u) for u in _extract_urls("html", output)):
            return "DANGEROUS_SCHEME"
        if _external_exfil(_extract_urls("html", output)):
            return "EXTERNAL_EXFIL"
        return None
    if channel in ("markdown", "url"):
        urls = _extract_urls(channel, output)
        if _dangerous_scheme(output) or any(_url_scheme_bad(u) for u in urls):
            return "DANGEROUS_SCHEME"
        if _external_exfil(urls):
            return "EXTERNAL_EXFIL"
        return None
    if channel == "sql":
        if _sql_metachar(output):
            return "SQL_METACHAR"
        return None
    if channel == "shell":
        if _shell_metachar(output):
            return "SHELL_METACHAR"
        return None
    return None

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({"safe": reason == "SAFE", "reason": reason})

    # Rule 1: INVALID_SCHEMA
    if not isinstance(body, dict):
        return out("INVALID_SCHEMA")
    channel = body.get("channel")
    output = body.get("output")
    if channel not in Q4_CHANNELS or not isinstance(output, str) or len(output) > 20000:
        return out("INVALID_SCHEMA")

    # Rule 2: ENCODED_PAYLOAD
    decoded = _decode_once(output)
    if decoded != output:
        if _channel_reason(channel, decoded) is not None:
            return out("ENCODED_PAYLOAD")

    # Rule 3: channel rules on the ORIGINAL output
    reason = _channel_reason(channel, output)
    if reason is not None:
        return out(reason)
    return out("SAFE")


# ==========================================================================
# Q5 — OSINT Corroboration Engine      POST /corroborate
# ==========================================================================

from datetime import datetime

Q5_VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

def _parse_iso(s):
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

@app.post("/corroborate")
async def corroborate(request: Request):
    body = await _json(request)

    def out(verdict, confidence, sources):
        return JSONResponse({"verdict": verdict, "confidence": confidence,
                             "corroboratingSources": sources})

    # Rule 1: invalid
    if not isinstance(body, dict):
        return out("invalid", "low", [])
    claim = body.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return out("invalid", "low", [])
    as_of = _parse_iso(body.get("asOf"))
    if as_of is None:
        return out("invalid", "low", [])
    staleness = body.get("stalenessDays")
    if not isinstance(staleness, (int, float)) or isinstance(staleness, bool):
        return out("invalid", "low", [])
    sources = body.get("sources")
    if not isinstance(sources, list):
        return out("invalid", "low", [])

    claim_value = claim["value"]

    # keep only valid sources
    valid = []
    for s in sources:
        if not isinstance(s, dict):
            continue
        if not all(isinstance(s.get(k), str) for k in ("id", "origin", "value", "observedAt")):
            continue
        if s.get("type") not in Q5_VALID_TYPES:
            continue
        obs = _parse_iso(s.get("observedAt"))
        if obs is None:
            continue
        fresh = (as_of - obs).total_seconds() <= staleness * 86400
        valid.append({**s, "_fresh": fresh, "_obs": obs})

    # Rule 2: contradicted — fresh + authoritative + value != claim
    contradictors = sorted(
        s["id"] for s in valid
        if s["_fresh"] and s.get("authoritative") is True and s["value"] != claim_value
    )
    if contradictors:
        return out("contradicted", "low", contradictors)

    # Rule 3: supported — fresh sources agreeing, one representative per origin
    agreeing = [s for s in valid if s["_fresh"] and s["value"] == claim_value]
    reps = {}
    for s in agreeing:
        origin = s["origin"]
        if origin not in reps or s["id"] < reps[origin]["id"]:
            reps[origin] = s
    rep_list = list(reps.values())
    if len(rep_list) >= 2:
        types = {s["type"] for s in rep_list}
        confidence = "high" if len(types) >= 2 else "medium"
        ids = sorted(s["id"] for s in rep_list)
        return out("supported", confidence, ids)

    # Rule 4: unverified
    return out("unverified", "low", [])
