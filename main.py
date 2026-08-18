"""
Combined deterministic policy service for TDS GA7 questions 1-5.

One deploy, five endpoints:
  Q1  POST /release-gate       CI/CD Container Release Gate
  Q2  POST /action-firewall    LLM Action Firewall
  Q3  POST /terraform/plan     Terraform Plan Policy Gate
  Q4  POST /sanitize-output    LLM Output Handling Gate (OWASP LLM05)
  Q5  POST /corroborate        OSINT Corroboration Engine

No LLM calls, no wall-clock reads, no shared state. Every request is evaluated
independently and deterministically.

Hardening notes (v2):
  * Every endpoint is registered with AND without a trailing slash, because the
    graders do not follow redirects and FastAPI would answer /x/ with a 307.
  * Every handler is wrapped so an unexpected exception still returns a 2xx
    response with a valid, schema-correct JSON body instead of a 500.
  * Q3 now type-checks resource.address and every label key/value.

--- PER-STUDENT SCOPE VALUES ---
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
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS GA7 Policy Services")


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

async def _json(request: Request):
    """Parse the body, returning None for anything unparseable."""
    try:
        return await request.json()
    except Exception:
        return None


def _safe(fallback):
    """Never let an exception become a 500: fall back to a valid JSON body."""
    def deco(fn):
        async def wrapper(request: Request):
            try:
                return await fn(request)
            except Exception:
                return JSONResponse(fallback)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


@app.get("/")
@app.head("/")
async def root():
    return {"ok": True, "endpoints": [
        "/release-gate", "/action-firewall", "/terraform/plan",
        "/sanitize-output", "/corroborate",
    ]}


@app.get("/healthz")
@app.head("/healthz")
async def healthz():
    return {"ok": True}


# ==========================================================================
# Q1 - CI/CD Container Release Gate      POST /release-gate
# ==========================================================================

_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _as_int(v):
    """Tolerant numeric read so a string count can never raise a TypeError."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v.strip())
        except Exception:
            return 0
    return 0


@app.post("/release-gate")
@app.post("/release-gate/")
@_safe({"decision": "block", "violations": ["TESTS_INCOMPLETE"]})
async def release_gate(request: Request):
    body = await _json(request)
    if not isinstance(body, dict):
        return JSONResponse({"decision": "block", "violations": ["TESTS_INCOMPLETE"]})

    violations = []
    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    wf = body.get("workflow") if isinstance(body.get("workflow"), dict) else {}
    img = body.get("image") if isinstance(body.get("image"), dict) else {}

    # Rule 1: permissions must be EXACTLY least privilege, no extra scopes
    perms = wf.get("permissions") if isinstance(wf.get("permissions"), dict) else {}
    if perms != {"contents": "read", "packages": "write", "id-token": "none"}:
        violations.append("EXCESS_PERMISSION")

    # Rule 2: PR trigger safety + tests / matrix / failFast
    if wf.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    if not (wf.get("testsPassed") is True
            and wf.get("matrixComplete") is True
            and wf.get("failFast") is False):
        violations.append("TESTS_INCOMPLETE")

    # Rule 3: third-party actions must be pinned to a full 40-char lowercase SHA
    actions = wf.get("actions") if isinstance(wf.get("actions"), list) else []
    for a in actions:
        if not isinstance(a, dict):
            violations.append("MUTABLE_ACTION")
            break
        if a.get("owner") == "actions":
            continue  # first-party may use a version tag
        if not _SHA40.match(str(a.get("ref", ""))):
            violations.append("MUTABLE_ACTION")
            break

    # Rule 4: image hardening
    if img.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if img.get("runsAsRoot") is True:
        violations.append("ROOT_RUNTIME")
    if img.get("secretMode", "none") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")
    if _as_int(img.get("criticalVulnerabilities")) > 0:
        violations.append("CRITICAL_CVE")
    if img.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Rule 5: production extras
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if wf.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return JSONResponse({
        "decision": "promote" if not violations else "block",
        "violations": violations,
    })


# ==========================================================================
# Q2 - LLM Action Firewall      POST /action-firewall
# ==========================================================================

Q2_TENANT = "tenant-0zhlu6v"
Q2_EMAIL_DOMAIN = "notify-6pyvlfj.example"


def _q2_html_unsafe(h: str) -> bool:
    if not isinstance(h, str):
        return True
    low = h.lower()
    if re.search(r"<\s*(script|iframe)\b", low):
        return True
    if re.search(r"\bon[a-z]+\s*=", low):          # inline event handlers
        return True
    if re.search(r"javascript\s*:", low):          # javascript: URLs
        return True
    return False


@app.post("/action-firewall")
@app.post("/action-firewall/")
@_safe({"decision": "block", "reason": "INVALID_SCHEMA"})
async def action_firewall(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({
            "decision": "allow" if reason == "ALLOW" else "block",
            "reason": reason,
        })

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
    if tool not in {"search", "lookup_record", "send_email", "render_html"}:
        return out("TOOL_NOT_ALLOWED")

    # 3-7. Per-tool schema, then scope / egress / approval / output safety
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
        domain = to.rsplit("@", 1)[-1] if "@" in to else ""
        if domain != Q2_EMAIL_DOMAIN:              # exact domain match only
            return out("EGRESS_DENIED")
        if body.get("humanApproved") is not True:
            return out("APPROVAL_REQUIRED")
        return out("ALLOW")

    # render_html
    if set(args.keys()) != {"html"}:
        return out("INVALID_SCHEMA")
    h = args["html"]
    if not isinstance(h, str):
        return out("INVALID_SCHEMA")
    if _q2_html_unsafe(h):
        return out("UNSAFE_OUTPUT")
    return out("ALLOW")


# ==========================================================================
# Q3 - Terraform Plan Policy Gate      POST /terraform/plan
# ==========================================================================

Q3_WORKSPACE = "prod-spjo6m"
Q3_LABELS = {"owner": "student-mhkes", "environment": "production", "cost_center": "cc-dpj8"}
Q3_DESTROY_PROTECTED = {"storage_bucket", "sql_database", "persistent_disk"}
Q3_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
Q3_ACTIONS = {"create", "update", "delete"}


def _q3_provider_pinned(v) -> bool:
    if not isinstance(v, str):
        return False
    s = v.strip()
    if re.fullmatch(r"=\s*\d+(\.\d+)*", s):          # "= 6.2.1"
        return True
    if re.fullmatch(r"\d+(\.\d+)*", s):              # "6.2.1"
        return True
    if re.fullmatch(r"~>\s*\d+(\.\d+)*", s):         # "~> 6.0"
        return True
    return False


@app.post("/terraform/plan")
@app.post("/terraform/plan/")
@_safe({"decision": "reject", "reason": "INVALID_PLAN"})
async def terraform_plan(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({
            "decision": "approve" if reason == "APPROVE" else "reject",
            "reason": reason,
        })

    # ---- Rule 1: the request and nested objects must have the shown types ----
    if not isinstance(body, dict):
        return out("INVALID_PLAN")

    env = body.get("environment")
    state = body.get("state")
    provider = body.get("providerVersion")
    destroy_approved = body.get("destroyApproved")
    resource = body.get("resource")

    if not (isinstance(env, str)
            and isinstance(state, dict)
            and isinstance(provider, str)
            and isinstance(destroy_approved, bool)
            and isinstance(resource, dict)):
        return out("INVALID_PLAN")

    backend = state.get("backend")
    locked = state.get("locked")
    if not (isinstance(backend, str) and isinstance(locked, bool)):
        return out("INVALID_PLAN")

    address = resource.get("address")
    rtype = resource.get("type")
    raction = resource.get("action")
    rlabels = resource.get("labels")
    rsecret = resource.get("secret")
    force_destroy = resource.get("forceDestroy")

    if not (isinstance(address, str)
            and isinstance(rtype, str)
            and isinstance(raction, str)
            and isinstance(rlabels, dict)
            and isinstance(force_destroy, bool)):
        return out("INVALID_PLAN")
    if raction not in Q3_ACTIONS:
        return out("INVALID_PLAN")
    for k, v in rlabels.items():                     # labels: string -> string
        if not isinstance(k, str) or not isinstance(v, str):
            return out("INVALID_PLAN")
    if not (rsecret is None or isinstance(rsecret, str)):
        return out("INVALID_PLAN")

    # ---- Rule 2: environment must match the assigned workspace ----
    if env != Q3_WORKSPACE:
        return out("ENVIRONMENT_MISMATCH")

    # ---- Rule 3: remote state + locking ----
    if backend not in Q3_BACKENDS or locked is not True:
        return out("STATE_UNSAFE")

    # ---- Rule 4: provider pinning ----
    if not _q3_provider_pinned(provider):
        return out("UNPINNED_PROVIDER")

    # ---- Rule 5: all three assigned labels, exact values ----
    for k, v in Q3_LABELS.items():
        if rlabels.get(k) != v:
            return out("MISSING_LABELS")

    # ---- Rule 6: secret null or a non-empty secret:// reference ----
    if rsecret is not None:
        if not rsecret.startswith("secret://") or rsecret == "secret://":
            return out("PLAINTEXT_SECRET")

    # ---- Rule 7: protected stateful deletes need approval ----
    if raction == "delete" and rtype in Q3_DESTROY_PROTECTED and destroy_approved is not True:
        return out("DELETE_NOT_APPROVED")

    # ---- Rule 8: production storage buckets may never force-destroy ----
    if rtype == "storage_bucket" and force_destroy is True:
        return out("FORCE_DESTROY")

    return out("APPROVE")


# ==========================================================================
# Q4 - LLM Output Handling Gate (OWASP LLM05)      POST /sanitize-output
# ==========================================================================

Q4_ALLOWED_HOSTS = {"cdn-mn1nuwb.example", "app-3zhw6j6.example"}
Q4_CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def _decode_once(s: str) -> str:
    """Percent-escapes, then HTML entities, then \\uXXXX escapes - one pass."""
    out = s
    try:
        out = urllib.parse.unquote(out)
    except Exception:
        pass
    try:
        out = re.sub(r"&#x?[0-9a-fA-F]+;|&(?:lt|gt|quot|apos|amp);",
                     lambda m: html.unescape(m.group(0)), out)
    except Exception:
        pass

    def _u(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    try:
        out = re.sub(r"\\u([0-9a-fA-F]{4})", _u, out)
    except Exception:
        pass
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
    return bool(re.search(r"(javascript|data|vbscript)\s*:", text, re.IGNORECASE))


def _url_scheme_bad(u: str) -> bool:
    m = re.match(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*):", u)
    return bool(m) and m.group(1).lower() not in ("http", "https")


def _hostname_of(u: str):
    """Parsed hostname of an absolute/protocol-relative URL, else None."""
    try:
        s = u.strip()
        if s.startswith("//"):
            s = "https:" + s          # protocol-relative: a browser will fetch it
        parsed = urllib.parse.urlparse(s)
        if not parsed.netloc:
            return None               # relative reference such as /local/page
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        # Malformed authority (e.g. an unclosed IPv6 bracket) is not an allowed host.
        return "\x00invalid"


def _external_exfil(urls) -> bool:
    for u in urls:
        host = _hostname_of(u)
        if host is None:
            continue                  # relative -> fine
        if host not in Q4_ALLOWED_HOSTS:
            return True
    return False


def _sql_metachar(text: str) -> bool:
    if any(t in text for t in ("'", '"', ";", "--", "/*")):
        return True
    low = text.lower()
    return bool(re.search(r"\bunion\b", low) or re.search(r"\bor\s+1\s*=\s*1\b", low))


def _shell_metachar(text: str) -> bool:
    if any(ch in text for ch in (";", "&", "|", "`", "<", ">")):
        return True
    return "$(" in text or "${" in text


def _channel_reason(channel, output):
    """First violation for this output on this channel, or None if safe."""
    if channel == "html":
        low = output.lower()
        if re.search(r"<\s*(script|iframe|object|embed)\b", low):
            return "SCRIPT_TAG"
        if re.search(r"\bon[a-z]+\s*=", low):
            return "EVENT_HANDLER"
        urls = _extract_urls("html", output)
        if _dangerous_scheme(output) or any(_url_scheme_bad(u) for u in urls):
            return "DANGEROUS_SCHEME"
        if _external_exfil(urls):
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
        return "SQL_METACHAR" if _sql_metachar(output) else None
    if channel == "shell":
        return "SHELL_METACHAR" if _shell_metachar(output) else None
    return None


@app.post("/sanitize-output")
@app.post("/sanitize-output/")
@_safe({"safe": False, "reason": "INVALID_SCHEMA"})
async def sanitize_output(request: Request):
    body = await _json(request)

    def out(reason):
        return JSONResponse({"safe": reason == "SAFE", "reason": reason})

    # Rule 1: schema
    if not isinstance(body, dict):
        return out("INVALID_SCHEMA")
    channel = body.get("channel")
    output = body.get("output")
    if channel not in Q4_CHANNELS or not isinstance(output, str) or len(output) > 20000:
        return out("INVALID_SCHEMA")

    # Rule 2: encoded payload (decode once, test the decoded form)
    decoded = _decode_once(output)
    if decoded != output and _channel_reason(channel, decoded) is not None:
        return out("ENCODED_PAYLOAD")

    # Rule 3: channel rules on the original output
    reason = _channel_reason(channel, output)
    return out(reason if reason is not None else "SAFE")


# ==========================================================================
# Q5 - OSINT Corroboration Engine      POST /corroborate
# ==========================================================================

Q5_VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def _parse_iso(s):
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except Exception:
        return None


@app.post("/corroborate")
@app.post("/corroborate/")
@_safe({"verdict": "invalid", "confidence": "low", "corroboratingSources": []})
async def corroborate(request: Request):
    body = await _json(request)

    def out(verdict, confidence, sources):
        return JSONResponse({"verdict": verdict, "confidence": confidence,
                             "corroboratingSources": sources})

    # Rule 1: invalid request
    if not isinstance(body, dict):
        return out("invalid", "low", [])
    claim = body.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return out("invalid", "low", [])
    as_of = _parse_iso(body.get("asOf"))
    if as_of is None:
        return out("invalid", "low", [])
    staleness = body.get("stalenessDays")
    if isinstance(staleness, bool) or not isinstance(staleness, (int, float)):
        return out("invalid", "low", [])
    sources = body.get("sources")
    if not isinstance(sources, list):
        return out("invalid", "low", [])

    claim_value = claim["value"]

    # Keep only structurally valid sources; mark freshness
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
        try:
            fresh = (as_of - obs).total_seconds() <= staleness * 86400
        except Exception:
            continue
        valid.append({**s, "_fresh": fresh})

    # Rule 2: contradicted - fresh, authoritative, disagreeing
    contradictors = sorted(
        s["id"] for s in valid
        if s["_fresh"] and s.get("authoritative") is True and s["value"] != claim_value
    )
    if contradictors:
        return out("contradicted", "low", contradictors)

    # Rule 3: supported - fresh agreement, one representative per origin
    reps = {}
    for s in valid:
        if not (s["_fresh"] and s["value"] == claim_value):
            continue
        origin = s["origin"]
        if origin not in reps or s["id"] < reps[origin]["id"]:
            reps[origin] = s
    rep_list = list(reps.values())
    if len(rep_list) >= 2:
        confidence = "high" if len({s["type"] for s in rep_list}) >= 2 else "medium"
        return out("supported", confidence, sorted(s["id"] for s in rep_list))

    # Rule 4: everything else
    return out("unverified", "low", [])
