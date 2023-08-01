#!/usr/bin/env python3
"""Step160 APP QR scan flow (standard HTTP page + protocol endpoints).

Create request -> authenticated browser-like page confirmation -> original
initiator claim. Secrets (claim_secret/session) stay in memory; no secret output.
"""
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

fixture = json.load(open(sys.argv[1], encoding="utf-8"))
base = fixture["base_url"]
app = fixture["app_id"]
session = open(fixture["session"], encoding="utf-8").read().strip()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect)
csrf_cookie = None

def request(method, path, form=None, use_session=True, json_body=None):
    if json_body is not None:
        data = json.dumps(json_body).encode()
        content_type = "application/json"
    else:
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        content_type = "application/x-www-form-urlencoded"
    req = urllib.request.Request(base + path, data=data, method=method)
    if use_session:
        req.add_header("Authorization", "Bearer " + session)
    req.add_header("Origin", base)
    req.add_header("Referer", base + path)
    if data is not None:
        req.add_header("Content-Type", content_type)
    if csrf_cookie:
        req.add_header("Cookie", "ln_page_csrf=" + csrf_cookie)
    try:
        resp = opener.open(req, timeout=15)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")

def hidden(body, name):
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), body)
    return m.group(1) if m else ""

def forms(body):
    return re.findall(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', body, re.S)

# 1) create QR request (public client)
status, headers, body = request("POST", "/oauth/qr/request", json_body={"client_id": app}, use_session=False)
try:
    begin = json.loads(body)
except Exception:
    begin = {}
if status != 200 or not begin.get("request_id") or not begin.get("claim_secret"):
    print(json.dumps({"step": "qr_create", "status": status, "ok": False}))
    raise SystemExit(1)
request_id, claim_secret = begin["request_id"], begin["claim_secret"]
print(json.dumps({"step": "qr_create", "status": status, "ok": True,
                  "payload_has_secret": "claim_secret" in (begin.get("qr_payload") or "")}))

# 2) authenticated confirmation page
status, headers, body = request("GET", "/app/scan?request_id=" + urllib.parse.quote(request_id))
m = re.search(r'ln_page_csrf=([^;]+)', headers.get("Set-Cookie", ""))
if m:
    csrf_cookie = m.group(1)
print(json.dumps({"step": "qr_scan_page", "status": status,
                  "has_form": bool(forms(body)), "has_csrf": bool(csrf_cookie)}))

# 3) submit approval
f = forms(body)
if not f:
    print(json.dumps({"step": "qr_scan_submit", "status": status, "ok": False,
                      "detail": "no form", "text": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))[:300]}))
    raise SystemExit(2)
action, form_html = f[0]
csrf = hidden(form_html, "csrf_token") or csrf_cookie or ""
expected_version = hidden(form_html, "expected_version")
status, headers, body = request("POST", action or "/app/scan",
                                {"csrf_token": csrf, "request_id": request_id,
                                 "expected_version": expected_version, "approve": "true"})
print(json.dumps({"step": "qr_scan_submit", "status": status,
                  "body_has_error": "ACCESS_DENIED" in body or "REQ_INVALID" in body}))

# 4a) wrong claim secret must not claim (cross-user/binding rejection)
statusW, headersW, bodyW = request("POST", "/oauth/qr/claim",
                                   json_body={"request_id": request_id, "claim_secret": claim_secret + "x"},
                                   use_session=False)
print(json.dumps({"step": "qr_claim_wrong_secret", "status": statusW, "rejected": statusW != 200}))

# 4) claim as original initiator
status, headers, body = request("POST", "/oauth/qr/claim",
                                json_body={"request_id": request_id, "claim_secret": claim_secret},
                                use_session=False)
try:
    claim = json.loads(body)
except Exception:
    claim = {}
print(json.dumps({"step": "qr_claim", "status": status, "ok": status == 200,
                  "status_value": claim.get("status"),
                  "has_session_cookie": any("login_session" in k for k in headers)}))

# 5) replay claim must fail
status2, _, body2 = request("POST", "/oauth/qr/claim",
                            json_body={"request_id": request_id, "claim_secret": claim_secret},
                            use_session=False)
print(json.dumps({"step": "qr_claim_replay", "status": status2, "rejected": status2 != 200,
                  "error": (json.loads(body2).get("error") if body2.startswith("{") else None)}))
