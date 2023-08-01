#!/usr/bin/env python3
"""Step160 device-code page flow (standard HTTP, no internal imports).

Drives the real host page /oauth/device with a protected fixture session and the
page CSRF cookie, then polls the token endpoint. Secrets are only kept in memory;
the output intentionally contains no device_code/user_code/token.
"""
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

fixture = json.load(open(sys.argv[1], encoding="utf-8"))
base = fixture["base_url"]
app = fixture["app_id"]
session = open(fixture["session"], encoding="utf-8").read().strip()
aud = "https://resource.example.test/api"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect)
csrf_cookie = None

def request(method, path, form=None, headers=None, use_session=True):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if use_session:
        req.add_header("Authorization", "Bearer " + session)
    req.add_header("Origin", base)
    req.add_header("Referer", base + path)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        resp = opener.open(req, timeout=15)
        body = resp.read().decode("utf-8", "replace")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")

def hidden(body, name):
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), body)
    return m.group(1) if m else ""

def forms(body):
    return re.findall(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', body, re.S)

def cookie_header():
    return {"Cookie": "ln_page_csrf=" + csrf_cookie} if csrf_cookie else {}

# 1) device authorization (public client, scope profile is within fixture client registration)
status, headers, body = request("POST", "/oauth/device_authorization",
                               {"client_id": app, "scope": "profile"}, use_session=False)
auth = json.loads(body)
if status != 200 or "user_code" not in auth:
    print(json.dumps({"step": "device_authorization", "status": status, "ok": False}))
    raise SystemExit(1)
user_code = auth["user_code"]
device_code = auth["device_code"]
print(json.dumps({"step": "device_authorization", "status": status, "ok": True,
                  "has_user_code": bool(user_code), "interval": auth.get("interval")}))

# 2) GET /oauth/device?user_code=... -> form (public page + session Bearer)
status, headers, body = request("GET", "/oauth/device?user_code=" + urllib.parse.quote(user_code))
set_cookie = headers.get("Set-Cookie", "")
m = re.search(r'ln_page_csrf=([^;]+)', set_cookie)
if m:
    csrf_cookie = m.group(1)
print(json.dumps({"step": "device_page_get", "status": status,
                  "has_form": bool(forms(body)), "has_csrf": bool(csrf_cookie)}))

# 3) POST /oauth/device with user_code and CSRF -> confirm page
f = forms(body)
if not f:
    print(json.dumps({"step": "device_page_post", "status": status, "ok": False,
                      "detail": "no form"}))
    raise SystemExit(2)
action, form_html = f[0]
fields = {"csrf_token": hidden(form_html, "csrf_token") or csrf_cookie or "",
          "user_code": user_code}
status, headers, body = request("POST", action or "/oauth/device", fields, cookie_header())
set_cookie = headers.get("Set-Cookie", "")
m = re.search(r'ln_page_csrf=([^;]+)', set_cookie)
if m:
    csrf_cookie = m.group(1)
csrf = hidden(body, "csrf_token") or csrf_cookie or ""
request_id = hidden(body, "request_id")
confirm_action = "/oauth/device/confirm"
for a, _ in forms(body):
    if a:
        confirm_action = a
print(json.dumps({"step": "device_describe", "status": status,
                  "has_request": bool(request_id), "has_csrf": bool(csrf)}))

# 4) approve on confirm page
status, headers, body = request("POST", confirm_action,
                               {"csrf_token": csrf, "user_code": user_code, "approve": "true"},
                               cookie_header())
print(json.dumps({"step": "device_approve", "status": status,
                  "location": headers.get("Location", "")[:120],
                  "forms": [a for a,_ in forms(body)],
                  "body_has_error": "ACCESS_DENIED" in body or "REAUTH" in body}))

# 5) poll token endpoint
for attempt in range(1, 8):
    status, headers, body = request("POST", "/oauth/token",
                                    {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                     "client_id": app, "device_code": device_code}, use_session=False)
    try:
        payload = json.loads(body)
    except Exception:
        payload = {}
    if status == 200 and payload.get("access_token"):
        claims = {}
        try:
            import base64
            p = payload["access_token"].split(".")[1]
            p += "=" * ((4 - len(p) % 4) % 4)
            claims = json.loads(base64.urlsafe_b64decode(p))
        except Exception:
            pass
        print(json.dumps({"step": "device_token", "status": status, "ok": True,
                          "has_refresh": bool(payload.get("refresh_token")),
                          "iss": claims.get("iss"), "aud": claims.get("aud"),
                          "scope": claims.get("scope")}))
        break
    if payload.get("error") not in ("authorization_pending", "slow_down"):
        print(json.dumps({"step": "device_token", "status": status, "ok": False,
                          "error": payload.get("error")}))
        break
    time.sleep(auth.get("interval", 5))
else:
    print(json.dumps({"step": "device_token", "status": 0, "ok": False, "error": "timeout"}))
