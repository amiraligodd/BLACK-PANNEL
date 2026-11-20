# ============================ KING_PANNEL ============================
import os, json, time, uuid, secrets, base64, sqlite3, subprocess, threading, hashlib, hmac, re, socket, urllib.parse
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel


def env(k, d=""):
    return (os.environ.get(k) or d).strip()

# optional override; by default the host of the incoming request is used for every config link
DOMAIN_ENV = re.sub(r"^https?://", "", env("DOMAIN")).split("/")[0]
TITLE = env("PANEL_TITLE", "KING_PANNEL")          # locked: cannot be changed from inside the panel
DATA = env("DATA_DIR", "/data")
WS_PATH = "/in2"
GB = 1024 ** 3
ADMIN_USER = env("ADMIN_USER", "admin").lower()    # owner username (password: variable ADMIN_PASSWORD)

# appearance settings each account may change (sensitive settings such as domain and title are locked)
APPEARANCE = {"accent": "#7c5cff", "accent2": "#38d4ff", "theme": "dark", "palette": "default", "radius": "16",
              "bg": "gradient", "fx": "none", "noise": "0", "cardstyle": "glass", "border": "normal", "hover": "lift",
              "spot": "1", "btn": "gradient", "titlefx": "gradient", "shape": "squircle", "pbar": "gradient",
              "layout": "list", "density": "normal", "enter": "fade", "anim": "1", "font": "system", "fsize": "15",
              "blur": "14", "opacity": "40", "glow": "40", "swidth": "20", "bgimg": "", "prefix": ""}
HEX_KEYS = ("accent", "accent2")
NUM_KEYS = ("radius", "fsize", "blur", "opacity", "glow", "swidth")

os.makedirs(DATA, exist_ok=True)
L = threading.RLock()
db = sqlite3.connect(os.path.join(DATA, "panel.db"), check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA synchronous=NORMAL")
db.execute("""CREATE TABLE IF NOT EXISTS accounts(
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, pw_hash TEXT, role TEXT DEFAULT 'user',
 status TEXT DEFAULT 'pending', max_users INTEGER DEFAULT 0, max_gb REAL DEFAULT 0, domain TEXT DEFAULT '', created INTEGER DEFAULT 0)""")
db.execute("""CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, uuid TEXT, token TEXT,
 limit_bytes INTEGER DEFAULT 0, expire INTEGER DEFAULT 0, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
 enabled INTEGER DEFAULT 1, note TEXT DEFAULT '', created INTEGER DEFAULT 0, protos TEXT DEFAULT 'vmess',
 port INTEGER DEFAULT 443, fp TEXT DEFAULT '', addr TEXT DEFAULT '', ttl_days INTEGER DEFAULT 0, owner_id INTEGER DEFAULT 1)""")
db.execute("CREATE TABLE IF NOT EXISTS account_settings(account_id INTEGER, k TEXT, v TEXT, PRIMARY KEY(account_id, k))")
db.execute("CREATE TABLE IF NOT EXISTS account_kv(account_id INTEGER, k TEXT, v TEXT, PRIMARY KEY(account_id, k))")
for col in ("note TEXT DEFAULT ''", "created INTEGER DEFAULT 0", "protos TEXT DEFAULT 'vmess'", "port INTEGER DEFAULT 443",
            "fp TEXT DEFAULT ''", "addr TEXT DEFAULT ''", "ttl_days INTEGER DEFAULT 0", "owner_id INTEGER DEFAULT 1"):
    try: db.execute("ALTER TABLE users ADD COLUMN " + col)
    except Exception: pass
try:  # migration from the previous version: old appearance settings ← owner
    if not db.execute("SELECT 1 FROM account_settings LIMIT 1").fetchone():
        for r in db.execute("SELECT k, v FROM settings").fetchall():
            if r["k"] in APPEARANCE:
                db.execute("INSERT OR IGNORE INTO account_settings VALUES(1, ?, ?)", (r["k"], r["v"]))
except sqlite3.OperationalError:
    pass
for r in db.execute("SELECT id, protos FROM users WHERE protos LIKE '%reality%'").fetchall():  # Reality removed
    db.execute("UPDATE users SET protos=? WHERE id=?",
               (",".join(x for x in r["protos"].split(",") if x != "reality") or "vmess", r["id"]))
db.commit()

def get_kv(aid, k, default=None):
    with L:
        r = db.execute("SELECT v FROM account_kv WHERE account_id=? AND k=?", (aid, k)).fetchone()
    try:
        return json.loads(r["v"]) if r else default
    except Exception:
        return default

def set_kv(aid, k, val):
    with L:
        db.execute("INSERT OR REPLACE INTO account_kv VALUES(?,?,?)", (aid, k, json.dumps(val, ensure_ascii=False)))
        db.commit()

# ------------------------- passwords and sessions -------------------------
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()

def check_pw(pw, stored):
    try:
        s, h = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(s), 200_000).hex(), h)
    except Exception:
        return False

DUMMY_HASH = hash_pw("dummy-password")

SETUP_KEY = env("SETUP_KEY")   # optional: the first-run setup page then requires ?key=<SETUP_KEY>
SETUP_USER_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

def needs_setup():
    with L:
        return db.execute("SELECT 1 FROM accounts WHERE role='owner'").fetchone() is None

def bootstrap_owner():
    """With ADMIN_PASSWORD set the owner is managed by variables; without it the first visitor creates the owner on the setup page."""
    pw = env("ADMIN_PASSWORD")
    if not pw:
        return
    with L:
        row = db.execute("SELECT id FROM accounts WHERE role='owner'").fetchone()
        if row:
            db.execute("UPDATE accounts SET email=?, pw_hash=?, status='active' WHERE id=?", (ADMIN_USER, hash_pw(pw), row["id"]))
        else:
            db.execute("INSERT INTO accounts(id,email,pw_hash,role,status,max_users,max_gb,created) VALUES(1,?,?,'owner','active',0,0,?)",
                       (ADMIN_USER, hash_pw(pw), int(time.time())))
        db.commit()

SESS = {}   # token -> (account_id, expiry)
fails = {}  # key (ip/email) -> (count, start)
regs = {}

def new_session(aid):
    t = secrets.token_urlsafe(32)
    SESS[t] = (aid, time.time() + 12 * 3600)
    return t

def drop_sessions(aid):
    for t in [t for t, v in SESS.items() if v[0] == aid]:
        SESS.pop(t, None)

def me_of(request: Request):
    t = request.cookies.get("sess") or ""
    s = SESS.get(t)
    if not s or s[1] < time.time():
        SESS.pop(t, None)
        return None
    with L:
        a = db.execute("SELECT * FROM accounts WHERE id=?", (s[0],)).fetchone()
    if not a or a["status"] != "active":
        SESS.pop(t, None)
        return None
    return a

def auth(request: Request):
    a = me_of(request)
    if not a:
        raise HTTPException(401)
    if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "panel":
        raise HTTPException(403)   # guard CSRF
    return a

def owner_only(a=Depends(auth)):
    if a["role"] != "owner":
        raise HTTPException(403)
    return a

def client_ip(request: Request):
    return (request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or request.client.host).split(",")[0].strip()

def throttle(key, limit, window=600):
    now = time.time()
    n, t = fails.get(key, (0, now))
    if now - t > window:
        n, t = 0, now
    if n >= limit:
        raise HTTPException(429, "Too many attempts; try again in a few minutes")
    return n, t

def is_active(u):
    now = time.time()
    return (u["enabled"] and (u["limit_bytes"] == 0 or u["up"] + u["down"] < u["limit_bytes"])
            and (u["expire"] == 0 or u["expire"] > now))

def active_users():
    return [u for u in db.execute("SELECT users.* FROM users JOIN accounts ON accounts.id=users.owner_id WHERE accounts.status='active'")
            if is_active(u)]

# ------------------------- Xray management -------------------------
PATHS = {"vmess": WS_PATH, "vless": "/vl", "trojan": "/tr", "vlessh": "/hu"}
LABEL = {"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan", "vlessh": "VLESS-HU"}
# protocol: (tag, internal port, xray protocol, transport type)
INB = {"vmess": ("vmess-in", 10000, "vmess", "ws"), "vless": ("vless-in", 10001, "vless", "ws"),
       "trojan": ("trojan-in", 10002, "trojan", "ws"), "vlessh": ("vlessh-in", 10003, "vless", "httpupgrade")}
CONF = os.path.join(DATA, "xray.json")
API = "127.0.0.1:10085"
proc = None
current = None
bad_ids = None
last_err = ""
pending = False

def clients_for(p, users):
    out = []
    for u in users:
        if p not in u["protos"].split(","):
            continue
        e = f"u{u['id']}"
        if p == "vmess": out.append({"id": u["uuid"], "email": e, "alterId": 0})
        elif p == "trojan": out.append({"password": u["uuid"], "email": e})
        else: out.append({"id": u["uuid"], "email": e})
    if not out:  # xray requires at least one client
        d = str(uuid.uuid4())
        out = [{"password": d, "email": "dummy"} if p == "trojan" else {"id": d, "email": "dummy"}]
    return out

def write_config(users, path=None):
    inbounds = [{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
                 "settings": {"address": "127.0.0.1"}}]
    for p, (tag, port, proto, net) in INB.items():
        st = {"clients": clients_for(p, users)}
        if proto == "vless":
            st["decryption"] = "none"
        ss = ({"network": "ws", "wsSettings": {"path": PATHS[p]}} if net == "ws"
              else {"network": "httpupgrade", "httpupgradeSettings": {"path": PATHS[p]}})
        inbounds.append({"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": proto, "settings": st, "streamSettings": ss})
    cfg = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
        # security: proxy users cannot reach the internal/local network (panel, Xray API, railway.internal)
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]},
    }
    with open(path or CONF, "w") as f:
        json.dump(cfg, f)
    return [i["port"] for i in inbounds]

def port_open(port, host="127.0.0.1"):
    try:
        socket.create_connection((host, port), 0.6).close()
        return True
    except OSError:
        return False

def xray_test(path):
    try:
        r = subprocess.run(["xray", "run", "-test", "-c", path], capture_output=True, text=True, timeout=20)
        msg = (r.stdout + r.stderr).strip()[-400:]
        if r.returncode != 0 and "not defined" in msg.lower():
            return True, ""
        return r.returncode == 0, msg
    except Exception:
        return True, ""

def wait_ready(ports, timeout=9):
    end = time.time() + timeout
    while time.time() < end:
        if proc is None or proc.poll() is not None:
            return False
        if all(port_open(p) for p in ports):
            return True
        time.sleep(0.3)
    return False

def pairs(users):
    return frozenset((u["id"], p) for u in users for p in u["protos"].split(",") if p in INB)

def sync():
    global proc, current, bad_ids, last_err
    with L:
        users = active_users()
        ids = pairs(users)
        alive = proc is not None and proc.poll() is None
        if alive and ids == current:
            return
        if ids == bad_ids:
            return
        new_conf = os.path.join(DATA, "xray.new.json")   # the extension must be .json
        ports = write_config(users, new_conf)
        ok, msg = xray_test(new_conf)
        if not ok:
            bad_ids = ids
            last_err = "Invalid Xray config; change not applied: " + msg
            print("[xray] config test failed:", msg, flush=True)
            return
        if alive:
            collect()  # save the usage before the restart
            proc.terminate()
            try: proc.wait(5)
            except Exception: proc.kill()
        os.replace(new_conf, CONF)
        for attempt in (1, 2):
            proc = subprocess.Popen(["xray", "run", "-c", CONF])
            if wait_ready(ports):
                break
            print(f"[xray] not ready (attempt {attempt}, exit={proc.poll()})", flush=True)
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(3)
                except Exception: proc.kill()
        closed = [p for p in ports if not port_open(p)]
        ready = proc.poll() is None and not closed
        last_err = "" if ready else f"Xray did not start; ports not open: {closed or '—'}; check the Railway logs"
        bad_ids = None
        current = ids
        print("[xray] started ready=%s users per protocol: %s" % (ready, {p: sum(1 for i, q in ids if q == p) for p in INB}), flush=True)

_ev = threading.Event()

def sync_async():
    """The API answers immediately; applying to Xray happens in the background (consecutive changes are batched)"""
    global pending
    pending = True
    _ev.set()

def _syncer():
    global pending
    while True:
        _ev.wait()
        time.sleep(0.35)
        _ev.clear()
        try:
            sync()
        except Exception as e:
            print("[sync] error:", e, flush=True)
        if not _ev.is_set():
            pending = False

def collect():
    try:
        out = subprocess.run(["xray", "api", "statsquery", "-s", API, "-pattern", "user>>>", "-reset"],
                             capture_output=True, text=True, timeout=10).stdout
        stats = json.loads(out).get("stat", []) if out.strip() else []
    except Exception:
        return
    with L:
        for s in stats:
            p = s["name"].split(">>>")
            if len(p) < 4 or not p[1].startswith("u"):
                continue
            col = "up" if p[3] == "uplink" else "down"
            db.execute(f"UPDATE users SET {col}={col}+? WHERE id=?", (int(s["value"]), int(p[1][1:])))
        db.execute("UPDATE users SET expire=?+ttl_days*86400, ttl_days=0 WHERE ttl_days>0 AND expire=0 AND up+down>0", (int(time.time()),))
        db.commit()

def loop():
    time.sleep(3)
    while True:
        try:
            collect()
            sync()
            now = time.time()
            for t in [t for t, v in SESS.items() if v[1] < now]:
                SESS.pop(t, None)
            if len(fails) > 2000: fails.clear()
        except Exception as e:
            print("loop error:", e, flush=True)
        time.sleep(10)

# ------------------------- links -------------------------
ALLOWED_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
FPS = {"", "android", "chrome", "firefox", "safari", "ios", "random"}

def links(u, dom, prefix):
    fp = u["fp"] or "chrome"
    port = u["port"] if u["port"] in ALLOWED_PORTS else 443
    name = prefix + u["name"]
    out = []
    for p in u["protos"].split(","):
        if p not in PATHS:
            continue
        if p == "vmess":
            cfg = {"v": "2", "ps": f"{name} VMess", "add": dom, "port": str(port), "id": u["uuid"], "aid": "0",
                   "scy": "auto", "net": "ws", "type": "none", "host": dom, "path": PATHS[p], "tls": "tls",
                   "sni": dom, "alpn": "http/1.1", "fp": fp}
            out.append((p, "vmess://" + base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()))
            continue
        q = {"security": "tls", "type": "httpupgrade" if p == "vlessh" else "ws", "host": dom, "path": PATHS[p]}
        if p != "trojan":
            q["encryption"] = "none"
        q.update(sni=dom, fp=fp, alpn="http/1.1")
        tag = urllib.parse.quote(f"{name} {LABEL[p]}")
        scheme = "trojan" if p == "trojan" else "vless"
        out.append((p, f"{scheme}://{u['uuid']}@{dom}:{port}?{urllib.parse.urlencode(q)}#{tag}"))
    return out

# clean-IP / multi-location variants: only the connect address changes, SNI and Host stay on the real domain
LINK_RE = re.compile(r"^([a-z]+://[^@]+@)(\[[^\]]+\]|[^:/?#]+)(:\d+)?([^#]*)(#.*)?$", re.I)

def with_ip(link, addr, port=""):
    try:
        if link.startswith("vmess://"):
            j = json.loads(base64.b64decode(link[8:]))
            j["host"] = j.get("host") or j["add"]
            j["sni"] = j.get("sni") or j["host"]
            j["add"] = addr
            if port:
                j["port"] = str(port)
            j["ps"] = f"{j.get('ps', '')} | {addr}"
            return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()
        m = LINK_RE.match(link)
        if not m:
            return link
        a, h, pt, q, f = m.groups()
        qd = dict(urllib.parse.parse_qsl(q.lstrip("?")))
        qd.setdefault("sni", h)
        if "host" not in qd and qd.get("type") in ("ws", "httpupgrade", "xhttp", "splithttp"):
            qd["host"] = h
        frag = (f + urllib.parse.quote(" | " + addr)) if f else "#" + urllib.parse.quote(addr)
        return f"{a}{addr}:{port or (pt[1:] if pt else 443)}?{urllib.parse.urlencode(qd)}{frag}"
    except Exception:
        return link

def full(u, dom, prefix):
    d = {k: u[k] for k in u.keys() if k not in ("owner_id", "addr")}
    d["active"] = bool(is_active(u))
    d["links"] = [{"p": p, "l": l} for p, l in links(u, dom, prefix)]
    return d

def settings_for(aid):
    d = dict(APPEARANCE)
    with L:
        d.update({r["k"]: r["v"] for r in db.execute("SELECT k, v FROM account_settings WHERE account_id=?", (aid,))})
    d["title"] = TITLE   # locked
    return d

HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")

def req_host(request):
    """Config links always point at the host the panel or subscription was opened with."""
    h = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip().split(":")[0].lower()
    return DOMAIN_ENV or (h if HOST_RE.match(h) else "localhost")

def clean_protos(l):
    l = [p for p in (l or []) if p in PATHS]
    return ",".join(dict.fromkeys(l)) or "vmess"

def used_bytes(aid, exclude=None):
    return db.execute("SELECT COALESCE(SUM(limit_bytes),0) s FROM users WHERE owner_id=? AND id IS NOT ?", (aid, exclude)).fetchone()["s"]

def meminfo():
    mem = {}
    try:
        for ln in open("/proc/meminfo"):
            k, v = ln.split(":")
            mem[k] = int(v.split()[0]) * 1024
    except Exception:
        pass
    total = mem.get("MemTotal", 0)
    return total - mem.get("MemAvailable", total), total

def my_stats(a):
    with L:
        us = db.execute("SELECT * FROM users WHERE owner_id=?", (a["id"],)).fetchall()
    d = {"users": len(us), "active": sum(1 for u in us if is_active(u)), "traffic": sum(u["up"] + u["down"] for u in us),
         "applying": pending, "ram_used": 0, "ram_total": 0, "load": 0, "xray_err": ""}
    if a["role"] == "owner":
        d["ram_used"], d["ram_total"] = meminfo()
        d["load"] = os.getloadavg()[0]
        d["xray_err"] = last_err
    return d

def me_info(a):
    return {"email": a["email"], "role": a["role"], "max_users": a["max_users"], "max_gb": a["max_gb"]}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# connect-src allows https: so the panel's Scanner page can time-test clean IPs straight from the browser
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; "
       "img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

@app.middleware("http")
async def secure_headers(request: Request, call_next):
    resp = await call_next(request)
    h = resp.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Strict-Transport-Security"] = "max-age=31536000"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.path.startswith("/api") or request.url.path in ("/login", "/register", "/admin", "/"):
        h["Cache-Control"] = "no-store"
    if h.get("content-type", "").startswith("text/html"):
        h["Content-Security-Policy"] = CSP
    return resp

@app.on_event("startup")
def start():
    threading.Thread(target=_syncer, daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    sync_async()

# ------------------------- login and sign-up -------------------------

def need_header(request: Request):
    if request.headers.get("x-requested-with") != "panel":
        raise HTTPException(403)

@app.post("/login")
def login(body: dict, request: Request):
    need_header(request)
    ident = str(body.get("username", body.get("email", ""))).strip().lower()[:100]
    pw = str(body.get("password", ""))[:200]
    ip = client_ip(request)
    n1, t1 = throttle("ip:" + ip, 15)
    n2, t2 = throttle("em:" + ident, 8)
    with L:
        a = db.execute("SELECT * FROM accounts WHERE email=?", (ident,)).fetchone()
    ok = check_pw(pw, a["pw_hash"] if a else DUMMY_HASH) and a is not None
    if not ok:
        fails["ip:" + ip] = (n1 + 1, t1)
        fails["em:" + ident] = (n2 + 1, t2)
        time.sleep(1.0)
        raise HTTPException(401, "Wrong username or password")
    if a["status"] == "pending":
        raise HTTPException(403, "Account is not yet approved by the owner")
    if a["status"] != "active":
        raise HTTPException(403, "Account is blocked")
    fails.pop("ip:" + ip, None)
    fails.pop("em:" + ident, None)
    r = Response('{"ok":true}', media_type="application/json")
    r.set_cookie("sess", new_session(a["id"]), max_age=12 * 3600, httponly=True, samesite="strict", secure=True, path="/")
    return r

@app.get("/logout")
def logout(request: Request):
    SESS.pop(request.cookies.get("sess") or "", None)
    r = RedirectResponse("/login")
    r.delete_cookie("sess", path="/")
    return r

@app.put("/api/password")
def change_password(body: dict, request: Request, a=Depends(auth)):
    """Change the password of the signed-in account (all other sessions are signed out)."""
    if a["role"] == "owner" and env("ADMIN_PASSWORD"):
        # bootstrap_owner() would overwrite the new password with the variable on the next restart
        raise HTTPException(409, "The owner password is managed by the ADMIN_PASSWORD variable; change it there")
    key = "pw:%s" % a["id"]
    n, t = throttle(key, 8)
    old, new = str(body.get("old", ""))[:200], str(body.get("new", ""))
    if not check_pw(old, a["pw_hash"]):
        fails[key] = (n + 1, t)
        time.sleep(1.0)
        raise HTTPException(403, "Current password is wrong")
    if not 8 <= len(new) <= 128:
        raise HTTPException(400, "Password must be 8 to 128 characters")
    if new.lower() == (a["email"] or "").lower():
        raise HTTPException(400, "Password must differ from the username")
    with L:
        db.execute("UPDATE accounts SET pw_hash=? WHERE id=?", (hash_pw(new), a["id"]))
        db.commit()
    fails.pop(key, None)
    drop_sessions(a["id"])
    r = Response('{"ok":true}', media_type="application/json")
    r.set_cookie("sess", new_session(a["id"]), max_age=12 * 3600, httponly=True, samesite="strict", secure=True, path="/")
    return r

# ------------------------- API users -------------------------
class NewUser(BaseModel):
    name: str
    gb: float = 0
    days: int = 0
    note: str = ""
    protos: list = ["vmess"]
    port: int = 443
    fp: str = ""
    first_use: bool = False
    count: int = 1
    uuid: str = ""
    enabled: bool = True

class EditUser(BaseModel):
    name: Optional[str] = None
    note: Optional[str] = None
    gb: Optional[float] = None
    days: Optional[int] = None
    add_gb: Optional[float] = None
    add_days: Optional[int] = None
    enabled: Optional[bool] = None
    protos: Optional[list] = None
    port: Optional[int] = None
    fp: Optional[str] = None
    reset: bool = False

@app.get("/api/all")
def api_all(request: Request, a=Depends(auth)):
    st, dom = settings_for(a["id"]), req_host(request)
    with L:
        us = db.execute("SELECT * FROM users WHERE owner_id=? ORDER BY id DESC", (a["id"],)).fetchall()
        users = [full(u, dom, st["prefix"]) for u in us]
    return {"me": me_info(a), "users": users, "settings": st, "stats": my_stats(a)}

@app.post("/api/users")
def add_user(n: NewUser, request: Request, a=Depends(auth)):
    cnt = max(1, min(n.count, 200))
    gb, days = max(0.0, n.gb), max(0, n.days)
    port = n.port if n.port in ALLOWED_PORTS else 443
    fp = n.fp if n.fp in FPS else ""
    with L:
        if a["max_users"] and db.execute("SELECT COUNT(*) c FROM users WHERE owner_id=?", (a["id"],)).fetchone()["c"] + cnt > a["max_users"]:
            raise HTTPException(403, "You reached the user limit of your account")
        if a["max_gb"]:
            if gb <= 0:
                raise HTTPException(400, "This account requires you to set a volume")
            if used_bytes(a["id"]) + cnt * int(gb * GB) > a["max_gb"] * GB:
                raise HTTPException(403, "This would exceed the volume limit of your account")
        ids = []
        for i in range(cnt):
            name = (n.name.strip() or "user")[:64]
            if cnt > 1:
                name = f"{name}-{i + 1}"
            uid_ = str(uuid.uuid4())
            if cnt == 1 and n.uuid:
                try: uid_ = str(uuid.UUID(n.uuid))
                except ValueError: raise HTTPException(400, "Invalid UUID")
            first = n.first_use and days > 0
            cur = db.execute("INSERT INTO users(name,uuid,token,limit_bytes,expire,note,created,protos,port,fp,ttl_days,enabled,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             (name, uid_, secrets.token_urlsafe(12), int(gb * GB),
                              0 if first or not days else int(time.time() + days * 86400), n.note[:200], int(time.time()),
                              clean_protos(n.protos), port, fp, days if first else 0, int(n.enabled), a["id"]))
            ids.append(cur.lastrowid)
        db.commit()
        st, dom = settings_for(a["id"]), req_host(request)
        rows = [db.execute("SELECT * FROM users WHERE id=?", (i,)).fetchone() for i in ids]
        created = [full(r, dom, st["prefix"]) for r in reversed(rows)]
    sync_async()
    return {"ok": True, "users": created, "stats": my_stats(a)}

@app.put("/api/users/{uid}")
def edit_user(uid: int, e: EditUser, request: Request, a=Depends(auth)):
    with L:
        u = db.execute("SELECT * FROM users WHERE id=? AND owner_id=?", (uid, a["id"])).fetchone()
        if not u:
            raise HTTPException(404)
        f = {}
        if e.name is not None: f["name"] = (e.name.strip() or u["name"])[:64]
        if e.note is not None: f["note"] = e.note[:200]
        if e.enabled is not None: f["enabled"] = int(e.enabled)
        if e.protos is not None: f["protos"] = clean_protos(e.protos)
        if e.port is not None: f["port"] = e.port if e.port in ALLOWED_PORTS else 443
        if e.fp is not None: f["fp"] = e.fp if e.fp in FPS else ""
        if e.gb is not None: f["limit_bytes"] = int(max(0.0, e.gb) * GB)
        if e.days is not None:
            f["expire"] = int(time.time() + max(0, e.days) * 86400) if e.days > 0 else 0
            f["ttl_days"] = 0
        if e.add_gb:
            f["limit_bytes"] = max(0, int(f.get("limit_bytes", u["limit_bytes"]) + e.add_gb * GB))
        if e.add_days:
            cur_exp = f.get("expire", u["expire"])
            f["expire"] = int((max(cur_exp, time.time()) if cur_exp else time.time()) + e.add_days * 86400)
        if "limit_bytes" in f and a["max_gb"]:
            if f["limit_bytes"] == 0:
                raise HTTPException(400, "This account requires you to set a volume")
            if used_bytes(a["id"], uid) + f["limit_bytes"] > a["max_gb"] * GB:
                raise HTTPException(403, "This would exceed the volume limit of your account")
        if e.reset: f["up"] = f["down"] = 0
        if f:
            db.execute("UPDATE users SET " + ",".join(f"{k}=?" for k in f) + " WHERE id=?", (*f.values(), uid))
            db.commit()
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        user = full(row, req_host(request), settings_for(a["id"])["prefix"])
    sync_async()
    return {"ok": True, "user": user, "stats": my_stats(a)}

@app.delete("/api/users/{uid}")
def del_user(uid: int, a=Depends(auth)):
    with L:
        db.execute("DELETE FROM users WHERE id=? AND owner_id=?", (uid, a["id"]))
        db.commit()
    sync_async()
    return {"ok": True, "stats": my_stats(a)}

@app.put("/api/settings")
def put_settings(body: dict, a=Depends(auth)):
    with L:
        for k, v in body.items():
            if k not in APPEARANCE:   # domain, title and other sensitive settings are ignored here
                continue
            v = str(v).strip()[:300]
            if k in HEX_KEYS and not re.fullmatch(r"#[0-9a-fA-F]{6}", v): v = APPEARANCE[k]
            elif k in NUM_KEYS and not v.isdigit(): v = APPEARANCE[k]
            elif k == "bgimg" and v and not re.match(r"^https://[^\s\"'()\\]+$", v): v = ""
            elif k == "prefix": v = re.sub(r"[\r\n]", "", v)[:20]
            elif k not in ("bgimg", "prefix") and k not in HEX_KEYS + NUM_KEYS and not re.fullmatch(r"[a-z0-9_-]{1,20}", v): v = APPEARANCE[k]
            db.execute("INSERT OR REPLACE INTO account_settings VALUES(?,?,?)", (a["id"], k, v))
        db.commit()
    return {"ok": True}

# ------------------------- clean-IP pool and multi-location (used by /sub) -------------------------
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")

def _port_ok(p):
    return p == "" or (p.isdigit() and 1 <= int(p) <= 65535)

@app.get("/api/pool")
def get_pool(a=Depends(auth)):
    return get_kv(a["id"], "pool", {"ips": [], "locs": [], "n": 10, "sub": 0})

@app.put("/api/pool")
def put_pool(body: dict, a=Depends(auth)):
    ips = []
    for x in (body.get("ips") or [])[:1000]:
        x = str(x).strip()
        if IP_RE.match(x) and _port_ok(x.partition(":")[2]):
            ips.append(x)
    locs = []
    for l in (body.get("locs") or [])[:100]:
        if not isinstance(l, dict):
            continue
        h, p = str(l.get("h", "")).strip(), str(l.get("p", "")).strip()
        if HOST_RE.match(h) and _port_ok(p):
            locs.append({"n": str(l.get("n", h)).strip()[:40], "h": h, "p": p})
    try:
        n = max(1, min(100, int(body.get("n", 10))))
    except (TypeError, ValueError):
        n = 10
    set_kv(a["id"], "pool", {"ips": ips, "locs": locs, "n": n, "sub": 1 if body.get("sub") else 0})
    return {"ok": True}

@app.get("/healthz")
def healthz():
    return Response("ok", media_type="text/plain")

@app.get("/sub/{token}")
def sub(token: str, request: Request):
    with L:
        u = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        acc = db.execute("SELECT * FROM accounts WHERE id=?", (u["owner_id"],)).fetchone() if u else None
    if not u or not acc or acc["status"] != "active":
        raise HTTPException(404)
    lk = links(u, req_host(request), settings_for(acc["id"])["prefix"])
    out = [l for _, l in lk]
    cfg = get_kv(acc["id"], "pool")
    if cfg and cfg.get("sub"):   # clean IPs and locations are appended after the normal links
        ips = cfg.get("ips", [])[:max(1, int(cfg.get("n", 10)))]
        for _, l in lk:
            for x in ips:
                h, _, p = x.partition(":")
                out.append(with_ip(l, h, p))
            for loc in cfg.get("locs", []):
                out.append(with_ip(l, loc["h"], loc["p"]))
    h = {"subscription-userinfo": f"upload={u['up']}; download={u['down']}; total={u['limit_bytes']}; expire={u['expire']}",
         "profile-update-interval": "1", "Cache-Control": "no-store",
         "profile-title": "base64:" + base64.b64encode(TITLE.encode()).decode()}
    return Response(base64.b64encode("\n".join(out).encode()), media_type="text/plain", headers=h)

HERE = os.path.dirname(os.path.abspath(__file__))
_admin_html = None

def panel_page(request: Request):
    global _admin_html
    if not me_of(request):
        return RedirectResponse("/login")
    if _admin_html is None:
        _admin_html = open(os.path.join(HERE, "admin.html"), encoding="utf-8").read()
    return HTMLResponse(_admin_html)

@app.get("/")
def root(request: Request):
    return panel_page(request)

@app.get("/admin")
def admin(request: Request):
    return panel_page(request)

@app.post("/setup")
def setup(body: dict, request: Request):
    need_header(request)
    ip = client_ip(request)
    n, t = throttle("setup:" + ip, 20)
    fails["setup:" + ip] = (n + 1, t)
    if SETUP_KEY and not hmac.compare_digest(str(body.get("key", "")).encode(), SETUP_KEY.encode()):
        time.sleep(1.0)
        raise HTTPException(403, "Invalid setup key")
    user = str(body.get("username", "")).strip().lower()
    pw = str(body.get("password", ""))
    if not SETUP_USER_RE.match(user):
        raise HTTPException(400, "Username must be 3 to 32 characters: letters, digits, dot, dash or underscore")
    if not 8 <= len(pw) <= 128:
        raise HTTPException(400, "Password must be 8 to 128 characters")
    if pw.lower() == user:
        raise HTTPException(400, "Password must differ from the username")
    with L:
        if db.execute("SELECT 1 FROM accounts WHERE role='owner'").fetchone():
            raise HTTPException(403, "Setup is already completed")
        db.execute("INSERT INTO accounts(id,email,pw_hash,role,status,max_users,max_gb,created) VALUES(1,?,?,'owner','active',0,0,?)",
                   (user, hash_pw(pw), int(time.time())))
        db.commit()
    r = Response('{"ok":true}', media_type="application/json")
    r.set_cookie("sess", new_session(1), max_age=12 * 3600, httponly=True, samesite="strict", secure=True, path="/")
    return r

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if needs_setup():
        key = request.query_params.get("key", "")
        if SETUP_KEY and not hmac.compare_digest(key.encode(), SETUP_KEY.encode()):
            raise HTTPException(404)
        return SETUP.replace("__TITLE__", TITLE)
    return LOGIN.replace("__TITLE__", TITLE)

@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    return login_page(request)

SETUP = """<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,Tahoma,sans-serif;
background:radial-gradient(900px 500px at 80% -10%,#4b34c4 0,transparent 60%),radial-gradient(700px 500px at 0 110%,#0f6e8c 0,transparent 55%),#0a0c13;color:#eef0f8}
.b{width:min(380px,92vw);padding:28px;border-radius:22px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);animation:fu .6s both}
@keyframes fu{from{opacity:0;transform:translateY(18px)}}
h2{margin:0 0 4px}p{margin:0 0 18px;color:#9aa3bd;font-size:14px;line-height:1.6}
input{width:100%;padding:13px 14px;margin:6px 0;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.3);color:#fff;font-size:15px}
button{width:100%;margin-top:12px;padding:13px;border:0;border-radius:12px;background:linear-gradient(135deg,#7c5cff,#38d4ff);color:#fff;font-size:16px;font-weight:700}
button:hover{filter:brightness(1.12)}#e{color:#ff6b7a;font-size:13px;min-height:18px;margin-top:8px}</style></head><body>
<form class="b" onsubmit="go(event)"><h2>🔐 __TITLE__</h2><p>Welcome! Choose a new username and password for your panel. Keep them safe: this is the only time they are set here.</p>
<input id="u" placeholder="New username" autocomplete="username" autocapitalize="none"><input id="p" type="password" placeholder="New password (8+ characters)" autocomplete="new-password"><input id="c" type="password" placeholder="Repeat password" autocomplete="new-password">
<label style="font-size:13px;color:#9aa3bd;display:block;margin-top:4px"><input type="checkbox" style="width:auto;margin:6px" onchange="p.type=c.type=this.checked?'text':'password'">Show password</label>
<button>Create account and continue</button><div id="e"></div></form>
<script>async function go(ev){ev.preventDefault();e.textContent='';
if(p.value!==c.value){e.textContent='Passwords do not match';return}
let r,j={};try{r=await fetch('/setup',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'panel'},
body:JSON.stringify({username:u.value,password:p.value,key:new URLSearchParams(location.search).get('key')||''})});
try{j=await r.json()}catch(x){}}catch(x){e.textContent='Network error';return}
if(r.ok)location='/admin';else e.textContent=j.detail||'Error ('+r.status+')'}</script></body></html>"""

LOGIN = """<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,Tahoma,sans-serif;
background:radial-gradient(900px 500px at 80% -10%,#4b34c4 0,transparent 60%),radial-gradient(700px 500px at 0 110%,#0f6e8c 0,transparent 55%),#0a0c13;color:#eef0f8}
.b{width:min(360px,92vw);padding:28px;border-radius:22px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);animation:fu .6s both}
@keyframes fu{from{opacity:0;transform:translateY(18px)}}
h2{margin:0 0 4px}p{margin:0 0 18px;color:#9aa3bd;font-size:14px}
input{width:100%;padding:13px 14px;margin:6px 0;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.3);color:#fff;font-size:15px}
button{width:100%;margin-top:12px;padding:13px;border:0;border-radius:12px;background:linear-gradient(135deg,#7c5cff,#38d4ff);color:#fff;font-size:16px;font-weight:700}
button:hover{filter:brightness(1.12)}#e{color:#ff6b7a;font-size:13px;min-height:18px;margin-top:8px}</style></head><body>
<form class="b" onsubmit="go(event)"><h2>🔐 __TITLE__</h2><p>Sign in to continue</p>
<input id="u" placeholder="Username" autocomplete="username" autocapitalize="none"><input id="p" type="password" placeholder="Password" autocomplete="current-password">
<label style="font-size:13px;color:#9aa3bd;display:block;margin-top:4px"><input type="checkbox" style="width:auto;margin:6px" onchange="p.type=this.checked?'text':'password'">Show password</label>
<button>Sign in</button><div id="e"></div></form>
<script>async function go(ev){ev.preventDefault();e.textContent='';let r,j={};
try{r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'panel'},body:JSON.stringify({username:u.value,password:p.value})});
try{j=await r.json()}catch(x){}}catch(x){e.textContent='Network error';return}
if(r.ok)location='/admin';else e.textContent=j.detail||'Error ('+r.status+')'}</script></body></html>"""

bootstrap_owner()
