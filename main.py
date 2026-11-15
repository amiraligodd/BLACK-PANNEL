# ============================ KING_PANNEL ============================
import os, json, time, uuid, secrets, base64, sqlite3, subprocess, threading, hashlib, hmac, re, socket, urllib.parse
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel


def env(k, d=""):
    return (os.environ.get(k) or d).strip()

# دامنه‌ی ریلوی: ترجیحاً متغیر DOMAIN (یا خودکار RAILWAY_PUBLIC_DOMAIN)؛ اگه هیچ‌کدوم نبود از این خط
RAILWAY_DOMAIN = "YOUR-DOMAIN.up.railway.app"
DOMAIN = re.sub(r"^https?://", "", env("DOMAIN") or env("RAILWAY_PUBLIC_DOMAIN") or RAILWAY_DOMAIN).split("/")[0]
TITLE = env("PANEL_TITLE", "KING_PANNEL")          # قفل: از داخل پنل قابل تغییر نیست
DATA = env("DATA_DIR", "/data")
WS_PATH = "/in2"
GB = 1024 ** 3
ADMIN_USER = env("ADMIN_USER", "admin").lower()    # نام کاربری مالک (رمزش: متغیر ADMIN_PASSWORD)
ALLOW_SIGNUP = env("ALLOW_SIGNUP", "1") == "1"     # ثبت‌نام عمومی
SIGNUP_APPROVAL = env("SIGNUP_APPROVAL", "1") == "1"   # حساب جدید تا تأیید مالک غیرفعاله
DEFAULT_MAX_USERS = int(env("DEFAULT_MAX_USERS", "5") or 5)
DEFAULT_MAX_GB = float(env("DEFAULT_MAX_GB", "50") or 50)   # جمع حجم کاربرهای هر حساب (0 = نامحدود)

# تنظیمات ظاهری قابل‌تغییر توسط هر حساب (تنظیمات حساس مثل دامنه و عنوان قفل هستن)
APPEARANCE = {"accent": "#7c5cff", "accent2": "#38d4ff", "theme": "dark", "palette": "default", "radius": "16",
              "bg": "gradient", "fx": "none", "noise": "0", "cardstyle": "glass", "border": "normal", "hover": "lift",
              "spot": "1", "btn": "gradient", "titlefx": "gradient", "shape": "squircle", "pbar": "gradient",
              "layout": "list", "density": "normal", "enter": "fade", "anim": "1", "font": "system", "fsize": "15",
              "blur": "14", "opacity": "40", "glow": "40", "bgimg": "", "prefix": ""}
HEX_KEYS = ("accent", "accent2")
NUM_KEYS = ("radius", "fsize", "blur", "opacity", "glow")

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
for col in ("note TEXT DEFAULT ''", "created INTEGER DEFAULT 0", "protos TEXT DEFAULT 'vmess'", "port INTEGER DEFAULT 443",
            "fp TEXT DEFAULT ''", "addr TEXT DEFAULT ''", "ttl_days INTEGER DEFAULT 0", "owner_id INTEGER DEFAULT 1"):
    try: db.execute("ALTER TABLE users ADD COLUMN " + col)
    except Exception: pass
try:  # مهاجرت از نسخه‌ی قبلی: تنظیمات ظاهری قدیمی ← مالک
    if not db.execute("SELECT 1 FROM account_settings LIMIT 1").fetchone():
        for r in db.execute("SELECT k, v FROM settings").fetchall():
            if r["k"] in APPEARANCE:
                db.execute("INSERT OR IGNORE INTO account_settings VALUES(1, ?, ?)", (r["k"], r["v"]))
except sqlite3.OperationalError:
    pass
for r in db.execute("SELECT id, protos FROM users WHERE protos LIKE '%reality%'").fetchall():  # Reality حذف شد
    db.execute("UPDATE users SET protos=? WHERE id=?",
               (",".join(x for x in r["protos"].split(",") if x != "reality") or "vmess", r["id"]))
db.commit()

# ------------------------- رمز و نشست‌ها -------------------------
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

def bootstrap_owner():
    pw = env("ADMIN_PASSWORD")
    path = os.path.join(DATA, "admin_password.txt")
    if not pw:
        if os.path.exists(path):
            pw = open(path).read().strip()
        else:
            pw = secrets.token_urlsafe(12)
            with open(path, "w") as f:
                f.write(pw)
            os.chmod(path, 0o600)
            print(f"[panel] ADMIN_PASSWORD not set -> generated one. user={ADMIN_USER} password={pw}", flush=True)
    with L:
        row = db.execute("SELECT id FROM accounts WHERE role='owner'").fetchone()
        if row:
            db.execute("UPDATE accounts SET email=?, pw_hash=?, status='active' WHERE id=?", (ADMIN_USER, hash_pw(pw), row["id"]))
        else:
            db.execute("INSERT INTO accounts(id,email,pw_hash,role,status,max_users,max_gb,created) VALUES(1,?,?,'owner','active',0,0,?)",
                       (ADMIN_USER, hash_pw(pw), int(time.time())))
        db.commit()

SESS = {}   # token -> (account_id, expiry)
fails = {}  # کلید (ip/email) -> (تعداد, شروع)
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
        raise HTTPException(403)   # محافظ CSRF
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
        raise HTTPException(429, "تلاش زیاد؛ چند دقیقه بعد دوباره امتحان کن")
    return n, t

def is_active(u):
    now = time.time()
    return (u["enabled"] and (u["limit_bytes"] == 0 or u["up"] + u["down"] < u["limit_bytes"])
            and (u["expire"] == 0 or u["expire"] > now))

def active_users():
    return [u for u in db.execute("SELECT users.* FROM users JOIN accounts ON accounts.id=users.owner_id WHERE accounts.status='active'")
            if is_active(u)]

# ------------------------- مدیریت Xray -------------------------
PATHS = {"vmess": WS_PATH, "vless": "/vl", "trojan": "/tr", "vlessh": "/hu"}
LABEL = {"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan", "vlessh": "VLESS-HU"}
# پروتکل: (tag, پورت داخلی, پروتکل xray, نوع انتقال)
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
    if not out:  # xray حداقل یک کلاینت می‌خواد
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
        # امنیت: کاربرهای پروکسی نمی‌تونن به شبکه‌ی داخلی/لوکال (پنل، API ی Xray، railway.internal) برسن
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
        new_conf = os.path.join(DATA, "xray.new.json")   # پسوند باید .json باشه
        ports = write_config(users, new_conf)
        ok, msg = xray_test(new_conf)
        if not ok:
            bad_ids = ids
            last_err = "کانفیگ Xray نامعتبره؛ تغییر اعمال نشد: " + msg
            print("[xray] config test failed:", msg, flush=True)
            return
        if alive:
            collect()  # قبل از ری‌استارت، مصرف ذخیره بشه
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
        last_err = "" if ready else f"Xray بالا نیومد؛ پورت‌های باز نشده: {closed or '—'}؛ لاگ Railway رو ببین"
        bad_ids = None
        current = ids
        print("[xray] started ready=%s users per protocol: %s" % (ready, {p: sum(1 for i, q in ids if q == p) for p in INB}), flush=True)

_ev = threading.Event()

def sync_async():
    """API فوری جواب می‌ده؛ اعمال روی Xray در پس‌زمینه (با تجمیع تغییرهای پشت‌سرهم) انجام می‌شه"""
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

# ------------------------- لینک‌ها -------------------------
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

def full(u, dom, prefix):
    d = {k: u[k] for k in u.keys() if k not in ("owner_id", "addr")}
    d["active"] = bool(is_active(u))
    d["links"] = [{"p": p, "l": l} for p, l in links(u, dom, prefix)]
    return d

def settings_for(aid):
    d = dict(APPEARANCE)
    with L:
        d.update({r["k"]: r["v"] for r in db.execute("SELECT k, v FROM account_settings WHERE account_id=?", (aid,))})
    d["title"] = TITLE   # قفل
    return d

def dom_of(a):
    return a["domain"] or DOMAIN

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
    return {"email": a["email"], "role": a["role"], "max_users": a["max_users"], "max_gb": a["max_gb"], "domain": dom_of(a)}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; "
       "img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

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

# ------------------------- ورود و ثبت‌نام -------------------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$")

def need_header(request: Request):
    if request.headers.get("x-requested-with") != "panel":
        raise HTTPException(403)

@app.post("/login")
def login(body: dict, request: Request):
    need_header(request)
    ident = str(body.get("email", "")).strip().lower()[:100]
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
        raise HTTPException(401, "ایمیل یا رمز اشتباه است")
    if a["status"] == "pending":
        raise HTTPException(403, "حساب هنوز توسط مالک تأیید نشده")
    if a["status"] != "active":
        raise HTTPException(403, "حساب مسدوده")
    fails.pop("ip:" + ip, None)
    fails.pop("em:" + ident, None)
    r = Response('{"ok":true}', media_type="application/json")
    r.set_cookie("sess", new_session(a["id"]), max_age=12 * 3600, httponly=True, samesite="strict", secure=True, path="/")
    return r

@app.post("/register")
def register(body: dict, request: Request):
    need_header(request)
    if not ALLOW_SIGNUP:
        raise HTTPException(403, "ثبت‌نام بسته‌ست")
    ip = client_ip(request)
    now = time.time()
    regs[ip] = [t for t in regs.get(ip, []) if now - t < 3600]
    if len(regs[ip]) >= 3:
        raise HTTPException(429, "تعداد ثبت‌نام از این آدرس زیاده؛ بعداً امتحان کن")
    email = str(body.get("email", "")).strip().lower()
    pw = str(body.get("password", ""))
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "ایمیل نامعتبره")
    if not 8 <= len(pw) <= 128:
        raise HTTPException(400, "رمز باید ۸ تا ۱۲۸ کاراکتر باشه")
    with L:
        if db.execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "این ایمیل قبلاً ثبت شده")
        db.execute("INSERT INTO accounts(email,pw_hash,role,status,max_users,max_gb,created) VALUES(?,?,'user',?,?,?,?)",
                   (email, hash_pw(pw), "pending" if SIGNUP_APPROVAL else "active", DEFAULT_MAX_USERS, DEFAULT_MAX_GB, int(now)))
        db.commit()
    regs[ip].append(now)
    return {"ok": True, "pending": SIGNUP_APPROVAL}

@app.get("/logout")
def logout(request: Request):
    SESS.pop(request.cookies.get("sess") or "", None)
    r = RedirectResponse("/login")
    r.delete_cookie("sess", path="/")
    return r

# ------------------------- API کاربران -------------------------
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
def api_all(a=Depends(auth)):
    st, dom = settings_for(a["id"]), dom_of(a)
    with L:
        us = db.execute("SELECT * FROM users WHERE owner_id=? ORDER BY id DESC", (a["id"],)).fetchall()
        users = [full(u, dom, st["prefix"]) for u in us]
    return {"me": me_info(a), "users": users, "settings": st, "stats": my_stats(a)}

@app.post("/api/users")
def add_user(n: NewUser, a=Depends(auth)):
    cnt = max(1, min(n.count, 200))
    gb, days = max(0.0, n.gb), max(0, n.days)
    port = n.port if n.port in ALLOWED_PORTS else 443
    fp = n.fp if n.fp in FPS else ""
    with L:
        if a["max_users"] and db.execute("SELECT COUNT(*) c FROM users WHERE owner_id=?", (a["id"],)).fetchone()["c"] + cnt > a["max_users"]:
            raise HTTPException(403, "به سقف تعداد کاربر حسابت رسیدی")
        if a["max_gb"]:
            if gb <= 0:
                raise HTTPException(400, "برای این حساب باید حجم مشخص کنی")
            if used_bytes(a["id"]) + cnt * int(gb * GB) > a["max_gb"] * GB:
                raise HTTPException(403, "از سقف حجم حسابت بیشتر می‌شه")
        ids = []
        for i in range(cnt):
            name = (n.name.strip() or "user")[:64]
            if cnt > 1:
                name = f"{name}-{i + 1}"
            uid_ = str(uuid.uuid4())
            if cnt == 1 and n.uuid:
                try: uid_ = str(uuid.UUID(n.uuid))
                except ValueError: raise HTTPException(400, "UUID نامعتبره")
            first = n.first_use and days > 0
            cur = db.execute("INSERT INTO users(name,uuid,token,limit_bytes,expire,note,created,protos,port,fp,ttl_days,enabled,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             (name, uid_, secrets.token_urlsafe(12), int(gb * GB),
                              0 if first or not days else int(time.time() + days * 86400), n.note[:200], int(time.time()),
                              clean_protos(n.protos), port, fp, days if first else 0, int(n.enabled), a["id"]))
            ids.append(cur.lastrowid)
        db.commit()
        st, dom = settings_for(a["id"]), dom_of(a)
        rows = [db.execute("SELECT * FROM users WHERE id=?", (i,)).fetchone() for i in ids]
        created = [full(r, dom, st["prefix"]) for r in reversed(rows)]
    sync_async()
    return {"ok": True, "users": created, "stats": my_stats(a)}

@app.put("/api/users/{uid}")
def edit_user(uid: int, e: EditUser, a=Depends(auth)):
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
                raise HTTPException(400, "برای این حساب باید حجم مشخص کنی")
            if used_bytes(a["id"], uid) + f["limit_bytes"] > a["max_gb"] * GB:
                raise HTTPException(403, "از سقف حجم حسابت بیشتر می‌شه")
        if e.reset: f["up"] = f["down"] = 0
        if f:
            db.execute("UPDATE users SET " + ",".join(f"{k}=?" for k in f) + " WHERE id=?", (*f.values(), uid))
            db.commit()
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        user = full(row, dom_of(a), settings_for(a["id"])["prefix"])
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
            if k not in APPEARANCE:   # دامنه، عنوان و بقیه‌ی تنظیمات حساس اینجا نادیده گرفته می‌شن
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

# ------------------------- مدیریت حساب‌ها (فقط مالک) -------------------------
class AccEdit(BaseModel):
    status: Optional[str] = None
    max_users: Optional[int] = None
    max_gb: Optional[float] = None
    domain: Optional[str] = None

@app.get("/api/accounts")
def accounts(a=Depends(owner_only)):
    with L:
        out = []
        for r in db.execute("SELECT * FROM accounts ORDER BY id").fetchall():
            us = db.execute("SELECT up, down FROM users WHERE owner_id=?", (r["id"],)).fetchall()
            out.append({"id": r["id"], "email": r["email"], "role": r["role"], "status": r["status"], "max_users": r["max_users"],
                        "max_gb": r["max_gb"], "domain": r["domain"], "users": len(us), "traffic": sum(x["up"] + x["down"] for x in us)})
    return {"accounts": out}

@app.put("/api/accounts/{aid}")
def acc_edit(aid: int, e: AccEdit, a=Depends(owner_only)):
    with L:
        r = db.execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
        if not r or r["role"] == "owner":
            raise HTTPException(404)
        f = {}
        if e.status is not None:
            if e.status not in ("active", "pending", "blocked"):
                raise HTTPException(400, "وضعیت نامعتبره")
            f["status"] = e.status
        if e.max_users is not None: f["max_users"] = max(0, e.max_users)
        if e.max_gb is not None: f["max_gb"] = max(0.0, e.max_gb)
        if e.domain is not None:
            d = re.sub(r"^https?://", "", e.domain.strip().lower()).split("/")[0]
            if d and not re.fullmatch(r"[a-z0-9.-]{3,253}", d):
                raise HTTPException(400, "دامنه نامعتبره")
            f["domain"] = d
        if f:
            db.execute("UPDATE accounts SET " + ",".join(f"{k}=?" for k in f) + " WHERE id=?", (*f.values(), aid))
            db.commit()
    if f.get("status", "active") != "active":
        drop_sessions(aid)
    sync_async()
    return {"ok": True}

@app.delete("/api/accounts/{aid}")
def acc_del(aid: int, a=Depends(owner_only)):
    with L:
        r = db.execute("SELECT role FROM accounts WHERE id=?", (aid,)).fetchone()
        if not r or r["role"] == "owner":
            raise HTTPException(404)
        db.execute("DELETE FROM users WHERE owner_id=?", (aid,))
        db.execute("DELETE FROM account_settings WHERE account_id=?", (aid,))
        db.execute("DELETE FROM accounts WHERE id=?", (aid,))
        db.commit()
    drop_sessions(aid)
    sync_async()
    return {"ok": True}

# ------------------------- ساب و صفحه‌ها -------------------------
@app.get("/sub/{token}")
def sub(token: str):
    with L:
        u = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        acc = db.execute("SELECT * FROM accounts WHERE id=?", (u["owner_id"],)).fetchone() if u else None
    if not u or not acc or acc["status"] != "active":
        raise HTTPException(404)
    lk = links(u, dom_of(acc), settings_for(acc["id"])["prefix"])
    h = {"subscription-userinfo": f"upload={u['up']}; download={u['down']}; total={u['limit_bytes']}; expire={u['expire']}",
         "profile-update-interval": "1", "Cache-Control": "no-store",
         "profile-title": "base64:" + base64.b64encode(TITLE.encode()).decode()}
    return Response(base64.b64encode("\n".join(l for _, l in lk).encode()), media_type="text/plain", headers=h)

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

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN.replace("__TITLE__", TITLE).replace("__SIGNUP__", "1" if ALLOW_SIGNUP else "0")

LOGIN = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,Tahoma,sans-serif;
background:radial-gradient(900px 500px at 80% -10%,#4b34c4 0,transparent 60%),radial-gradient(700px 500px at 0 110%,#0f6e8c 0,transparent 55%),#0a0c13;color:#eef0f8}
.b{width:min(380px,92vw);padding:26px;border-radius:22px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);animation:fu .6s both}
@keyframes fu{from{opacity:0;transform:translateY(18px)}}
h2{margin:0 0 14px;text-align:center;font-size:24px;letter-spacing:.5px}
.tabs{display:flex;gap:6px;margin-bottom:12px}.tabs button{flex:1;margin:0;padding:10px;border-radius:12px;background:rgba(255,255,255,.06);color:#9aa3bd;font-size:14px}
.tabs button.on{background:linear-gradient(135deg,#7c5cff,#38d4ff);color:#fff}
input{width:100%;padding:13px 14px;margin:6px 0;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.3);color:#fff;font-size:15px}
button{width:100%;margin-top:10px;padding:13px;border:0;border-radius:12px;background:linear-gradient(135deg,#7c5cff,#38d4ff);color:#fff;font-size:16px;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.12)}#e{font-size:13px;min-height:18px;margin-top:8px;text-align:center}</style></head><body>
<form class="b" onsubmit="go(event)"><h2>👑 __TITLE__</h2>
<div class="tabs"><button type="button" id="t1" class="on" onclick="tab(1)">ورود</button><button type="button" id="t2" onclick="tab(2)">ثبت‌نام</button></div>
<input id="u" placeholder="ایمیل" autocomplete="username" autocapitalize="none"><input id="p" type="password" placeholder="رمز عبور" autocomplete="current-password">
<button id="sb">ورود</button><div id="e"></div></form>
<script>let reg=false;const H={'Content-Type':'application/json','X-Requested-With':'panel'};
if(__SIGNUP__!=1)t2.style.display='none';
function tab(n){reg=n==2;t1.className=reg?'':'on';t2.className=reg?'on':'';sb.textContent=reg?'ساخت حساب':'ورود';e.textContent=''}
async function go(ev){ev.preventDefault();e.style.color='#ff6b7a';const r=await fetch(reg?'/register':'/login',{method:'POST',headers:H,body:JSON.stringify({email:u.value,password:p.value})});
let j={};try{j=await r.json()}catch(x){}
if(r.ok){if(reg){e.style.color='#35d68a';e.textContent=j.pending?'ثبت شد؛ بعد از تأیید مالک می‌تونی وارد بشی':'ثبت شد؛ حالا وارد شو';tab(1)}else location='/admin'}
else e.textContent=j.detail||'خطا ('+r.status+')'}</script></body></html>"""

bootstrap_owner()
