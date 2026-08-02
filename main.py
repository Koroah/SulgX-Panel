import asyncio
import json
import os
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("Vipira")

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
}

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {"hourly": defaultdict(int), "daily": defaultdict(int)}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

async def init_db():
    global db_conn
    db_path = CONFIG["db_path"]
    try:
        db_conn = await aiosqlite.connect(db_path)
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                limit_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                color TEXT DEFAULT '#39ff14',
                flag TEXT DEFAULT '',
                fragment TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS custom_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT ''
            );
        """)
        await db_conn.commit()
    except Exception as e:
        logger.error(f"Database init error: {e}")

async def db_execute(sqlite_q: str, params: tuple = ()):
    async with db_lock:
        await db_conn.execute(sqlite_q, params)
        await db_conn.commit()

async def db_fetchall(sqlite_q: str, params: tuple = ()) -> list:
    async with db_lock:
        cur = await db_conn.execute(sqlite_q, params)
        rows = await cur.fetchall()
    return [dict(r) for r in rows]

async def db_fetchone(sqlite_q: str, params: tuple = ()) -> Optional[dict]:
    async with db_lock:
        cur = await db_conn.execute(sqlite_q, params)
        row = await cur.fetchone()
    return dict(row) if row else None

async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        async with traffic_buffer_lock:
            if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                continue
            for hour, bytes_val in traffic_buffer["hourly"].items():
                await db_execute("INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?", (hour, bytes_val, bytes_val))
            for day, bytes_val in traffic_buffer["daily"].items():
                await db_execute("INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?", (day, bytes_val, bytes_val))
            traffic_buffer["hourly"].clear()
            traffic_buffer["daily"].clear()

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                await db_execute("UPDATE links SET used_bytes = ? WHERE uid = ?", (link["used_bytes"], uid))

async def load_initial_data():
    rows = await db_fetchall("SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
    if not LINKS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_link = {
            "uid": default_uuid, "label": "This Server is Free", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
            "color": "#39ff14", "flag": "", "fragment": ""
        }
        async with LINKS_LOCK:
            LINKS[default_uuid] = default_link
        await db_execute("INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES (?,?,?,?,?,1,?,'','')", (default_uuid, "This Server is Free", 0, 0, now, None))

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time(), "upload_bytes": 0, "download_bytes": 0}
error_logs: deque = deque(maxlen=2000)
SESSION_COOKIE = "Vipira_session"
ADMIN_PASSWORD_HASH: str = ""

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def get_domain() -> str:
    return os.environ.get("DOMAIN") or os.environ.get("RAILWAY_PUBLIC_DOMAIN") or "localhost"

def generate_vless_link(uid: str, remark: str = "Vipira", address: str = None, extra: dict = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    params = {"encryption": "none", "security": "tls", "type": "ws", "host": host, "path": path, "sni": sni, "fp": fp}
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    except Exception:
        return None

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "type": etype, "error": message, "ip": ip, "ua": ua})

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await load_initial_data()
    hash_row = await db_fetchone("SELECT value FROM settings WHERE key = 'admin_password_hash'")
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)", (ADMIN_PASSWORD_HASH,))
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    yield

app = FastAPI(title="Vipira Panel", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
async def root():
    return {"service": "Vipira Panel", "status": "active"}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if not verify_password(password, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60, httponly=True, path="/")
    return resp

@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(_: str = Depends(require_auth)):
    return {"authenticated": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with connections_lock: conn_count = len(connections)
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "uptime": uptime(),
        "links_count": len(LINKS),
        "domain": get_domain(),
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    result = []
    for row in items:
        uid = row["uid"]
        extra = {"custom_path": row.get("custom_path", ""), "custom_sni": row.get("custom_sni", ""), "custom_host": row.get("custom_host", ""), "custom_fp": row.get("custom_fp", "chrome")}
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "expires_at": row.get("expires_at"),
            "vless_link": generate_vless_link(uid, remark=f"Vipira-{row['label']}", extra=extra),
        })
    return {"links": result}

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "This Server is Free").strip()[:60]
    uid = str(uuid_lib.uuid4())
    limit_val = float(body.get("limit_value") or 0)
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, "GB")
    max_conn = int(body.get("max_connections") or 0)
    days_valid = int(body.get("days_valid") or 0)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat() if days_valid > 0 else None
    now = datetime.now(timezone.utc).isoformat()
    link_data = {"uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": now, "active": 1, "expires_at": expires_at}
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute("INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at) VALUES (?,?,?,?,?,1,?)", (uid, label, limit_bytes, max_conn, now, expires_at))
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "max_connections": max_conn, "active": True, "created_at": now, "expires_at": expires_at, "vless_link": generate_vless_link(uid, remark=f"Vipira-{label}")}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            link["active"] = int(body["active"])
            await db_execute("UPDATE links SET active = ? WHERE uid = ?", (link["active"], uid))

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await db_execute("DELETE FROM links WHERE uid = ?", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    return {"ok": True}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", (addr,))
    return {"ok": True}

PANEL_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Vipira Panel</title>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        :root{
            --bg-dark: #0b0c0e;
            --card-bg: #18191c;
            --card-hover: #232529;
            --text-main: #f0f0f0;
            --text-muted: #86888d;
            --accent-green: #00c853;
            --accent-red: #ff1744;
            --border-color: #2a2b30;
            --sidebar-width: 260px;
            --font-family: 'Vazirmatn', sans-serif;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: var(--font-family);
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
        }
        #login-page, #dashboard-page { direction: rtl; text-align: right; }
        .fl, label { float: right !important; text-align: right !important; margin-bottom: 6px; }

        .sidebar {
            position: fixed; right: 0; top: 0; width: var(--sidebar-width); background-color: var(--card-bg); padding: 20px; border-left: 1px solid var(--border-color); display: flex; flex-direction: column; height: 100vh; overflow-y: auto; z-index: 1000; transition: right 0.3s ease;
        }
        .sidebar-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 40px; }
        .logo-text { font-weight: bold; font-size: 1.2rem; letter-spacing: 1px; color: #fff; }
        .profile-icon { width: 40px; height: 40px; background: #2a2b30; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #fff; }
        .menu-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
        .menu-item { display: flex; align-items: center; padding: 12px 15px; border-radius: 10px; cursor: pointer; color: var(--text-muted); transition: all 0.2s ease; background: transparent; width: 100%; border: none; font-size: 1rem; gap: 15px; }
        .menu-item:hover, .menu-item.active { background-color: #25262b; color: var(--text-main); }
        .menu-item i { width: 25px; font-size: 1.1rem; text-align: center; }
        .sidebar-bottom { margin-top: auto; padding-top: 20px; color: var(--text-muted); font-size: 0.8rem; }

        .main-content { margin-right: var(--sidebar-width); flex: 1; padding: 25px 30px; overflow-y: auto; display: flex; flex-direction: column; gap: 20px; height: 100vh; }
        .dashboard-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .dashboard-header-left { display: flex; align-items: center; gap: 15px; }
        .dashboard-title { font-size: 1.3rem; font-weight: bold; }
        .status-pill { background: #1a2a1a; color: var(--accent-green); padding: 5px 12px; border-radius: 20px; border: 1px solid var(--accent-green); font-size: 0.8rem; display: flex; align-items: center; gap: 5px; }
        .header-controls { display: flex; gap: 10px; }

        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; display: flex; flex-direction: column; justify-content: center; min-height: 90px; }
        .stat-card .stat-val { font-size: 1.8rem; font-weight: bold; margin-top: 5px; }
        .stat-card .stat-val small { font-size: 0.9rem; font-weight: normal; color: var(--text-muted); }
        .stat-card .stat-label { color: var(--text-muted); font-size: 0.85rem; }

        .content-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; }
        .card-title { font-weight: bold; font-size: 1.1rem; }

        .tbl-wrap { overflow-x: auto; margin-top: 10px; }
        .tbl { width: 100%; border-collapse: collapse; text-align: right; }
        .tbl th, .tbl td { padding: 12px 8px; border-bottom: 1px solid var(--border-color); }
        .tbl th { color: var(--text-muted); font-weight: normal; font-size: 0.85rem; }
        .tbl td { font-size: 0.9rem; }

        .form-group { margin-bottom: 15px; }
        .form-input { width: 100%; padding: 10px 14px; border-radius: 10px; border: 1px solid var(--border-color); background: #111213; color: #fff; outline: none; transition: 0.2s; }
        .form-input:focus { border-color: var(--accent-green); }

        .btn-primary { background: var(--accent-green); color: #000; border: none; padding: 10px 20px; border-radius: 10px; font-weight: bold; transition: 0.2s; }
        .btn-primary:hover { opacity: 0.8; }
        .btn-outline { background: transparent; color: #fff; border: 1px solid var(--border-color); padding: 10px 20px; border-radius: 10px; transition: 0.2s; }
        .btn-outline:hover { background: var(--card-hover); }
        .btn-danger { background: rgba(255, 23, 68, 0.1); color: var(--accent-red); border: 1px solid rgba(255, 23, 68, 0.3); padding: 5px 12px; border-radius: 8px; }
        .btn-sm { padding: 6px 14px; font-size: 0.85rem; }

        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 9999; display: none; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
        .modal-box { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 20px; padding: 30px; width: 100%; max-width: 500px; position: relative; }
        .modal-close { position: absolute; top: 15px; left: 15px; background: transparent; border: 1px solid var(--border-color); color: var(--text-muted); padding: 5px 12px; border-radius: 8px; font-size: 1.2rem; }
        .modal-close:hover { color: #fff; border-color: #fff; }

        .sidebar-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 999; display: none; }
        @media(max-width: 992px){
            .sidebar { right: -100%; }
            .sidebar.open { right: 0; }
            .sidebar-overlay.open { display: block; }
            .main-content { margin-right: 0; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media(max-width: 600px){
            .stats-grid { grid-template-columns: 1fr; }
            .dashboard-header { flex-direction: column; align-items: flex-start; gap: 15px; }
        }
    </style>
</head>
<body>

<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-header">
        <div class="logo-text">Vipira</div>
        <div class="profile-icon">V</div>
    </div>
    <ul class="menu-list">
        <button class="menu-item active" data-page="dashboard" onclick="switchPage('dashboard')"><i class="fas fa-home"></i> <span>داشبورد</span></button>
        <button class="menu-item" data-page="inbounds" onclick="switchPage('inbounds')"><i class="fas fa-network-wired"></i> <span>اینباندها</span></button>
        <button class="menu-item" data-page="addresses" onclick="switchPage('addresses')"><i class="fas fa-shield-alt"></i> <span>آی‌پی تمیز</span></button>
        <button class="menu-item" data-page="logs" onclick="switchPage('logs')"><i class="fas fa-list"></i> <span>لاگ‌ها</span></button>
        <button class="menu-item" data-page="settings" onclick="switchPage('settings')"><i class="fas fa-cog"></i> <span>تنظیمات</span></button>
    </ul>
    <div class="sidebar-bottom">
        <span onclick="doLogout()" style="cursor:pointer; display:block; margin-top:15px; color:var(--accent-red);"><i class="fas fa-sign-out-alt"></i> خروج</span>
        <div style="margin-top:20px;">Vipira v1.1.0</div>
    </div>
</aside>

<div id="dashboard-page" class="main-content">
    <div class="dashboard-header">
        <div class="dashboard-header-left">
            <button class="btn-primary btn-sm" onclick="toggleSidebar()" style="display:none;" id="hamburgerBtn"><i class="fas fa-bars"></i></button>
            <h1 class="dashboard-title">داشبورد</h1>
            <div class="status-pill"><i class="fas fa-circle" style="font-size: 8px;"></i> فعال</div>
        </div>
        <div class="header-controls">
            <button class="btn-primary btn-sm" onclick="randomInbound()">+ تصادفی</button>
        </div>
    </div>

    <section class="page active" id="page-dashboard">
        <div class="stats-grid" id="statsContainer"></div>
        <div class="content-card" style="margin-top:20px;">
            <div class="card-header">
                <span class="card-title">اینباندها</span>
                <button class="btn-primary btn-sm" onclick="showAddMo()">+ ایجاد</button>
            </div>
            <div class="tbl-wrap">
                <table class="tbl" id="inbound-table">
                    <thead><tr><th>نام</th><th>مصرف</th><th>وضعیت</th><th>عملیات</th></tr></thead>
                    <tbody id="ltb"></tbody>
                </table>
            </div>
        </div>
    </section>

    <section class="page" id="page-inbounds" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">مدیریت اینباندها</span>
                <div><button class="btn-primary btn-sm" onclick="showAddMo()">+ ایجاد</button></div>
            </div>
            <div class="tbl-wrap"><table class="tbl" id="inbound-table-full"><thead><tr><th>نام</th><th>مصرف</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="ltb-full"></tbody></table></div>
        </div>
    </section>

    <section class="page" id="page-addresses" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">آی‌پی‌های تمیز</span></div>
            <div class="form-group"><textarea class="form-input" id="batch-addrs" rows="4" placeholder="هر خط یک آدرس"></textarea></div>
            <button class="btn-primary btn-sm" onclick="addBatchAddrs()">افزودن</button>
            <div class="tbl-wrap" id="addr-list"></div>
        </div>
    </section>
    <section class="page" id="page-logs" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">لاگ‌ها</span></div>
            <div class="tbl-wrap logs-table-container"><table class="tbl"><thead><tr><th>زمان</th><th>رویداد</th></tr></thead><tbody id="logs-tbody"></tbody></table></div>
        </div>
    </section>
    <section class="page" id="page-settings" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">تنظیمات</span></div>
            <div class="form-group"><label>متن فوتر</label><input class="form-input" id="set-footer"></div>
            <button class="btn-primary btn-sm" onclick="saveGeneralSettings()">ذخیره تنظیمات</button>
        </div>
    </section>
</div>

<div class="modal-overlay" id="mo-add">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('mo-add')">✕</button>
        <h3 style="margin-bottom:20px;">ایجاد اینباند جدید</h3>
        <div class="form-group"><label>نام</label><input class="form-input" id="nl" placeholder="مثلاً: کاربر ۱"></div>
        <div class="form-group"><label>محدودیت (GB)</label><input class="form-input" type="number" id="nv" value="0" placeholder="0 = نامحدود"></div>
        <div class="form-group"><label>حداکثر اتصالات</label><input class="form-input" type="number" id="nc" value="0" placeholder="0 = نامحدود"></div>
        <div class="form-group"><label>اعتبار (روز)</label><input class="form-input" type="number" id="nd" value="0" placeholder="0 = بدون انقضا"></div>
        <div style="display:flex; gap:10px; margin-top:10px;">
            <button class="btn-primary" onclick="createLink()" style="flex:1;">ایجاد</button>
            <button class="btn-outline" onclick="closeModal('mo-add')" style="flex:1;">انصراف</button>
        </div>
    </div>
</div>

<script>
const $=s=>document.querySelector(s), $m=id=>document.getElementById(id);
let allLinks=[], allAddrs=[], isAuthenticated=false;

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); document.getElementById('sidebarOverlay').classList.toggle('open'); }
function switchPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.style.display='none');
    document.getElementById('page-'+pageId).style.display='block';
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    document.querySelector(`.menu-item[data-page="${pageId}"]`).classList.add('active');
    if(window.innerWidth <= 992) toggleSidebar();
}
function showAddMo() { document.getElementById('mo-add').style.display = 'flex'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }

async function checkAuth(){
    try{const r=await fetch('/api/me');
    if((await r.json()).authenticated){isAuthenticated=true; loadDashboard();}
    else showLogin();}catch{showLogin();}
}
function showLogin(){
    document.getElementById('dashboard-page').style.display='none';
    document.body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg-dark);">
        <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:20px;padding:40px;width:100%;max-width:400px;">
            <h2 style="text-align:center;margin-bottom:30px;">ورود به پنل Vipira</h2>
            <div class="form-group"><label>رمز عبور</label><input class="form-input" type="password" id="login-pw"></div>
            <button class="btn-primary" style="width:100%;" onclick="doLogin()">ورود</button>
        </div>
    </div>`;
}
async function doLogin(){
    const pw=$m('login-pw').value;
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    if(r.ok){isAuthenticated=true; location.reload();}
    else alert('رمز عبور اشتباه است');
}
async function doLogout(){ await fetch('/api/logout',{method:'POST'}); location.reload(); }

async function loadDashboard(){
    document.getElementById('dashboard-page').style.display='flex';
    if(window.innerWidth <= 992) document.getElementById('hamburgerBtn').style.display='block';
    await loadLinks(); await loadStats();
    setInterval(()=>{loadStats(); loadLinks();}, 10000);
}
async function loadStats(){
    const r=await fetch('/stats'); const data=await r.json();
    const container = document.getElementById('statsContainer');
    if(container) container.innerHTML = `
        <div class="stat-card"><div class="stat-label">ترافیک کل</div><div class="stat-val">${(data.total_traffic_mb||0).toFixed(1)} <small>MB</small></div></div>
        <div class="stat-card"><div class="stat-label">اتصالات فعال</div><div class="stat-val">${data.active_connections||0}</div></div>
        <div class="stat-card"><div class="stat-label">آپتایم</div><div class="stat-val">${data.uptime||'0:00:00'}</div></div>
        <div class="stat-card"><div class="stat-label">درخواست‌ها</div><div class="stat-val">${data.total_requests||0}</div></div>
    `;
}
async function loadLinks(){
    const r=await fetch('/api/links'); const data=await r.json();
    allLinks=data.links || []; renderLinks(allLinks);
}
function renderLinks(links){
    const tb=$m('ltb');
    if(!tb) return;
    tb.innerHTML = links.map(l => {
        const usedGB = (l.used_bytes/1024/1024/1024).toFixed(2);
        const limitGB = l.limit_bytes > 0 ? (l.limit_bytes/1024/1024/1024).toFixed(2) : '∞';
        return `<tr>
            <td><strong>${l.label}</strong></td>
            <td>${usedGB} GB / ${limitGB} GB</td>
            <td><span style="color:${l.active?'var(--accent-green)':'var(--accent-red)'}">${l.active?'فعال':'غیرفعال'}</span></td>
            <td>
                <button class="btn-outline btn-sm" onclick="cpLink('${l.vless_link}')">کپی</button>
                ${l.label !== 'This Server is Free' ? `<button class="btn-danger btn-sm" onclick="delLink('${l.uuid}')">حذف</button>` : ''}
            </td>
        </tr>`;
    }).join('');
}
function cpLink(txt){ navigator.clipboard.writeText(txt).then(()=>alert('لینک کپی شد')); }
async function delLink(uid){ if(confirm('آیا مطمئن هستید؟')){ await fetch('/api/links/'+uid,{method:'DELETE'}); loadLinks(); }}

async function randomInbound(){
    const names=['User','Client','Node']; const n=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*1000);
    await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:n,limit_value:0})});
    loadLinks(); loadStats();
}

async function loadAddrs(){
    const r=await fetch('/api/addresses'); const data=await r.json(); allAddrs=data.addresses || [];
    const el=$m('addr-list'); if(el) el.innerHTML = allAddrs.map(a=>`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);"><span>${a}</span><button class="btn-danger btn-sm" onclick="delAddr('${a}')">حذف</button></div>`).join('');
}
async function addBatchAddrs(){
    const raw=$m('batch-addrs').value; const lines=raw.split('\n').filter(l=>l.trim());
    await fetch('/api/addresses/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({addresses:lines})});
    loadAddrs();
}
async function delAddr(addr){ /* Placeholder */ }

async function createLink(){
    const label = $m('nl').value.trim() || 'بی‌نام';
    const limit_val = parseFloat($m('nv').value) || 0;
    const max_conn = parseInt($m('nc').value) || 0;
    const days_valid = parseInt($m('nd').value) || 0;
    const body = { label: label, limit_value: limit_val, limit_unit: 'GB', max_connections: max_conn, days_valid: days_valid };
    try {
        const r = await fetch('/api/links', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if(r.ok){ alert('اینباند با موفقیت ساخته شد!'); closeModal('mo-add'); $m('nl').value=''; $m('nv').value='0'; $m('nc').value='0'; $m('nd').value='0'; loadLinks(); loadStats(); }
        else { const err = await r.json(); alert('خطا: ' + (err.detail || 'مشکلی پیش آمده')); }
    } catch(e) { alert('خطای ارتباط با سرور'); }
}

checkAuth();
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, proxy_headers=True, forwarded_allow_ips="*")
