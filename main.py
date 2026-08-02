import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, StreamingResponse
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

try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

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
print("--- APPLICATION IS STARTING ---")
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "/data/panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {
    "hourly": defaultdict(int),
    "daily": defaultdict(int),
}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

_scan_lock = asyncio.Lock()

if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0, used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                    color TEXT DEFAULT '#39ff14',
                    flag TEXT DEFAULT '',
                    fragment TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS custom_addresses (id SERIAL PRIMARY KEY, address TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '',
                    path TEXT DEFAULT ''
                );
            """)
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS flag TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS fragment TEXT DEFAULT ''")
            except Exception:
                pass

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(pg_q, *params)

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(pg_q, *params)
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(pg_q, *params)
            return dict(row) if row else None

    async def get_db():
        return None
else:
    DB_BACKEND = "sqlite"

    async def init_db():
        global db_conn
        db_path = CONFIG["db_path"]
        try:
            test_file = os.path.join(os.path.dirname(db_path), ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            logger.warning(f"Cannot write to {db_path}, falling back to /tmp/panel.db")
            CONFIG["db_path"] = "/tmp/panel.db"
            db_path = "/tmp/panel.db"
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
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN flag TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN fragment TEXT DEFAULT ''")
        except Exception:
            pass
        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_db():
        return db_conn

async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        try:
            async with traffic_buffer_lock:
                if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                    continue
                for hour, bytes_val in traffic_buffer["hourly"].items():
                    await db_execute(
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                        (hour, bytes_val, bytes_val)
                    )
                for day, bytes_val in traffic_buffer["daily"].items():
                    await db_execute(
                        "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                        (day, bytes_val, bytes_val)
                    )
                traffic_buffer["hourly"].clear()
                traffic_buffer["daily"].clear()
        except Exception as e:
            logger.error(f"flush_traffic_buffer error: {e}", exc_info=True)

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    await db_execute(
                        "UPDATE links SET used_bytes = ? WHERE uid = ?",
                        "UPDATE links SET used_bytes = $1 WHERE uid = $2",
                        (link["used_bytes"], uid)
                    )
        except Exception as e:
            logger.error(f"sync_usage_to_db error: {e}", exc_info=True)

async def load_initial_data():
    rows = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
    if not CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append("www.speedtest.net")
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
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES (?,?,?,?,?,1,?,'','')",
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,'','')",
            (default_uuid, "This Server is Free", 0, 0, now, None),
        )
    total_usage = sum(link.get("used_bytes", 0) for link in LINKS.values())
    stats["total_bytes"] = total_usage

async def _keepalive_simple_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    while True:
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "simple":
            continue
        domain = get_domain()
        if domain == "localhost":
            continue
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://{domain}/health")
                if resp.status_code == 200:
                    logger.info(f"Simple keep-alive successful: {domain}/health")
        except Exception:
            pass

async def _keepalive_advanced_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    await asyncio.sleep(30)
    while True:
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "advanced":
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            continue
        domain = os.environ.get("DOMAIN", "").strip()
        port = os.environ.get("PORT", "8000")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        target_urls = []
        if domain:
            if not domain.startswith(("http://", "https://")):
                target_urls.append(f"https://{domain}/login")
                target_urls.append(f"http://{domain}/login")
            else:
                target_urls.append(f"{domain}/login")
        target_urls.append(f"http://127.0.0.1:{port}/login")
        async with httpx.AsyncClient(verify=False, timeout=15.0, headers=headers) as client:
            success = False
            for url in target_urls:
                try:
                    final_url = url + ("&" if "?" in url else "?") + f"_nocache={secrets.token_hex(4)}"
                    resp = await client.get(final_url, follow_redirects=True)
                    if resp.status_code == 200:
                        logger.info(f"Advanced keep-alive successful: {url}")
                        success = True
                        break
                except Exception as e:
                    logger.debug(f"Advanced keep-alive attempt failed for {url}: {e}")
            if not success:
                logger.warning("Advanced keep-alive: all attempts failed.")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)

async def cleanup_link_cache():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [k for k, v in link_cache.items() if v["expires"] <= now]
        for k in expired:
            del link_cache[k]

@asynccontextmanager
async def lifespan(app: FastAPI):
    global TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    sk = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'",
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'"
    )
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1)",
            (CONFIG["secret_key"],)
        )

    hash_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
            (ADMIN_PASSWORD_HASH,),
        )

    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'log_enabled'",
        "SELECT value FROM settings WHERE key = 'log_enabled'"
    )
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    tz_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='timezone_offset'",
        "SELECT value FROM settings WHERE key='timezone_offset'"
    )
    if tz_row and tz_row["value"]:
        try:
            TIMEZONE_OFFSET = float(tz_row["value"])
        except:
            TIMEZONE_OFFSET = 0.0

    ke_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_enabled'",
        "SELECT value FROM settings WHERE key='keep_alive_enabled'"
    )
    if ke_row and ke_row["value"] is not None:
        KEEP_ALIVE_ENABLED = (ke_row["value"] == "1")

    km_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_mode'",
        "SELECT value FROM settings WHERE key='keep_alive_mode'"
    )
    if km_row and km_row["value"]:
        KEEP_ALIVE_MODE = km_row["value"]

    interval_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_interval'",
        "SELECT value FROM settings WHERE key='keep_alive_interval'"
    )
    if interval_row and interval_row["value"]:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(interval_row["value"]))
        except:
            pass

    asyncio.create_task(_keepalive_simple_loop())
    asyncio.create_task(_keepalive_advanced_loop())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    asyncio.create_task(auto_disable_expired_links())
    asyncio.create_task(cleanup_link_cache())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="Vipira Panel", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "upload_bytes": 0,
    "download_bytes": 0,
}
error_logs: deque = deque(maxlen=2000)

CACHE_TTL = 60
link_cache: dict = {}

SESSION_COOKIE = "Vipira_session"
UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING: bool = True
KEEP_ALIVE_ENABLED: bool = True
KEEP_ALIVE_MODE: str = "simple"

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

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try: await ws.close(code=1000, reason="idle timeout")
                except Exception: pass
            async with connections_lock: connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def auto_disable_expired_links():
    while True:
        await asyncio.sleep(60)
        try:
            row = await db_fetchone("SELECT value FROM settings WHERE key='auto_disable_enabled'", "SELECT value FROM settings WHERE key='auto_disable_enabled'")
            if row and row["value"] != "1":
                continue
            now = datetime.now(timezone.utc)
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    if link.get("active") and link.get("expires_at"):
                        exp = parse_expires_at(link["expires_at"])
                        if exp and exp < now:
                            link["active"] = 0
                            await db_execute("UPDATE links SET active = 0 WHERE uid = ?", "UPDATE links SET active = FALSE WHERE uid = $1", (uid,))
                            log_event("Auto", f"Expired inbound {link['label']} auto-disabled")
        except Exception as e:
            logger.error(f"auto_disable_expired_links error: {e}", exc_info=True)

async def telegram_reporter():
    while True:
        interval_hours = 1
        row = await db_fetchone("SELECT value FROM settings WHERE key = 'telegram_interval'", "SELECT value FROM settings WHERE key = 'telegram_interval'")
        if row and row["value"]:
            try: interval_hours = float(row["value"])
            except: interval_hours = 1
        await asyncio.sleep(3600 * interval_hours)
        en_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_report_enabled'", "SELECT value FROM settings WHERE key='telegram_report_enabled'")
        if en_row and en_row["value"] != "1":
            continue
        try:
            token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
            chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
            if token_row and chat_row and token_row["value"] and chat_row["value"]:
                msg = (
                    f"📊 Vipira Panel Stats\n"
                    f"🕒 Uptime: {uptime()}\n"
                    f"🔗 Conns: {len(connections)}\n"
                    f"📦 Traffic: {round(stats['total_bytes']/(1024*1024),2)} MB\n"
                    f"📡 Requests: {stats['total_requests']}\n"
                    f"❌ Errors: {stats['total_errors']}"
                )
                url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
        except Exception:
            pass

def get_domain() -> str:
    domain = (
        os.environ.get("DOMAIN") or
        os.environ.get("RENDER_EXTERNAL_URL") or
        os.environ.get("RAILWAY_PUBLIC_DOMAIN") or
        "localhost"
    )
    return domain.replace("https://", "").replace("http://", "")

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip('[]'))
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr.strip('[]'), strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def format_host_port(host: str, port: int = 443) -> str:
    host = host.strip('[]')
    try:
        ipaddress.IPv6Address(host)
        return f"[{host}]:{port}"
    except ipaddress.AddressValueError:
        return f"{host}:{port}"

def code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        return ""

def generate_vless_link(uid: str, remark: str = "Vipira", address: str = None, extra: dict = None) -> str:
    cache_key = f"{uid}:{remark}:{address}:{json.dumps(extra) if extra else ''}"
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    fragment = extra.get("fragment", "") if extra else ""
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": sni, "fp": fp, "alpn": "http/1.1"
    }
    if fragment:
        params["fragment"] = fragment
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    link = f"vless://{uid}@{format_host_port(addr, 443)}?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception: return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted/blocked")
            except Exception: pass
        async with connections_lock: connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock: link_ip_map.pop(uid, None)

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message or "(no detail)",
        "ip": ip,
        "ua": ua,
    })

# ═══ ROUTES ═══

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "Vipira Panel", "version": "1.1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    result = {}
    for r in rows:
        result[r["key"]] = r["value"]
    return result

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login attempt from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Successful panel login from {ip}", ip, user_agent)
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=True if get_domain()!="localhost" else False, path="/")
    return resp

async def log_login(ip: str, success: bool, ua: str, path: str):
    if not ENABLE_LOGGING:
        return
    try:
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES (?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES ($1,$2,$3,$4,$5)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path)
        )
        if success:
            await notify_telegram_login(ip, ua)
    except Exception as e:
        logger.error(f"log_login error: {e}")

async def notify_telegram_login(ip: str, ua: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    if lang == 'fa':
        default_login = f"🔐 ورود Vipira\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    else:
        default_login = f"🔐 Vipira Panel login\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    msg = templates.get('login', default_login)
    msg = msg.replace("{ip}", ip).replace("{ua}", ua).replace("{time}", now_str)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open Vipira Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except Exception:
        pass

@app.post("/api/logout")
async def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(_: str = Depends(require_auth)):
    return {"authenticated": True}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new) or not re.search(r'[0-9]', new):
        raise HTTPException(status_code=400, detail="Password must contain uppercase, lowercase, and digit")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,),
    )
    log_event("Security", "Admin password changed")
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'max_scan_ips', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
            'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
            'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
            'log_max_entries', 'scanner_timeout', 'theme_color',
            'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
            'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
            'monthly_limit_gb']
    result = {}
    for k in keys:
        row = await db_fetchone("SELECT value FROM settings WHERE key = ?", "SELECT value FROM settings WHERE key = $1", (k,))
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    body = await request.json()
    for k in ('tg_bot_token', 'tg_chat_id', 'max_scan_ips', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
              'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
              'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
              'log_max_entries', 'scanner_timeout', 'theme_color',
              'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
              'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
              'monthly_limit_gb'):
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body:
        ENABLE_LOGGING = body['log_enabled'] == '1'
    if 'keep_alive_enabled' in body:
        KEEP_ALIVE_ENABLED = body['keep_alive_enabled'] == '1'
    if 'keep_alive_mode' in body:
        KEEP_ALIVE_MODE = body['keep_alive_mode']
    if 'keep_alive_interval' in body:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(body['keep_alive_interval']))
        except:
            pass
    if 'timezone_offset' in body:
        try:
            TIMEZONE_OFFSET = float(body['timezone_offset'])
        except:
            TIMEZONE_OFFSET = 0.0
    return {"ok": True}

@app.post("/api/settings/reset")
@limiter.limit("3/minute")
async def reset_settings(request: Request, _=Depends(require_auth)):
    PROTECTED_KEYS = {'jwt_secret_key', 'admin_password_hash'}
    all_keys = await db_fetchall("SELECT key FROM settings", "SELECT key FROM settings")
    for row in all_keys:
        k = row["key"]
        if k not in PROTECTED_KEYS:
            await db_execute("DELETE FROM settings WHERE key = ?", "DELETE FROM settings WHERE key = $1", (k,))
    global ENABLE_LOGGING, KEEP_ALIVE_INTERVAL, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    ENABLE_LOGGING = True
    KEEP_ALIVE_INTERVAL = 300
    TIMEZONE_OFFSET = 0.0
    KEEP_ALIVE_ENABLED = True
    KEEP_ALIVE_MODE = "simple"
    log_event("Settings", "All settings reset to defaults")
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    global TIMEZONE_OFFSET
    async with connections_lock: conn_count = len(connections)
    cpu = 0.0
    try:
        cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
        if cpu == 0.0:
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu = float(f.readline().split()[0]) * 10
            except:
                cpu = None
    except:
        try:
            with open('/proc/loadavg', 'r') as f:
                cpu = float(f.readline().split()[0]) * 10
        except:
            cpu = None
    mem_percent = 0
    try: mem_percent = psutil.virtual_memory().percent
    except: pass
    disk_percent = 0; disk_free = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
    except: pass
    now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
    today_str = now.strftime("%Y-%m-%d")
    rows = await db_fetchall(
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE ? ORDER BY hour ASC",
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE $1 ORDER BY hour ASC",
        (today_str + '%',)
    )
    hourly_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for r in rows:
        hour_part = r["hour"][-5:] if len(r["hour"]) >= 5 else r["hour"]
        if hour_part in hourly_dict:
            hourly_dict[hour_part] = r["bytes"]
    async with traffic_buffer_lock:
        for h_key, b_val in traffic_buffer["hourly"].items():
            hour_part = h_key[-5:] if len(h_key) >= 5 else h_key
            if hour_part in hourly_dict:
                hourly_dict[hour_part] += b_val
    sorted_hours = [f"{h:02d}:00" for h in range(24)]
    hourly_data = {h: hourly_dict[h] for h in sorted_hours}
    month_start = now.strftime("%Y-%m") + "-01"
    monthly_bytes = 0
    month_rows = await db_fetchall(
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1",
        (month_start,)
    )
    if month_rows and month_rows[0]["total"]:
        monthly_bytes = month_rows[0]["total"]
    monthly_limit = 0
    limit_row = await db_fetchone("SELECT value FROM settings WHERE key='monthly_limit_gb'", "SELECT value FROM settings WHERE key='monthly_limit_gb'")
    if limit_row and limit_row["value"]:
        try: monthly_limit = float(limit_row["value"]) * 1024**3
        except: pass
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-20:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_data,
        "hourly_labels": sorted_hours,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
        "monthly_usage_bytes": monthly_bytes,
        "monthly_limit_bytes": int(monthly_limit),
    }

@app.get("/stats/detailed")
async def get_detailed_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    active = sum(1 for l in links if l["active"])
    inactive = sum(1 for l in links if not l["active"])
    expired = 0
    now = datetime.now(timezone.utc)
    for l in links:
        if l.get("expires_at"):
            exp = parse_expires_at(l["expires_at"])
            if exp and exp < now:
                expired += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?", "SELECT bytes FROM daily_traffic WHERE day = $1", (today,))
    today_bytes = today_row["bytes"] if today_row else 0
    daily_rows = await db_fetchall("SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7",
                                   "SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7")
    daily_traffic = {row["day"]: row["bytes"] for row in daily_rows}
    return {
        "total_links": len(links),
        "active_links": active,
        "inactive_links": inactive,
        "expired_links": expired,
        "today_traffic_bytes": today_bytes,
        "daily_traffic": daily_traffic,
    }

@app.get("/api/login-logs")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20",
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20"
    )
    return {"logs": [dict(r) for r in rows]}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.delete("/api/logs/clear")
async def clear_logs(_=Depends(require_auth)):
    error_logs.clear()
    await db_execute("DELETE FROM login_logs", "DELETE FROM login_logs")
    return {"ok": True}

@app.get("/api/logs/size")
async def logs_size(_=Depends(require_auth)):
    total_chars = sum(len(json.dumps(log)) for log in error_logs)
    return {"count": len(error_logs), "size_kb": round(total_chars / 1024, 2)}

@app.get("/api/backup/full")
async def full_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    rows = await db_fetchall("SELECT key, value FROM settings", "SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in rows}
    backup = {"links": links, "addresses": addrs, "settings": settings}
    return backup

MAX_RESTORE_SIZE = 5 * 1024 * 1024

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_RESTORE_SIZE:
        raise HTTPException(status_code=413, detail="Backup file too large")
    body = await request.json()
    if "settings" in body:
        for k, v in body["settings"].items():
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, str(v))
            )
    if "addresses" in body:
        await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES[:] = []
            for a in body["addresses"]:
                addr = str(a).strip()
                if addr and validate_address(addr):
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
    if "links" in body:
        await db_execute("DELETE FROM links", "DELETE FROM links")
        async with LINKS_LOCK:
            LINKS.clear()
        for link in body["links"]:
            uid = link.get("uid") or str(uuid_lib.uuid4())
            label = link.get("label", "Restored")
            limit_bytes = int(link.get("limit_bytes", 0))
            used_bytes = int(link.get("used_bytes", 0))
            max_conn = int(link.get("max_connections", 0))
            created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
            active = 1 if link.get("active", True) else 0
            expires_at = link.get("expires_at")
            custom_path = link.get("custom_path", "")
            custom_sni = link.get("custom_sni", "")
            custom_host = link.get("custom_host", "")
            custom_fp = link.get("custom_fp", "chrome")
            color = link.get("color", "#39ff14")
            flag = link.get("flag", "")
            fragment = link.get("fragment", "")
            await db_execute(
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
                (uid, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
            )
            async with LINKS_LOCK:
                LINKS[uid] = {
                    "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                    "max_connections": max_conn, "created_at": created_at, "active": active,
                    "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                    "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
                }
    return {"ok": True}

# ═══ INBOUNDS ═══

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "This Server is Free").strip()[:60]
    uuid_input = (body.get("uuid") or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="Remark is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Remark must contain only English letters, numbers, and characters: - _ . space")
    if uuid_input:
        try:
            uuid_lib.UUID(uuid_input)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid UUID format")
        uid = uuid_input
    else:
        uid = str(uuid_lib.uuid4())
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this UUID already exists")
    default_limit = 0
    def_limit_row = await db_fetchone("SELECT value FROM settings WHERE key='default_limit_bytes'", "SELECT value FROM settings WHERE key='default_limit_bytes'")
    if def_limit_row and def_limit_row["value"]:
        default_limit = int(def_limit_row["value"])
    default_expiry_days = 0
    def_exp_row = await db_fetchone("SELECT value FROM settings WHERE key='default_expiry_days'", "SELECT value FROM settings WHERE key='default_expiry_days'")
    if def_exp_row and def_exp_row["value"]:
        default_expiry_days = int(def_exp_row["value"])
    default_max_conn = 0
    def_conn_row = await db_fetchone("SELECT value FROM settings WHERE key='default_max_connections'", "SELECT value FROM settings WHERE key='default_max_connections'")
    if def_conn_row and def_conn_row["value"]:
        default_max_conn = int(def_conn_row["value"])

    limit_val = float(body.get("limit_value") or default_limit)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit)
    max_conn = int(body.get("max_connections") or default_max_conn)
    if max_conn < 0: max_conn = 0
    days_valid = body.get("days_valid") if body.get("days_valid") is not None else default_expiry_days
    expires_at = None
    try:
        days_valid = int(days_valid)
        if days_valid > 0: expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
    except (ValueError, TypeError): pass
    now = datetime.now(timezone.utc).isoformat()
    custom_path = body.get("custom_path", "")
    custom_sni = body.get("custom_sni", "")
    custom_host = body.get("custom_host", "")
    custom_fp = body.get("custom_fp", "chrome")
    color = body.get("color", "#39ff14")
    flag = body.get("flag", "")
    fragment = body.get("fragment", "")
    if flag:
        flag = flag.strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag):
            flag = ""
        else:
            flag = flag.upper()
    if fragment:
        fragment = fragment.strip()[:50]
    link_data = {
        "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1,
        "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni,
        "custom_host": custom_host, "custom_fp": custom_fp, "color": color,
        "flag": flag, "fragment": fragment,
    }
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,$8,$9,$10,$11,$12,$13)",
        (uid, label, limit_bytes, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp, "fragment": fragment}
    log_event("Inbound", f"Created inbound {label} ({uid})")
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at, "color": color, "flag": flag, "fragment": fragment,
        "vless_link": generate_vless_link(uid, remark=f"Vipira-{label}", extra=extra),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    items.sort(key=lambda x: x["created_at"], reverse=True)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {
            "custom_path": row.get("custom_path", ""),
            "custom_sni": row.get("custom_sni", ""),
            "custom_host": row.get("custom_host", ""),
            "custom_fp": row.get("custom_fp", "chrome"),
            "fragment": row.get("fragment", ""),
        }
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"],
            "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"],
            "custom_fp": extra["custom_fp"],
            "color": row.get("color", "#39ff14"),
            "flag": row.get("flag", ""),
            "fragment": row.get("fragment", ""),
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"Vipira-{row['label']}", extra=extra),
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    return JSONResponse(content=links)

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = 0
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a list of links")
    for item in body:
        if not isinstance(item, dict):
            continue
        uid_input = item.get("uid") or str(uuid_lib.uuid4())
        try:
            uuid_lib.UUID(uid_input)
        except ValueError:
            continue
        label = item.get("label", "Imported")[:60]
        if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
            continue
        limit_bytes = int(item.get("limit_bytes", 0))
        used_bytes = int(item.get("used_bytes", 0))
        max_conn = int(item.get("max_connections", 0))
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if item.get("active", True) else 0
        expires_at = item.get("expires_at")
        custom_path = item.get("custom_path", "")
        custom_sni = item.get("custom_sni", "")
        custom_host = item.get("custom_host", "")
        custom_fp = item.get("custom_fp", "chrome")
        color = item.get("color", "#39ff14")
        flag = item.get("flag", "")
        fragment = item.get("fragment", "")
        if flag:
            flag = flag.strip()[:2]
            if not re.match(r'^[a-zA-Z]{2}$', flag):
                flag = ""
            else:
                flag = flag.upper()
        async with LINKS_LOCK:
            if uid_input in LINKS:
                continue
            LINKS[uid_input] = {
                "uid": uid_input, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                "max_connections": max_conn, "created_at": created_at, "active": active,
                "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
            }
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            (uid_input, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
        )
        imported += 1
    return {"ok": True, "imported": imported}

@app.patch("/api/links/batch")
async def batch_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uids = body.get("uids", [])
    action = body.get("action", "")
    async with LINKS_LOCK:
        for uid in uids:
            link = LINKS.get(uid)
            if not link: continue
            if action == "activate":
                link["active"] = 1
                await db_execute("UPDATE links SET active=1 WHERE uid=?", "UPDATE links SET active=TRUE WHERE uid=$1", (uid,))
            elif action == "deactivate":
                link["active"] = 0
                await db_execute("UPDATE links SET active=0 WHERE uid=?", "UPDATE links SET active=FALSE WHERE uid=$1", (uid,))
                await close_connections_for_link(uid)
            elif action == "reset_usage":
                link["used_bytes"] = 0
                await db_execute("UPDATE links SET used_bytes=0 WHERE uid=?", "UPDATE links SET used_bytes=0 WHERE uid=$1", (uid,))
            elif action == "delete":
                if link.get("label") == "This Server is Free":
                    continue
                await db_execute("DELETE FROM links WHERE uid=?", "DELETE FROM links WHERE uid=$1", (uid,))
                LINKS.pop(uid, None)
                await close_connections_for_link(uid)
    return {"ok": True}

@app.post("/api/links/{uid}/new-uuid")
async def regenerate_uuid(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if LINKS[uid].get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Cannot regenerate UUID for the default inbound.")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())
        link = LINKS.pop(uid)
        link["uid"] = new_uid
        LINKS[new_uid] = link
        await db_execute("UPDATE links SET uid=? WHERE uid=?", "UPDATE links SET uid=$1 WHERE uid=$2", (new_uid, uid))
        async with connections_lock:
            to_update = [(cid, info) for cid, info in connections.items() if info.get("uuid") == uid]
            for cid, info in to_update:
                info["uuid"] = new_uid
            if uid in link_ip_map:
                link_ip_map[new_uid] = link_ip_map.pop(uid)
        log_event("Inbound", f"UUID regenerated for {link['label']}: {uid} -> {new_uid}")
        return {"new_uuid": new_uid}

@app.post("/api/links/{uid}/disconnect")
async def disconnect_link(uid: str, _=Depends(require_auth)):
    await close_connections_for_link(uid)
    log_event("Inbound", f"Disconnected all connections for {uid}")
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        if link.get("label") == "This Server is Free":
            if "label" in body and body["label"].strip() != "This Server is Free":
                raise HTTPException(status_code=400, detail="Cannot rename the default system inbound.")
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body: updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_val = float(body.get("limit_value") or 0)
        unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        updates["label"] = new_label
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0: updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else: updates["expires_at"] = None
        except (ValueError, TypeError): pass
    if "custom_path" in body: updates["custom_path"] = str(body["custom_path"])[:100]
    if "custom_sni" in body: updates["custom_sni"] = str(body["custom_sni"])[:100]
    if "custom_host" in body: updates["custom_host"] = str(body["custom_host"])[:100]
    if "custom_fp" in body: updates["custom_fp"] = str(body["custom_fp"])[:20]
    if "color" in body: updates["color"] = str(body["color"])[:20]
    if "flag" in body:
        flag_val = str(body["flag"]).strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag_val):
            flag_val = ""
        else:
            flag_val = flag_val.upper()
        updates["flag"] = flag_val
    if "fragment" in body:
        updates["fragment"] = str(body["fragment"]).strip()[:50]
    if updates:
        async with LINKS_LOCK:
            link.update(updates)
        if DB_BACKEND == "sqlite":
            set_str = ", ".join(f"{k} = ?" for k in updates)
            vals = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_str} WHERE uid = ?", "", tuple(vals))
        else:
            set_str = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            vals = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_str} WHERE uid = ${len(vals)}", tuple(vals))
    log_event("Inbound", f"Updated inbound {uid}")
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link and link.get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Default inbound (This Server is Free) cannot be deleted.")
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    log_event("Inbound", f"Deleted inbound {uid}")
    return {"ok": True}

# ═══ ADDRESSES ═══

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(addr)
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
    except ADDRESS_INTEGRITY_ERRORS:
        pass
    log_event("Clean IP", f"Added address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.patch("/api/addresses/{index}")
async def edit_address(index: int, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_addr = (body.get("address") or "").strip()
    if not new_addr or not validate_address(new_addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            old = CUSTOM_ADDRESSES[index]
            if new_addr in CUSTOM_ADDRESSES and new_addr != old:
                raise HTTPException(status_code=400, detail="Address already exists")
            CUSTOM_ADDRESSES[index] = new_addr
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (old,))
            await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (new_addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Edited address from {old} to {new_addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
@limiter.limit("5/minute")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    errors = 0
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr):
                errors += 1
                continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
                    added += 1
                else:
                    errors += 1
    if added > 0:
        log_event("Clean IP", f"Batch added {added} addresses")
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Deleted address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    log_event("Clean IP", "All addresses deleted")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    async with CUSTOM_ADDRESSES_LOCK:
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(CUSTOM_ADDRESSES):
                addr = CUSTOM_ADDRESSES.pop(idx)
                await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
    log_event("Clean IP", "Bulk deleted addresses")
    return {"ok": True}

# ═══ USER DASHBOARD & SUBSCRIPTION ═══

@app.get("/user/{uid}")
async def user_dashboard(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "Active ✅"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "Quota Exceeded 🚫"
    elif expires and expires < datetime.now(timezone.utc):
        status = "Expired ⏰"
    elif not link["active"]:
        status = "Blocked 🔒"
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    usage_percent = 0 if limit == 0 else min(100, round(used / limit * 100, 1))
    usage_bar_color = "#4ade80" if usage_percent < 80 else ("#fbbf24" if usage_percent < 95 else "#f87171")
    vless_link = generate_vless_link(uid, remark=link["label"])
    sub_url = f"https://{get_domain()}/sub/{uid}"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(sub_url)}"
    expiry_str = "Unlimited ∞" if not expires else expires.strftime("%Y-%m-%d %H:%M (UTC)")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Dashboard | {link['label']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#0a0a0a;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}}
.card{{background:rgba(20,20,20,0.9);border:1px solid rgba(57,255,20,0.15);border-radius:24px;padding:36px 24px;max-width:420px;width:100%;box-shadow:0 0 40px rgba(57,255,20,0.1);text-align:center;}}
h1{{color:#39ff14;font-size:1.8rem;margin-bottom:8px;font-weight:800;}}
.subtitle{{color:#a0a0a0;font-size:0.9rem;margin-bottom:24px;}}
.info-box{{background:rgba(255,255,255,0.03);border-radius:16px;padding:16px;margin-bottom:24px;text-align:left;}}
.row{{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:0.95rem;}}
.row:last-child{{border-bottom:none;}}
.label{{color:#888;font-weight:600;}}
.value{{color:#fff;font-weight:600;}}
.progress-bar-bg{{height:8px;background:rgba(255,255,255,0.1);border-radius:4px;margin-top:12px;overflow:hidden;}}
.progress-bar-fill{{height:100%;width:{usage_percent}%;background:{usage_bar_color};border-radius:4px;transition:width 0.3s;}}
.progress-text{{font-size:0.8rem;color:#aaa;margin-top:4px;text-align:right;}}
.qr{{background:#fff;padding:12px;border-radius:16px;display:inline-block;margin-bottom:24px;}}
.qr img{{display:block;border-radius:8px;}}
.btn{{display:flex;align-items:center;justify-content:center;width:100%;padding:14px;background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;font-weight:800;border-radius:12px;text-decoration:none;transition:all 0.2s;margin-bottom:12px;border:none;cursor:pointer;font-family:inherit;font-size:1rem;}}
.btn:hover{{filter:brightness(1.1);box-shadow:0 0 20px rgba(57,255,20,0.3);}}
.btn-outline{{background:transparent;color:#39ff14;border:2px solid rgba(57,255,20,0.3);}}
.btn-outline:hover{{background:rgba(57,255,20,0.1);box-shadow:none;}}
#toast{{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#39ff14;color:#000;padding:10px 20px;border-radius:30px;font-weight:700;opacity:0;transition:opacity 0.3s;pointer-events:none;}}
</style>
</head>
<body>
<div class="card">
    <h1>{link['label']}</h1>
    <div class="subtitle">Secure Subscription Dashboard</div>
    <div class="info-box">
        <div class="row"><span class="label">Status</span><span class="value">{status}</span></div>
        <div class="row"><span class="label">Data Usage</span><span class="value">{_fmt_bytes(used)} / {'∞' if limit == 0 else _fmt_bytes(limit)}</span></div>
        <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
        <div class="progress-text">{usage_percent}% used</div>
        <div class="row"><span class="label">Expiration</span><span class="value">{expiry_str}</span></div>
    </div>
    <div class="qr">
        <img src="{qr_url}" alt="Scan to Import" width="200" height="200">
    </div>
    <button class="btn" onclick="copyToClip('{sub_url}', 'Subscription Link Copied!')">🔗 Copy Subscription Link</button>
    <button class="btn btn-outline" onclick="copyToClip('{vless_link}', 'VLESS Link Copied!')">📋 Copy Single VLESS Link</button>
</div>
<div id="toast">Copied!</div>
<script>
function copyToClip(text, msg) {{
    navigator.clipboard.writeText(text).then(() => {{
        const toast = document.getElementById('toast');
        toast.innerText = msg;
        toast.style.opacity = '1';
        setTimeout(() => toast.style.opacity = '0', 2500);
    }});
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/user/{uid}/sub")
@limiter.limit("10/minute")
async def user_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    status = "active"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "quota_exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "expired"
    elif not link["active"]:
        status = "blocked"
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": link.get("custom_path", ""),
        "custom_sni": link.get("custom_sni", ""),
        "custom_host": link.get("custom_host", ""),
        "custom_fp": link.get("custom_fp", "chrome"),
        "fragment": link.get("fragment", ""),
    }
    sub_content = generate_subscription_content(link, uid, addresses, extra, status)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
        "X-Status": status,
    }
    log_event("Subscription", f"Subscription accessed for {link['label']} ({uid}) status={status}", ip=request.client.host)
    return Response(content=encoded, headers=headers)

@app.get("/sub/{uid}")
@limiter.limit("10/minute")
async def subscription_endpoint(uid: str, request: Request):
    return await user_subscription(uid, request)

def generate_subscription_content(link: dict, uid: str, addresses: list, extra: dict = None, status: str = "active") -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_remark = ""
    if status == "quota_exceeded":
        status_remark = "🚫 Quota Exceeded"
    elif status == "expired":
        status_remark = "⏰ Expired"
    elif status == "blocked":
        status_remark = "🔒 Blocked"
    full_remark = f"📊 {usage_str} | ⏳ {expiry_str}"
    if status_remark:
        full_remark += f" | {status_remark}"
    flag_emoji = code_to_flag(link.get("flag", ""))
    if flag_emoji:
        full_remark = flag_emoji + " " + full_remark
    status_node = generate_vless_link(uid, remark=full_remark, address="0.0.0.0", extra=extra)
    server_node = generate_vless_link(uid, remark=f"{flag_emoji}This Service is Free" if flag_emoji else "This Service is Free", extra=extra)
    links = [status_node, server_node]
    for i, addr in enumerate(addresses):
        links.append(generate_vless_link(uid, remark=f"{flag_emoji}Vipira-{link['label']}-IP{i+1}" if flag_emoji else f"Vipira-{link['label']}-IP{i+1}", address=addr, extra=extra))
    return "\n".join(links)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# ═══ SCANNER ═══

@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    tasks = []
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        if not isinstance(items, list) or len(items) == 0:
            await websocket.close()
            return
        max_ips = 256
        max_row = await db_fetchone("SELECT value FROM settings WHERE key='max_scan_ips'", "SELECT value FROM settings WHERE key='max_scan_ips'")
        if max_row and max_row["value"]:
            try: max_ips = int(max_row["value"])
            except: pass
        if len(items) > max_ips:
            await websocket.send_json({"done": True, "error": f"Maximum {max_ips} IPs allowed."})
            return
        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'", "SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]:
            timeout_str = row["value"]
        try:
            timeout = float(timeout_str)
            if timeout <= 0: timeout = 4
        except:
            timeout = 4
        sem = asyncio.Semaphore(20)
        async def scan_one(item):
            async with sem:
                ip_str = str(item).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})
                        return
                except ValueError:
                    pass
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{ip_str}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                except Exception:
                    result = {"ip": ip_str, "ok": False, "latency": None}
                await websocket.send_json(result)
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Scanner WS error: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await websocket.close()
        except Exception:
            pass

# ═══ TUNNEL ═══

RELAY_BUF = 512 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24: 
        raise ValueError("VLESS header chunk too small for parsing")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    if len(first_chunk) < pos + 3:
        raise ValueError("Malformed VLESS header structure")
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        if len(first_chunk) < pos + 4: 
            raise ValueError("Incomplete IPv4 address bytes")
        addr_bytes = first_chunk[pos:pos+4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        if len(first_chunk) < pos + 1: 
            raise ValueError("Missing domain name length indicator")
        domain_len = first_chunk[pos]
        pos += 1
        if len(first_chunk) < pos + domain_len: 
            raise ValueError("Incomplete domain name bytes")
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(first_chunk) < pos + 16: 
            raise ValueError("Incomplete IPv6 address bytes")
        addr_bytes = first_chunk[pos:pos+16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else: 
        raise ValueError(f"Unsupported VLESS address type identifier: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            link = LINKS[uid]
            link["used_bytes"] += n
            limit = link["limit_bytes"]
            if limit > 0 and link["used_bytes"] >= limit * 0.9 and (link["used_bytes"] - n) < limit * 0.9:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 90% of quota")
                await notify_telegram_event("quota_90", link["label"], uid)
            elif limit > 0 and link["used_bytes"] >= limit * 0.8 and (link["used_bytes"] - n) < limit * 0.8:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 80% of quota")

async def notify_telegram_event(event: str, label: str, uid: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    if lang == 'fa':
        default_msg = f"رویداد: {event} برای {label}"
    else:
        default_msg = f"Event: {event} for {label}"
    msg = templates.get(event, default_msg)
    msg = msg.replace("{label}", label).replace("{uid}", uid)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open Vipira Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except: pass

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["upload_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"ws_to_tcp {conn_id}: {e}", "type": "Tunnel"})
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"tcp_to_ws {conn_id}: {e}", "type": "Tunnel"})

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS accepted {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link or not link["active"]:
                await websocket.close(code=1008, reason="not found or disabled")
                log_event("Tunnel", f"Inactive/not found uuid {uuid}", ip=client_ip)
                return
            max_conn = link.get("max_connections", 0)
        expires = parse_expires_at(link.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired")
            log_event("Tunnel", f"Expired uuid {uuid}", ip=client_ip)
            return
        if max_conn > 0:
            if await count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="connection limit")
                log_event("Tunnel", f"Connection limit reached for {uuid}", ip=client_ip)
                return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        try: command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header")
            log_event("Tunnel", f"Invalid header from {client_ip}: {e}")
            return
        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now(timezone.utc).isoformat(), "bytes": 0, "last_active": now}
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        stats["total_requests"] += 1
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size; stats["upload_bytes"] += p_size
            await add_usage(uuid, p_size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Tunnel {uuid}: {exc}", "type": "WebSocket"})
        logger.exception("WS error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        if not any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values()):
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

# ── HTML Panel v1.1.0 (Vipira Full Remaster) ───────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Vipira Panel</title>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
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
        a{text-decoration:none;color:inherit;}
        button{cursor:pointer;font-family:inherit;}
        
        #login-page, #dashboard-page { direction: rtl; text-align: right; }
        .fl, label { float: right !important; text-align: right !important; margin-bottom: 6px; }

        .sidebar {
            position: fixed;
            right: 0;
            top: 0;
            width: var(--sidebar-width);
            background-color: var(--card-bg);
            padding: 20px;
            border-left: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            transition: right 0.3s ease;
        }
        .sidebar-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 40px;
        }
        .logo-text { font-weight: bold; font-size: 1.2rem; letter-spacing: 1px; color: #fff; }
        .profile-icon { width: 40px; height: 40px; background: #2a2b30; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #fff; }
        .menu-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
        .menu-item {
            display: flex;
            align-items: center;
            padding: 12px 15px;
            border-radius: 10px;
            cursor: pointer;
            color: var(--text-muted);
            transition: all 0.2s ease;
            background: transparent;
            width: 100%;
            border: none;
            font-size: 1rem;
            gap: 15px;
        }
        .menu-item:hover, .menu-item.active { background-color: #25262b; color: var(--text-main); }
        .menu-item i { width: 25px; font-size: 1.1rem; text-align: center; }
        .sidebar-bottom { margin-top: auto; padding-top: 20px; color: var(--text-muted); font-size: 0.8rem; }

        .main-content {
            margin-right: var(--sidebar-width);
            flex: 1;
            padding: 25px 30px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
            height: 100vh;
        }
        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .dashboard-header-left { display: flex; align-items: center; gap: 15px; }
        .dashboard-title { font-size: 1.3rem; font-weight: bold; }
        .status-pill { background: #1a2a1a; color: var(--accent-green); padding: 5px 12px; border-radius: 20px; border: 1px solid var(--accent-green); font-size: 0.8rem; display: flex; align-items: center; gap: 5px; }
        .header-controls { display: flex; gap: 10px; }

        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }
        .stat-card {
            background: var(--card-bg); border: 1px solid var(--border-color);
            border-radius: 16px; padding: 20px; display: flex; flex-direction: column;
            justify-content: center; min-height: 90px;
        }
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
        <button class="menu-item" data-page="ipscanner" onclick="switchPage('ipscanner')"><i class="fas fa-search"></i> <span>اسکنر</span></button>
        <button class="menu-item" data-page="logs" onclick="switchPage('logs')"><i class="fas fa-list"></i> <span>لاگ‌ها</span></button>
        <button class="menu-item" data-page="telegram" onclick="switchPage('telegram')"><i class="fab fa-telegram"></i> <span>ربات</span></button>
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
    <section class="page" id="page-ipscanner" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">اسکنر آی‌پی</span></div>
            <div class="form-group"><textarea class="form-input" id="scan-ips" rows="5" placeholder="آدرس‌ها"></textarea></div>
            <button class="btn-primary btn-sm" id="scan-start-btn" onclick="startIPScan()">شروع اسکن</button>
            <div class="tbl-wrap" style="margin-top:15px;"><table class="tbl"><thead><tr><th>آدرس</th><th>وضعیت</th><th>تأخیر</th></tr></thead><tbody id="scan-tbody"></tbody></table></div>
        </div>
    </section>
    <section class="page" id="page-logs" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">لاگ‌ها</span></div>
            <div class="tbl-wrap logs-table-container"><table class="tbl"><thead><tr><th>زمان</th><th>رویداد</th></tr></thead><tbody id="logs-tbody"></tbody></table></div>
        </div>
    </section>
    <section class="page" id="page-telegram" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">ربات تلگرام</span></div>
            <div class="form-group"><label>توکن</label><input class="form-input" id="tg-token"></div>
            <div class="form-group"><label>آیدی چت</label><input class="form-input" id="tg-chat-id"></div>
            <button class="btn-primary btn-sm" onclick="saveTelegramSettings()">ذخیره</button>
        </div>
    </section>
    <section class="page" id="page-settings" style="display:none;">
        <div class="content-card">
            <div class="card-header"><span class="card-title">تنظیمات</span></div>
            <div class="form-group"><label>متن فوتر</label><input class="form-input" id="set-footer"></div>
            <div class="form-group"><label>محدودیت پیش‌فرض (GB)</label><input class="form-input" type="number" id="set-default-limit" placeholder="0"></div>
            <button class="btn-primary btn-sm" onclick="saveGeneralSettings()">ذخیره تنظیمات</button>
            <div style="margin-top:20px;"><button class="btn-danger btn-sm" onclick="resetAllSettings()">بازنشانی به پیش‌فرض</button></div>
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
    await loadLinks(); await loadStats(); await loadAddrs();
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
async function delAddr(addr){ /* Placeholder for simplicity in full code */ }

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

async function startIPScan(){ /* Placeholder Logic */ }
async function saveTelegramSettings(){ /* Placeholder Logic */ }
async function saveGeneralSettings(){ /* Placeholder Logic */ }
async function resetAllSettings(){ /* Placeholder Logic */ }

checkAuth();
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    import sys
    import subprocess
    import os
    port = int(os.environ.get("PORT", CONFIG.get("port", 8000)))
    logger.info(f"Starting Vipira Panel on port {port}")
    try:
        subprocess.run(
            [
                sys.executable, "-m", "uvicorn",
                "main:app",
                "--host", "0.0.0.0", 
                "--port", str(port),  
                "--proxy-headers",
                "--forwarded-allow-ips", "*"
            ],
            check=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
