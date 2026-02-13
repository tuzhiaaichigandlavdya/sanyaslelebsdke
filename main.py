import asyncio
import base64
import datetime as dt
import hmac
import hashlib
import json
import os
import secrets
import sqlite3
import string
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import bcrypt
from fastapi import Body, Depends, FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("CHAT_DB_PATH") or os.path.join(APP_DIR, "app.db")
JWT_SECRET = os.environ.get("CHAT_JWT_SECRET") or ""
JWT_TTL_SECONDS = int(os.environ.get("CHAT_JWT_TTL_SECONDS", "86400"))

_SCHEMA_READY = False


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def ensure_jwt_secret() -> str:
    global JWT_SECRET
    if JWT_SECRET:
        return JWT_SECRET
    raw = os.environ.get("CHAT_JWT_SECRET")
    if raw:
        JWT_SECRET = str(raw)
        return JWT_SECRET
    try:
        stored = db_get_state("jwt_secret")
        if stored:
            JWT_SECRET = stored
            return JWT_SECRET
    except Exception:
        pass
    JWT_SECRET = secrets.token_urlsafe(48)
    try:
        db_set_state("jwt_secret", JWT_SECRET)
    except Exception:
        pass
    return JWT_SECRET


def jwt_sign(payload: Dict[str, Any]) -> str:
    ensure_jwt_secret()
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    msg = f"{h}.{p}".encode("ascii")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), msg, hashlib.sha256).digest()
    s = _b64url_encode(sig)
    return f"{h}.{p}.{s}"


def jwt_verify(token: str) -> Dict[str, Any]:
    ensure_jwt_secret()
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token")
    h_b64, p_b64, s_b64 = parts
    msg = f"{h_b64}.{p_b64}".encode("ascii")
    sig = _b64url_decode(s_b64)
    exp_sig = hmac.new(JWT_SECRET.encode("utf-8"), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, exp_sig):
        raise HTTPException(status_code=401, detail="Invalid token")
    payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise HTTPException(status_code=401, detail="Invalid token")
    if int(time.time()) > exp:
        raise HTTPException(status_code=401, detail="Token expired")
    return payload


def now_ts() -> int:
    return int(time.time())


def iso_from_ts(ts: int) -> str:
    return dt.datetime.utcfromtimestamp(ts).replace(tzinfo=dt.timezone.utc).isoformat()


def db_connect(ensure_schema: bool = True) -> sqlite3.Connection:
    global DB_PATH
    try:
        db_dir = os.path.dirname(DB_PATH)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    except Exception:
        pass
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA foreign_keys=OFF;")
    except Exception:
        pass

    global _SCHEMA_READY
    if ensure_schema and not _SCHEMA_READY:
        try:
            db_init()
            _SCHEMA_READY = True
        except Exception:
            pass
    return con


def db_init() -> None:
    con = db_connect(ensure_schema=False)
    cur = con.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS server_state (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          must_reset_password INTEGER NOT NULL DEFAULT 0,
          ecdh_p256_spki_b64 TEXT,
          ecdsa_p256_spki_b64 TEXT,
          key_version INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
          user_id TEXT PRIMARY KEY,
          display_name TEXT,
          bio TEXT,
          status TEXT,
          avatar_blob BLOB,
          avatar_mime TEXT,
          updated_at INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS conversations (
          id TEXT PRIMARY KEY,
          type TEXT NOT NULL,
          title TEXT,
          created_by TEXT NOT NULL,
          direct_user_a_id TEXT,
          direct_user_b_id TEXT,
          created_at INTEGER NOT NULL,
          last_activity_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_direct_pair ON conversations(type, direct_user_a_id, direct_user_b_id)
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_conversations_last ON conversations(last_activity_at)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS conversation_members (
          conversation_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          role TEXT NOT NULL,
          joined_at INTEGER NOT NULL,
          PRIMARY KEY (conversation_id, user_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_conv_members_user ON conversation_members(user_id)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          conversation_id TEXT NOT NULL,
          sender_id TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_conv_time ON messages(conversation_id, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(created_at)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
          id TEXT PRIMARY KEY,
          conversation_id TEXT NOT NULL,
          sender_id TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          blob BLOB NOT NULL,
          created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_conv_time ON files(conversation_id, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_time ON files(created_at)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS file_uploads (
          id TEXT PRIMARY KEY,
          conversation_id TEXT NOT NULL,
          sender_id TEXT NOT NULL,
          filename TEXT NOT NULL,
          mime TEXT NOT NULL,
          size INTEGER NOT NULL,
          total_chunks INTEGER NOT NULL,
          envelope_json TEXT NOT NULL,
          created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_file_uploads_time ON file_uploads(created_at)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS file_upload_chunks (
          upload_id TEXT NOT NULL,
          idx INTEGER NOT NULL,
          blob BLOB NOT NULL,
          PRIMARY KEY (upload_id, idx)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deletion_requests (
          user_id TEXT PRIMARY KEY,
          requested_at INTEGER NOT NULL,
          scheduled_at INTEGER NOT NULL,
          canceled_at INTEGER
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS master_audit (
          id TEXT PRIMARY KEY,
          ts INTEGER NOT NULL,
          action TEXT NOT NULL,
          actor TEXT NOT NULL,
          target_user_id TEXT,
          meta_json TEXT NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_master_audit_ts ON master_audit(ts)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_keys (
          user_id TEXT PRIMARY KEY,
          key_version INTEGER NOT NULL,
          ecdh_spki_b64 TEXT NOT NULL,
          ecdsa_spki_b64 TEXT NOT NULL,
          enc_json TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
        """
    )

    con.commit()
    con.close()


def db_get_state(k: str) -> Optional[str]:
    con = db_connect()
    row = con.execute("SELECT v FROM server_state WHERE k = ?", (k,)).fetchone()
    con.close()
    return None if row is None else str(row["v"])


def db_set_state(k: str, v: str) -> None:
    con = db_connect()
    con.execute(
        "INSERT INTO server_state(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (k, v),
    )
    con.commit()
    con.close()


def gen_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}"


def bcrypt_hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def bcrypt_verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def parse_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return auth.split(" ", 1)[1].strip()


async def get_current_user(request: Request) -> sqlite3.Row:
    token = parse_bearer_token(request)
    payload = jwt_verify(token)
    if payload.get("role") != "user":
        raise HTTPException(status_code=403, detail="Forbidden")
    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid token")
    con = db_connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    return row


async def get_master(request: Request) -> Dict[str, Any]:
    token = parse_bearer_token(request)
    payload = jwt_verify(token)
    if payload.get("role") != "master":
        raise HTTPException(status_code=403, detail="Forbidden")
    return payload


def require_username(username: str) -> str:
    u = username.strip()
    if len(u) < 3 or len(u) > 32:
        raise HTTPException(status_code=400, detail="Username must be 3-32 characters")
    allowed = set(string.ascii_letters + string.digits + "_" + "-")
    if any(ch not in allowed for ch in u):
        raise HTTPException(status_code=400, detail="Username has invalid characters")
    return u


def require_password(password: str) -> str:
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
    return password


def conv_pair(a: str, b: str) -> Tuple[str, str]:
    return (a, b) if a < b else (b, a)


def ensure_conv_member(con: sqlite3.Connection, conversation_id: str, user_id: str) -> None:
    row = con.execute(
        "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?",
        (conversation_id, user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Not a member")


def ensure_conv_admin(con: sqlite3.Connection, conversation_id: str, user_id: str) -> None:
    row = con.execute(
        "SELECT role FROM conversation_members WHERE conversation_id = ? AND user_id = ?",
        (conversation_id, user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Not a member")
    if str(row["role"]) != "admin":
        raise HTTPException(status_code=403, detail="Admin required")


def conv_member_ids(con: sqlite3.Connection, conversation_id: str) -> List[str]:
    rows = con.execute(
        "SELECT user_id FROM conversation_members WHERE conversation_id = ?",
        (conversation_id,),
    ).fetchall()
    return [str(r["user_id"]) for r in rows]


class WSManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._by_user: Dict[str, Set[WebSocket]] = {}

    async def add(self, user_id: str, ws: WebSocket) -> None:
        async with self._lock:
            self._by_user.setdefault(user_id, set()).add(ws)

    async def remove(self, user_id: str, ws: WebSocket) -> None:
        async with self._lock:
            s = self._by_user.get(user_id)
            if not s:
                return
            s.discard(ws)
            if not s:
                self._by_user.pop(user_id, None)

    async def send_to(self, user_id: str, data: Dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self._by_user.get(user_id, set()))
        if not targets:
            return
        for ws in targets:
            try:
                await ws.send_text(json.dumps(data, separators=(",", ":")))
            except Exception:
                await self.remove(user_id, ws)

    async def broadcast(self, user_ids: List[str], data: Dict[str, Any]) -> None:
        await asyncio.gather(*(self.send_to(uid, data) for uid in user_ids), return_exceptions=True)


app = FastAPI()

cors_raw = (os.environ.get("CHAT_CORS_ORIGINS") or "").strip()
if cors_raw:
    if cors_raw == "*":
        allow_origins = ["*"]
    else:
        allow_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
        max_age=86400,
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
        max_age=86400,
    )
ws_manager = WSManager()


def normalize_master_code(code: str) -> str:
    return code.strip().upper()


def get_master_code_value() -> str:
    try:
        stored = db_get_state("master_code")
        if stored:
            return str(stored)
    except Exception:
        pass
    return os.environ.get("MASTER_CODE") or "X1X2X3"


def _require_b64_field(obj: Dict[str, Any], k: str, max_len: int = 20000) -> str:
    v = obj.get(k)
    if not isinstance(v, str) or not v:
        raise HTTPException(status_code=400, detail=f"Missing {k}")
    if len(v) > max_len:
        raise HTTPException(status_code=400, detail=f"{k} too large")
    return v


def _get_keysync_secret() -> bytes:
    env_b64 = os.environ.get("CHAT_KEYSYNC_SECRET_B64")
    if env_b64:
        try:
            b = base64.b64decode(env_b64.encode("ascii"))
        except Exception:
            raise HTTPException(status_code=500, detail="Invalid keysync secret")
        if len(b) != 32:
            raise HTTPException(status_code=500, detail="Invalid keysync secret")
        return b

    raw = db_get_state("keysync_secret_b64")
    if raw is None:
        b = secrets.token_bytes(32)
        db_set_state("keysync_secret_b64", base64.b64encode(b).decode("ascii"))
        return b
    try:
        b = base64.b64decode(raw.encode("ascii"))
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid keysync secret")
    if len(b) != 32:
        raise HTTPException(status_code=500, detail="Invalid keysync secret")
    return b


def _encrypt_for_storage(obj: Dict[str, Any]) -> str:
    key = _get_keysync_secret()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    pt = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    ct = aes.encrypt(nonce, pt, b"user_keys:v1")
    pack = {"v": 1, "nonce_b64": base64.b64encode(nonce).decode("ascii"), "ct_b64": base64.b64encode(ct).decode("ascii")}
    return json.dumps(pack, separators=(",", ":"))


def _decrypt_from_storage(enc_json: str) -> Dict[str, Any]:
    try:
        pack = json.loads(enc_json)
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt key material")
    if not isinstance(pack, dict) or int(pack.get("v", 0)) != 1:
        raise HTTPException(status_code=500, detail="Corrupt key material")
    nonce_b64 = pack.get("nonce_b64")
    ct_b64 = pack.get("ct_b64")
    if not isinstance(nonce_b64, str) or not isinstance(ct_b64, str):
        raise HTTPException(status_code=500, detail="Corrupt key material")
    try:
        nonce = base64.b64decode(nonce_b64.encode("ascii"))
        ct = base64.b64decode(ct_b64.encode("ascii"))
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt key material")
    key = _get_keysync_secret()
    aes = AESGCM(key)
    try:
        pt = aes.decrypt(nonce, ct, b"user_keys:v1")
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt key material")
    try:
        obj = json.loads(pt.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt key material")
    if not isinstance(obj, dict):
        raise HTTPException(status_code=500, detail="Corrupt key material")
    return obj


def master_audit_log(action: str, actor: str, target_user_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> None:
    con = db_connect()
    con.execute(
        "INSERT INTO master_audit(id, ts, action, actor, target_user_id, meta_json) VALUES (?, ?, ?, ?, ?, ?)",
        (gen_id("ma"), now_ts(), action, actor, target_user_id, json.dumps(meta or {}, separators=(",", ":"))),
    )
    con.commit()
    con.close()


@app.on_event("startup")
async def _startup() -> None:
    db_init()
    ensure_jwt_secret()

    master_code = get_master_code_value()
    stored = db_get_state("master_code")
    if stored is None:
        db_set_state("master_code", master_code)
        print(f"MASTER_CODE={master_code}")

    asyncio.create_task(retention_purge_loop())
    asyncio.create_task(deletion_purge_loop())


async def deletion_purge_loop() -> None:
    while True:
        try:
            con = db_connect()
            due = con.execute(
                "SELECT user_id FROM deletion_requests WHERE canceled_at IS NULL AND scheduled_at <= ?",
                (now_ts(),),
            ).fetchall()
            for r in due:
                user_id = str(r["user_id"])
                con.execute("DELETE FROM messages WHERE sender_id = ?", (user_id,))
                con.execute("DELETE FROM files WHERE sender_id = ?", (user_id,))
                uploads = con.execute("SELECT id FROM file_uploads WHERE sender_id = ?", (user_id,)).fetchall()
                for up in uploads:
                    up_id = str(up["id"])
                    con.execute("DELETE FROM file_upload_chunks WHERE upload_id = ?", (up_id,))
                    con.execute("DELETE FROM file_uploads WHERE id = ?", (up_id,))
                con.execute("DELETE FROM conversation_members WHERE user_id = ?", (user_id,))

                orphan_convs = con.execute(
                    """
                    SELECT c.id
                    FROM conversations c
                    LEFT JOIN conversation_members m ON m.conversation_id = c.id
                    GROUP BY c.id
                    HAVING COUNT(m.user_id) = 0
                    """
                ).fetchall()
                for oc in orphan_convs:
                    cid = str(oc["id"])
                    con.execute("DELETE FROM messages WHERE conversation_id = ?", (cid,))
                    con.execute("DELETE FROM files WHERE conversation_id = ?", (cid,))
                    ups = con.execute("SELECT id FROM file_uploads WHERE conversation_id = ?", (cid,)).fetchall()
                    for up in ups:
                        up_id = str(up["id"])
                        con.execute("DELETE FROM file_upload_chunks WHERE upload_id = ?", (up_id,))
                        con.execute("DELETE FROM file_uploads WHERE id = ?", (up_id,))
                    con.execute("DELETE FROM conversations WHERE id = ?", (cid,))

                con.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
                con.execute("DELETE FROM user_keys WHERE user_id = ?", (user_id,))
                con.execute("DELETE FROM users WHERE id = ?", (user_id,))
                con.execute("DELETE FROM deletion_requests WHERE user_id = ?", (user_id,))
            con.commit()
            con.close()
        except Exception:
            pass
        await asyncio.sleep(900)


@app.get("/")
async def root() -> HTMLResponse:
    return HTMLResponse(
        content='OK. Backend is running. Frontend: <a href="https://sdchat.in">sdchat.in</a> · Health: <a href="/api/health">/api/health</a>',
        status_code=200,
    )


@app.get("/manifest.webmanifest")
async def manifest() -> Any:
    path = os.path.join(APP_DIR, "manifest.webmanifest")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="manifest not found")
    return FileResponse(path, media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker() -> Any:
    path = os.path.join(APP_DIR, "sw.js")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="sw not found")
    return FileResponse(path, media_type="application/javascript")


@app.get("/config.js")
async def config_js() -> Any:
    path = os.path.join(APP_DIR, "config.js")
    if not os.path.exists(path):
        return Response(content="window.SD_CONFIG = window.SD_CONFIG || {}\n", media_type="application/javascript")
    return FileResponse(path, media_type="application/javascript")


@app.get("/icon.svg")
async def icon_svg() -> Any:
    path = os.path.join(APP_DIR, "icon.svg")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="icon not found")
    return FileResponse(path, media_type="image/svg+xml")


@app.post("/api/auth/register")
async def register(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    username = require_username(str(payload.get("username", "")))
    password = require_password(str(payload.get("password", "")))
    user_id = gen_id("u")
    ts = now_ts()
    con = db_connect()
    try:
        con.execute(
            "INSERT INTO users(id, username, password_hash, must_reset_password, key_version, created_at, updated_at) VALUES (?, ?, ?, 0, 0, ?, ?)",
            (user_id, username, bcrypt_hash_password(password), ts, ts),
        )
        con.execute(
            "INSERT INTO profiles(user_id, display_name, bio, status, avatar_blob, avatar_mime, updated_at) VALUES (?, ?, '', '', NULL, NULL, ?)",
            (user_id, username, ts),
        )
        con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    finally:
        con.close()

    token = jwt_sign(
        {
            "sub": user_id,
            "username": username,
            "role": "user",
            "exp": now_ts() + JWT_TTL_SECONDS,
        }
    )
    return {"token": token, "user": {"id": user_id, "username": username, "must_reset_password": False}}


@app.post("/api/auth/login")
async def login(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    username = require_username(str(payload.get("username", "")))
    password = str(payload.get("password", ""))
    con = db_connect()
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt_verify_password(password, str(row["password_hash"])):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt_sign(
        {
            "sub": str(row["id"]),
            "username": str(row["username"]),
            "role": "user",
            "exp": now_ts() + JWT_TTL_SECONDS,
        }
    )
    return {
        "token": token,
        "user": {"id": str(row["id"]), "username": str(row["username"]), "must_reset_password": bool(row["must_reset_password"])},
    }


@app.post("/api/auth/refresh")
async def refresh_token(request: Request) -> Dict[str, Any]:
    token = parse_bearer_token(request)
    payload = jwt_verify(token)
    role = payload.get("role")
    if role not in ("user", "master"):
        raise HTTPException(status_code=403, detail="Forbidden")
    now = now_ts()
    new_payload: Dict[str, Any] = {"role": role, "exp": now + JWT_TTL_SECONDS}

    if role == "master":
        new_payload["sub"] = "master"
        return {"token": jwt_sign(new_payload)}

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid token")
    con = db_connect()
    row = con.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    new_payload["sub"] = str(row["id"])
    new_payload["username"] = str(row["username"])
    if payload.get("impersonated_by") == "master":
        new_payload["impersonated_by"] = "master"
    return {"token": jwt_sign(new_payload)}


@app.get("/api/me/keys")
async def get_my_keys(user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    user_id = str(user["id"])
    con = db_connect()
    row = con.execute("SELECT * FROM user_keys WHERE user_id = ?", (user_id,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Keys not found")
    obj = _decrypt_from_storage(str(row["enc_json"]))
    return {
        "user_id": user_id,
        "key_version": int(row["key_version"]),
        "public_keys": {"ecdh_p256_spki_b64": str(row["ecdh_spki_b64"]), "ecdsa_p256_spki_b64": str(row["ecdsa_spki_b64"])},
        "private_keys": {
            "ecdh_p256_pkcs8_b64": _require_b64_field(obj, "ecdh_p256_pkcs8_b64"),
            "ecdsa_p256_pkcs8_b64": _require_b64_field(obj, "ecdsa_p256_pkcs8_b64"),
        },
        "updated_at": int(row["updated_at"]),
    }


@app.post("/api/me/keys")
async def put_my_keys(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    user_id = str(user["id"])
    key_version = int(payload.get("key_version", int(user["key_version"])))
    pub_ecdh = _require_b64_field(payload, "ecdh_p256_spki_b64")
    pub_ecdsa = _require_b64_field(payload, "ecdsa_p256_spki_b64")
    priv_ecdh = _require_b64_field(payload, "ecdh_p256_pkcs8_b64")
    priv_ecdsa = _require_b64_field(payload, "ecdsa_p256_pkcs8_b64")

    con = db_connect()
    existing = con.execute("SELECT ecdh_spki_b64, ecdsa_spki_b64 FROM user_keys WHERE user_id = ?", (user_id,)).fetchone()
    if existing is not None:
        if str(existing["ecdh_spki_b64"]) != pub_ecdh or str(existing["ecdsa_spki_b64"]) != pub_ecdsa:
            con.close()
            raise HTTPException(status_code=409, detail="Keys already exist for this account")
        con.execute(
            "UPDATE user_keys SET key_version=?, enc_json=?, updated_at=? WHERE user_id=?",
            (key_version, _encrypt_for_storage({"ecdh_p256_pkcs8_b64": priv_ecdh, "ecdsa_p256_pkcs8_b64": priv_ecdsa}), now_ts(), user_id),
        )
    else:
        con.execute(
            "INSERT INTO user_keys(user_id, key_version, ecdh_spki_b64, ecdsa_spki_b64, enc_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, key_version, pub_ecdh, pub_ecdsa, _encrypt_for_storage({"ecdh_p256_pkcs8_b64": priv_ecdh, "ecdsa_p256_pkcs8_b64": priv_ecdsa}), now_ts()),
        )
    con.commit()
    con.close()
    return {"ok": True}


@app.get("/api/master/users/{user_id}/keys")
async def master_get_user_keys(user_id: str, _: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    row = con.execute("SELECT * FROM user_keys WHERE user_id = ?", (user_id,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Keys not found")
    obj = _decrypt_from_storage(str(row["enc_json"]))
    master_audit_log("read_user_keys", "master", user_id, {})
    return {
        "user_id": str(row["user_id"]),
        "key_version": int(row["key_version"]),
        "public_keys": {"ecdh_p256_spki_b64": str(row["ecdh_spki_b64"]), "ecdsa_p256_spki_b64": str(row["ecdsa_spki_b64"])},
        "private_keys": {
            "ecdh_p256_pkcs8_b64": _require_b64_field(obj, "ecdh_p256_pkcs8_b64"),
            "ecdsa_p256_pkcs8_b64": _require_b64_field(obj, "ecdsa_p256_pkcs8_b64"),
        },
        "updated_at": int(row["updated_at"]),
    }


@app.post("/api/master/login")
async def master_login(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    code = str(payload.get("code", ""))
    stored = get_master_code_value()
    if normalize_master_code(code) != normalize_master_code(stored):
        raise HTTPException(status_code=401, detail="Invalid master code")
    token = jwt_sign({"sub": "master", "role": "master", "exp": now_ts() + JWT_TTL_SECONDS})
    master_audit_log("master_login", "master", None, {"ip": ""})
    return {"token": token}


@app.get("/api/health")
async def health() -> Dict[str, Any]:
    try:
        con = db_connect()
        con.execute("SELECT 1")
        con.close()
        db_ok = True
    except Exception:
        db_ok = False
    return {"ok": True, "db_ok": db_ok}


@app.post("/api/master/reset-db")
async def master_reset_db(_: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    for t in [
        "messages",
        "files",
        "conversation_members",
        "conversations",
        "profiles",
        "user_keys",
        "deletion_requests",
        "master_audit",
        "users",
    ]:
        try:
            con.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    con.commit()
    con.close()
    master_audit_log("reset_db", "master", None, {})
    return {"ok": True}


@app.post("/api/master/impersonate")
async def master_impersonate(payload: Dict[str, Any] = Body(...), master: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    user_id = str(payload.get("user_id", "")).strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    con = db_connect()
    row = con.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    token = jwt_sign(
        {
            "sub": str(row["id"]),
            "username": str(row["username"]),
            "role": "user",
            "impersonated_by": "master",
            "exp": now_ts() + JWT_TTL_SECONDS,
        }
    )
    master_audit_log("impersonate", str(master.get("sub")), str(row["id"]), {"username": str(row["username"])})
    return {"token": token, "user": {"id": str(row["id"]), "username": str(row["username"]), "must_reset_password": False}}


@app.get("/api/master/audit")
async def master_audit(_: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    rows = con.execute("SELECT * FROM master_audit ORDER BY ts DESC LIMIT 200").fetchall()
    con.close()
    items = []
    for r in rows:
        items.append(
            {
                "id": str(r["id"]),
                "ts": iso_from_ts(int(r["ts"])),
                "action": str(r["action"]),
                "actor": str(r["actor"]),
                "target_user_id": r["target_user_id"],
                "meta": json.loads(str(r["meta_json"])) if r["meta_json"] else {},
            }
        )
    return {"items": items}


@app.get("/api/master/conversations/{conversation_id}/messages")
async def master_list_conv_messages(conversation_id: str, _: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    msgs = con.execute(
        "SELECT id, sender_id, envelope_json, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 200",
        (conversation_id,),
    ).fetchall()
    files = con.execute(
        "SELECT id, sender_id, envelope_json, created_at FROM files WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 200",
        (conversation_id,),
    ).fetchall()
    con.close()
    items = []
    for m in msgs:
        items.append(
            {
                "id": str(m["id"]),
                "kind": "msg",
                "sender_id": str(m["sender_id"]),
                "created_at": int(m["created_at"]),
                "envelope_json": str(m["envelope_json"]),
            }
        )
    for f in files:
        items.append(
            {
                "id": str(f["id"]),
                "kind": "file",
                "sender_id": str(f["sender_id"]),
                "created_at": int(f["created_at"]),
                "envelope_json": str(f["envelope_json"]),
            }
        )
    items.sort(key=lambda x: int(x["created_at"]), reverse=True)
    return {"items": items[:200]}


@app.get("/api/me")
async def me(user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    prof = con.execute(
        "SELECT display_name, bio, status, avatar_mime, updated_at FROM profiles WHERE user_id = ?",
        (str(user["id"]),),
    ).fetchone()
    con.close()
    return {
        "id": str(user["id"]),
        "username": str(user["username"]),
        "must_reset_password": bool(user["must_reset_password"]),
        "key_version": int(user["key_version"]),
        "public_keys": {
            "ecdh_p256_spki_b64": user["ecdh_p256_spki_b64"],
            "ecdsa_p256_spki_b64": user["ecdsa_p256_spki_b64"],
        },
        "profile": None
        if prof is None
        else {
            "display_name": prof["display_name"],
            "bio": prof["bio"],
            "status": prof["status"],
            "has_avatar": prof["avatar_mime"] is not None,
            "updated_at": iso_from_ts(int(prof["updated_at"])) if prof["updated_at"] is not None else None,
        },
    }


@app.put("/api/me/password")
async def change_password(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    current = str(payload.get("current_password", ""))
    new_pw = require_password(str(payload.get("new_password", "")))
    if not bcrypt_verify_password(current, str(user["password_hash"])):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    con = db_connect()
    con.execute(
        "UPDATE users SET password_hash=?, must_reset_password=0, updated_at=? WHERE id=?",
        (bcrypt_hash_password(new_pw), now_ts(), str(user["id"])),
    )
    con.commit()
    con.close()
    return {"ok": True}


@app.get("/api/me/export")
async def export_account(user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    user_id = str(user["id"])
    con = db_connect()
    prof = con.execute(
        "SELECT display_name, bio, status, avatar_mime, updated_at FROM profiles WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    convs = con.execute(
        """
        SELECT c.*
        FROM conversations c
        JOIN conversation_members m ON m.conversation_id = c.id
        WHERE m.user_id = ?
        ORDER BY c.last_activity_at DESC
        """,
        (user_id,),
    ).fetchall()
    items = []
    for c in convs:
        cid = str(c["id"])
        mems = con.execute(
            "SELECT u.id, u.username, m.role FROM conversation_members m JOIN users u ON u.id = m.user_id WHERE m.conversation_id = ? ORDER BY u.username",
            (cid,),
        ).fetchall()
        msgs = con.execute(
            "SELECT id, sender_id, envelope_json, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at",
            (cid,),
        ).fetchall()
        files = con.execute(
            "SELECT id, sender_id, envelope_json, created_at FROM files WHERE conversation_id = ? ORDER BY created_at",
            (cid,),
        ).fetchall()
        items.append(
            {
                "conversation": {
                    "id": cid,
                    "type": str(c["type"]),
                    "title": c["title"],
                    "created_by": str(c["created_by"]),
                    "created_at": iso_from_ts(int(c["created_at"])),
                    "last_activity_at": iso_from_ts(int(c["last_activity_at"])),
                    "members": [{"id": str(m["id"]), "username": str(m["username"]), "role": str(m["role"])} for m in mems],
                },
                "messages": [
                    {"id": str(m["id"]), "sender_id": str(m["sender_id"]), "created_at": int(m["created_at"]), "envelope_json": str(m["envelope_json"])}
                    for m in msgs
                ],
                "files": [
                    {"id": str(f["id"]), "sender_id": str(f["sender_id"]), "created_at": int(f["created_at"]), "envelope_json": str(f["envelope_json"])}
                    for f in files
                ],
            }
        )
    dr = con.execute(
        "SELECT requested_at, scheduled_at, canceled_at FROM deletion_requests WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    con.close()
    return {
        "exported_at": iso_from_ts(now_ts()),
        "user": {"id": user_id, "username": str(user["username"]), "key_version": int(user["key_version"])},
        "profile": None
        if prof is None
        else {
            "display_name": prof["display_name"],
            "bio": prof["bio"],
            "status": prof["status"],
            "has_avatar": prof["avatar_mime"] is not None,
            "updated_at": iso_from_ts(int(prof["updated_at"])) if prof["updated_at"] is not None else None,
        },
        "deletion_request": None
        if dr is None
        else {
            "requested_at": iso_from_ts(int(dr["requested_at"])),
            "scheduled_at": iso_from_ts(int(dr["scheduled_at"])),
            "canceled_at": None if dr["canceled_at"] is None else iso_from_ts(int(dr["canceled_at"])),
        },
        "conversations": items,
    }


@app.post("/api/me/delete-request")
async def request_account_deletion(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    password = str(payload.get("password", ""))
    if not bcrypt_verify_password(password, str(user["password_hash"])):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = str(user["id"])
    now = now_ts()
    scheduled = now + (7 * 86400)
    con = db_connect()
    con.execute(
        "INSERT INTO deletion_requests(user_id, requested_at, scheduled_at, canceled_at) VALUES (?, ?, ?, NULL) ON CONFLICT(user_id) DO UPDATE SET requested_at=excluded.requested_at, scheduled_at=excluded.scheduled_at, canceled_at=NULL",
        (user_id, now, scheduled),
    )
    con.commit()
    con.close()
    return {"ok": True, "scheduled_at": iso_from_ts(scheduled)}


@app.post("/api/me/delete-cancel")
async def cancel_account_deletion(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    password = str(payload.get("password", ""))
    if not bcrypt_verify_password(password, str(user["password_hash"])):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = str(user["id"])
    con = db_connect()
    row = con.execute(
        "SELECT user_id FROM deletion_requests WHERE user_id = ? AND canceled_at IS NULL",
        (user_id,),
    ).fetchone()
    if row is None:
        con.close()
        return {"ok": True, "canceled": False}
    con.execute("UPDATE deletion_requests SET canceled_at = ? WHERE user_id = ?", (now_ts(), user_id))
    con.commit()
    con.close()
    return {"ok": True, "canceled": True}


@app.get("/api/me/deletion-status")
async def deletion_status(user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    user_id = str(user["id"])
    con = db_connect()
    row = con.execute(
        "SELECT requested_at, scheduled_at, canceled_at FROM deletion_requests WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    con.close()
    if row is None:
        return {"active": False}
    if row["canceled_at"] is not None:
        return {"active": False}
    return {
        "active": True,
        "requested_at": iso_from_ts(int(row["requested_at"])),
        "scheduled_at": iso_from_ts(int(row["scheduled_at"])),
    }


@app.put("/api/me/profile")
async def update_profile(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    display_name = str(payload.get("display_name", "")).strip()[:64]
    bio = str(payload.get("bio", ""))[:280]
    status = str(payload.get("status", ""))[:64]
    con = db_connect()
    con.execute(
        "UPDATE profiles SET display_name=?, bio=?, status=?, updated_at=? WHERE user_id=?",
        (display_name, bio, status, now_ts(), str(user["id"])),
    )
    con.commit()
    con.close()
    return {"ok": True}


@app.post("/api/me/avatar")
async def set_avatar(user: sqlite3.Row = Depends(get_current_user), file: UploadFile = File(...)) -> Dict[str, Any]:
    content = await file.read()
    if len(content) > 2_000_000:
        raise HTTPException(status_code=413, detail="Avatar too large")
    mime = file.content_type or "application/octet-stream"
    if not mime.startswith("image/"):
        raise HTTPException(status_code=400, detail="Avatar must be an image")
    con = db_connect()
    con.execute(
        "UPDATE profiles SET avatar_blob=?, avatar_mime=?, updated_at=? WHERE user_id=?",
        (content, mime, now_ts(), str(user["id"])),
    )
    con.commit()
    con.close()
    return {"ok": True}


@app.get("/api/avatars/{user_id}")
async def get_avatar(user_id: str) -> Any:
    con = db_connect()
    row = con.execute("SELECT avatar_blob, avatar_mime FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
    con.close()
    if row is None or row["avatar_blob"] is None:
        raise HTTPException(status_code=404, detail="Avatar not found")
    from fastapi.responses import Response

    return Response(content=row["avatar_blob"], media_type=row["avatar_mime"])


@app.put("/api/me/public-keys")
async def put_public_keys(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    ecdh = str(payload.get("ecdh_p256_spki_b64", ""))
    ecdsa = str(payload.get("ecdsa_p256_spki_b64", ""))
    if not ecdh or not ecdsa:
        raise HTTPException(status_code=400, detail="Missing keys")
    con = db_connect()
    row = con.execute("SELECT key_version FROM users WHERE id = ?", (str(user["id"]),)).fetchone()
    if row is None:
        con.close()
        raise HTTPException(status_code=404, detail="User not found")
    next_ver = int(row["key_version"]) + 1
    con.execute(
        "UPDATE users SET ecdh_p256_spki_b64=?, ecdsa_p256_spki_b64=?, key_version=?, updated_at=? WHERE id=?",
        (ecdh, ecdsa, next_ver, now_ts(), str(user["id"])),
    )
    con.commit()
    con.close()
    return {"ok": True, "key_version": next_ver}


@app.get("/api/users/search")
async def search_users(q: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    term = q.strip()
    if len(term) < 1:
        return {"items": []}
    con = db_connect()
    rows = con.execute(
        """
        SELECT u.id, u.username, u.key_version, p.display_name, p.status, p.avatar_mime
        FROM users u
        JOIN profiles p ON p.user_id = u.id
        WHERE u.username LIKE ? OR p.display_name LIKE ?
        ORDER BY u.username
        LIMIT 20
        """,
        (f"%{term}%", f"%{term}%"),
    ).fetchall()
    con.close()
    items = []
    for r in rows:
        items.append(
            {
                "id": str(r["id"]),
                "username": str(r["username"]),
                "display_name": r["display_name"],
                "status": r["status"],
                "has_avatar": r["avatar_mime"] is not None,
                "key_version": int(r["key_version"]),
            }
        )
    return {"items": items}


@app.get("/api/users/{user_id}")
async def get_user_profile(user_id: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    u = con.execute("SELECT id, username, key_version FROM users WHERE id = ?", (user_id,)).fetchone()
    p = con.execute(
        "SELECT display_name, bio, status, avatar_mime, updated_at FROM profiles WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    con.close()
    if u is None or p is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(u["id"]),
        "username": str(u["username"]),
        "key_version": int(u["key_version"]),
        "profile": {
            "display_name": p["display_name"],
            "bio": p["bio"],
            "status": p["status"],
            "has_avatar": p["avatar_mime"] is not None,
            "updated_at": iso_from_ts(int(p["updated_at"])) if p["updated_at"] is not None else None,
        },
    }


@app.get("/api/users/{user_id}/keys")
async def get_user_keys(user_id: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    row = con.execute(
        "SELECT id, username, ecdh_p256_spki_b64, ecdsa_p256_spki_b64, key_version FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    con.close()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(row["id"]),
        "username": str(row["username"]),
        "key_version": int(row["key_version"]),
        "public_keys": {
            "ecdh_p256_spki_b64": row["ecdh_p256_spki_b64"],
            "ecdsa_p256_spki_b64": row["ecdsa_p256_spki_b64"],
        },
    }


@app.post("/api/conversations/direct")
async def get_or_create_direct(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    other_user_id = str(payload.get("user_id", ""))
    if not other_user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    if other_user_id == str(user["id"]):
        raise HTTPException(status_code=400, detail="Cannot chat with yourself")
    a, b = conv_pair(str(user["id"]), other_user_id)
    con = db_connect()
    other = con.execute("SELECT id FROM users WHERE id = ?", (other_user_id,)).fetchone()
    if other is None:
        con.close()
        raise HTTPException(status_code=404, detail="User not found")
    row = con.execute(
        "SELECT * FROM conversations WHERE type='direct' AND direct_user_a_id=? AND direct_user_b_id=?",
        (a, b),
    ).fetchone()
    if row is None:
        conv_id = gen_id("c")
        ts = now_ts()
        con.execute(
            "INSERT INTO conversations(id, type, title, created_by, direct_user_a_id, direct_user_b_id, created_at, last_activity_at) VALUES (?, 'direct', NULL, ?, ?, ?, ?, ?)",
            (conv_id, str(user["id"]), a, b, ts, ts),
        )
        con.execute(
            "INSERT INTO conversation_members(conversation_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
            (conv_id, a, ts),
        )
        con.execute(
            "INSERT INTO conversation_members(conversation_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
            (conv_id, b, ts),
        )
        con.commit()
        row = con.execute("SELECT * FROM conversations WHERE id = ?", (conv_id,)).fetchone()
    con.close()
    return {
        "conversation": {
            "id": str(row["id"]),
            "type": str(row["type"]),
            "title": row["title"],
            "created_at": iso_from_ts(int(row["created_at"])),
            "last_activity_at": iso_from_ts(int(row["last_activity_at"])),
        }
    }


@app.post("/api/conversations/group")
async def create_group(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    title = str(payload.get("title", "")).strip()[:64]
    members = payload.get("members")
    admins = payload.get("admins")
    if not title:
        raise HTTPException(status_code=400, detail="Missing title")
    if not isinstance(members, list) or len(members) < 1:
        raise HTTPException(status_code=400, detail="Members must be a list")
    if not isinstance(admins, list):
        admins = []
    user_id = str(user["id"])
    member_ids = set(str(x) for x in members if x)
    member_ids.add(user_id)
    admin_ids = set(str(x) for x in admins if x)
    admin_ids.add(user_id)
    con = db_connect()
    rows = con.execute(
        f"SELECT id FROM users WHERE id IN ({','.join(['?'] * len(member_ids))})",
        tuple(member_ids),
    ).fetchall()
    if len(rows) != len(member_ids):
        con.close()
        raise HTTPException(status_code=400, detail="One or more members not found")
    conv_id = gen_id("g")
    ts = now_ts()
    con.execute(
        "INSERT INTO conversations(id, type, title, created_by, direct_user_a_id, direct_user_b_id, created_at, last_activity_at) VALUES (?, 'group', ?, ?, NULL, NULL, ?, ?)",
        (conv_id, title, user_id, ts, ts),
    )
    for mid in member_ids:
        role = "admin" if mid in admin_ids else "member"
        con.execute(
            "INSERT INTO conversation_members(conversation_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (conv_id, mid, role, ts),
        )
    con.commit()
    con.close()
    return {"conversation": {"id": conv_id, "type": "group", "title": title, "created_at": iso_from_ts(ts), "last_activity_at": iso_from_ts(ts)}}


@app.get("/api/conversations")
async def list_conversations(user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    uid = str(user["id"])
    con = db_connect()
    rows = con.execute(
        """
        SELECT c.*
        FROM conversations c
        JOIN conversation_members m ON m.conversation_id = c.id
        WHERE m.user_id = ?
        ORDER BY c.last_activity_at DESC
        LIMIT 100
        """,
        (uid,),
    ).fetchall()
    items = []
    for r in rows:
        conv_id = str(r["id"])
        mem_rows = con.execute(
            """
            SELECT u.id, u.username, p.display_name, p.avatar_mime, m.role
            FROM conversation_members m
            JOIN users u ON u.id = m.user_id
            JOIN profiles p ON p.user_id = u.id
            WHERE m.conversation_id = ?
            ORDER BY u.username
            """,
            (conv_id,),
        ).fetchall()
        members = []
        for mr in mem_rows:
            members.append(
                {
                    "id": str(mr["id"]),
                    "username": str(mr["username"]),
                    "display_name": mr["display_name"],
                    "has_avatar": mr["avatar_mime"] is not None,
                    "role": str(mr["role"]),
                }
            )
        items.append(
            {
                "id": conv_id,
                "type": str(r["type"]),
                "title": r["title"],
                "created_by": str(r["created_by"]),
                "created_at": iso_from_ts(int(r["created_at"])),
                "last_activity_at": iso_from_ts(int(r["last_activity_at"])),
                "members": members,
            }
        )
    con.close()
    return {"items": items}


@app.get("/api/conversations/{conversation_id}/members")
async def get_conversation_members(conversation_id: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    ensure_conv_member(con, conversation_id, str(user["id"]))
    rows = con.execute(
        """
        SELECT u.id, u.username, p.display_name, p.status, p.avatar_mime, m.role
        FROM conversation_members m
        JOIN users u ON u.id = m.user_id
        JOIN profiles p ON p.user_id = u.id
        WHERE m.conversation_id = ?
        ORDER BY u.username
        """,
        (conversation_id,),
    ).fetchall()
    con.close()
    return {
        "items": [
            {
                "id": str(r["id"]),
                "username": str(r["username"]),
                "display_name": r["display_name"],
                "status": r["status"],
                "has_avatar": r["avatar_mime"] is not None,
                "role": str(r["role"]),
            }
            for r in rows
        ]
    }


@app.post("/api/conversations/{conversation_id}/members/add")
async def add_conversation_member(conversation_id: str, user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    target_user_id = str(payload.get("user_id", ""))
    role = str(payload.get("role", "member"))
    if role not in ("member", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    if not target_user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    con = db_connect()
    conv = con.execute("SELECT type FROM conversations WHERE id=?", (conversation_id,)).fetchone()
    if conv is None:
        con.close()
        raise HTTPException(status_code=404, detail="Conversation not found")
    if str(conv["type"]) != "group":
        con.close()
        raise HTTPException(status_code=400, detail="Only group conversations support membership changes")
    ensure_conv_admin(con, conversation_id, str(user["id"]))
    exists = con.execute("SELECT id FROM users WHERE id=?", (target_user_id,)).fetchone()
    if exists is None:
        con.close()
        raise HTTPException(status_code=404, detail="User not found")
    ts = now_ts()
    con.execute(
        "INSERT INTO conversation_members(conversation_id, user_id, role, joined_at) VALUES (?, ?, ?, ?) ON CONFLICT(conversation_id, user_id) DO UPDATE SET role=excluded.role",
        (conversation_id, target_user_id, role, ts),
    )
    con.execute("UPDATE conversations SET last_activity_at=? WHERE id=?", (ts, conversation_id))
    member_ids = conv_member_ids(con, conversation_id)
    con.commit()
    con.close()
    await ws_manager.broadcast(member_ids, {"type": "conversation:members", "conversation_id": conversation_id, "ts": ts})
    return {"ok": True}


@app.post("/api/conversations/{conversation_id}/members/remove")
async def remove_conversation_member(conversation_id: str, user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    target_user_id = str(payload.get("user_id", ""))
    if not target_user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    con = db_connect()
    conv = con.execute("SELECT type FROM conversations WHERE id=?", (conversation_id,)).fetchone()
    if conv is None:
        con.close()
        raise HTTPException(status_code=404, detail="Conversation not found")
    if str(conv["type"]) != "group":
        con.close()
        raise HTTPException(status_code=400, detail="Only group conversations support membership changes")
    ensure_conv_admin(con, conversation_id, str(user["id"]))
    if target_user_id == str(user["id"]):
        con.close()
        raise HTTPException(status_code=400, detail="Admin cannot remove themselves")
    admins = con.execute(
        "SELECT COUNT(1) AS c FROM conversation_members WHERE conversation_id=? AND role='admin'",
        (conversation_id,),
    ).fetchone()
    target_role = con.execute(
        "SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?",
        (conversation_id, target_user_id),
    ).fetchone()
    if target_role is not None and str(target_role["role"]) == "admin" and int(admins["c"]) <= 1:
        con.close()
        raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    con.execute(
        "DELETE FROM conversation_members WHERE conversation_id=? AND user_id=?",
        (conversation_id, target_user_id),
    )
    ts = now_ts()
    con.execute("UPDATE conversations SET last_activity_at=? WHERE id=?", (ts, conversation_id))
    member_ids = conv_member_ids(con, conversation_id)
    con.commit()
    con.close()
    await ws_manager.broadcast(member_ids, {"type": "conversation:members", "conversation_id": conversation_id, "ts": ts})
    return {"ok": True}


@app.post("/api/conversations/{conversation_id}/members/role")
async def set_conversation_member_role(conversation_id: str, user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    target_user_id = str(payload.get("user_id", ""))
    role = str(payload.get("role", "member"))
    if role not in ("member", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    if not target_user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    con = db_connect()
    conv = con.execute("SELECT type FROM conversations WHERE id=?", (conversation_id,)).fetchone()
    if conv is None:
        con.close()
        raise HTTPException(status_code=404, detail="Conversation not found")
    if str(conv["type"]) != "group":
        con.close()
        raise HTTPException(status_code=400, detail="Only group conversations support membership changes")
    ensure_conv_admin(con, conversation_id, str(user["id"]))
    if target_user_id == str(user["id"]) and role != "admin":
        con.close()
        raise HTTPException(status_code=400, detail="Cannot demote yourself")
    admins = con.execute(
        "SELECT COUNT(1) AS c FROM conversation_members WHERE conversation_id=? AND role='admin'",
        (conversation_id,),
    ).fetchone()
    target_role = con.execute(
        "SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?",
        (conversation_id, target_user_id),
    ).fetchone()
    if target_role is None:
        con.close()
        raise HTTPException(status_code=404, detail="Member not found")
    if str(target_role["role"]) == "admin" and role != "admin" and int(admins["c"]) <= 1:
        con.close()
        raise HTTPException(status_code=400, detail="Cannot demote the last admin")
    con.execute(
        "UPDATE conversation_members SET role=? WHERE conversation_id=? AND user_id=?",
        (role, conversation_id, target_user_id),
    )
    ts = now_ts()
    con.execute("UPDATE conversations SET last_activity_at=? WHERE id=?", (ts, conversation_id))
    member_ids = conv_member_ids(con, conversation_id)
    con.commit()
    con.close()
    await ws_manager.broadcast(member_ids, {"type": "conversation:members", "conversation_id": conversation_id, "ts": ts})
    return {"ok": True}


@app.get("/api/messages")
async def list_messages(conversation_id: str, limit: int = 50, before: Optional[int] = None, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    limit = max(1, min(int(limit), 200))
    con = db_connect()
    ensure_conv_member(con, conversation_id, str(user["id"]))
    if before is None:
        rows = con.execute(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT ?",
            (conversation_id, limit),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM messages WHERE conversation_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?",
            (conversation_id, int(before), limit),
        ).fetchall()
    items = []
    for r in rows[::-1]:
        items.append(
            {
                "id": str(r["id"]),
                "conversation_id": str(r["conversation_id"]),
                "sender_id": str(r["sender_id"]),
                "envelope_json": str(r["envelope_json"]),
                "created_at": int(r["created_at"]),
            }
        )
    con.close()
    return {"items": items}


@app.post("/api/messages")
async def send_message(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conversation_id = str(payload.get("conversation_id", ""))
    envelope_json = payload.get("envelope_json")
    if not conversation_id or envelope_json is None:
        raise HTTPException(status_code=400, detail="Missing fields")
    envelope_text = envelope_json if isinstance(envelope_json, str) else json.dumps(envelope_json)
    msg_id = gen_id("m")
    ts = now_ts()
    con = db_connect()
    ensure_conv_member(con, conversation_id, str(user["id"]))
    con.execute(
        "INSERT INTO messages(id, conversation_id, sender_id, envelope_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (msg_id, conversation_id, str(user["id"]), envelope_text, ts),
    )
    con.execute("UPDATE conversations SET last_activity_at=? WHERE id=?", (ts, conversation_id))
    member_ids = conv_member_ids(con, conversation_id)
    con.commit()
    con.close()
    await ws_manager.broadcast(
        member_ids,
        {
            "type": "message:new",
            "message": {
                "id": msg_id,
                "conversation_id": conversation_id,
                "sender_id": str(user["id"]),
                "envelope_json": envelope_text,
                "created_at": ts,
            },
        },
    )
    return {"ok": True, "id": msg_id, "created_at": ts}


@app.post("/api/files/uploads/init")
async def init_file_upload(user: sqlite3.Row = Depends(get_current_user), payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conversation_id = str(payload.get("conversation_id", ""))
    filename = str(payload.get("filename", ""))[:255]
    mime = str(payload.get("mime", "application/octet-stream"))[:128]
    size = int(payload.get("size", 0))
    total_chunks = int(payload.get("total_chunks", 0))
    envelope_json = payload.get("envelope_json")
    if not conversation_id or not filename or size <= 0 or total_chunks <= 0 or envelope_json is None:
        raise HTTPException(status_code=400, detail="Missing fields")
    env_text = envelope_json if isinstance(envelope_json, str) else json.dumps(envelope_json)
    upload_id = gen_id("up")
    ts = now_ts()
    con = db_connect()
    ensure_conv_member(con, conversation_id, str(user["id"]))
    con.execute(
        "INSERT INTO file_uploads(id, conversation_id, sender_id, filename, mime, size, total_chunks, envelope_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (upload_id, conversation_id, str(user["id"]), filename, mime, size, total_chunks, env_text, ts),
    )
    con.commit()
    con.close()
    return {"upload_id": upload_id}


@app.post("/api/files/uploads/{upload_id}/chunk")
async def upload_chunk(upload_id: str, idx: int, request: Request, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    raw = await request.body()
    if raw is None:
        raise HTTPException(status_code=400, detail="Missing chunk")
    if len(raw) > 1_500_000:
        raise HTTPException(status_code=413, detail="Chunk too large")
    con = db_connect()
    up = con.execute("SELECT * FROM file_uploads WHERE id=?", (upload_id,)).fetchone()
    if up is None:
        con.close()
        raise HTTPException(status_code=404, detail="Upload not found")
    if str(up["sender_id"]) != str(user["id"]):
        con.close()
        raise HTTPException(status_code=403, detail="Forbidden")
    con.execute(
        "INSERT INTO file_upload_chunks(upload_id, idx, blob) VALUES (?, ?, ?) ON CONFLICT(upload_id, idx) DO UPDATE SET blob=excluded.blob",
        (upload_id, int(idx), raw),
    )
    con.commit()
    con.close()
    return {"ok": True}


@app.post("/api/files/uploads/{upload_id}/finalize")
async def finalize_upload(upload_id: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    up = con.execute("SELECT * FROM file_uploads WHERE id=?", (upload_id,)).fetchone()
    if up is None:
        con.close()
        raise HTTPException(status_code=404, detail="Upload not found")
    if str(up["sender_id"]) != str(user["id"]):
        con.close()
        raise HTTPException(status_code=403, detail="Forbidden")
    conversation_id = str(up["conversation_id"])
    ensure_conv_member(con, conversation_id, str(user["id"]))
    total = int(up["total_chunks"])
    chunks = con.execute(
        "SELECT idx, blob FROM file_upload_chunks WHERE upload_id=? ORDER BY idx",
        (upload_id,),
    ).fetchall()
    if len(chunks) != total:
        con.close()
        raise HTTPException(status_code=400, detail="Missing chunks")
    assembled = b"".join([bytes(r["blob"]) for r in chunks])
    expected = int(up["size"])
    if len(assembled) != expected:
        con.close()
        raise HTTPException(status_code=400, detail="Size mismatch")
    file_id = gen_id("f")
    ts = now_ts()
    con.execute(
        "INSERT INTO files(id, conversation_id, sender_id, envelope_json, blob, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (file_id, conversation_id, str(user["id"]), str(up["envelope_json"]), assembled, ts),
    )
    con.execute("UPDATE conversations SET last_activity_at=? WHERE id=?", (ts, conversation_id))
    con.execute("DELETE FROM file_upload_chunks WHERE upload_id=?", (upload_id,))
    con.execute("DELETE FROM file_uploads WHERE id=?", (upload_id,))
    member_ids = conv_member_ids(con, conversation_id)
    con.commit()
    con.close()
    await ws_manager.broadcast(
        member_ids,
        {
            "type": "file:new",
            "file": {"id": file_id, "conversation_id": conversation_id, "sender_id": str(user["id"]), "created_at": ts},
        },
    )
    return {"ok": True, "file_id": file_id, "created_at": ts}


@app.get("/api/files/{file_id}")
async def download_file(file_id: str, user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    con = db_connect()
    row = con.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if row is None:
        con.close()
        raise HTTPException(status_code=404, detail="File not found")
    ensure_conv_member(con, str(row["conversation_id"]), str(user["id"]))
    con.close()
    return {
        "id": str(row["id"]),
        "conversation_id": str(row["conversation_id"]),
        "sender_id": str(row["sender_id"]),
        "created_at": int(row["created_at"]),
        "envelope_json": str(row["envelope_json"]),
        "blob_b64": base64.b64encode(bytes(row["blob"])).decode("ascii"),
    }


@app.get("/api/master/users")
async def master_list_users(_: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    rows = con.execute(
        """
        SELECT u.id, u.username, u.created_at, u.updated_at, u.must_reset_password, u.key_version,
               p.display_name, p.status, p.avatar_mime
        FROM users u
        JOIN profiles p ON p.user_id = u.id
        ORDER BY u.created_at DESC
        LIMIT 500
        """
    ).fetchall()
    con.close()
    items = []
    for r in rows:
        items.append(
            {
                "id": str(r["id"]),
                "username": str(r["username"]),
                "display_name": r["display_name"],
                "status": r["status"],
                "has_avatar": r["avatar_mime"] is not None,
                "must_reset_password": bool(r["must_reset_password"]),
                "key_version": int(r["key_version"]),
                "created_at": iso_from_ts(int(r["created_at"])),
                "updated_at": iso_from_ts(int(r["updated_at"])),
            }
        )
    return {"items": items}


@app.post("/api/master/users/{user_id}/reset-password")
async def master_reset_password(user_id: str, payload: Dict[str, Any] = Body(...), _: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    new_pw = require_password(str(payload.get("new_password", "")))
    force_reset = bool(payload.get("force_reset", True))
    con = db_connect()
    row = con.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        con.close()
        raise HTTPException(status_code=404, detail="User not found")
    con.execute(
        "UPDATE users SET password_hash=?, must_reset_password=?, updated_at=? WHERE id=?",
        (bcrypt_hash_password(new_pw), 1 if force_reset else 0, now_ts(), user_id),
    )
    con.commit()
    con.close()
    master_audit_log("reset_password", "master", user_id, {"force_reset": bool(force_reset)})
    return {"ok": True}


@app.delete("/api/master/users/{user_id}")
async def master_delete_user(user_id: str, _: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    con.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM conversation_members WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM user_keys WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()
    con.close()
    master_audit_log("delete_user", "master", user_id, {})
    return {"ok": True}


@app.get("/api/master/metadata/conversations")
async def master_chat_metadata(_: Dict[str, Any] = Depends(get_master)) -> Dict[str, Any]:
    con = db_connect()
    rows = con.execute("SELECT * FROM conversations ORDER BY last_activity_at DESC LIMIT 500").fetchall()
    items = []
    for r in rows:
        conv_id = str(r["id"])
        mems = con.execute(
            """
            SELECT u.id, u.username, m.role
            FROM conversation_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.conversation_id = ?
            ORDER BY u.username
            """,
            (conv_id,),
        ).fetchall()
        items.append(
            {
                "id": conv_id,
                "type": str(r["type"]),
                "title": r["title"],
                "created_by": str(r["created_by"]),
                "created_at": iso_from_ts(int(r["created_at"])),
                "last_activity_at": iso_from_ts(int(r["last_activity_at"])),
                "members": [{"id": str(m["id"]), "username": str(m["username"]), "role": str(m["role"])} for m in mems],
            }
        )
    con.close()
    return {"items": items}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    token = ws.query_params.get("token") or ""
    payload = jwt_verify(token)
    if payload.get("role") != "user":
        await ws.close(code=4403)
        return
    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        await ws.close(code=4401)
        return
    await ws.accept()
    await ws_manager.add(user_id, ws)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            t = msg.get("type")
            if t == "typing:e2ee":
                conversation_id = str(msg.get("conversation_id", ""))
                envelope_json = msg.get("envelope_json")
                if not conversation_id or envelope_json is None:
                    continue
                envelope_text = envelope_json if isinstance(envelope_json, str) else json.dumps(envelope_json)
                con = db_connect()
                try:
                    ensure_conv_member(con, conversation_id, user_id)
                    member_ids = conv_member_ids(con, conversation_id)
                finally:
                    con.close()
                targets = [uid for uid in member_ids if uid != user_id]
                await ws_manager.broadcast(
                    targets,
                    {"type": "typing:e2ee", "conversation_id": conversation_id, "from": user_id, "envelope_json": envelope_text, "ts": now_ts()},
                )
            elif t == "typing":
                conversation_id = str(msg.get("conversation_id", ""))
                is_typing = bool(msg.get("is_typing", False))
                if not conversation_id:
                    continue
                con = db_connect()
                try:
                    ensure_conv_member(con, conversation_id, user_id)
                    member_ids = conv_member_ids(con, conversation_id)
                finally:
                    con.close()
                targets = [uid for uid in member_ids if uid != user_id]
                await ws_manager.broadcast(
                    targets,
                    {"type": "typing", "conversation_id": conversation_id, "from": user_id, "is_typing": is_typing, "ts": now_ts()},
                )
            elif t == "ping":
                await ws.send_text(json.dumps({"type": "pong", "ts": now_ts()}))
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.remove(user_id, ws)


async def retention_purge_loop() -> None:
    while True:
        try:
            cutoff = now_ts() - (30 * 86400)
            con = db_connect()
            con.execute("DELETE FROM messages WHERE created_at < ?", (cutoff,))
            con.execute("DELETE FROM files WHERE created_at < ?", (cutoff,))
            upload_cutoff = now_ts() - 86400
            old_uploads = con.execute("SELECT id FROM file_uploads WHERE created_at < ?", (upload_cutoff,)).fetchall()
            for r in old_uploads:
                con.execute("DELETE FROM file_upload_chunks WHERE upload_id=?", (str(r["id"]),))
                con.execute("DELETE FROM file_uploads WHERE id=?", (str(r["id"]),))
            con.commit()
            con.close()
        except Exception:
            pass
        await asyncio.sleep(900)
