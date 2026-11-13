"""
FreeFire Player Info API — OB55 (JWT-only)
All auth via JWT API. No uid/password backup path.
"""

import asyncio
import logging
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

import httpx
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from google.protobuf import json_format

# ============= Proto imports =============
try:
    import main_pb2, AccountPersonalShow_pb2
    print("✅ Proto files imported successfully")
except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)

# ============= Logging =============
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("ff-api")

# ============= Config =============
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"

JWT_API_BASE = "https://najmiob55jwttokengen.vercel.app/token"  # JWT API BY JAHID X EMPIRE

REGION_CONFIG = {
    "BD":  {"server_url": "https://clientbp.ppmainecoonghj.com",      "release_version": "OB55"},
    "IND": {"server_url": "https://client.ind.freefiremobile.com",    "release_version": "OB55"},
    "BR":  {"server_url": "https://client.us.freefiremobile.com",     "release_version": "OB55"},
}

REGION_PRIORITY = ["BD", "IND", "BR"]

DEFAULT_REGION = "BD"

TOKEN_TTL = 25200               # 7 hours
JWT_FETCH_TIMEOUT = 10.0
FF_REQUEST_TIMEOUT = 15.0
JWT_FETCH_RETRIES = 3

# ============= App =============
app = Flask(__name__)
CORS(app)

START_TIME = time.time()

# ============= Token cache =============
_token_cache: dict[str, dict] = {}

# ============= JWT Fetch =============
async def _fetch_jwt_once(region: str, client: httpx.AsyncClient) -> Optional[dict]:
    """
    One JWT API request. Returns token dict or None.
    The JWT API takes region implicitly via endpoint (uid/pass baked into API key).
    Here we pass region as a hint only — the API decides.
    """
    params = {"region": region}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    try:
        resp = await client.get(
            JWT_API_BASE, params=params, headers=headers,
            timeout=JWT_FETCH_TIMEOUT,
        )
    except httpx.HTTPError as e:
        log.warning("JWT fetch transport error [%s]: %s", region, e)
        return None

    if resp.status_code != 200:
        log.warning("JWT fetch non-200 [%s]: %s", region, resp.status_code)
        return None

    try:
        data = resp.json()
    except Exception as e:
        log.warning("JWT fetch bad JSON [%s]: %s", region, e)
        return None

    token = data.get("token")
    if not token:
        log.warning("JWT fetch missing token [%s]", region)
        return None

    api_region = data.get("region") or region
    cfg = REGION_CONFIG.get(api_region, REGION_CONFIG[DEFAULT_REGION])

    return {
        "token": f"Bearer {token}",
        "region": api_region,
        "server_url": cfg["server_url"],
        "release_version": cfg["release_version"],
        "expires_at": time.time() + TOKEN_TTL,
    }

async def _fetch_jwt_with_retry(region: str) -> Optional[dict]:
    """JWT fetch with exponential backoff."""
    async with httpx.AsyncClient() as client:
        for attempt in range(JWT_FETCH_RETRIES):
            result = await _fetch_jwt_once(region, client)
            if result:
                return result
            if attempt < JWT_FETCH_RETRIES - 1:
                await asyncio.sleep(0.5 * (2 ** attempt))
    return None

async def get_token(region: str) -> Optional[dict]:
    """Cache-first token getter."""
    cached = _token_cache.get(region)
    if cached and cached["expires_at"] > time.time() + 60:  # 60s safety margin
        return cached

    fresh = await _fetch_jwt_with_retry(region)
    if fresh:
        _token_cache[region] = fresh
    return fresh

def invalidate_token(region: str) -> None:
    _token_cache.pop(region, None)

# ============= AES helpers =============
from Crypto.Cipher import AES

MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
MAIN_IV  = b"6oyZDr22E3ychjM%"

def _pad(data: bytes) -> bytes:
    n = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([n] * n)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pad(plaintext))

def _serialize(json_dict: dict, proto_msg) -> bytes:
    json_format.ParseDict(json_dict, proto_msg)
    return proto_msg.SerializeToString()

# ============= Core API call =============
async def _call_player_show(uid: int, region: str) -> Optional[dict]:
    """Single attempt against one region."""
    token_info = await get_token(region)
    if not token_info:
        return None

    actual_region = token_info["region"]
    token = token_info["token"]
    server_url = token_info["server_url"]

    payload = _serialize({"a": uid, "b": "7"}, main_pb2.GetPlayerPersonalShow())
    enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Authorization": token,
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": token_info["release_version"],
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server_url}/GetPlayerPersonalShow",
                content=enc, headers=headers, timeout=FF_REQUEST_TIMEOUT,
            )
    except httpx.HTTPError as e:
        log.warning("FF request transport error [%s]: %s", region, e)
        return None

    if resp.status_code in (401, 403):
        # Token dead — nuke it, let next call refresh
        invalidate_token(region)
        return None

    if resp.status_code != 200:
        log.warning("FF request non-200 [%s]: %s", region, resp.status_code)
        return None

    info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
    info.ParseFromString(resp.content)
    result = json.loads(json_format.MessageToJson(info))

    if not result.get("basicInfo"):
        return None

    is_banned = bool(result.get("isBanned", False))
    result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
    result["region"] = actual_region
    return result

async def get_account(uid: int, prefer_region: Optional[str] = None) -> Optional[dict]:
    """Race regions; first success wins. `prefer_region` gets a head start."""
    order = list(REGION_PRIORITY)
    if prefer_region and prefer_region in order:
        order.remove(prefer_region)
        order.insert(0, prefer_region)

    tasks = [asyncio.create_task(_call_player_show(uid, r)) for r in order]

    try:
        for coro in asyncio.as_completed(tasks, timeout=25):
            try:
                data = await coro
            except Exception:
                continue
            if data:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                return data
    except asyncio.TimeoutError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
    return None

# ============= Lookups =============
def get_item_name(item_id) -> str:
    if not item_id or item_id in ("0", 0):
        return "N/A"
    try:
        import requests
        r = requests.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=3)
        if r.status_code == 200:
            return r.json().get("name", str(item_id))
    except Exception:
        pass
    return str(item_id)

def get_rank_name(rp) -> str:
    try:
        rp = int(rp)
    except Exception:
        return "N/A"
    tiers = [
        (100, "Bronze II"), (200, "Bronze III"), (300, "Silver I"),
        (400, "Silver II"), (500, "Silver III"), (600, "Gold I"),
        (700, "Gold II"), (800, "Gold III"), (900, "Platinum I"),
        (1000, "Platinum II"), (1100, "Platinum III"), (1200, "Diamond I"),
        (1300, "Diamond II"), (1400, "Diamond III"), (1500, "Heroic"),
        (2000, "Master"),
    ]
    if rp == 0:
        return "Bronze I"
    for threshold, name in tiers:
        if rp < threshold:
            return name
    return "Grandmaster"

def ts_to_bst(ts) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=6)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except Exception:
        return "N/A"

# ============= Response shaper =============
def build_response(uid: str, data: dict) -> dict:
    basic   = data.get("basicInfo", {})
    clan    = data.get("clanBasicInfo", {})
    social  = data.get("socialInfo", {})
    pet     = data.get("petInfo", {})
    captain = data.get("captainBasicInfo", {})
    credit  = data.get("creditScoreInfo", {})

    prime_level = "N/A"
    prime_data = basic.get("primeLevel")
    if isinstance(prime_data, dict):
        prime_level = prime_data.get("level", "N/A")
    elif prime_data is not None:
        prime_level = str(prime_data)

    return {
        "status": "success",
        "server_used": data.get("region", "Unknown"),
        "BanStatus": data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "CelebrityStatus": "Yes" if basic.get("showBrRank") else "No",
            "Title": get_item_name(basic.get("title", "0")),
            "Signature": social.get("signature", "N/A"),
        },
        "ActivityInformation": {
            "MostRecentOB": basic.get("releaseVersion", "N/A"),
            "BooyahPass": "Yes" if basic.get("hasElitePass") else "No",
            "CurrentBpBadges": basic.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(basic.get("rankingPoints", 0)),
            "BRPoints": basic.get("rankingPoints", 0),
            "ShowBRRank": "True" if basic.get("showBrRank") else "False",
            "ShowCSRank": "True" if basic.get("showCsRank") else "False",
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0)),
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A"),
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("isSelected") else "No",
            "PetNick": pet.get("name", "N/A"),
            "PetType": get_item_name(pet.get("id", "0")),
            "PetSkill": get_item_name(pet.get("selectedSkillId", "0")),
            "PetSkin": get_item_name(pet.get("skinId", "0")),
            "PetExp": pet.get("exp", "N/A"),
            "PetLevel": pet.get("level", "N/A"),
        },
        "LeaderInformation": {
            "Name": captain.get("nickname", "N/A"),
            "UID": captain.get("accountId", "N/A"),
            "Level": captain.get("level", "N/A"),
            "Region": captain.get("region", "N/A"),
            "BooyahPass": "Yes" if captain.get("hasElitePass") else "No",
            "CreatedAt": ts_to_bst(captain.get("createAt", 0)),
            "LastLogin": ts_to_bst(captain.get("lastLoginAt", 0)),
            "MostRecentOB": captain.get("releaseVersion", "N/A"),
            "Title": get_item_name(captain.get("title", "0")),
            "BpBadges": captain.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(captain.get("rankingPoints", 0)),
            "BRPoints": captain.get("rankingPoints", 0),
        },
    }

# ============= Routes =============
@app.route("/info")
def route_info():
    uid = request.args.get("uid")
    prefer = request.args.get("region", "").upper() or None

    if not uid:
        return jsonify({"success": False, "status": "error", "error": "UID required"}), 400

    try:
        uid_int = int(uid)
    except ValueError:
        return jsonify({"success": False, "status": "error", "error": "Invalid UID"}), 400

    t0 = time.time()
    try:
        data = asyncio.run(get_account(uid_int, prefer_region=prefer))
    except Exception as e:
        log.exception("Unhandled error for UID %s", uid)
        return jsonify({"success": False, "status": "error", "error": str(e)}), 500

    elapsed_ms = int((time.time() - t0) * 1000)

    if not data:
        return jsonify({
            "success": False,
            "status": "error",
            "error": "Player not found on any region",
            "uid": uid,
            "elapsed_ms": elapsed_ms,
        }), 404

    resp = build_response(uid, data)
    resp["elapsed_ms"] = elapsed_ms
    return jsonify(resp)

@app.route("/")
def route_home():
    return jsonify({
        "status": "running",
        "version": RELEASEVERSION,
        "auth": "JWT",
        "endpoint": "/info?uid=UID[&region=BD|IND|BR]",
        "example": "/info?uid=2084018498",
        "priority": " → ".join(REGION_PRIORITY),
        "uptime_s": int(time.time() - START_TIME),
        "credit": "@NAJMI_ADMIN_2",
    })

@app.route("/status")
def route_status():
    now = time.time()
    tokens = {}
    for region, info in _token_cache.items():
        tokens[region] = {
            "region": info["region"],
            "expires_in_hours": round((info["expires_at"] - now) / 3600, 2),
            "expired": info["expires_at"] <= now,
        }
    return jsonify({
        "cached_tokens": len(tokens),
        "tokens": tokens,
        "uptime_s": int(now - START_TIME),
    })

@app.route("/health")
def route_health():
    return jsonify({"ok": True, "uptime_s": int(time.time() - START_TIME)}), 200

@app.errorhandler(404)
def handle_404(_):
    return jsonify({"success": False, "error": "route not found"}), 404

@app.errorhandler(405)
def handle_405(_):
    return jsonify({"success": False, "error": "method not allowed"}), 405

# ============= Entry =============
if __name__ == "__main__":
    log.info("Starting FF API — version %s, JWT auth only", RELEASEVERSION)
    app.run(host="0.0.0.0", port=5004, debug=False, threaded=True)
