"""
FreeFire Player Info API — OB55 (Direct JWT)
Static per-region JWTs. No uid/password. No external JWT API.
Rotate tokens at runtime via POST /update-token.
"""

import asyncio
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

import httpx
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from google.protobuf import json_format
from Crypto.Cipher import AES

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

# FF tokens live ~7 hours. We treat them as fresh for 6h to be safe.
TOKEN_TTL = 25200
TOKEN_SAFETY = 3600

FF_REQUEST_TIMEOUT = 15.0

# Admin key for /update-token. Set via env in production.
ADMIN_KEY = os.environ.get("FF_ADMIN_KEY", "change-me-in-env")

# ============= Region tokens (edit here or POST /update-token) =============
REGION_TOKENS: dict[str, dict[str, str]] = {
    "BD":  {"jwt": "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxOTExNTU3MTA0OCwibmlja25hbWUiOiJkUVJIVTl1NTFZSGpnWWJuMHFhSzBMRGYiLCJub3RpX3JlZ2lvbiI6IkJEIiwibG9ja19yZWdpb24iOiJCRCIsImV4dGVybmFsX2lkIjoiMzIyNWQyYjFkNzkxY2YyNzE1OGM3ZmMwZGJkYWQwOTAiLCJleHRlcm5hbF90eXBlIjo0LCJwbGF0X2lkIjoxLCJjbGllbnRfdmVyc2lvbiI6IjIuMTMzLjkiLCJjbGllbnRfdmVyc2lvbl9jb2RlIjoiMjAxOTExODUyNyIsImVtdWxhdG9yX3Njb3JlIjowLCJpc19lbXVsYXRvciI6ZmFsc2UsImNvdW50cnlfY29kZSI6IkJEIiwiZXh0ZXJuYWxfdWlkIjo4NDQzNTM3Mzk3LCJyZWdfYXZhdGFyIjoxMDIwMDAwMDcsInNvdXJjZSI6MCwibG9ja19yZWdpb25fdGltZSI6MCwiY2xpZW50X3R5cGUiOjIsInNpZ25hdHVyZV9tZDUiOiIxYWM0YjgwZWNmMDQ3OGE0NDIwM2JmOGZhYzYxMjBmNSIsInVzaW5nX3ZlcnNpb24iOjIsInJlbGVhc2VfY2hhbm5lbCI6ImFuZHJvaWRfbWF4IiwicmVsZWFzZV92ZXJzaW9uIjoiT0I1NSIsImV4cCI6MTc5NDU3MDk0OX0.6VWt2un4mzvlNMH0rB6djZHL_fGxu8sc7mToSk-AQfE"},   # <-- paste BD JWT here
    "IND": {"jwt": ""},   # <-- paste IND JWT here
    "BR":  {"jwt": ""},   # <-- paste BR JWT here
}

REGION_CONFIG = {
    "BD":  {"server_url": "https://clientbp.ppmainecoonghj.com",   "release_version": "OB55"},
    "IND": {"server_url": "https://client.ind.freefiremobile.com", "release_version": "OB55"},
    "BR":  {"server_url": "https://client.us.freefiremobile.com",  "release_version": "OB55"},
}

REGION_PRIORITY = ["BD", "IND", "BR"]

# ============= AES helpers =============
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

# ============= App =============
app = Flask(__name__)
CORS(app)

START_TIME = time.time()

# ============= Token cache =============
# {region: {"jwt": str, "loaded_at": float, "expires_at": float}}
_token_cache: dict[str, dict] = {}

def _normalize_jwt(raw: str) -> str:
    """Strip 'Bearer ' prefix if present, return bare token."""
    if not raw:
        return ""
    raw = raw.strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw

def _install_token(region: str, raw_jwt: str) -> bool:
    """Cache a JWT for a region. Returns True if installed."""
    jwt = _normalize_jwt(raw_jwt)
    if not jwt:
        _token_cache.pop(region, None)
        return False
    now = time.time()
    _token_cache[region] = {
        "jwt": jwt,
        "loaded_at": now,
        "expires_at": now + TOKEN_TTL,
    }
    log.info("Token installed for %s (ttl %ss)", region, TOKEN_TTL)
    return True

def _bootstrap_tokens() -> None:
    """Load initial tokens from REGION_TOKENS on startup."""
    for region, entry in REGION_TOKENS.items():
        jwt = entry.get("jwt", "")
        if jwt:
            _install_token(region, jwt)
        else:
            log.warning("No initial JWT for region %s", region)

def _get_cached_jwt(region: str) -> Optional[str]:
    """Return a fresh cached JWT, or None if missing/stale."""
    entry = _token_cache.get(region)
    if not entry:
        return None
    if entry["expires_at"] <= time.time() + TOKEN_SAFETY:
        return None
    return entry["jwt"]

def _invalidate(region: str) -> None:
    if region in _token_cache:
        log.info("Invalidating cached token for %s", region)
        _token_cache.pop(region, None)

# ============= Core FF call =============
async def _call_player_show(uid: int, region: str) -> Optional[dict]:
    jwt = _get_cached_jwt(region)
    if not jwt:
        log.debug("No fresh JWT for %s, skipping", region)
        return None

    cfg = REGION_CONFIG[region]
    server_url = cfg["server_url"]

    payload = _serialize({"a": uid, "b": "7"}, main_pb2.GetPlayerPersonalShow())
    enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": cfg["release_version"],
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
        # Token dead. Drop it so /status reflects reality.
        _invalidate(region)
        log.warning("FF returned %s for %s — token invalidated", resp.status_code, region)
        return None

    if resp.status_code != 200:
        log.warning("FF non-200 [%s]: %s", region, resp.status_code)
        return None

    info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
    info.ParseFromString(resp.content)
    result = json.loads(json_format.MessageToJson(info))

    if not result.get("basicInfo"):
        return None

    is_banned = bool(result.get("isBanned", False))
    result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
    result["region"] = region
    return result

async def get_account(uid: int, prefer_region: Optional[str] = None) -> Optional[dict]:
    """Race regions with installed tokens. First success wins."""
    # Only regions that actually have a token
    order = [r for r in REGION_PRIORITY if _get_cached_jwt(r)]

    if prefer_region and prefer_region in order:
        order.remove(prefer_region)
        order.insert(0, prefer_region)

    if not order:
        log.error("No valid tokens installed for any region")
        return None

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
    prefer = (request.args.get("region") or "").upper() or None

    if not uid:
        return jsonify({"success": False, "error": "UID required"}), 400

    try:
        uid_int = int(uid)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid UID"}), 400

    t0 = time.time()
    try:
        data = asyncio.run(get_account(uid_int, prefer_region=prefer))
    except Exception as e:
        log.exception("Unhandled error for UID %s", uid)
        return jsonify({"success": False, "error": str(e)}), 500

    elapsed_ms = int((time.time() - t0) * 1000)

    if not data:
        return jsonify({
            "success": False,
            "error": "Player not found, or no valid tokens installed",
            "uid": uid,
            "elapsed_ms": elapsed_ms,
        }), 404

    resp = build_response(uid, data)
    resp["elapsed_ms"] = elapsed_ms
    return jsonify(resp)

@app.route("/update-token", methods=["POST"])
def route_update_token():
    """
    Rotate a JWT for a region at runtime.
    Header: X-Admin-Key: <FF_ADMIN_KEY>
    Body: {"region": "BD", "jwt": "eyJ..."}
    """
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    region = (body.get("region") or "").upper()
    jwt = body.get("jwt", "")

    if region not in REGION_CONFIG:
        return jsonify({
            "success": False,
            "error": f"region must be one of {list(REGION_CONFIG)}",
        }), 400

    if not _install_token(region, jwt):
        return jsonify({"success": False, "error": "empty jwt"}), 400

    # Also persist into the in-memory dict so /status stays consistent
    REGION_TOKENS[region]["jwt"] = _normalize_jwt(jwt)

    return jsonify({"success": True, "region": region, "installed": True})

@app.route("/clear-token", methods=["POST"])
def route_clear_token():
    """Wipe a region's cached token. Same admin key required."""
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    region = (body.get("region") or "").upper()
    if region not in REGION_CONFIG:
        return jsonify({"success": False, "error": "invalid region"}), 400

    _invalidate(region)
    REGION_TOKENS[region]["jwt"] = ""
    return jsonify({"success": True, "region": region, "cleared": True})

@app.route("/")
def route_home():
    return jsonify({
        "status": "running",
        "version": RELEASEVERSION,
        "auth": "direct-jwt",
        "endpoint": "/info?uid=UID[&region=BD|IND|BR]",
        "example": "/info?uid=2084018498",
        "regions_loaded": [r for r in REGION_PRIORITY if _get_cached_jwt(r)],
        "uptime_s": int(time.time() - START_TIME),
        "credit": "@NAJMI_ADMIN_2",
    })

@app.route("/status")
def route_status():
    now = time.time()
    tokens = {}
    for region in REGION_PRIORITY:
        entry = _token_cache.get(region)
        if entry:
            remaining = entry["expires_at"] - now
            tokens[region] = {
                "installed": True,
                "fresh": remaining > TOKEN_SAFETY,
                "expires_in_hours": round(remaining / 3600, 2),
                "loaded_at": datetime.fromtimestamp(entry["loaded_at"]).isoformat(),
            }
        else:
            tokens[region] = {"installed": False}
    return jsonify({
        "cached_tokens": sum(1 for t in tokens.values() if t.get("installed")),
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

# ============= Bootstrap =============
_bootstrap_tokens()

# ============= Entry =============
if __name__ == "__main__":
    log.info("Starting FF API — %s, direct-JWT auth", RELEASEVERSION)
    app.run(host="0.0.0.0", port=5004, debug=False, threaded=True)
