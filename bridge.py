#!/usr/bin/env python3
"""
technocore-matrix - a Matrix Application Service bridge for technocore.chat rooms,
implementing the shape flop-labs/technocore-chat's own docs/interop.md Matrix section
describes.

interop.md: "Matrix bridges third-party networks through an Application Service: you
register a namespace of user ids and room aliases with a homeserver, it pushes events to
you, and you act as any user in your namespace. This is the closest fit of the six, because
Matrix's /sync?since= and this service's ?since=&wait= are the same idea, and puppeting
gives the identity distinction above somewhere natural to live."

What this registers and mints, per interop.md's own instructions:

- **Namespace `@tc_.*` / `#tc_.*`** on the homeserver, via an Application Service
  registration (see `register` subcommand) - this is what makes the homeserver push events
  in that namespace to this bridge instead of handling them itself.
- **One ghost per did:key writer** (`@tc_<fingerprint>:<domain>`), ghosts of the writer
  puppeting technocore.chat's writer into Matrix. Unlike this ecosystem's ActivityPub bridge
  (where a per-writer identity confirmed live does NOT surface in a follower's timeline),
  Matrix's room timeline renders every event's own `sender` distinctly by design - puppeting
  is the standard, load-bearing pattern real Matrix bridges use (IRC, Discord, etc.), not an
  experimental one. Still verify live before trusting this note over what you observe.
- **A single shared ghost for every unsigned writer** (`@tc_anon:<domain>`), with the
  claimed nickname put in the message body - interop.md's "collapse every unsigned writer
  into one shared actor" pattern, mirrored here for the unsigned lane exactly as the
  ActivityPub bridge does.
- The same collapsing in reverse for *inbound*: a real Matrix user's message is written into
  technocore.chat as one signed message under the bridge's own did:key identity, with their
  Matrix id in the body - a Matrix account has no technocore did:key to hold.

**Room topic maps to `/kv/topic/<room>`** (interop.md: "`m.room.topic` maps to
`/kv/topic/<room>`, with `?if=` settling a clobber race") - set once, when this bridge
creates the room, and not fought over afterward.

**No redaction.** interop.md: "Redaction is the one thing not to implement. It promises the
content is gone, and here it is not." A Matrix-side redaction is not mirrored back to
technocore.chat; nothing here would make that safe to claim.

Dependency: only `cryptography` (Ed25519 for the bridge's own technocore did:key identity,
same primitive this ecosystem's other tools already use) - the rest is standard library.
Talks to a homeserver's Application Service + Client-Server APIs directly over HTTP; no
Matrix SDK.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_NAME = "technocore-matrix"
APP_VERSION = "0.1.0"

TECHNOCORE_BASE = "https://technocore.chat"
DEFAULT_HOME = Path.home() / ".technocore-matrix"
DEFAULT_HS_URL = "http://127.0.0.1:8008"
MESSAGE_MAX_CHARS = 4096
POLL_WAIT_SECONDS = 10
DELIVERY_MAX_WORKERS = 8
LARGE_BATCH_WARN_THRESHOLD = 50
DEFAULT_MAX_PER_MINUTE = 10  # see technocore-activitypub's README - the same lesson applies
MAX_TXN_BODY_BYTES = 4_194_304  # 4 MiB - a homeserver transaction can legitimately batch many events
MULTICODEC_ED25519 = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

UA = f"{APP_NAME}/{APP_VERSION}"


class BridgeError(Exception):
    pass


class RateLimiter:
    """Token bucket, `capacity` tokens refilled at `rate_per_minute` per minute - see
    technocore-activitypub's README for why this exists at all (confirmed live there that
    even a moderately-active room floods a follower fast; the same technocore.chat rooms are
    the source here too, so the same limit applies)."""

    def __init__(self, rate_per_minute: float):
        self.rate_per_second = rate_per_minute / 60.0
        self.capacity = max(1.0, rate_per_minute)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def try_take(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.rate_per_second)
            self.last_refill = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True


# =============================================================== bridge's own did:key


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519 + public_bytes)


def sign_message(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")


def load_or_create_ed25519(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o600)
    return key


def did_fingerprint16(did: str) -> str:
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


# =================================================================== technocore.chat client


def technocore_get(base: str, path: str, params: dict | None = None, timeout: float = 15) -> bytes:
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    last_exc: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404 or (exc.code < 500 and exc.code != 429):
                raise
            last_exc = exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_exc = exc
        time.sleep(min(0.5 * (2**attempt), 5))
    raise BridgeError(f"GET {path} failed after retries: {last_exc}")


def technocore_read_room(base: str, room: str, since: int, wait: int = 0) -> dict:
    body = technocore_get(base, f"/r/{room}", {"since": since, "wait": wait, "format": "json"}, timeout=wait + 5)
    return json.loads(body.decode("utf-8"))


def technocore_say_signed(base: str, key: Ed25519PrivateKey, did: str, room: str, text: str) -> int:
    if len(text) > MESSAGE_MAX_CHARS:
        text = text[: MESSAGE_MAX_CHARS - 1] + "…"
    nonce = str(time.time_ns())
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = sign_message(key, payload)
    body = json.dumps({"did": did, "sig": signature, "nonce": nonce, "text": text}).encode("utf-8")
    url = base.rstrip("/") + f"/r/{room}?format=json"
    last_exc: Exception | None = None
    for attempt in range(4):
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json", "User-Agent": UA}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))["posted"]["seq"]
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                raise BridgeError(f"signed write to {room} -> {exc.code} {exc.read().decode('utf-8','replace')}") from exc
            last_exc = exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_exc = exc
        time.sleep(min(0.5 * (2**attempt), 5))
    raise BridgeError(f"signed write to {room} failed after retries: {last_exc}")


def kv_set(base: str, ns: str, key: str, value: str) -> None:
    url = base.rstrip("/") + f"/kv/{ns}/{key}/set/{urllib.parse.quote(value, safe='')}"
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=10):
            pass
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError):
        pass  # best-effort; the topic just won't be set this time, not fatal to the bridge


UNTRUSTED_BANNER_PREFIX = "!! UNTRUSTED CONTENT"


def strip_untrusted_banner(body: str) -> str:
    """A plain /kv/<ns>/<key> read always prepends a warning banner + blank line before the
    value (confirmed live - see technocore-a2a). Not used for writes; kv_set here is
    fire-and-forget and never reads its own value back."""
    if body.startswith(UNTRUSTED_BANNER_PREFIX):
        _, _, rest = body.partition("\n\n")
        return rest.rstrip("\n")
    return body.rstrip("\n")


# ======================================================================== Matrix HTTP client


class MatrixError(Exception):
    pass


def matrix_request(
    hs_url: str, method: str, path: str, token: str, body: dict | None = None, user_id: str | None = None, timeout: float = 15
) -> dict:
    params = {}
    if user_id:
        params["user_id"] = user_id
    url = hs_url.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise MatrixError(f"{method} {path} -> {exc.code} {detail}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise MatrixError(f"{method} {path} failed: {exc}") from exc


def matrix_errcode(exc: MatrixError) -> str | None:
    match = re.search(r'"errcode"\s*:\s*"([^"]+)"', str(exc))
    return match.group(1) if match else None


# ==================================================================================== state


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


class Bridge:
    """All the state one running bridge process needs: the technocore did:key identity
    (inbound writes), the AS/HS tokens, room-name <-> Matrix room-id mappings, which ghosts
    have already been registered/joined (so we don't re-attempt every message), per-room
    cursors, and processed-transaction dedup. Persisted under --home."""

    def __init__(
        self,
        home: Path,
        domain: str,
        base: str,
        hs_url: str,
        as_token: str,
        rooms: list[str],
        max_per_minute: float = DEFAULT_MAX_PER_MINUTE,
    ):
        self.home = home
        self.domain = domain
        self.base = base
        self.hs_url = hs_url
        self.as_token = as_token
        self.rooms = rooms
        self.ed25519_key = load_or_create_ed25519(home / "identity.pem")
        self.did = did_from_private_key(self.ed25519_key)
        self.rooms_path = home / "rooms.json"
        self.room_ids: dict[str, str] = load_json(self.rooms_path, {})  # technocore room -> matrix room id
        self.cursors_path = home / "cursors.json"
        self.cursors: dict[str, int] = load_json(self.cursors_path, {})  # technocore room -> last_seq
        self.ghosts_path = home / "ghosts.json"
        self.registered_ghosts: set[str] = set(load_json(self.ghosts_path, []))  # localparts
        self.joined_path = home / "joined.json"
        self.joined: dict[str, list[str]] = load_json(self.joined_path, {})  # room -> [localpart, ...]
        self.processed_txns_path = home / "processed_txns.json"
        self.processed_txns: collections.OrderedDict[str, bool] = collections.OrderedDict(
            (t, True) for t in load_json(self.processed_txns_path, [])
        )
        self.rate_limiters = {room: RateLimiter(max_per_minute) for room in rooms}
        self.dropped_since_report: dict[str, int] = dict.fromkeys(rooms, 0)
        self.last_drop_report: dict[str, float] = dict.fromkeys(rooms, 0.0)
        self._lock = threading.Lock()
        self.delivery_pool = ThreadPoolExecutor(max_workers=DELIVERY_MAX_WORKERS, thread_name_prefix="deliver")

    def save_rooms(self) -> None:
        save_json(self.rooms_path, self.room_ids)

    def save_cursors(self) -> None:
        save_json(self.cursors_path, self.cursors)

    def save_ghosts(self) -> None:
        save_json(self.ghosts_path, sorted(self.registered_ghosts))

    def save_joined(self) -> None:
        save_json(self.joined_path, self.joined)

    def mark_txn_processed(self, txn_id: str) -> None:
        with self._lock:
            self.processed_txns[txn_id] = True
            while len(self.processed_txns) > 2000:
                self.processed_txns.popitem(last=False)
            save_json(self.processed_txns_path, list(self.processed_txns))

    def was_txn_processed(self, txn_id: str) -> bool:
        return txn_id in self.processed_txns

    # ------------------------------------------------------------------------------ naming

    def ghost_localpart_for_did(self, did: str) -> str:
        return f"tc_{did_fingerprint16(did)}"

    ANON_LOCALPART = "tc_anon"

    def ghost_user_id(self, localpart: str) -> str:
        return f"@{localpart}:{self.domain}"

    def room_alias_localpart(self, room: str) -> str:
        return f"tc_{room}"

    def room_alias(self, room: str) -> str:
        return f"#{self.room_alias_localpart(room)}:{self.domain}"

    def room_from_alias(self, alias: str) -> str | None:
        match = re.match(rf"^#tc_([a-z0-9][a-z0-9_-]{{0,47}}):{re.escape(self.domain)}$", alias)
        return match.group(1) if match else None

    def localpart_from_user_id(self, user_id: str) -> str | None:
        match = re.match(rf"^@(tc_[a-z0-9_-]+):{re.escape(self.domain)}$", user_id)
        return match.group(1) if match else None

    def ghost_for_message(self, message: dict) -> str:
        """The ghost LOCALPART that should send an outbound message - a stable ghost per
        did:key writer, or the shared anon ghost with the nickname folded into the body by
        the caller (interop.md's "collapse every unsigned writer into one shared actor")."""
        from_field = message.get("from", "")
        if from_field.startswith("did:key:"):
            return self.ghost_localpart_for_did(from_field)
        return self.ANON_LOCALPART

    # -------------------------------------------------------------------------- ghost/room setup

    def ensure_ghost(self, localpart: str) -> None:
        """Register the ghost (idempotent: M_USER_IN_USE means it already exists) and give
        it a recognisable display name, once."""
        if localpart in self.registered_ghosts:
            return
        try:
            matrix_request(
                self.hs_url, "POST", "/_matrix/client/v3/register", self.as_token,
                body={"type": "m.login.application_service", "username": localpart},
            )
        except MatrixError as exc:
            if matrix_errcode(exc) != "M_USER_IN_USE":
                raise
        display = f"~{localpart[3:]}" if localpart == self.ANON_LOCALPART else f"technocore {localpart[3:19]}"
        try:
            matrix_request(
                self.hs_url, "PUT", f"/_matrix/client/v3/profile/{self.ghost_user_id(localpart)}/displayname",
                self.as_token, body={"displayname": display}, user_id=self.ghost_user_id(localpart),
            )
        except MatrixError:
            pass  # cosmetic only - never block on it
        with self._lock:
            self.registered_ghosts.add(localpart)
            self.save_ghosts()

    def ensure_room(self, room: str) -> str:
        """Return the Matrix room id for a technocore room, creating it (as this bridge's
        own AS user) the first time - either proactively at startup or on demand when the
        homeserver asks whether #tc_<room>:domain exists (see the `rooms` query handler)."""
        if room in self.room_ids:
            return self.room_ids[room]
        alias = self.room_alias(room)
        try:
            resolved = matrix_request(self.hs_url, "GET", f"/_matrix/client/v3/directory/room/{urllib.parse.quote(alias)}", self.as_token)
            room_id = resolved["room_id"]
        except MatrixError as exc:
            if matrix_errcode(exc) != "M_NOT_FOUND":
                raise
            created = matrix_request(
                self.hs_url, "POST", "/_matrix/client/v3/createRoom", self.as_token,
                body={
                    "room_alias_name": self.room_alias_localpart(room),
                    "name": f"#{room} (technocore.chat, bridged)",
                    "topic": f"Bridged, read-only-in-spirit mirror of the technocore.chat room '{room}'. "
                    "Messages sent here are written back signed under this bridge's own identity.",
                    "preset": "public_chat",
                    "visibility": "public",
                },
            )
            room_id = created["room_id"]
            kv_set(self.base, "topic", room, f"bridged to Matrix: {alias}")
        with self._lock:
            self.room_ids[room] = room_id
            self.save_rooms()
        return room_id

    def ensure_joined(self, room: str, room_id: str, localpart: str) -> None:
        joined_here = self.joined.setdefault(room, [])
        if localpart in joined_here:
            return
        try:
            matrix_request(
                self.hs_url, "POST", f"/_matrix/client/v3/join/{urllib.parse.quote(room_id)}", self.as_token,
                body={}, user_id=self.ghost_user_id(localpart),
            )
        except MatrixError as exc:
            if matrix_errcode(exc) != "M_FORBIDDEN":  # already joined, or some other benign race
                pass
        with self._lock:
            joined_here.append(localpart)
            self.save_joined()


# ========================================================================== outbound: polling


def _format_writer_prefix(message: dict) -> str:
    """technocore.chat's own text-view convention (README: "the text view shows a verified
    writer as <z6Mk...2doK> and everything else as <~nick>") - folded into the body for the
    shared anon ghost; the did:key ghost's own display name already carries this for signed
    writers, so no prefix is added there (Matrix, unlike the ActivityPub bridge's target,
    renders each event's sender distinctly - the whole reason per-writer ghosts are used
    here at all)."""
    from_field = message.get("from", "")
    return f"<~{from_field or 'anon'}> "


def _note_dropped_for_rate_limit(bridge: Bridge, room: str) -> None:
    bridge.dropped_since_report[room] = bridge.dropped_since_report.get(room, 0) + 1
    now = time.monotonic()
    if now - bridge.last_drop_report.get(room, 0.0) >= 60:
        dropped = bridge.dropped_since_report[room]
        print(f"{APP_NAME}: [{room}] rate limit: dropped {dropped} message(s) in the last ~60s", file=sys.stderr)
        bridge.dropped_since_report[room] = 0
        bridge.last_drop_report[room] = now


def outbound_loop(bridge: Bridge, room: str) -> None:
    """One thread per bridged room: the "two loops against one room" shape from interop.md."""
    room_id = bridge.ensure_room(room)
    since = bridge.cursors.get(room, 0)
    while True:
        try:
            view = technocore_read_room(bridge.base, room, since, wait=POLL_WAIT_SECONDS)
        except BridgeError as exc:
            print(f"{APP_NAME}: [{room}] poll error, retrying: {exc}", file=sys.stderr)
            time.sleep(2)
            continue
        messages = view.get("messages", [])
        if len(messages) > LARGE_BATCH_WARN_THRESHOLD:
            print(f"{APP_NAME}: [{room}] {len(messages)} messages in one poll - consider a quieter room", file=sys.stderr)
        for message in messages:
            since = message["seq"]
            if message.get("from") == bridge.did:
                continue  # our own echoed inbound write coming back around - not a foreign post
            if bridge.rate_limiters[room].try_take():
                bridge.delivery_pool.submit(_deliver_message, bridge, room, room_id, message)
            else:
                _note_dropped_for_rate_limit(bridge, room)
        if view.get("last_seq", since) != since:
            since = view["last_seq"]
        bridge.cursors[room] = since
        bridge.save_cursors()


def _deliver_message(bridge: Bridge, room: str, room_id: str, message: dict) -> None:
    localpart = bridge.ghost_for_message(message)
    text = message.get("text", "")
    if localpart == bridge.ANON_LOCALPART:
        text = _format_writer_prefix(message) + text
    try:
        bridge.ensure_ghost(localpart)
        bridge.ensure_joined(room, room_id, localpart)
        txn_id = f"technocore-{room}-{message['seq']}"  # derived from the record, not random -
        # interop.md: "so a crash replays into the same id rather than duplicating"
        matrix_request(
            bridge.hs_url, "PUT", f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id)}/send/m.room.message/{txn_id}",
            bridge.as_token, body={"msgtype": "m.text", "body": text}, user_id=bridge.ghost_user_id(localpart),
        )
    except MatrixError as exc:
        print(f"{APP_NAME}: [{room}] delivery of seq {message['seq']} failed: {exc}", file=sys.stderr)


# ============================================================================ inbound: events


def _handle_transaction_events(bridge: Bridge, events: list[dict]) -> None:
    for event in events:
        if event.get("type") != "m.room.message":
            continue
        sender = event.get("sender", "")
        if bridge.localpart_from_user_id(sender) is not None:
            continue  # one of our own ghosts echoing back - not a real Matrix user's message
        room_id = event.get("room_id")
        room = next((r for r, rid in bridge.room_ids.items() if rid == room_id), None)
        if room is None:
            continue  # an event in a room we don't recognise as one of ours
        content = event.get("content", {})
        # interop.md: "take body (never formatted_body)" - body is always plain text per the
        # Matrix spec, unlike ActivityPub's HTML content, so no stripping is needed here.
        text = content.get("body", "")
        if not text:
            continue
        message = f"{sender} (via Matrix): {text}"  # sender is already "@user:domain" - no extra @
        try:
            technocore_say_signed(bridge.base, bridge.ed25519_key, bridge.did, room, message)
            print(f"{APP_NAME}: [{room}] bridged message from {sender}", file=sys.stderr)
        except BridgeError as exc:
            print(f"{APP_NAME}: could not bridge message from {sender} into {room}: {exc}", file=sys.stderr)


# ========================================================================================= AS server


class Handler(BaseHTTPRequestHandler):
    bridge: Bridge = None  # set by main() before serving
    hs_token: str = ""

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply_json(self, status: int, obj: dict) -> None:
        self._reply(status, json.dumps(obj).encode("utf-8"))

    def _authorized(self, query: dict) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):] == self.hs_token
        return (query.get("access_token") or [""])[0] == self.hs_token

    def do_GET(self) -> None:  # noqa: N802
        bridge = self.bridge
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authorized(query):
            self._reply(401, b'{"errcode":"M_UNAUTHORIZED"}')
            return
        match = re.match(r"^/_matrix/app/(?:v1/)?users/([^/]+)$", parsed.path)
        if match:
            user_id = urllib.parse.unquote(match.group(1))
            exists = bridge.localpart_from_user_id(user_id) is not None
            self._reply_json(200 if exists else 404, {} if exists else {"errcode": "M_NOT_FOUND"})
            return
        match = re.match(r"^/_matrix/app/(?:v1/)?rooms/([^/]+)$", parsed.path)
        if match:
            alias = urllib.parse.unquote(match.group(1))
            room = bridge.room_from_alias(alias)
            if room is None or room not in bridge.rooms:
                self._reply_json(404, {"errcode": "M_NOT_FOUND"})
                return
            try:
                bridge.ensure_room(room)
            except MatrixError as exc:
                print(f"{APP_NAME}: could not provision {alias}: {exc}", file=sys.stderr)
                self._reply_json(500, {"errcode": "M_UNKNOWN"})
                return
            self._reply_json(200, {})
            return
        self._reply(404, b'{"errcode":"M_NOT_FOUND"}')

    def do_PUT(self) -> None:  # noqa: N802
        bridge = self.bridge
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authorized(query):
            self._reply(401, b'{"errcode":"M_UNAUTHORIZED"}')
            return
        match = re.match(r"^/_matrix/app/(?:v1/)?transactions/([^/]+)$", parsed.path)
        if not match:
            self._reply(404, b'{"errcode":"M_NOT_FOUND"}')
            return
        txn_id = urllib.parse.unquote(match.group(1))
        if bridge.was_txn_processed(txn_id):
            self._reply_json(200, {})  # already handled - HS retried, per the spec's at-least-once delivery
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._reply(400, b'{"errcode":"M_BAD_JSON"}')
            return
        if length < 0 or length > MAX_TXN_BODY_BYTES:
            self._reply(413, b'{"errcode":"M_TOO_LARGE"}')
            return
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._reply(400, b'{"errcode":"M_BAD_JSON"}')
            return
        events = payload.get("events", [])
        threading.Thread(target=_handle_transaction_events, args=(bridge, events), daemon=True).start()
        bridge.mark_txn_processed(txn_id)
        self._reply_json(200, {})


# ========================================================================================= CLI


AS_ID = "technocore-matrix-bridge"


def _tokens_path(home: Path) -> Path:
    return home / "as_tokens.json"


def load_or_create_tokens(home: Path) -> tuple[str, str]:
    path = _tokens_path(home)
    data = load_json(path, None)
    if data is not None and "as_token" in data and "hs_token" in data:
        return data["as_token"], data["hs_token"]
    as_token, hs_token = secrets.token_hex(32), secrets.token_hex(32)
    save_json(path, {"as_token": as_token, "hs_token": hs_token})
    return as_token, hs_token


def cmd_register(args: argparse.Namespace) -> int:
    """Prints the Application Service registration YAML a homeserver ADMIN installs
    (`app_service_config_files` in homeserver.yaml, then restart) - this is the one step
    only the homeserver operator can do; everything else this tool does itself."""
    as_token, hs_token = load_or_create_tokens(args.home)
    yaml_text = f"""id: {AS_ID}
url: http://{args.as_host}:{args.as_port}
as_token: "{as_token}"
hs_token: "{hs_token}"
sender_localpart: tcbridge
namespaces:
  users:
    - exclusive: true
      regex: "@tc_.*"
  aliases:
    - exclusive: true
      regex: "#tc_.*"
  rooms: []
rate_limited: false
"""
    print(yaml_text)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
    if not rooms:
        print(f"{APP_NAME}: --rooms must name at least one room", file=sys.stderr)
        return 1
    as_token, hs_token = load_or_create_tokens(args.home)
    bridge = Bridge(args.home, args.domain, args.base, args.hs_url, as_token, rooms, max_per_minute=args.max_per_minute)
    print(f"{APP_NAME}: technocore did={bridge.did}", file=sys.stderr)
    print(f"{APP_NAME}: domain={args.domain}", file=sys.stderr)
    for room in rooms:
        print(f"{APP_NAME}: bridging '{room}' as {bridge.room_alias(room)}", file=sys.stderr)
        try:
            bridge.ensure_room(room)
        except MatrixError as exc:
            print(f"{APP_NAME}: could not provision {room} at startup, will retry via room query: {exc}", file=sys.stderr)

    Handler.bridge = bridge
    Handler.hs_token = hs_token
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    for room in rooms:
        threading.Thread(target=outbound_loop, args=(bridge, room), daemon=True).start()
    print(f"{APP_NAME}: listening on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        bridge.delivery_pool.shutdown(wait=False, cancel_futures=True)
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    key = load_or_create_ed25519(args.home / "identity.pem")
    print(f"technocore did: {did_from_private_key(key)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=__doc__.strip().splitlines()[0])
    parser.add_argument("--home", type=Path, default=DEFAULT_HOME)
    parser.add_argument("--base", default=TECHNOCORE_BASE, help="technocore.chat base URL")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register", help="print the Application Service registration YAML for a homeserver admin to install")
    p.add_argument("--as-host", default="127.0.0.1", help="host the homeserver should reach this bridge at")
    p.add_argument("--as-port", type=int, default=8739)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("serve", help="run the bridge: AS HTTP server + one outbound poll loop per room")
    p.add_argument("--domain", required=True, help="the Matrix server_name this bridge's homeserver runs as")
    p.add_argument("--hs-url", default=DEFAULT_HS_URL, help="the homeserver's Client-Server API base URL")
    p.add_argument("--rooms", required=True, help="comma-separated technocore.chat room names to bridge")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8739)
    p.add_argument(
        "--max-per-minute", type=float, default=DEFAULT_MAX_PER_MINUTE,
        help=f"cap on delivered messages per room per minute - excess are dropped, not queued (default {DEFAULT_MAX_PER_MINUTE})",
    )
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("identity", help="show the bridge's technocore did:key (used for inbound writes)")
    p.set_defaults(func=cmd_identity)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
