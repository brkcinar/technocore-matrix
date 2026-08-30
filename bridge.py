#!/usr/bin/env python3
"""A small, durable Matrix application-service bridge for technocore.chat."""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

APP_NAME = "technocore-matrix"
APP_VERSION = "0.2.0"
TECHNOCORE_BASE = "https://technocore.chat"
DEFAULT_HOME = Path.home() / ".technocore-matrix"
DEFAULT_HS_URL = "http://127.0.0.1:8008"
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
DOMAIN_RE = re.compile(r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]{1,5})?$")
DID_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$")
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
MESSAGE_MAX_CHARS = 4096
MAX_TXN_BODY_BYTES = 4_194_304
MAX_TXN_EVENTS = 1000
MAX_JSON_DEPTH = 64
MAX_ROOMS = 256
LEDGER_LIMIT = 4096
POLL_WAIT_SECONDS = 10
DEFAULT_MAX_PER_MINUTE = 10.0
UA = f"{APP_NAME}/{APP_VERSION}"


class BridgeError(Exception):
    """Fail-closed bridge operation error."""


class RetryableError(BridgeError):
    """An operation the caller should retry."""


class ReplayForkError(BridgeError):
    """A durable identifier was reused for different content."""


class InvalidTransactionError(BridgeError):
    """A malformed Application Service transaction that must not be retried."""


class MatrixError(BridgeError):
    def __init__(self, message: str, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def validate_room(room: str) -> str:
    if not isinstance(room, str) or ROOM_RE.fullmatch(room) is None:
        raise ValueError(f"invalid technocore room name: {room!r}")
    return room


def validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or DOMAIN_RE.fullmatch(domain) is None:
        raise ValueError(f"invalid Matrix domain: {domain!r}")
    host, sep, port = domain.rpartition(":")
    if sep and port.isdigit() and int(port) > 65535:
        raise ValueError(f"invalid Matrix domain port: {domain!r}")
    return domain


def validate_base_url(value: str, name: str = "URL") -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"invalid {name}: {value!r}")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError(f"{name} must be an HTTP(S) origin without a path")
    return value.rstrip("/")


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58[remainder] + encoded
    return "1" * zeroes + encoded


def base58btc_decode(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in BASE58:
            raise ValueError("invalid base58btc")
        number = number * 58 + BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def valid_ed25519_did(did: object) -> bool:
    if not isinstance(did, str) or DID_RE.fullmatch(did) is None:
        return False
    try:
        decoded = base58btc_decode(did[9:])
    except ValueError:
        return False
    return decoded.startswith(MULTICODEC_ED25519) and len(decoded) == 34 and (
        "did:key:z" + base58btc_encode(decoded) == did
    )


def verified_record_did(room: str, message: dict) -> str | None:
    did, nonce, signature, text = (
        message.get("from"), message.get("nonce"), message.get("sig"), message.get("text")
    )
    if not valid_ed25519_did(did) or not isinstance(nonce, int) or isinstance(nonce, bool):
        return None
    if nonce < 1 or nonce >= 10**19 or not isinstance(signature, str) or len(signature) != 86:
        return None
    if not isinstance(text, str):
        return None
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        if len(raw_signature) != 64:
            return None
        if base64.urlsafe_b64encode(raw_signature).decode().rstrip("=") != signature:
            return None
        public_bytes = base58btc_decode(did[9:])[2:]
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            raw_signature, f"{room}|{nonce}|{text}".encode()
        )
    except (UnicodeError, ValueError, InvalidSignature):
        return None
    return did


def did_from_private_key(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519 + raw)


def did_fingerprint16(did: str) -> str:
    if not valid_ed25519_did(did):
        raise ValueError("not a canonical Ed25519 did:key")
    return hashlib.sha256(did.encode()).hexdigest()[:16]


def sign_message(key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")


def ensure_private_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = home.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise BridgeError(f"bridge home is not a real directory: {home}")
    home.chmod(0o700)


def atomic_write(path: Path, data: bytes) -> None:
    ensure_private_home(path.parent)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BridgeError(f"corrupt state file {path}") from exc


def save_json(path: Path, data) -> None:
    atomic_write(path, (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode())


def require_regular_file(path: Path, missing_ok: bool = False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise BridgeError(f"missing sensitive file {path}")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise BridgeError(f"sensitive path is not a regular file: {path}")
    return True


@contextlib.contextmanager
def creation_lock(path: Path):
    lock_path = path.parent / ("." + path.name + ".lock")
    if require_regular_file(lock_path, missing_ok=True):
        flags = os.O_RDWR
    else:
        flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise BridgeError(f"cannot securely open creation lock {lock_path}") from exc
    stream = os.fdopen(descriptor, "a+", encoding="utf-8")
    os.fchmod(stream.fileno(), 0o600)
    try:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(stream, fcntl.LOCK_UN)
        stream.close()


def load_or_create_ed25519(path: Path) -> Ed25519PrivateKey:
    ensure_private_home(path.parent)
    with creation_lock(path):
        if require_regular_file(path, missing_ok=True):
            path.chmod(0o600)
            try:
                key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            except Exception as exc:
                raise BridgeError(f"invalid identity file {path}") from exc
            if not isinstance(key, Ed25519PrivateKey):
                raise BridgeError("identity is not an Ed25519 private key")
            return key
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        atomic_write(path, raw)
        return key


def load_or_create_tokens(home: Path) -> tuple[str, str]:
    ensure_private_home(home)
    path = home / "as_tokens.json"
    with creation_lock(path):
        if require_regular_file(path, missing_ok=True):
            path.chmod(0o600)
            data = load_json(path)
            if not isinstance(data, dict) or not all(
                isinstance(data.get(k), str) and len(data[k]) >= 32
                for k in ("as_token", "hs_token")
            ):
                raise BridgeError(f"invalid token state {path}")
            return data["as_token"], data["hs_token"]
        data = {"as_token": secrets.token_hex(32), "hs_token": secrets.token_hex(32)}
        save_json(path, data)
        return data["as_token"], data["hs_token"]


def _retry_after(exc: urllib.error.HTTPError, attempt: int) -> float:
    value = exc.headers.get("Retry-After") if exc.headers else None
    try:
        return min(max(float(value), 0.0), 30.0)
    except (TypeError, ValueError):
        return min(0.25 * (2**attempt), 4.0)


def _http_json(request: urllib.request.Request, timeout: float = 15, attempts: int = 4) -> dict:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                value = json.loads(raw.decode()) if raw else {}
                if not isinstance(value, dict):
                    raise BridgeError("HTTP response is not a JSON object")
                return value
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or exc.code >= 500
            if not retryable:
                detail = exc.read(2048).decode("utf-8", "replace")
                raise MatrixError(f"HTTP {exc.code}: {detail}", exc.code, False) from exc
            last = exc
            if attempt + 1 < attempts:
                time.sleep(_retry_after(exc, attempt))
        except (
            urllib.error.URLError, OSError, TimeoutError, UnicodeError,
            json.JSONDecodeError, RecursionError,
        ) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(min(0.25 * (2**attempt), 4))
    raise MatrixError(f"request failed after retries: {last}", retryable=True)


def matrix_request(
    hs_url: str, method: str, path: str, token: str, body: dict | None = None,
    user_id: str | None = None, timeout: float = 15,
) -> dict:
    url = hs_url.rstrip("/") + path
    if user_id:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode({"user_id": user_id})
    request = urllib.request.Request(
        url, method=method, data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": UA},
    )
    return _http_json(request, timeout)


def matrix_errcode(exc: MatrixError) -> str | None:
    match = re.search(r'"errcode"\s*:\s*"([^"]+)"', str(exc))
    return match.group(1) if match else None


def technocore_get(base: str, path: str, params: dict | None = None, timeout: float = 15) -> bytes:
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    last: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code != 429 and exc.code < 500:
                raise
            last = exc
            if attempt < 3:
                time.sleep(_retry_after(exc, attempt))
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
            if attempt < 3:
                time.sleep(min(.25 * (2**attempt), 4))
    raise RetryableError(f"GET {path} failed after retries: {last}")


def technocore_read_room(base: str, room: str, since: int | None = None, wait: int = 0) -> dict:
    params: dict[str, object] = {"format": "json", "limit": 200, "n": secrets.token_hex(8)}
    if since is not None:
        params.update({"since": since, "wait": wait})
    try:
        value = json.loads(technocore_get(base, f"/r/{room}", params, wait + 15).decode())
    except urllib.error.HTTPError as exc:
        raise BridgeError(f"room read permanently failed: HTTP {exc.code}") from exc
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise BridgeError("malformed technocore room response") from exc
    if not isinstance(value, dict):
        raise BridgeError("malformed technocore room response")
    return value


def strip_untrusted_banner(body: str) -> str:
    if body.startswith("!! UNTRUSTED CONTENT"):
        return body.partition("\n\n")[2].rstrip("\n")
    return body.rstrip("\n")


def kv_get(base: str, namespace: str, key: str) -> str | None:
    try:
        return strip_untrusted_banner(
            technocore_get(base, f"/kv/{namespace}/{key}", {"n": secrets.token_hex(8)}).decode()
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RetryableError(f"note read failed: HTTP {exc.code}") from exc
    except UnicodeError as exc:
        raise RetryableError("malformed technocore note response") from exc


def kv_set_cas(base: str, namespace: str, key: str, value: str, previous: str | None) -> None:
    path = f"/kv/{namespace}/{key}/set/{urllib.parse.quote(value, safe='')}"
    params = {"if_absent": "1"} if previous is None else {"if": previous}
    url = base.rstrip("/") + path + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=15):
            return
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            raise RetryableError("topic compare-and-set conflict") from exc
        raise RetryableError(f"topic write failed: HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise RetryableError("topic write failed") from exc


def sanitize_line(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    cleaned = []
    for char in normalized:
        point = ord(char)
        category = unicodedata.category(char)
        noncharacter = 0xFDD0 <= point <= 0xFDEF or point & 0xFFFF in {0xFFFE, 0xFFFF}
        cleaned.append(" " if category in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"} or noncharacter else char)
    return " ".join("".join(cleaned).split())[:MESSAGE_MAX_CHARS]


def utf8_safe(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeError:
        return False
    return True


def validate_json_depth(value: object) -> None:
    stack = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise InvalidTransactionError("transaction JSON is too deeply nested")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def canonical_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise InvalidTransactionError("transaction cannot be canonically encoded") from exc
    return hashlib.sha256(encoded).hexdigest()


def event_marker(event_id: str) -> str:
    return "[mx:" + hashlib.sha256(event_id.encode()).hexdigest()[:16] + "]"


_nonce_lock = threading.Lock()
_last_nonce = 0


def _fresh_nonce() -> str:
    global _last_nonce
    with _nonce_lock:
        _last_nonce = max(_last_nonce + 1, time.time_ns())
        if _last_nonce >= 10**19:
            raise BridgeError("nonce clock exceeds 19 digits")
        return str(_last_nonce)


def signed_frame_landed(base: str, room: str, did: str, text: str) -> bool:
    view = technocore_read_room(base, room)
    messages = view.get("messages")
    if not isinstance(messages, list):
        raise RetryableError("malformed reconciliation response")
    return any(
        isinstance(message, dict)
        and verified_record_did(room, message) == did
        and message.get("text") == text
        and isinstance(message.get("seq"), int)
        and not isinstance(message.get("seq"), bool)
        for message in messages[-200:]
    )


def technocore_say_signed(
    base: str, key: Ed25519PrivateKey, did: str, room: str, text: str, marker: str | None = None,
) -> int:
    text = sanitize_line(text)
    last: Exception | None = None
    for attempt in range(4):
        nonce = _fresh_nonce()
        signature = sign_message(key, f"{room}|{nonce}|{text}".encode())
        body = json.dumps({"did": did, "sig": signature, "nonce": nonce, "text": text}).encode()
        request = urllib.request.Request(
            base.rstrip("/") + f"/r/{room}?format=json", data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": UA},
        )
        try:
            value = _http_json(request, attempts=1)
            seq = value.get("posted", {}).get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
                raise RetryableError("malformed signed-write response")
            return seq
        except MatrixError as exc:
            last = exc
            if not exc.retryable and exc.status not in {408, 409, 429}:
                raise BridgeError(f"signed write permanently failed: {exc}") from exc
        except RetryableError as exc:
            last = exc
        if marker and signed_frame_landed(base, room, did, text):
            return 0
        if attempt < 3:
            time.sleep(min(.25 * (2**attempt), 4))
    raise RetryableError(f"signed write failed after retries: {last}")


class RateLimiter:
    """Optional non-lossy per-room throttle."""

    def __init__(self, per_minute: float):
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            delay = self.next - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next = time.monotonic() + self.interval


def _valid_localpart(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"tc_(?:anon|bridge|[0-9a-f]{16})", value) is not None


def _validate_loaded_state(state: object) -> dict:
    if not isinstance(state, dict):
        raise BridgeError("state root is not an object")
    expected = {
        "rooms": dict, "cursors": dict, "epochs": dict, "checkpoints": dict,
        "ghosts": list, "joined": dict, "events": dict, "txns": dict,
        "topics": dict, "pending_topics": dict,
    }
    if set(state) - set(expected):
        raise BridgeError("unknown bridge state fields")
    result = {key: state.get(key, kind()) for key, kind in expected.items()}
    if not all(isinstance(result[key], kind) for key, kind in expected.items()):
        raise BridgeError("invalid bridge state collection")
    room_keys = set()
    for collection in ("rooms", "cursors", "epochs", "checkpoints", "joined", "topics"):
        room_keys.update(result[collection])
    if any(not isinstance(room, str) or ROOM_RE.fullmatch(room) is None for room in room_keys):
        raise BridgeError("invalid room key in state")
    if any(
        not isinstance(room_id, str) or len(room_id) > 1024 or not room_id.startswith("!") or
        any(ord(char) < 33 for char in room_id)
        for room_id in result["rooms"].values()
    ):
        raise BridgeError("invalid Matrix room ID in state")
    for collection in ("cursors", "epochs"):
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in result[collection].values()
        ):
            raise BridgeError(f"invalid {collection} state")
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in result["checkpoints"].values()
    ):
        raise BridgeError("invalid checkpoint state")
    for room, cursor in result["cursors"].items():
        if cursor and room not in result["checkpoints"]:
            raise BridgeError(f"nonzero cursor for {room} lacks a checkpoint")
    if (
        any(not _valid_localpart(value) for value in result["ghosts"])
        or len(result["ghosts"]) != len(set(result["ghosts"]))
    ):
        raise BridgeError("invalid ghost state")
    for values in result["joined"].values():
        if (
            not isinstance(values, list) or any(not _valid_localpart(value) for value in values)
            or len(values) != len(set(values))
        ):
            raise BridgeError("invalid joined state")
    for event_id, record in result["events"].items():
        if (
            not isinstance(event_id, str) or not event_id or len(event_id) > 1024
            or not isinstance(record, dict) or set(record) != {"status", "digest"}
            or record["status"] not in {"pending", "done"}
            or not isinstance(record["digest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", record["digest"]) is None
        ):
            raise BridgeError("invalid event ledger")
    if len(result["events"]) > LEDGER_LIMIT:
        raise BridgeError("oversized event ledger")
    if any(
        not isinstance(txn, str) or not txn or len(txn) > 1024
        or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for txn, digest in result["txns"].items()
    ):
        raise BridgeError("invalid transaction ledger")
    if len(result["txns"]) > LEDGER_LIMIT:
        raise BridgeError("invalid transaction ledger bounds")
    if any(not isinstance(topic, str) or len(topic) > MESSAGE_MAX_CHARS for topic in result["topics"].values()):
        raise BridgeError("invalid topic state")
    for event_id, metadata in result["pending_topics"].items():
        if (
            not isinstance(event_id, str) or not isinstance(metadata, dict)
            or set(metadata) != {"room", "desired", "previous"}
            or not isinstance(metadata["room"], str) or ROOM_RE.fullmatch(metadata["room"]) is None
            or not isinstance(metadata["desired"], str)
            or metadata["previous"] is not None and not isinstance(metadata["previous"], str)
            or len(metadata["desired"]) > MESSAGE_MAX_CHARS
            or metadata["previous"] is not None and len(metadata["previous"]) > MESSAGE_MAX_CHARS
            or result["events"].get(event_id, {}).get("status") != "pending"
        ):
            raise BridgeError("invalid pending topic state")
    if len(result["pending_topics"]) > LEDGER_LIMIT:
        raise BridgeError("oversized pending topic state")
    return result


class Bridge:
    ANON_LOCALPART = "tc_anon"

    def __init__(
        self, home: Path, domain: str, base: str, hs_url: str, as_token: str, rooms: list[str],
        max_per_minute: float = DEFAULT_MAX_PER_MINUTE,
    ):
        ensure_private_home(home)
        if (
            not isinstance(max_per_minute, (int, float)) or isinstance(max_per_minute, bool)
            or not math.isfinite(max_per_minute) or max_per_minute < 0
        ):
            raise ValueError("max_per_minute must be finite and nonnegative")
        self.home = home
        self.domain = validate_domain(domain)
        self.base = validate_base_url(base, "technocore URL")
        self.hs_url = validate_base_url(hs_url, "homeserver URL")
        self.as_token = as_token
        self.rooms = [validate_room(r) for r in rooms]
        if len(set(self.rooms)) != len(self.rooms):
            raise ValueError("duplicate room")
        self.ed25519_key = load_or_create_ed25519(home / "identity.pem")
        self.did = did_from_private_key(self.ed25519_key)
        self.state_path = home / "state.json"
        state_exists = require_regular_file(self.state_path, missing_ok=True)
        state = _validate_loaded_state(load_json(self.state_path, {}))
        if state_exists:
            self.state_path.chmod(0o600)
        self.state = {
            "rooms": state.get("rooms", {}), "cursors": state.get("cursors", {}),
            "epochs": state.get("epochs", {}), "checkpoints": state.get("checkpoints", {}),
            "ghosts": state.get("ghosts", []),
            "joined": state.get("joined", {}), "events": state.get("events", {}),
            "txns": state.get("txns", {}), "topics": state.get("topics", {}),
            "pending_topics": state.get("pending_topics", {}),
        }
        self.room_ids = self.state["rooms"]
        self.cursors = self.state["cursors"]
        self.epochs = self.state["epochs"]
        self.checkpoints = self.state["checkpoints"]
        self.registered_ghosts = set(self.state["ghosts"])
        self.joined = {k: set(v) for k, v in self.state["joined"].items()}
        self.events = collections.OrderedDict(self.state["events"])
        self.processed_txns = collections.OrderedDict(self.state["txns"])
        self.topics = self.state["topics"]
        self.pending_topics = self.state["pending_topics"]
        self._lock = threading.RLock()
        self.transaction_lock = threading.Lock()
        self.ensure_locks = {r: threading.Lock() for r in self.rooms}
        self.rate_limiters = {r: RateLimiter(max_per_minute) for r in self.rooms}

    def save(self) -> None:
        with self._lock:
            self.state.update({
                "rooms": self.room_ids, "cursors": self.cursors, "epochs": self.epochs,
                "checkpoints": self.checkpoints,
                "ghosts": sorted(self.registered_ghosts),
                "joined": {k: sorted(v) for k, v in self.joined.items()},
                "events": dict(self.events), "txns": dict(self.processed_txns),
                "topics": self.topics, "pending_topics": self.pending_topics,
            })
            save_json(self.state_path, self.state)

    def ghost_localpart_for_did(self, did: str) -> str:
        return "tc_" + did_fingerprint16(did)

    def ghost_for_message(self, room: str, message: dict) -> str:
        writer = verified_record_did(room, message)
        return self.ghost_localpart_for_did(writer) if writer else self.ANON_LOCALPART

    def ghost_user_id(self, localpart: str) -> str:
        return f"@{localpart}:{self.domain}"

    def room_alias_localpart(self, room: str) -> str:
        return "tc_" + validate_room(room)

    def room_alias(self, room: str) -> str:
        return f"#{self.room_alias_localpart(room)}:{self.domain}"

    def room_from_alias(self, alias: str) -> str | None:
        suffix = ":" + self.domain
        if not isinstance(alias, str) or not alias.startswith("#tc_") or not alias.endswith(suffix):
            return None
        room = alias[4:-len(suffix)]
        return room if ROOM_RE.fullmatch(room) else None

    def localpart_from_user_id(self, user_id: str) -> str | None:
        suffix = ":" + self.domain
        if not isinstance(user_id, str) or not user_id.startswith("@tc_") or not user_id.endswith(suffix):
            return None
        localpart = user_id[1:-len(suffix)]
        return localpart if _valid_localpart(localpart) else None

    def ensure_ghost(self, localpart: str) -> None:
        with self._lock:
            if localpart in self.registered_ghosts:
                return
            try:
                matrix_request(self.hs_url, "POST", "/_matrix/client/v3/register", self.as_token, {
                    "type": "m.login.application_service", "username": localpart,
                })
            except MatrixError as exc:
                if matrix_errcode(exc) != "M_USER_IN_USE":
                    raise
            self.registered_ghosts.add(localpart)
            self.save()

    def read_topic(self, room: str) -> str:
        topic = kv_get(self.base, "topic", room) or ""
        if len(topic) > MESSAGE_MAX_CHARS:
            raise BridgeError("Technocore topic exceeds supported size")
        return sanitize_line(topic)

    def ensure_room(self, room: str) -> str:
        with self.ensure_locks[room]:
            if room in self.room_ids:
                return self.room_ids[room]
            alias = self.room_alias(room)
            encoded = urllib.parse.quote(alias, safe="")
            topic = self.read_topic(room)
            try:
                room_id = matrix_request(
                    self.hs_url, "GET", f"/_matrix/client/v3/directory/room/{encoded}", self.as_token
                ).get("room_id")
            except MatrixError as exc:
                if matrix_errcode(exc) != "M_NOT_FOUND":
                    raise
                private = room.startswith("mb-")
                created = matrix_request(self.hs_url, "POST", "/_matrix/client/v3/createRoom", self.as_token, {
                    "room_alias_name": self.room_alias_localpart(room),
                    "name": f"#{room} (technocore.chat, bridged)", "topic": topic,
                    "preset": "private_chat" if private else "public_chat",
                    "visibility": "private" if private else "public",
                })
                room_id = created.get("room_id")
            if not isinstance(room_id, str) or not room_id.startswith("!"):
                raise MatrixError("homeserver returned invalid room_id")
            self.room_ids[room] = room_id
            self.topics[room] = topic
            self.save()
            return room_id

    def ensure_joined(self, room: str, room_id: str, localpart: str) -> None:
        with self._lock:
            joined = self.joined.setdefault(room, set())
            if localpart in joined:
                return
            if room.startswith("mb-"):
                matrix_request(
                    self.hs_url, "POST",
                    f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id, safe='')}/invite",
                    self.as_token, {"user_id": self.ghost_user_id(localpart)},
                    self.ghost_user_id("tc_bridge"),
                )
            matrix_request(
                self.hs_url, "POST", f"/_matrix/client/v3/join/{urllib.parse.quote(room_id, safe='')}",
                self.as_token, {}, self.ghost_user_id(localpart),
            )
            joined.add(localpart)
            self.save()

    def event_status(self, event_id: str, digest: str | None = None) -> str | None:
        record = self.events.get(event_id)
        if record is None:
            return None
        if digest is not None and record["digest"] != digest:
            raise ReplayForkError(f"event ID {event_id!r} was reused with different content")
        return record["status"]

    def mark_event(self, event_id: str, status: str, digest: str) -> None:
        self.event_status(event_id, digest)
        self.events[event_id] = {"status": status, "digest": digest}
        self.events.move_to_end(event_id)
        while len(self.events) > LEDGER_LIMIT:
            removed, _status = self.events.popitem(last=False)
            self.pending_topics.pop(removed, None)
        self.save()

    def mark_txn(self, txn_id: str, digest: str) -> None:
        existing = self.processed_txns.get(txn_id)
        if existing is not None and existing != digest:
            raise ReplayForkError(f"transaction ID {txn_id!r} was reused with different content")
        self.processed_txns[txn_id] = digest
        self.processed_txns.move_to_end(txn_id)
        while len(self.processed_txns) > LEDGER_LIMIT:
            self.processed_txns.popitem(last=False)
        self.save()


def _format_writer_prefix(message: dict) -> str:
    writer = message.get("from")
    claimed = sanitize_line(writer)[:128] if isinstance(writer, str) and writer else "anon"
    return f"<~{claimed}> "


def deterministic_txn_id(bridge: Bridge, room: str, room_id: str, seq: int) -> str:
    fingerprint = hashlib.sha256(room.encode()).hexdigest()[:12]
    binding = hashlib.sha256(room_id.encode()).hexdigest()[:12]
    return f"tc-{fingerprint}-e{bridge.epochs.get(room, 0)}-{seq}-{binding}"


def _validated_view(view: dict, since: int) -> list[dict]:
    last = view.get("last_seq")
    first = view.get("first_seq")
    messages = view.get("messages")
    if not isinstance(last, int) or isinstance(last, bool) or last < 0 or not isinstance(messages, list):
        raise BridgeError("invalid room sequence response")
    if first is not None and (not isinstance(first, int) or isinstance(first, bool) or first < 1):
        raise BridgeError("invalid first_seq")
    if messages and first != since + 1:
        raise BridgeError(f"room history gap: expected {since + 1}, first available is {first}")
    if not messages and last != since:
        raise BridgeError("empty room response advanced or rewound last_seq")
    expected = since + 1
    for message in messages:
        if not isinstance(message, dict):
            raise BridgeError("invalid message")
        seq = message.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != expected:
            raise BridgeError(f"room sequence discontinuity at {expected}")
        if not isinstance(message.get("text"), str):
            raise BridgeError(f"invalid message text at {seq}")
        if len(message["text"]) > MESSAGE_MAX_CHARS:
            raise BridgeError(f"oversized message text at {seq}")
        if not isinstance(message.get("from"), str):
            raise BridgeError(f"invalid message writer at {seq}")
        expected += 1
    if messages and last != messages[-1]["seq"]:
        raise BridgeError("last_seq does not match final message")
    return messages


def _validated_probe(view: dict) -> tuple[int, list[dict]]:
    last, first, messages = view.get("last_seq"), view.get("first_seq"), view.get("messages")
    if not isinstance(last, int) or isinstance(last, bool) or last < 0 or not isinstance(messages, list):
        raise BridgeError("invalid tail probe")
    if not messages:
        if last != 0 or first is not None:
            raise BridgeError("inconsistent empty tail probe")
        return last, messages
    if not isinstance(first, int) or isinstance(first, bool) or first < 1:
        raise BridgeError("invalid tail first_seq")
    expected = first
    for message in messages:
        if not isinstance(message, dict) or message.get("seq") != expected:
            raise BridgeError("tail probe sequence discontinuity")
        if not isinstance(message.get("from"), str) or not isinstance(message.get("text"), str):
            raise BridgeError("invalid tail probe message")
        if len(message["text"]) > MESSAGE_MAX_CHARS:
            raise BridgeError("oversized tail probe message")
        expected += 1
    if last != messages[-1]["seq"]:
        raise BridgeError("tail last_seq does not match final message")
    return last, messages


def record_checkpoint(message: dict) -> str:
    encoded = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def deliver_message(bridge: Bridge, room: str, room_id: str, message: dict) -> None:
    localpart = bridge.ghost_for_message(room, message)
    text = sanitize_line(message["text"])
    if localpart == bridge.ANON_LOCALPART:
        text = sanitize_line(_format_writer_prefix(message) + text)
    bridge.rate_limiters[room].wait()
    bridge.ensure_ghost(localpart)
    bridge.ensure_joined(room, room_id, localpart)
    txn = deterministic_txn_id(bridge, room, room_id, message["seq"])
    path = (
        f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id, safe='')}/"
        f"send/m.room.message/{urllib.parse.quote(txn, safe='')}"
    )
    matrix_request(
        bridge.hs_url, "PUT", path, bridge.as_token, {"msgtype": "m.text", "body": text},
        bridge.ghost_user_id(localpart),
    )


def poll_room_once(bridge: Bridge, room: str, probe: bool = True) -> int:
    room_id = bridge.ensure_room(room)
    sync_topic(bridge, room)
    since = bridge.cursors.get(room, 0)
    if not isinstance(since, int) or isinstance(since, bool) or since < 0:
        raise BridgeError("invalid persisted cursor")
    if since and room not in bridge.checkpoints:
        raise BridgeError("nonzero cursor lacks checkpoint")
    if probe:
        tail = technocore_read_room(bridge.base, room)
        actual, tail_messages = _validated_probe(tail)
        boundary_changed = False
        if actual >= since and since:
            current = next((message for message in tail_messages if message["seq"] == since), None)
            if current is None:
                raise BridgeError("tail probe omitted cursor checkpoint record")
            boundary_changed = record_checkpoint(current) != bridge.checkpoints[room]
        if actual < since or boundary_changed:
            bridge.epochs[room] = bridge.epochs.get(room, 0) + 1
            bridge.cursors[room] = since = 0
            bridge.checkpoints.pop(room, None)
            bridge.save()
    view = technocore_read_room(bridge.base, room, since, POLL_WAIT_SECONDS)
    for message in _validated_view(view, since):
        seq = message["seq"]
        if verified_record_did(room, message) != bridge.did:
            deliver_message(bridge, room, room_id, message)
        bridge.cursors[room] = seq
        bridge.checkpoints[room] = record_checkpoint(message)
        bridge.save()
        since = seq
    return since


def outbound_loop(bridge: Bridge, room: str) -> None:
    while True:
        try:
            poll_room_once(bridge, room, probe=True)
        except MatrixError as exc:
            if not exc.retryable:
                print(f"{APP_NAME}: [{room}] permanent Matrix failure, stopped: {exc}", file=sys.stderr)
                return
            print(f"{APP_NAME}: [{room}] transient Matrix failure, retrying: {exc}", file=sys.stderr)
            time.sleep(2)
        except RetryableError as exc:
            print(f"{APP_NAME}: [{room}] transient poll failure, retrying: {exc}", file=sys.stderr)
            time.sleep(2)
        except BridgeError as exc:
            print(f"{APP_NAME}: [{room}] outbound stopped fail-closed: {exc}", file=sys.stderr)
            return


def _allow_d_room(bridge: Bridge, room: str) -> None:
    if not room.startswith("d-"):
        return
    owner = kv_get(bridge.base, "room-owners", room)
    if owner is None or not owner.strip():
        return
    value = kv_get(bridge.base, "room-allow", room)
    entries = re.split(r"[\s,]+", value or "")
    if bridge.did not in entries:
        raise RetryableError(f"bridge DID is not in /kv/room-allow/{room}")


def _room_for_event(bridge: Bridge, room_id: str) -> str | None:
    return next((name for name, rid in bridge.room_ids.items() if rid == room_id), None)


def handle_event(bridge: Bridge, event: dict) -> None:
    event_id, sender, room_id = event.get("event_id"), event.get("sender"), event.get("room_id")
    if not all(isinstance(x, str) and x for x in (event_id, sender, room_id)):
        return
    if len(event_id) > 1024 or len(sender) > 1024 or len(room_id) > 1024:
        return
    if not all(utf8_safe(value) for value in (event_id, sender, room_id)):
        raise InvalidTransactionError("Matrix identifiers must be valid Unicode scalar text")
    if bridge.localpart_from_user_id(sender) is not None:
        return
    room = _room_for_event(bridge, room_id)
    if room is None:
        return
    kind, content = event.get("type"), event.get("content")
    if not isinstance(content, dict):
        return
    if kind == "m.room.message":
        if content.get("msgtype") != "m.text" or not isinstance(content.get("body"), str):
            return
        digest = canonical_digest(event)
        status = bridge.event_status(event_id, digest)
        body = content["body"]
        if len(body) > MAX_TXN_BODY_BYTES:
            return
        marker = event_marker(event_id)
        if status == "done":
            return
        prefix = sanitize_line(f"{sender} (via Matrix): {body}")
        text = prefix[: MESSAGE_MAX_CHARS - len(marker) - 1] + " " + marker
        if (
            status == "pending"
            and signed_frame_landed(bridge.base, room, bridge.did, text)
        ):
            bridge.mark_event(event_id, "done", digest)
            return
        _allow_d_room(bridge, room)
        bridge.mark_event(event_id, "pending", digest)
        technocore_say_signed(bridge.base, bridge.ed25519_key, bridge.did, room, text, marker)
        bridge.mark_event(event_id, "done", digest)
    elif kind == "m.room.topic":
        topic = content.get("topic")
        if not isinstance(topic, str) or len(topic) > MESSAGE_MAX_CHARS:
            return
        digest = canonical_digest(event)
        status = bridge.event_status(event_id, digest)
        if status == "done":
            return
        cleaned = sanitize_line(topic)
        metadata = bridge.pending_topics.get(event_id)
        if metadata is not None and (
            metadata.get("room") != room or metadata.get("desired") != cleaned
        ):
            raise BridgeError("pending topic event metadata mismatch")
        current = kv_get(bridge.base, "topic", room)
        if current is not None and len(current) > MESSAGE_MAX_CHARS:
            raise BridgeError("Technocore topic exceeds supported size")
        if current == cleaned:
            bridge.topics[room] = cleaned
            bridge.pending_topics.pop(event_id, None)
            bridge.mark_event(event_id, "done", digest)
            return
        previous = current if metadata is None else metadata["previous"]
        if metadata is not None and current != previous:
            raise RetryableError("topic changed since original compare-and-set basis")
        if metadata is None:
            bridge.pending_topics[event_id] = {
                "room": room, "desired": cleaned, "previous": previous,
            }
        bridge.mark_event(event_id, "pending", digest)
        kv_set_cas(bridge.base, "topic", room, cleaned, previous)
        bridge.topics[room] = cleaned
        bridge.pending_topics.pop(event_id, None)
        bridge.mark_event(event_id, "done", digest)


def handle_transaction(
    bridge: Bridge, txn_id: str, events: list[dict], payload_digest: str | None = None,
) -> None:
    digest = payload_digest or canonical_digest({"events": events})
    with bridge.transaction_lock:
        existing = bridge.processed_txns.get(txn_id)
        if existing is not None:
            if existing != digest:
                raise ReplayForkError(f"transaction ID {txn_id!r} was reused with different content")
            return
        for event in events:
            if isinstance(event, dict):
                handle_event(bridge, event)
        bridge.mark_txn(txn_id, digest)


def sync_topic(bridge: Bridge, room: str) -> None:
    topic = bridge.read_topic(room)
    if bridge.topics.get(room) == topic:
        return
    room_id = bridge.ensure_room(room)
    path = f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id, safe='')}/state/m.room.topic"
    matrix_request(
        bridge.hs_url, "PUT", path, bridge.as_token, {"topic": topic},
        bridge.ghost_user_id("tc_bridge"),
    )
    bridge.topics[room] = topic
    bridge.save()


class Handler(BaseHTTPRequestHandler):
    bridge: Bridge
    hs_token: str

    def log_message(self, fmt: str, *args) -> None:
        return

    def reply(self, status: int, obj: dict) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self, query: dict) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[7:]
        else:
            supplied = (query.get("hs_token") or query.get("access_token") or [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.hs_token)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self.authorized(query):
            self.reply(401, {"errcode": "M_UNAUTHORIZED"})
            return
        match = re.fullmatch(r"/_matrix/app/(?:v1/)?users/([^/]+)", parsed.path)
        if match:
            exists = self.bridge.localpart_from_user_id(urllib.parse.unquote(match.group(1))) is not None
            self.reply(200 if exists else 404, {} if exists else {"errcode": "M_NOT_FOUND"})
            return
        match = re.fullmatch(r"/_matrix/app/(?:v1/)?rooms/([^/]+)", parsed.path)
        if match:
            room = self.bridge.room_from_alias(urllib.parse.unquote(match.group(1)))
            if room not in self.bridge.rooms:
                self.reply(404, {"errcode": "M_NOT_FOUND"})
                return
            try:
                self.bridge.ensure_room(room)
            except BridgeError:
                self.reply(500, {"errcode": "M_UNKNOWN"})
                return
            self.reply(200, {})
            return
        self.reply(404, {"errcode": "M_NOT_FOUND"})

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self.authorized(query):
            self.reply(401, {"errcode": "M_UNAUTHORIZED"})
            return
        match = re.fullmatch(r"/_matrix/app/(?:v1/)?transactions/([^/]+)", parsed.path)
        if not match:
            self.reply(404, {"errcode": "M_NOT_FOUND"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        if length < 0 or length > MAX_TXN_BODY_BYTES:
            self.reply(413, {"errcode": "M_TOO_LARGE"})
            return
        try:
            payload = json.loads(
                self.rfile.read(length).decode(),
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            )
        except (UnicodeError, ValueError, RecursionError):
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        events = payload.get("events") if isinstance(payload, dict) else None
        if not isinstance(events, list):
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        if len(events) > MAX_TXN_EVENTS:
            self.reply(413, {"errcode": "M_TOO_LARGE"})
            return
        txn_id = urllib.parse.unquote(match.group(1))
        if not txn_id or len(txn_id) > 1024:
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        try:
            validate_json_depth(payload)
            handle_transaction(self.bridge, txn_id, events, canonical_digest(payload))
        except InvalidTransactionError as exc:
            print(f"{APP_NAME}: rejected invalid transaction: {exc}", file=sys.stderr)
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        except ReplayForkError as exc:
            print(f"{APP_NAME}: rejected replay fork: {exc}", file=sys.stderr)
            self.reply(400, {"errcode": "M_BAD_JSON"})
            return
        except BridgeError as exc:
            print(f"{APP_NAME}: transaction retry requested: {exc}", file=sys.stderr)
            self.reply(500, {"errcode": "M_UNKNOWN"})
            return
        self.reply(200, {})


class ServeLock:
    def __init__(self, home: Path):
        ensure_private_home(home)
        path = home / "serve.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        if require_regular_file(path, missing_ok=True):
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise BridgeError(f"cannot securely open serve lock {path}") from exc
        self.file = os.fdopen(descriptor, "a+", encoding="utf-8")
        os.fchmod(self.file.fileno(), 0o600)
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.file.close()
            raise BridgeError(f"another bridge process is using {home}") from exc

    def close(self) -> None:
        fcntl.flock(self.file, fcntl.LOCK_UN)
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


AS_ID = "technocore-matrix-bridge"


def cmd_register(args: argparse.Namespace) -> int:
    as_token, hs_token = load_or_create_tokens(args.home)
    domain = validate_domain(args.domain)
    print(f"""id: {AS_ID}
url: http://{args.as_host}:{args.as_port}
as_token: "{as_token}"
hs_token: "{hs_token}"
sender_localpart: tc_bridge
namespaces:
  users:
    - exclusive: true
      regex: '^@tc_(?:anon|bridge|[0-9a-f]{{16}}):{re.escape(domain)}$'
  aliases:
    - exclusive: true
      regex: '^#tc_[a-z0-9][a-z0-9_-]{{0,47}}:{re.escape(domain)}$'
  rooms: []
rate_limited: false
""")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        rooms = [validate_room(r.strip()) for r in args.rooms.split(",") if r.strip()]
        if not rooms:
            raise ValueError("--rooms must name at least one room")
        if len(rooms) > MAX_ROOMS:
            raise ValueError(f"--rooms is limited to {MAX_ROOMS} rooms")
        with ServeLock(args.home):
            as_token, hs_token = load_or_create_tokens(args.home)
            bridge = Bridge(
                args.home, args.domain, args.base, args.hs_url, as_token, rooms, args.max_per_minute
            )
            Handler.bridge, Handler.hs_token = bridge, hs_token
            server = HTTPServer((args.host, args.port), Handler)
            for room in rooms:
                threading.Thread(target=outbound_loop, args=(bridge, room), daemon=True).start()
            server.serve_forever()
    except (BridgeError, ValueError) as exc:
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    print(f"technocore did: {did_from_private_key(load_or_create_ed25519(args.home / 'identity.pem'))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME)
    parser.add_argument("--home", type=Path, default=DEFAULT_HOME)
    parser.add_argument("--base", default=TECHNOCORE_BASE)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("--domain", required=True)
    register.add_argument("--as-host", default="127.0.0.1")
    register.add_argument("--as-port", type=int, default=8739)
    register.set_defaults(func=cmd_register)
    serve = sub.add_parser("serve")
    serve.add_argument("--domain", required=True)
    serve.add_argument("--hs-url", default=DEFAULT_HS_URL)
    serve.add_argument("--rooms", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8739)
    serve.add_argument("--max-per-minute", type=float, default=DEFAULT_MAX_PER_MINUTE)
    serve.set_defaults(func=cmd_serve)
    identity = sub.add_parser("identity")
    identity.set_defaults(func=cmd_identity)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (BridgeError, ValueError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())