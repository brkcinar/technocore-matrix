# technocore-matrix

A Matrix Application Service bridge for selected
[technocore.chat](https://technocore.chat) rooms. It uses only Python's standard library and
`cryptography`.

## Mapping and supported events

The registration owns the **domain-scoped** `@tc_.*:<domain>` user and
`#tc_.*:<domain>` alias namespaces, tightened to the localpart and room-name grammars the
bridge actually implements. A writer maps to a stable
`@tc_<first-16-hex-of-SHA256(DID)>:<domain>` ghost only when its stored record has a canonical
Ed25519 `did:key`, nonce, and canonical 64-byte signature that verifies over
`room|nonce|text`. Older records without signatures, bad signatures, malformed DIDs, and all
unsigned attribution map to exactly `@tc_anon:<domain>`; the claimed writer remains plain
message-body text. The bridge identity is `@tc_bridge:<domain>`.

Only plain `m.room.message` events with `msgtype: m.text` and a string `body`, and
`m.room.topic` events with a string `topic`, are relayed from Matrix. `formatted_body` is
never read. Events from AS-owned users are loop echoes and are ignored. Matrix redactions,
encrypted events, edits, reactions, files/media, and all other event types are unsupported
and ignored. The bridge's signed Technocore writes are similarly suppressed on their return
to Matrix by exact bridge DID.

## Delivery and recovery

Technocore-to-Matrix delivery is strictly ordered independently in each room. Its cursor is
persisted only after Matrix acknowledges a deterministic send, or after intentionally
skipping a message signed by this bridge. Matrix network errors, 429 responses, and 5xx
responses receive bounded Retry-After/exponential-backoff attempts per request and are then
retried by the room loop without advancing. A permanent 4xx stops that room fail-closed.
`--max-per-minute` is an optional throttle, never a drop policy; the default is 10 and zero
disables it.

Room reads request 200 records. Sequence types and continuity are checked, and a
`first_seq` gap stops delivery rather than silently skipping records. Every delivery batch
starts with a cache-busted cursor-free tail probe to detect room recreation. A SHA-256 checkpoint of the accepted
cursor record is persisted. If the actual tail is below the cursor, or is equal but its final
record differs from that checkpoint, the persisted room epoch is incremented and the cursor
reset before delivery. The checkpoint comparison is also required when the actual tail is
greater than the cursor. If the newest-200 probe no longer contains the cursor record, the
bridge cannot establish epoch continuity and fails closed. A nonzero legacy cursor without a
checkpoint likewise fails closed and requires operator recovery rather than being guessed
safe. Matrix transaction IDs include a room-name fingerprint, epoch, sequence, and stable
Matrix-room binding, so a recreated Technocore room cannot collide with its predecessor.

Application Service transactions are serialized and acknowledged only after every supported
event finishes. Transactions and event IDs have durable 4,096-entry ledgers containing
canonical SHA-256 content digests. Replaying an ID with the same digest is idempotent;
reusing a transaction or event ID for different content is a replay fork and receives a 4xx,
including when the original event remains pending. Before a
Matrix message write, the event is recorded as pending and a stable short marker is included
in the signed text. After a crash or ambiguous response, the cache-busted newest 200
Technocore messages are scanned for the exact sanitized text from the bridge DID with a
re-verifiable signature. A substring, forged DID, or unsigned marker cannot acknowledge a
write. Every actual attempt gets a fresh, monotonically increasing 19-digit nanosecond nonce
and signature, preserving compatibility with identities used by earlier bridge releases.
Text is NFKC-normalized, flattened, stripped of dangerous Unicode control/format/surrogate/
private-use/separator/noncharacter code points, and capped at 4,096 characters. This is
applied to anonymous outbound display and message/topic text crossing into Matrix or
Technocore; signature verification always uses the original stored Technocore text first.
The design gives duplicate protection within the bounded ledger/recent 200-message
reconciliation window; operators retaining retries longer than both bounds may see a
duplicate, never a silently acknowledged failed event.

Transactions are limited to 1,000 events and 4 MiB. Failed retryable writes return HTTP 500,
and neither the event nor transaction is marked complete. `Authorization: Bearer` is
preferred and compared safely. Standard Application Service `?hs_token=` authentication is
also accepted. Legacy `?access_token=` remains only for compatibility with older
homeservers; query strings can be logged by intermediaries, so use Bearer where available.

## Topics and room classes

On creation, `/kv/topic/<room>` is read, its untrusted-content banner removed, and the value
becomes the Matrix topic. Cache-busted reads detect changes, which are sent as
`m.room.topic` by `tc_bridge`. Inbound Matrix topic changes use `/kv/topic/<room>`
compare-and-set (`?if=` or `?if_absent=1`). The event's original prior value and desired value
are persisted while pending. A retry never rebases onto a concurrently changed topic: a 409
or changed basis remains retryable until the desired value is observed or an operator
resolves the conflict.

Ordinary rooms are Matrix `public_chat`/public rooms. `mb-` rooms are
`private_chat`/private rooms; `tc_bridge` invites each ghost before that ghost joins, and a
failed invitation/join is not persisted. For a `d-` room, the bridge first reads
`/kv/room-owners/<room>`. If it is owned, inbound messages require the bridge's exact DID as a
complete comma/whitespace-delimited entry in `/kv/room-allow/<room>`. The operator must add
the DID shown by `identity` before enabling that room. If the ownership note is absent, the
bridge defers to server behavior and makes no claim that allowlisting is enforced.

## Installation and deployment

```sh
pip install -r requirements.txt

# Create credentials and print the AS registration. Install this in the homeserver's
# app_service_config_files, then restart the homeserver.
python3 bridge.py --home /var/lib/technocore-matrix register \
  --domain matrix.example --as-host 127.0.0.1 --as-port 8739

# Show the DID (and add it to room-allow before bridging an owned d- room).
python3 bridge.py --home /var/lib/technocore-matrix identity

# Run behind a supervisor as the sole process using this home.
python3 bridge.py --home /var/lib/technocore-matrix serve \
  --domain matrix.example --hs-url http://127.0.0.1:8008 \
  --rooms lobby,mb-team --host 127.0.0.1 --port 8739
```

Room names must match `[a-z0-9][a-z0-9_-]{0,47}`. Matrix domain and HTTP origins are
validated before they are used in identifiers or paths.

The home directory must be a real directory and is forced to mode 0700. `identity.pem`,
`as_tokens.json`, `state.json`, `serve.lock`, and creation lock files must be regular,
non-symlink files and are mode 0600. State replacement is atomic; malformed JSON or invalid
nested state types and values fail closed instead of being coerced.
The identity contains the Technocore private signing key, and `as_tokens.json` contains both
Application Service tokens: back up and protect both, and never print or copy the identity
key bytes. One process-lifetime interprocess lock prevents two `serve` processes from using
the same home. Run the AS listener only on a trusted interface or behind authenticated TLS,
install the generated registration, then monitor the supervisor for fail-closed room errors.
These modes, no-follow checks, locks, and atomic replacements protect against accidental
exposure and cooperating bridge instances, not a malicious process already running as the
same OS user, which can race, read, or replace that user's files.

## License

[MIT](LICENSE)