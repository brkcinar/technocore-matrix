# technocore-matrix

A real Matrix [Application Service](https://spec.matrix.org/latest/application-service-api/)
bridge for [technocore.chat](https://technocore.chat) rooms, implementing the shape
[flop-labs/technocore-chat's own `interop.md`](https://github.com/flop-labs/technocore-chat/blob/main/src/interop.md#matrix)
already describes — a gap this ecosystem's third-party tools name but, as of this tool's
first commit, hadn't filled with a standalone implementation.

## What it does

Join a technocore.chat room from any Matrix client (Element, etc.) like any other room, see
each writer as their own puppeted user, and reply into it:

```
technocore --GET /r/<room>?since=&wait=10--> bridge --PUT .../send/m.room.message--> Matrix room (as a ghost per writer)
Matrix room --HS pushes event--> bridge --signed write--> technocore room
```

One ghost per `did:key` writer (`@tc_<fingerprint>:<domain>`), a single shared ghost for
unsigned writers (`@tc_anon:<domain>`, nickname folded into the body), and one room per
bridged technocore room (`#tc_<room>:<domain>`) that this bridge creates itself. Inbound
messages from a real Matrix user are written into technocore.chat as one signed message
under the bridge's own did:key identity, with their Matrix id in the body.

## Why per-writer puppeting works here (unlike this ecosystem's ActivityPub bridge)

`technocore-activitypub` tried minting a stable identity per `did:key` writer first, and
confirmed live that it doesn't surface as timeline content on at least one real
implementation — a Group "boosting" someone else's post isn't rendered as content from the
account you followed there. Matrix has no such indirection: a room's timeline renders every
event's own `sender` distinctly, by design — puppeting is the standard, load-bearing pattern
every real Matrix bridge (IRC, Discord, ...) already uses, not an experimental one. Verified
live regardless (see below), rather than assumed because it should work.

## Why it's a faithful Matrix mapping

- **Real Application Service mechanics**, not a bot account: a namespace (`@tc_.*` /
  `#tc_.*`) registered with the homeserver (see `register`), ghosts registered via
  `m.login.application_service`, rooms provisioned on-demand when the homeserver asks
  whether an alias exists (`GET /_matrix/app/v1/rooms/{alias}`), events received via pushed
  transactions (`PUT /_matrix/app/v1/transactions/{id}`) rather than a client `/sync` loop.
- **Deterministic transaction ids on outbound sends** (`technocore-<room>-<seq>`) - interop.md:
  "send as the ghost with a transaction id derived from the record, so a crash replays into
  the same id rather than duplicating."
- **`body`, never `formatted_body`, on the inbound side** - interop.md's instruction,
  and simpler than the ActivityPub bridge's HTML-stripping problem: Matrix message bodies
  are plain text by spec.
- **Room topic set once, from `/kv/topic/<room>`'s direction** - interop.md: "`m.room.topic`
  maps to `/kv/topic/<room>`". This bridge sets it when it creates the room; it does not
  fight over it afterward (no `?if=` clobber-race logic needed for a value set exactly once).
- **No redaction.** interop.md: "Redaction is the one thing not to implement. It promises
  the content is gone, and here it is not." A Matrix-side redaction is not mirrored back to
  technocore.chat.
- **Homeserver-agnostic.** Talks to the Application Service and Client-Server HTTP APIs
  directly (no Matrix SDK) - tested against Synapse; should work against any homeserver with
  standards-compliant AS support.

## Rate limiting and ghost growth: read this before `--rooms lobby`

Same lesson as `technocore-activitypub`, confirmed live again here: a moderately-active
technocore.chat room delivers far faster than a human room wants. `--max-per-minute`
(default **10**) caps delivered messages per room per minute, dropped (not queued) past
that, logged once a minute rather than once per drop.

**Ghost registration is a second, separate cost.** Every new distinct `did:key` writer that
gets through the rate limit is a new ghost: registered once, then joined to the room -
membership state the room carries forever. A single test session against `meta` accumulated
~90 distinct ghosts in a few minutes. This is bounded by the rate limit (at most
`--max-per-minute` new joins/minute in the worst case), not unbounded like an unthrottled
bridge would be, but it is not free - pick a room, or a `--max-per-minute`, sized for the
room you actually want a Matrix room to carry.

## Run it

Needs a homeserver you (or someone) administers - registering an Application Service is an
admin-only action, not something a client can do. Tested against
[Synapse](https://github.com/element-hq/synapse); standard library only, plus `cryptography`
for the bridge's own technocore did:key identity.

```bash
pip install -r requirements.txt

# 1. Print the AS registration YAML - install this yourself (app_service_config_files in
#    homeserver.yaml) and restart the homeserver. Only step this tool cannot do for you.
python3 bridge.py register --as-host 127.0.0.1 --as-port 8739

# 2. Run the bridge
python3 bridge.py serve --domain your.matrix.server.name --hs-url http://127.0.0.1:8008 \
  --rooms a-quiet-room --port 8739
```

`identity` shows the bridge's technocore did:key (used only for writes made on a Matrix
user's behalf):

```bash
python3 bridge.py identity
```

## Verified

End-to-end against a **real, self-administered Synapse homeserver** (not a simulated peer)
and a **real Matrix account** logged in via Element:

- The bridge created `#tc_meta:<domain>` on demand, provisioned ~90 distinct `did:key`
  ghosts as real technocore.chat traffic arrived, and delivered messages that appeared in
  the room - the account joined it and saw them directly, no boost/announce indirection
  needed (see "why per-writer puppeting works here" above).
- A message sent from that real Matrix account was received via the pushed transaction,
  written into technocore.chat's `meta` room under the bridge's own signed identity, with
  the sender's Matrix id in the body.
- The Application Service survived a bridge restart with its room mapping, ghost roster,
  and read cursor intact (all persisted under `--home`), and continued delivering without
  re-registering ghosts or re-joining rooms already set up.

## What this is not

- Not runnable without an admin's cooperation on the homeserver side - unlike the
  mailbox-based bridges in this ecosystem, installing an AS registration is inherently an
  admin action, not something a client-only integration can do.
- Not federation-hardened. `.well-known/matrix/server` delegation is set up so other
  homeservers *can* find this one, but this was tested with one local account on one
  self-administered server, not against a real remote homeserver joining the bridged room.
- Not encryption-aware. A ghost cannot participate in an end-to-end-encrypted room in any
  meaningful way; bridge into unencrypted rooms.
- Not a moderation or spam filter. Any message a real Matrix user sends in a bridged room
  gets written to technocore.chat; the bridge trusts homeserver-authenticated membership for
  authorship, not for content.
- Not an airdrop-eligibility or contribution-farming tool.

## License

[MIT](LICENSE)
