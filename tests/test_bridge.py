import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MODULE = Path(__file__).parents[1] / "bridge.py"
SPEC = importlib.util.spec_from_file_location("technocore_matrix_bridge", MODULE)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.did = bridge.did_from_private_key(self.key)

    def tearDown(self):
        self.temp.cleanup()

    def make_bridge(self, rooms=None):
        return bridge.Bridge(
            self.home, "matrix.example", "https://technocore.chat",
            "http://127.0.0.1:8008", "a" * 64, rooms or ["lobby"], 0,
        )

    def signed_record(self, room="lobby", text="hello", nonce=1):
        signature = bridge.sign_message(self.key, f"{room}|{nonce}|{text}".encode())
        return {"seq": 1, "from": self.did, "text": text, "nonce": nonce, "sig": signature}

    def test_did_conversion_and_validation(self):
        self.assertTrue(bridge.valid_ed25519_did(self.did))
        self.assertEqual(bridge.base58btc_decode(self.did[9:])[:2], b"\xed\x01")
        for bad in (
            "", "did:key:", "did:key:z0", "did:key:z" + "1" * 33,
            self.did + "1", self.did.replace("z", "u", 1),
        ):
            self.assertFalse(bridge.valid_ed25519_did(bad), bad)

    def test_names_and_origins_are_validated(self):
        for good in ("a", "mb-team", "under_score", "a" * 48):
            self.assertEqual(bridge.validate_room(good), good)
        for bad in ("", "Upper", "../x", "a/b", "a" * 49):
            with self.assertRaises(ValueError):
                bridge.validate_room(bad)
        with self.assertRaises(ValueError):
            bridge.validate_base_url("http://host/path")
        with self.assertRaises(ValueError):
            bridge.validate_domain("bad/domain")

    def test_only_verified_signed_record_gets_stable_ghost(self):
        instance = self.make_bridge()
        self.assertEqual(instance.ghost_for_message("lobby", {"from": "alice"}), "tc_anon")
        malformed = {"from": "did:key:not-a-key", "text": "x"}
        self.assertEqual(instance.ghost_for_message("lobby", malformed), "tc_anon")
        self.assertEqual(instance.ghost_for_message("lobby", {"from": self.did}), "tc_anon")
        signed = self.signed_record()
        self.assertTrue(instance.ghost_for_message("lobby", signed).startswith("tc_"))
        signed["text"] = "tampered"
        self.assertEqual(instance.ghost_for_message("lobby", signed), "tc_anon")

    @mock.patch.object(bridge, "technocore_say_signed")
    def test_plain_body_only_and_loop_suppression(self, say):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!room:matrix.example"
        event = {
            "event_id": "$one", "sender": "@alice:matrix.example",
            "room_id": "!room:matrix.example", "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "plain", "formatted_body": "<b>evil</b>"},
        }
        bridge.handle_event(instance, event)
        self.assertIn("plain", say.call_args.args[4])
        self.assertNotIn("evil", say.call_args.args[4])
        event["event_id"] = "$two"
        event["sender"] = "@tc_anon:matrix.example"
        bridge.handle_event(instance, event)
        self.assertEqual(say.call_count, 1)

    @mock.patch.object(bridge, "technocore_say_signed")
    def test_unsupported_and_malformed_events_have_no_effect(self, say):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!room:matrix.example"
        base = {"event_id": "$x", "sender": "@a:m", "room_id": "!room:matrix.example"}
        bridge.handle_event(instance, {**base, "type": "m.room.redaction", "content": {}})
        bridge.handle_event(instance, {
            **base, "type": "m.room.message", "content": {"msgtype": "m.image", "body": "x"},
        })
        bridge.handle_event(instance, {
            **base, "event_id": 2, "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "x"},
        })
        say.assert_not_called()
        self.assertFalse(instance.events)

    @mock.patch.object(bridge, "technocore_say_signed")
    def test_event_and_transaction_duplicate_suppression(self, say):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$same", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.message", "content": {"msgtype": "m.text", "body": "hello"},
        }
        bridge.handle_transaction(instance, "one", [event])
        bridge.handle_transaction(instance, "one", [event])
        bridge.handle_transaction(instance, "two", [event])
        self.assertEqual(say.call_count, 1)

    @mock.patch.object(bridge, "technocore_say_signed", side_effect=bridge.RetryableError("down"))
    def test_failed_write_is_not_acknowledged(self, _say):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$retry", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.message", "content": {"msgtype": "m.text", "body": "hello"},
        }
        with self.assertRaises(bridge.RetryableError):
            bridge.handle_transaction(instance, "txn", [event])
        self.assertNotIn("txn", instance.processed_txns)
        self.assertEqual(instance.event_status("$retry"), "pending")

    @mock.patch.object(bridge, "signed_frame_landed", return_value=True)
    @mock.patch.object(
        bridge, "_http_json",
        side_effect=bridge.MatrixError("ambiguous", retryable=True),
    )
    def test_ambiguous_write_reconciles(self, _http, landed):
        result = bridge.technocore_say_signed(
            "https://technocore.chat", self.key, self.did, "lobby",
            "hello [mx:abc]", "[mx:abc]",
        )
        self.assertEqual(result, 0)
        landed.assert_called_once()

    def test_nonce_is_fresh_each_actual_attempt(self):
        nonces = []

        def capture(request, **_kwargs):
            nonces.append(int(json.loads(request.data)["nonce"]))
            if len(nonces) == 1:
                raise bridge.MatrixError("ambiguous", retryable=True)
            return {"posted": {"seq": 1}}

        bridge._last_nonce = 0
        clock = 1_800_000_000_000_000_000
        with mock.patch.object(bridge, "_http_json", side_effect=capture), \
                mock.patch.object(bridge, "signed_frame_landed", return_value=False), \
                mock.patch.object(bridge.time, "time_ns", return_value=clock), \
                mock.patch.object(bridge.time, "sleep"):
            bridge.technocore_say_signed(
                "https://technocore.chat", self.key, self.did, "lobby", "hello", "[mx:x]"
            )
        self.assertEqual(len(nonces), 2)
        self.assertEqual(nonces[0], clock)
        self.assertGreater(nonces[1], nonces[0])
        self.assertLessEqual(len(str(nonces[1])), 19)

    def test_cursor_advances_only_after_success_and_in_order(self):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        view = {
            "first_seq": 1, "last_seq": 2,
            "messages": [{"seq": 1, "from": "a", "text": "one"},
                         {"seq": 2, "from": "b", "text": "two"}],
        }
        with mock.patch.object(bridge, "sync_topic"), \
                mock.patch.object(bridge, "technocore_read_room", return_value=view), \
                mock.patch.object(bridge, "deliver_message", side_effect=[None, bridge.MatrixError("no")]):
            with self.assertRaises(bridge.MatrixError):
                bridge.poll_room_once(instance, "lobby", probe=False)
        self.assertEqual(instance.cursors["lobby"], 1)

    def test_epoch_reset_changes_transaction_id(self):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        instance.cursors["lobby"] = 9
        instance.checkpoints["lobby"] = "0" * 64
        old = bridge.deterministic_txn_id(instance, "lobby", "!r:m", 1)
        tail = {"first_seq": None, "last_seq": 0, "messages": []}
        with mock.patch.object(bridge, "sync_topic"), \
                mock.patch.object(bridge, "technocore_read_room", side_effect=[tail, tail]):
            bridge.poll_room_once(instance, "lobby", probe=True)
        new = bridge.deterministic_txn_id(instance, "lobby", "!r:m", 1)
        self.assertNotEqual(old, new)
        self.assertEqual(instance.cursors["lobby"], 0)

    def test_gap_fails_closed(self):
        view = {"first_seq": 4, "last_seq": 4, "messages": [{"seq": 4, "text": "lost"}]}
        with self.assertRaises(bridge.BridgeError):
            bridge._validated_view(view, 1)

    def test_inconsistent_room_views_fail_closed(self):
        cases = [
            ({"first_seq": 3, "last_seq": 3, "messages": [{"seq": 2, "from": "a", "text": "x"}]}, 1),
            ({"first_seq": 2, "last_seq": 9, "messages": [{"seq": 2, "from": "a", "text": "x"}]}, 1),
            ({"first_seq": None, "last_seq": 2, "messages": []}, 1),
        ]
        for view, since in cases:
            with self.subTest(view=view), self.assertRaises(bridge.BridgeError):
                bridge._validated_view(view, since)

    def test_same_tail_changed_checkpoint_resets_epoch(self):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        old = {"seq": 1, "from": "a", "text": "old"}
        new = {"seq": 1, "from": "b", "text": "new"}
        instance.cursors["lobby"] = 1
        instance.checkpoints["lobby"] = bridge.record_checkpoint(old)
        tail = {"first_seq": 1, "last_seq": 1, "messages": [new]}
        empty = {"first_seq": None, "last_seq": 0, "messages": []}
        with mock.patch.object(bridge, "sync_topic"), \
                mock.patch.object(bridge, "technocore_read_room", side_effect=[tail, empty]):
            bridge.poll_room_once(instance, "lobby", probe=True)
        self.assertEqual(instance.epochs["lobby"], 1)
        self.assertEqual(instance.cursors["lobby"], 0)

    def test_greater_tail_compares_cursor_checkpoint(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                with tempfile.TemporaryDirectory() as directory:
                    instance = bridge.Bridge(
                        Path(directory), "matrix.example", "https://technocore.chat",
                        "http://127.0.0.1:8008", "a" * 64, ["lobby"], 0,
                    )
                    instance.room_ids["lobby"] = "!r:m"
                    old = {"seq": 1, "from": "a", "text": "old"}
                    boundary = {"seq": 1, "from": "a", "text": "new" if changed else "old"}
                    later = [{"seq": 2, "from": "b", "text": "two"},
                             {"seq": 3, "from": "c", "text": "three"}]
                    instance.cursors["lobby"] = 1
                    instance.checkpoints["lobby"] = bridge.record_checkpoint(old)
                    tail = {"first_seq": 1, "last_seq": 3, "messages": [boundary, *later]}
                    polled = tail if changed else {
                        "first_seq": 2, "last_seq": 3, "messages": later,
                    }
                    with mock.patch.object(bridge, "sync_topic"), \
                            mock.patch.object(
                                bridge, "technocore_read_room", side_effect=[tail, polled]
                            ), mock.patch.object(bridge, "deliver_message"):
                        bridge.poll_room_once(instance, "lobby", probe=True)
                    self.assertEqual(instance.epochs.get("lobby", 0), int(changed))
                    self.assertEqual(instance.cursors["lobby"], 3)

    def test_tail_window_without_cursor_checkpoint_record_fails_closed(self):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        instance.cursors["lobby"] = 1
        instance.checkpoints["lobby"] = "0" * 64
        messages = [{"seq": seq, "from": "a", "text": str(seq)} for seq in range(2, 202)]
        tail = {"first_seq": 2, "last_seq": 201, "messages": messages}
        with mock.patch.object(bridge, "sync_topic"), \
                mock.patch.object(bridge, "technocore_read_room", return_value=tail):
            with self.assertRaises(bridge.BridgeError):
                bridge.poll_room_once(instance, "lobby", probe=True)

    @mock.patch.object(bridge, "kv_set_cas")
    @mock.patch.object(bridge, "kv_get", return_value="old")
    def test_topic_inbound_uses_cas_and_conflict_retries(self, _get, cas):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$topic", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.topic", "content": {"topic": "new"},
        }
        cas.side_effect = bridge.RetryableError("conflict")
        with self.assertRaises(bridge.RetryableError):
            bridge.handle_event(instance, event)
        self.assertEqual(instance.event_status("$topic"), "pending")
        cas.assert_called_once_with(instance.base, "topic", "lobby", "new", "old")

    @mock.patch.object(bridge, "kv_set_cas")
    @mock.patch.object(bridge, "kv_get", side_effect=["old", "other"])
    def test_topic_retry_does_not_rebase_after_conflict(self, _get, cas):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$topic-retry", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.topic", "content": {"topic": "new"},
        }
        cas.side_effect = bridge.RetryableError("conflict")
        with self.assertRaises(bridge.RetryableError):
            bridge.handle_event(instance, event)
        cas.reset_mock()
        with self.assertRaises(bridge.RetryableError):
            bridge.handle_event(instance, event)
        cas.assert_not_called()
        self.assertEqual(instance.pending_topics["$topic-retry"]["previous"], "old")

    @mock.patch.object(bridge, "technocore_say_signed")
    def test_replay_digests_detect_transaction_and_event_forks(self, say):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$digest", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.message", "content": {"msgtype": "m.text", "body": "one"},
        }
        bridge.handle_transaction(instance, "txn", [event])
        bridge.handle_transaction(instance, "txn", [event])
        self.assertEqual(say.call_count, 1)
        changed = {**event, "content": {"msgtype": "m.text", "body": "two"}}
        with self.assertRaises(bridge.ReplayForkError):
            bridge.handle_transaction(instance, "txn", [changed])
        with self.assertRaises(bridge.ReplayForkError):
            bridge.handle_transaction(instance, "other", [changed])

    def test_pending_event_fork_is_rejected(self):
        instance = self.make_bridge()
        instance.room_ids["lobby"] = "!r:m"
        event = {
            "event_id": "$pending-fork", "sender": "@a:m", "room_id": "!r:m",
            "type": "m.room.message", "content": {"msgtype": "m.text", "body": "one"},
        }
        with mock.patch.object(
            bridge, "technocore_say_signed", side_effect=bridge.RetryableError("down")
        ):
            with self.assertRaises(bridge.RetryableError):
                bridge.handle_transaction(instance, "first", [event])
        changed = {**event, "content": {"msgtype": "m.text", "body": "changed"}}
        with self.assertRaises(bridge.ReplayForkError):
            bridge.handle_transaction(instance, "second", [changed])

    @mock.patch.object(bridge, "matrix_request")
    @mock.patch.object(bridge.Bridge, "read_topic", return_value="Mailbox")
    def test_mailbox_room_is_private(self, _topic, matrix):
        instance = self.make_bridge(["mb-team"])
        matrix.side_effect = [
            bridge.MatrixError('{"errcode":"M_NOT_FOUND"}', status=404),
            {"room_id": "!mb:m"},
        ]
        instance.ensure_room("mb-team")
        create = matrix.call_args_list[1].args[4]
        self.assertEqual(create["preset"], "private_chat")
        self.assertEqual(create["visibility"], "private")

    @mock.patch.object(bridge, "matrix_request")
    def test_mailbox_ghost_is_invited_before_join_and_only_then_persisted(self, matrix):
        instance = self.make_bridge(["mb-team"])
        instance.ensure_joined("mb-team", "!mb:m", "tc_anon")
        self.assertIn("/invite", matrix.call_args_list[0].args[2])
        self.assertIn("/join/", matrix.call_args_list[1].args[2])
        self.assertIn("tc_anon", instance.joined["mb-team"])
        instance.joined["mb-team"].clear()
        matrix.reset_mock()
        matrix.side_effect = bridge.MatrixError("invite failed")
        with self.assertRaises(bridge.MatrixError):
            instance.ensure_joined("mb-team", "!mb:m", "tc_anon")
        self.assertNotIn("tc_anon", instance.joined["mb-team"])

    @mock.patch.object(bridge, "kv_get")
    def test_d_room_allowlist_requires_complete_did(self, get):
        instance = self.make_bridge(["d-owned"])
        get.return_value = "prefix" + instance.did + "suffix"
        with self.assertRaises(bridge.RetryableError):
            bridge._allow_d_room(instance, "d-owned")
        get.return_value = "other,\n" + instance.did
        bridge._allow_d_room(instance, "d-owned")

    @mock.patch.object(bridge, "kv_get", return_value=None)
    def test_unowned_d_room_defers_to_server(self, get):
        instance = self.make_bridge(["d-open"])
        bridge._allow_d_room(instance, "d-open")
        get.assert_called_once_with(instance.base, "room-owners", "d-open")

    @mock.patch.object(bridge, "technocore_read_room")
    def test_unsigned_forged_marker_does_not_reconcile(self, read):
        read.return_value = {
            "messages": [{"seq": 1, "from": self.did, "text": "exact frame"}],
        }
        self.assertFalse(
            bridge.signed_frame_landed(
                "https://technocore.chat", "lobby", self.did, "exact frame"
            )
        )
        signed = self.signed_record(text="exact frame")
        read.return_value = {"messages": [signed]}
        self.assertTrue(
            bridge.signed_frame_landed(
                "https://technocore.chat", "lobby", self.did, "exact frame"
            )
        )

    def test_corrupt_private_state_fails_closed(self):
        bridge.ensure_private_home(self.home)
        (self.home / "state.json").write_text("{bad", encoding="utf-8")
        with self.assertRaises(bridge.BridgeError):
            self.make_bridge()

    def test_single_serve_lock(self):
        first = bridge.ServeLock(self.home)
        try:
            with self.assertRaises(bridge.BridgeError):
                bridge.ServeLock(self.home)
        finally:
            first.close()

    def test_sensitive_symlink_and_invalid_rate_are_rejected(self):
        target = self.home / "target"
        target.write_text("not a key", encoding="utf-8")
        (self.home / "identity.pem").symlink_to(target)
        with self.assertRaises(bridge.BridgeError):
            self.make_bridge()
        (self.home / "identity.pem").unlink()
        with self.assertRaises(ValueError):
            bridge.Bridge(
                self.home, "matrix.example", "https://technocore.chat",
                "http://127.0.0.1:8008", "a" * 64, ["lobby"], float("nan"),
            )

    def test_application_service_auth_forms(self):
        class Request:
            hs_token = "correct"

            def __init__(self, authorization=""):
                self.headers = {"Authorization": authorization}

        self.assertTrue(bridge.Handler.authorized(Request("Bearer correct"), {}))
        self.assertTrue(bridge.Handler.authorized(Request(), {"hs_token": ["correct"]}))
        self.assertTrue(bridge.Handler.authorized(Request(), {"access_token": ["correct"]}))
        self.assertFalse(bridge.Handler.authorized(Request("Bearer wrong"), {}))
        self.assertFalse(bridge.Handler.authorized(Request(), {}))

    def test_application_service_rejects_surrogate_ids_and_deep_json(self):
        instance = self.make_bridge()
        bridge.Handler.bridge = instance
        bridge.Handler.hs_token = "correct"
        server = bridge.HTTPServer(("127.0.0.1", 0), bridge.Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        def put(txn_id, payload):
            raw = json.dumps(payload).encode()
            request = bridge.urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/_matrix/app/v1/transactions/{txn_id}"
                "?hs_token=correct",
                data=raw,
                method="PUT",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(bridge.urllib.error.HTTPError) as raised:
                bridge.urllib.request.urlopen(request, timeout=2)
            self.assertEqual(raised.exception.code, 400)

        try:
            put("surrogate", {
                "events": [{
                    "event_id": json.loads('"\\ud800"'),
                    "sender": "@alice:matrix.example",
                    "room_id": "!room:matrix.example",
                    "type": "m.room.message",
                    "content": {"msgtype": "m.text", "body": "hello"},
                }],
            })
            nested = None
            for _ in range(bridge.MAX_JSON_DEPTH + 2):
                nested = [nested]
            put("deep", {"events": [], "extra": nested})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_unicode_controls_do_not_survive_sanitizing(self):
        dangerous = (
            "A\u202eB\u2066C\u200bD\u0085E\ue000F"
            + chr(0xFDD0) + "G" + chr(0x10FFFF) + "H\u2028I\u2029J"
        )
        cleaned = bridge.sanitize_line(dangerous)
        for char in dangerous:
            point = ord(char)
            if (
                bridge.unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
                or 0xFDD0 <= point <= 0xFDEF or point & 0xFFFF in {0xFFFE, 0xFFFF}
            ):
                self.assertNotIn(char, cleaned)
        self.assertEqual(bridge.sanitize_line("Ａ  topic\u200b"), "A topic")

    @mock.patch.object(bridge.Bridge, "ensure_joined")
    @mock.patch.object(bridge.Bridge, "ensure_ghost")
    @mock.patch.object(bridge, "matrix_request")
    def test_verified_signed_message_is_sanitized_before_matrix(self, matrix, _ghost, _joined):
        instance = self.make_bridge()
        dangerous = "signed\u202e\ntext\u200b\ue000" + chr(0xFDD0)
        message = self.signed_record(text=dangerous)
        bridge.deliver_message(instance, "lobby", "!room:matrix.example", message)
        payload = matrix.call_args.args[4]
        self.assertEqual(payload, {"msgtype": "m.text", "body": bridge.sanitize_line(dangerous)})
        self.assertNotEqual(instance.ghost_for_message("lobby", message), instance.ANON_LOCALPART)

    @mock.patch.object(bridge.Bridge, "ensure_joined")
    @mock.patch.object(bridge.Bridge, "ensure_ghost")
    @mock.patch.object(bridge, "matrix_request")
    @mock.patch.object(bridge, "sync_topic")
    @mock.patch.object(bridge.Bridge, "ensure_room", return_value="!room:matrix.example")
    @mock.patch.object(bridge, "technocore_read_room")
    def test_lone_surrogate_is_anonymous_and_does_not_break_polling(
        self, read, _room, _topic, matrix, _ghost, _joined,
    ):
        instance = self.make_bridge()
        surrogate = json.loads('"\\ud800"')
        message = {
            "seq": 1, "from": self.did, "text": surrogate, "nonce": 1, "sig": "A" * 86,
        }
        view = {"last_seq": 1, "first_seq": 1, "messages": [message]}
        read.side_effect = [view, view, {"messages": [message]}]
        self.assertEqual(bridge.poll_room_once(instance, "lobby"), 1)
        self.assertEqual(instance.cursors["lobby"], 1)
        self.assertEqual(matrix.call_args.args[4]["body"], f"<~{self.did}>")
        self.assertFalse(
            bridge.signed_frame_landed(
                "https://technocore.chat", "lobby", self.did, surrogate
            )
        )

    @mock.patch.object(bridge, "technocore_get", return_value=b"\xff")
    def test_invalid_technocore_utf8_is_a_controlled_error(self, _get):
        with self.assertRaisesRegex(bridge.BridgeError, "malformed technocore room"):
            bridge.technocore_read_room("https://technocore.chat", "lobby")
        with self.assertRaisesRegex(bridge.RetryableError, "malformed technocore note"):
            bridge.kv_get("https://technocore.chat", "topic", "lobby")


if __name__ == "__main__":
    unittest.main()