from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import SIMCARD.profile_store as profile_store
import SIMCARD.sgp as sgp
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.profile_store import sync_profiles_to_store
from SIMCARD.state import SimProfileEntry
from SIMCARD.utils import tlv

SOURCE_AID = "A0000005591010FFFFFFFF8900001101"
TARGET_AID = "A0000005591010FFFFFFFF8900001102"
SOURCE_ICCID = "89881111111111111111"
TARGET_ICCID = "89881111111111111112"


def _enable_apdu(aid: str) -> bytes:
    request = tlv("BF31", tlv("4F", bytes.fromhex(aid)) + tlv("01", b"\x00"))
    return bytes((0x80, 0xE2, 0x91, 0x00, len(request))) + request


class EnableProfilePersistenceFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self.euicc_root = self.root / "euicc-root"
        self.profile_root = self.root / "profiles"
        self.config_path = self.root / "identity.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "eid": "89049032123451234512345678901235",
                    "root_ci_pkid_hex": "0102030405060708090A0B0C0D0E0F10",
                    "scp03_keys": {
                        "kenc_hex": "11111111111111111111111111111111",
                        "kmac_hex": "11111111111111111111111111111111",
                        "dek_hex": "11111111111111111111111111111111",
                        "kvn": 48,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.engine = self._new_engine()
        self.engine.state.profiles = [
            SimProfileEntry(aid=SOURCE_AID, iccid=SOURCE_ICCID, state="enabled"),
            SimProfileEntry(aid=TARGET_AID, iccid=TARGET_ICCID, state="disabled"),
        ]
        self.engine.state.active_profile_aid = SOURCE_AID
        sync_profiles_to_store(self.engine.state.profile_store_path, self.engine.state.profiles)

    def _new_engine(self) -> SimulatedSimCardEngine:
        return SimulatedSimCardEngine(
            isdr_config_path=str(self.config_path),
            euicc_store_root=str(self.euicc_root),
            profile_store_path=str(self.profile_root),
        )

    def test_enable_persistence_failure_returns_error_and_restores_both_profiles(self) -> None:
        target_manifest = self.profile_root / f"AID_{TARGET_AID}" / "manifest.json"
        write_json = profile_store._write_json_file

        def fail_target_manifest(path: str, value: object) -> None:
            if Path(path) == target_manifest:
                raise OSError("injected target profile manifest write failure")
            write_json(path, value)

        apdu = _enable_apdu(TARGET_AID)
        notifications_before = list(self.engine.state.notifications)
        with mock.patch.object(profile_store, "_write_json_file", side_effect=fail_target_manifest):
            response, sw1, sw2 = self.engine.transmit(apdu)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(
            response,
            bytes.fromhex("BF310380017F"),
            "failed persistence must report undefinedError",
        )
        self.assertEqual(
            [(profile.aid, profile.state) for profile in self.engine.state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )
        self.assertEqual(self.engine.state.notifications, notifications_before)

        reloaded = self._new_engine()
        self.assertEqual(
            [(profile.aid, profile.state) for profile in reloaded.state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )

    def test_unsupported_snapshot_prevents_engine_start_without_overwriting_store(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        profile_store._write_json_file(str(snapshot), {"store_version": 999, "states": {}})
        original = snapshot.read_bytes()

        with self.assertRaises(ValueError):
            self._new_engine()

        self.assertEqual(snapshot.read_bytes(), original)

    def test_malformed_snapshot_prevents_engine_start_without_overwriting_store(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        snapshot.write_bytes(b"{")
        with self.assertRaises(ValueError):
            self._new_engine()
        self.assertEqual(snapshot.read_bytes(), b"{")

    def test_snapshot_with_invalid_state_prevents_engine_start(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        profile_store._write_json_file(
            str(snapshot), {"store_version": 1, "states": {SOURCE_AID: "unknown"}}
        )
        with self.assertRaises(ValueError):
            self._new_engine()

    def test_missing_snapshot_from_migrated_store_prevents_engine_start(self) -> None:
        (self.profile_root / "profile-states.json").unlink()
        with self.assertRaises(ValueError):
            self._new_engine()

    def test_malformed_format_marker_prevents_engine_start_without_overwrite(self) -> None:
        marker = self.profile_root / "profile-states-format.json"
        marker.write_bytes(b"{")
        with self.assertRaises(ValueError):
            self._new_engine()
        self.assertEqual(marker.read_bytes(), b"{")

    def test_snapshot_with_missing_committed_manifest_prevents_engine_start(self) -> None:
        (self.profile_root / f"AID_{TARGET_AID}" / "manifest.json").unlink()
        with self.assertRaises(ValueError):
            self._new_engine()

    def test_profile_directory_read_failure_prevents_engine_start(self) -> None:
        listdir = profile_store.os.listdir

        def fail_profile_listing(path):
            if path == str(self.profile_root):
                raise OSError("injected profile directory read failure")
            return listdir(path)

        with mock.patch.object(profile_store.os, "listdir", side_effect=fail_profile_listing):
            with self.assertRaises(OSError):
                self._new_engine()

    def test_snapshot_commit_failure_preserves_original_profiles(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        write_json = profile_store._write_json_file

        def fail_commit(path: str, value: object) -> None:
            if Path(path) == snapshot:
                raise OSError("injected snapshot commit failure")
            write_json(path, value)

        apdu = _enable_apdu(TARGET_AID)
        with mock.patch.object(profile_store, "_write_json_file", side_effect=fail_commit):
            response, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF310380017F"))
        self.assertEqual(
            [(p.aid, p.state) for p in self._new_engine().state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )

    def test_filesystem_rebuild_failure_preserves_original_profiles(self) -> None:
        rebuild = sgp.rebuild_runtime_filesystem
        calls = 0

        def fail_once(state):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected rebuild failure")
            return rebuild(state)

        apdu = _enable_apdu(TARGET_AID)
        with mock.patch.object(sgp, "rebuild_runtime_filesystem", side_effect=fail_once):
            response, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF310380017F"))
        self.assertEqual(
            [(p.aid, p.state) for p in self.engine.state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )
        self.assertEqual(
            [(p.aid, p.state) for p in self._new_engine().state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )

    def test_notification_generation_failure_rolls_back_switch_and_notification(self) -> None:
        enqueue = self.engine.sgp._enqueue_notification
        notifications_before = list(self.engine.state.notifications)
        sequence_before = self.engine.state.next_notification_seq

        def fail_after_enqueue(*args, **kwargs):
            enqueue(*args, **kwargs)
            raise OSError("injected notification generation failure")

        with mock.patch.object(
            self.engine.sgp, "_enqueue_notification", side_effect=fail_after_enqueue
        ):
            response, sw1, sw2 = self.engine.transmit(_enable_apdu(TARGET_AID))

        self.assertEqual((response, sw1, sw2), (bytes.fromhex("BF310380017F"), 0x90, 0x00))
        expected = [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")]
        self.assertEqual([(p.aid, p.state) for p in self.engine.state.profiles], expected)
        self.assertEqual(self.engine.state.notifications, notifications_before)
        self.assertEqual(self.engine.state.next_notification_seq, sequence_before)
        self.assertEqual([(p.aid, p.state) for p in self._new_engine().state.profiles], expected)

    def test_cleanup_scan_failure_prevents_snapshot_commit(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        snapshot_before = snapshot.read_bytes()
        listdir = profile_store.os.listdir

        def fail_cleanup_listing(path):
            if path == str(self.profile_root):
                raise OSError("injected cleanup directory listing failure")
            return listdir(path)

        apdu = _enable_apdu(TARGET_AID)
        with mock.patch.object(profile_store.os, "listdir", side_effect=fail_cleanup_listing):
            response, sw1, sw2 = self.engine.transmit(apdu)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF310380017F"))
        expected = [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")]
        self.assertEqual([(p.aid, p.state) for p in self.engine.state.profiles], expected)
        self.assertEqual(snapshot.read_bytes(), snapshot_before)
        self.assertEqual([(p.aid, p.state) for p in self._new_engine().state.profiles], expected)

    def test_legacy_store_migrates_preserving_profile_states(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        snapshot.unlink()
        (self.profile_root / "profile-states-format.json").unlink()
        engine = self._new_engine()
        self.assertTrue(snapshot.is_file())
        self.assertEqual(
            [(profile.aid, profile.state) for profile in engine.state.profiles],
            [(SOURCE_AID, "enabled"), (TARGET_AID, "disabled")],
        )

    def test_failed_legacy_snapshot_migration_does_not_start_or_fall_back(self) -> None:
        snapshot = self.profile_root / "profile-states.json"
        marker = self.profile_root / "profile-states-format.json"
        snapshot.unlink()
        marker.unlink()
        write_json = profile_store._write_json_file

        def fail_initial_snapshot(path: str, value: object) -> None:
            if Path(path) == snapshot:
                raise OSError("injected initial snapshot write failure")
            write_json(path, value)

        with mock.patch.object(
            profile_store, "_write_json_file", side_effect=fail_initial_snapshot
        ):
            with self.assertRaises(OSError):
                self._new_engine()
        self.assertTrue(marker.is_file())
        self.assertFalse(snapshot.exists())
        with self.assertRaises(ValueError):
            self._new_engine()

    def test_successful_switch_survives_restart(self) -> None:
        apdu = _enable_apdu(TARGET_AID)
        response, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF3103800100"))
        reloaded = self._new_engine()
        self.assertEqual(
            [(profile.aid, profile.state) for profile in reloaded.state.profiles],
            [(SOURCE_AID, "disabled"), (TARGET_AID, "enabled")],
        )


if __name__ == "__main__":
    unittest.main()
