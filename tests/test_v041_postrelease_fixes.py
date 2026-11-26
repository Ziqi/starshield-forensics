# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Regression & Security Invariant Suite for `starshield-forensics v0.4.1` (`tests/test_v041_postrelease_fixes.py`).

Covers:
  1. Per-substore budget isolation & zero self-deduplication under `active_liveness_truncated` (`TRUE-01`).
  2. Four-state LevelDB store reconciliation (`LIVENESS_INDETERMINATE` on broken `CURRENT`/`MANIFEST`,
     budget truncation, `lost/` target dir, or mid-`MANIFEST` corruption + malformed `WriteBatch`
     counting & active-corruption caveat flags — `TRUE-02`).
  3. Odd/even-aligned `0x00 + UTF-16LE` CJK JSON carving, out-of-the-box `--schema auto` Chromium
     LocalStorage (`_<origin>\\x00\\x01<key>`) extraction across WAL/SSTable/store/`precheck`, and
     `generic_json_records_available` intake guidance (`TRUE-03`).
  4. Chromium IndexedDB leading-varint Blink/V8 header detection (`is_blink_v8_serialized_value`)
     preventing Latin-1 garbage misdecoding on `b"\\x01\\xff\\x14..."` (`TRUE-04`).
  5. IOC precision & recall: case-insensitive IBAN/RF/LEI/explicit-BIC, card prefix Luhn recovery
     before trailing expiry/CVV, horizontal card non-newline bounds, UK sort code space/compact +
     order-number exclusion, and nested `cards`/`blocks`/`wire_details` IOC scanning (`TRUE-05`).
  6. CLI & MCP hardening: `python3 -m starshield`, `detokenize` `args.vault` guard, `--unredacted` +
     `--vault-file` mutual exclusion & MCP warning, cross-call MCP evidence-dir vault guard,
     cross-session vault overwrite protection (`--vault-overwrite`), `0600`/UID vault check, and
     strict ASCII-digit `Content-Length` framing (`TRUE-06`).
  7. Native Slack channel array `[...]` & Microsoft Teams `conversations[].MessageList` JSON exports
     in `triage-json`, plus pure-stdlib zero-UID reproducible `wheel`/`sdist` builds (`TRUE-07`).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT_STR = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT_STR not in sys.path:
    sys.path.insert(0, _REPO_ROOT_STR)

from starshield import __version__  # noqa: E402
from starshield.cli import main as cli_main, triage_exported_chatsvc_json  # noqa: E402
from starshield.ioc_validators import extract_validated_iocs  # noqa: E402
from starshield.leveldb_log import (  # noqa: E402
    REC_FULL,
    SafeDiagnosticError,
    build_writebatch,
    encode_leveldb_log_record,
    inspect_chromium_storage_path,
    is_blink_v8_serialized_value,
    parse_leveldb_wal,
)
from starshield.leveldb_sstable import (  # noqa: E402
    _decode_chromium_string_prefixed,
    build_leveldb_sstable,
    build_version_edit,
    pack_internal_key,
    parse_leveldb_sstable,
    parse_leveldb_store,
)
from starshield.mcp_server import handle_mcp_message, run_mcp_stdio_server  # noqa: E402
from starshield.pseudonymizer import SessionPseudonymizer, load_vault_strict  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestV041PostReleaseFixes(unittest.TestCase):
    def test_01_per_substore_budget_isolation_and_zero_self_dedup_on_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "multi_origin_parent"
            sub_a = root / "01_exhausted.indexeddb.leveldb"
            sub_b = root / "02_healthy.indexeddb.leveldb"
            sub_a.mkdir(parents=True)
            sub_b.mkdir(parents=True)

            entries_a = [
                (
                    f"k_a_{i}".encode("ascii"),
                    100 + i,
                    1,
                    json.dumps({"id": f"a_{i}", "from": "8:live:u1", "content": f"msg {i}"}).encode("utf-8"),
                )
                for i in range(6)
            ]
            (sub_a / "000002.ldb").write_bytes(build_leveldb_sstable(entries_a, compress=True, block_target_bytes=48))
            (sub_b / "000002.ldb").write_bytes(
                build_leveldb_sstable(
                    [(b"k_b_live", 500, 1, b'{"id":"b_ok","from":"8:live:u2","content":"healthy substore"}')],
                    compress=True,
                )
            )

            # Cap per-store op budget to 9 ops (6 index entries + 3 data entries < 6 data entries):
            # sub_a hits budget mid-SSTable (must NOT self-dedup its parsed records to 0, and must mark
            # them LIVENESS_INDETERMINATE), AND sub_b gets a fresh independent budget!
            with mock.patch("starshield.leveldb_sstable.MAX_STORE_RAW_OPS", 9):
                res = parse_leveldb_store(root, redact=False)

            self.assertEqual(res["leveldb_stores_reconciled"], 2)
            by_id = {r["message_id"]: r for r in res["recovered_records"]}
            self.assertIn("b_ok", by_id)
            self.assertEqual(by_id["b_ok"]["retention_state"], "LIVE_ACTIVE")

            sub_a_recs = [r for k, r in by_id.items() if k.startswith("a_")]
            self.assertGreaterEqual(len(sub_a_recs), 1)
            for ra in sub_a_recs:
                self.assertEqual(ra["retention_state"], "LIVENESS_INDETERMINATE")
            self.assertGreaterEqual(res["liveness_indeterminate_records_count"], 1)

    def test_02_liveness_indeterminate_wal_writebatch_corruption_and_lost_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)

            # 1. Malformed WriteBatch inside valid-CRC32C physical WAL frame is counted in store corruption
            wal_bad_dir = td / "bad_wb_store"
            wal_bad_dir.mkdir()
            good_wb = build_writebatch(10, [(1, b"k1", b'{"id":"m1","from":"8:live:u","content":"ok"}')])
            bad_wb_short = b"SHORT"  # <12B header inside valid CRC32C physical frame
            bad_wb_mismatch = struct.pack("<QI", 20, 5) + b"\x00\x01k"  # declared 5 ops, only 1 op
            (wal_bad_dir / "000003.log").write_bytes(
                encode_leveldb_log_record(REC_FULL, good_wb)
                + encode_leveldb_log_record(REC_FULL, bad_wb_short)
                + encode_leveldb_log_record(REC_FULL, bad_wb_mismatch)
            )
            st_wb = parse_leveldb_store(wal_bad_dir, redact=False)
            self.assertEqual(st_wb["corrupted_blocks_or_frames_count"], 2)
            self.assertTrue(st_wb["active_tier_has_unreadable_or_corrupted_regions"])
            self.assertIsNotNone(st_wb["liveness_caveat"])
            self.assertTrue(st_wb["recovered_records"][0].get("unverified_active_corruption_in_store"))

            # 2. Mid-MANIFEST corruption + higher-seq unreferenced SSTable marks key LIVENESS_INDETERMINATE
            mid_man_dir = td / "mid_manifest_corrupt"
            mid_man_dir.mkdir()
            sst1 = build_leveldb_sstable([(b"k_shared", 10, 1, b'{"id":"m_old","from":"8:live:u","content":"v1"}')])
            sst2 = build_leveldb_sstable([(b"k_shared", 90, 0, b"")])
            (mid_man_dir / "000002.ldb").write_bytes(sst1)
            (mid_man_dir / "000007.ldb").write_bytes(sst2)
            ik = pack_internal_key(b"k_shared", 10, 1)
            ve_ok = build_version_edit(
                comparator="leveldb.BytewiseComparator",
                log_number=8,
                next_file_number=9,
                last_sequence=10,
                new_files=[(1, 2, len(sst1), ik, ik)],
            )
            (mid_man_dir / "MANIFEST-000001").write_bytes(
                encode_leveldb_log_record(REC_FULL, ve_ok) + encode_leveldb_log_record(REC_FULL, b"\x63")
            )
            (mid_man_dir / "CURRENT").write_text("MANIFEST-000001\r\n", encoding="utf-8")
            st_mm = parse_leveldb_store(mid_man_dir, redact=False)
            self.assertEqual(st_mm["recovered_records"][0]["retention_state"], "LIVENESS_INDETERMINATE")
            self.assertEqual(inspect_chromium_storage_path(mid_man_dir)["feasibility_verdict"], "PARTIAL")

            # 3. Pointing parse_leveldb_store directly at a `lost` directory marks records LIVENESS_INDETERMINATE
            lost_dir = td / "lost"
            lost_dir.mkdir()
            (lost_dir / "000004.ldb").write_bytes(sst1)
            st_lost = parse_leveldb_store(lost_dir, redact=False)
            self.assertEqual(st_lost["recovered_records"][0]["retention_state"], "LIVENESS_INDETERMINATE")

    def test_03_utf16le_odd_prefix_auto_localstorage_and_blink_varint_guard(self) -> None:
        # 1. 0x00 + UTF-16LE CJK JSON (odd byte alignment) + Blink V8 varint prefix `b"\x01\xff\x14..."`
        cjk_json = {"id": "cjk_1", "from": "8:live:u1", "content": "转账测试 GB82WEST12345698765432"}
        odd_utf16_val = b"\x00" + json.dumps(cjk_json, ensure_ascii=False).encode("utf-16-le")
        idb_varint_v8 = b"\x01\xff\x14" + b"printablePropertyNameInsideBlinkBinaryBlob" * 2

        self.assertTrue(is_blink_v8_serialized_value(idb_varint_v8))
        self.assertIsNone(_decode_chromium_string_prefixed(idb_varint_v8))

        with tempfile.TemporaryDirectory() as tmpdir:
            ls_dir = Path(tmpdir) / "chrome_local_storage"
            ls_dir.mkdir()
            (ls_dir / "000003.ldb").write_bytes(
                build_leveldb_sstable(
                    [
                        (b"_https://portal.example\x00\x00cjk_draft", 10, 1, odd_utf16_val),
                        (b"_https://portal.example\x00\x01plain_token", 11, 1, b"\x01SessionActive=true"),
                        (b"idb:binary:v8", 12, 1, idb_varint_v8),
                    ],
                    compress=True,
                )
            )
            # Default `schema_mode="auto"` extracts BOTH odd-offset UTF-16LE JSON AND LocalStorage KV text,
            # while skipping `b"\x01\xff\x14..."` as Blink V8 binary!
            st_auto = parse_leveldb_store(ls_dir, schema_mode="auto", redact=False)
            self.assertEqual(st_auto["blink_v8_non_json_values_skipped"], 1)
            self.assertEqual(st_auto["recovered_records_count"], 2)
            sst_direct = parse_leveldb_sstable((ls_dir / "000003.ldb").read_bytes(), schema_mode="auto")
            self.assertEqual(sst_direct["recovered_records_count"], 2)
            self.assertEqual(sst_direct["blink_v8_non_json_values_skipped"], 1)
            contents = [r["cached_content"] for r in st_auto["recovered_records"]]
            self.assertTrue(any("转账测试" in c for c in contents))
            self.assertTrue(any("SessionActive=true" in c for c in contents))

            # Verify storage_origin is redacted in default masked mode
            st_masked = parse_leveldb_store(ls_dir, schema_mode="auto", redact=True)
            from starshield.cli import apply_wal_record_redaction

            red_out = apply_wal_record_redaction(st_masked, redact=True)
            self.assertNotIn("portal.example", json.dumps(red_out))

            # WAL with odd-aligned 0x00+UTF-16LE JSON & LocalStorage KV in `auto` mode
            wal_ls = encode_leveldb_log_record(
                REC_FULL,
                build_writebatch(
                    1,
                    [
                        (1, b"_https://app.example\x00\x00u16", odd_utf16_val),
                        (1, b"_https://app.example\x00\x01kv", b"\x01 IBAN GB82WEST12345698765432"),
                    ],
                ),
            )
            wal_res = parse_leveldb_wal(wal_ls, schema_mode="auto")
            self.assertEqual(wal_res["recovered_records_count"], 2)

            # Extension-style generic JSON store reports `generic_json_records_available > 0` & `PARTIAL` in precheck
            ext_dir = Path(tmpdir) / "extension_settings"
            ext_dir.mkdir()
            (ext_dir / "000001.ldb").write_bytes(
                build_leveldb_sstable([(b"ext_state", 1, 1, b'{"theme":"dark","vault_locked":true}')])
            )
            pre_ext = inspect_chromium_storage_path(ext_dir, schema_mode="auto", redact=True)
            self.assertEqual(pre_ext["feasibility_verdict"], "PARTIAL")
            self.assertEqual(pre_ext["generic_json_records_available"], 1)

    def test_04_ioc_case_insensitivity_card_prefix_uk_sort_and_stopwords(self) -> None:
        txt = (
            "1) Lowercase IBAN gb82 west 1234 5698 7654 32 and ref rf18 5390 0754 7034\n"
            "11) Card 4111-1111-1111-1111 06/28 with STERLING FINANCES SHIPMENT REMITTED\n"
            "Sort code 40 47 84, quote order number 70872490 and pay account 12345678\n"
            "Explicit lowercase swift: deutdeff and random ID00IN01 without swift context."
        )
        iocs = extract_validated_iocs(txt, redact=False)
        self.assertIn("GB82WEST12345698765432", iocs["mod97_validated_ibans"])
        self.assertIn("RF18539007547034", iocs["iso11649_creditor_references"])
        self.assertIn("4111111111111111", iocs["luhn_validated_cards"])
        self.assertEqual(iocs["unvalidated_card_candidates"], [])
        self.assertEqual(iocs["validated_swift_bics"], ["DEUTDEFF"])
        self.assertEqual(len(iocs["context_paired_uk_accounts"]), 1)
        self.assertEqual(iocs["context_paired_uk_accounts"][0]["sort_code"], "40-47-84")
        self.assertEqual(iocs["context_paired_uk_accounts"][0]["account_number"], "12345678")

    def test_05_native_slack_array_teams_conversations_and_nested_field_iocs(self) -> None:
        slack_export = [
            {
                "type": "message",
                "subtype": "message_deleted",
                "user": "U0123ABC",
                "ts": "1742292600.000100",
                "text": "See rich block",
                "blocks": [
                    {
                        "type": "rich_text",
                        "elements": [{"type": "text", "text": "Wire to GB82WEST12345698765432"}],
                    }
                ],
            }
        ]
        res_slack = triage_exported_chatsvc_json(slack_export, redact=False)
        self.assertEqual(res_slack["messages_present_in_input"], 1)
        self.assertEqual(res_slack["soft_deleted_messages_in_input"], 1)
        self.assertIn("GB82WEST12345698765432", res_slack["corpus_validated_iocs"]["mod97_validated_ibans"])

        teams_export = {
            "userId": "8:orgid:abc",
            "conversations": [
                {
                    "id": "19:chat_01@thread.v2",
                    "MessageList": [
                        {
                            "id": "1742292700000",
                            "from": None,
                            "imdisplayname": "External Supplier",
                            "originalarrivaltime": "2025-03-18T10:05:00Z",
                            "content": "Card approval",
                            "properties": {
                                "deletetime": 1742292900000,
                                "cards": [{"beneficiary_iban": "NO9386011117947"}],
                            },
                        }
                    ],
                }
            ],
        }
        res_teams = triage_exported_chatsvc_json(teams_export, redact=False)
        self.assertEqual(res_teams["messages_present_in_input"], 1)
        self.assertEqual(res_teams["soft_deleted_messages_in_input"], 1)
        self.assertEqual(res_teams["soft_deleted_records"][0]["sender_mri"], "External Supplier")
        self.assertEqual(res_teams["soft_deleted_records"][0]["compose_time"], "2025-03-18T10:05:00Z")
        self.assertIn("NO9386011117947", res_teams["corpus_validated_iocs"]["mod97_validated_ibans"])

    def test_06_cli_module_entrypoint_vault_guards_and_mcp_cross_call_protection(self) -> None:
        # 1. `python3 -m starshield --version` works via `starshield/__main__.py`
        proc = subprocess.run(
            [sys.executable, "-m", "starshield", "--version"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(proc.stdout.strip(), f"starshield-forensics {__version__}")

        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            ev_dir = td / "evidence_dir"
            ev_dir.mkdir()
            (ev_dir / "000001.ldb").write_bytes(
                build_leveldb_sstable([(b"k", 1, 1, b'{"id":"1","from":"8:live:u","content":"hi"}')])
            )

            # 2. `--unredacted` + `--vault-file` rejected in CLI & MCP; `--unredacted` MCP initialize warns
            err_b = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_b):
                rc_u = cli_main(["--unredacted", "--vault-file", str(td / "v.json"), "demo"])
            self.assertEqual(rc_u, 2)

            init_unred = handle_mcp_message(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                redact=False,
            )
            assert init_unred is not None
            self.assertIn("UNREDACTED LAB MODE", init_unred["result"]["instructions"])

            # 3. Cross-session vault overwrite blocked unless `--vault-overwrite` is passed; 0644 vault rejected
            v_file = td / "case_vault.json"
            p1 = SessionPseudonymizer()
            p1.assign("IBAN", "GB82WEST12345698765432")
            p1.save_vault_atomic(v_file)

            p2 = SessionPseudonymizer()
            p2.assign("IBAN", "NO9386011117947")
            with self.assertRaises(SafeDiagnosticError):
                p2.save_vault_atomic(v_file)
            p2.save_vault_atomic(v_file, allow_overwrite=True)

            if os.name == "posix":
                os.chmod(v_file, 0o644)
                with self.assertRaises(SafeDiagnosticError):
                    load_vault_strict(v_file)
                os.chmod(v_file, 0o600)

            # 4. `detokenize` guards `args.vault` against aliasing `args.input`, and CLI rejects option abbreviations (`--unred`)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc_same = cli_main(["detokenize", "--vault", str(v_file), "--input", str(v_file)])
                with self.assertRaises(SystemExit) as cm_abbrev:
                    cli_main(["--unred", "demo"])
            self.assertEqual(rc_same, 2)
            self.assertEqual(cm_abbrev.exception.code, 2)

            # 5. MCP cross-call evidence directory protection + non-dict `params` safety + strict Content-Length
            inside_vault = ev_dir / "mcp_inside_vault.json"
            mcp_reqs = [
                # Non-dict `params` must return -32602 without crashing vault block
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["bad"]},
                # Call #1 accesses `ev_dir` (0 tokens) -> blocked immediately because `inside_vault` sits inside `ev_dir`!
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "starshield_precheck_leveldb", "arguments": {"target_path": str(ev_dir)}},
                },
                # Call #2 has no path arg (emits token), STILL blocked because `ev_dir` stays in `seen_target_paths`!
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_validate_financial_iocs",
                        "arguments": {"text": "GB82WEST12345698765432"},
                    },
                },
            ]
            in_raw = b"\n".join(json.dumps(r).encode("utf-8") for r in mcp_reqs) + b"\n"
            out_raw = io.BytesIO()
            self.assertEqual(
                run_mcp_stdio_server(redact=True, vault_file=inside_vault, instream=io.BytesIO(in_raw), outstream=out_raw),
                0,
            )
            resps = [json.loads(line) for line in out_raw.getvalue().decode("utf-8").strip().splitlines()]
            self.assertEqual(resps[0]["error"]["code"], -32602)
            self.assertTrue(resps[1]["result"]["isError"])
            self.assertTrue(resps[2]["result"]["isError"])
            self.assertFalse(inside_vault.exists())

            # `+2` signed Content-Length rejected cleanly
            bad_cl_out = io.BytesIO()
            self.assertEqual(
                run_mcp_stdio_server(instream=io.BytesIO(b"Content-Length: +2\r\n\r\n{}"), outstream=bad_cl_out),
                0,
            )
            cl_body = bad_cl_out.getvalue().decode("utf-8").split("\r\n\r\n", 1)[1]
            self.assertEqual(json.loads(cl_body)["error"]["code"], -32700)

    def test_07_reproducible_wheel_and_zero_uid_sdist_builder(self) -> None:
        from scripts.build_reproducible import (
            FIXED_EPOCH,
            build_deterministic_pyz,
            build_deterministic_sdist,
            build_deterministic_wheel,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            pyz1 = td / "a.pyz"
            pyz2 = td / "b.pyz"
            whl1 = td / f"starshield_forensics-{__version__}-py3-none-any.whl"
            whl2 = td / "second.whl"
            sd1 = td / f"starshield_forensics-{__version__}.tar.gz"
            sd2 = td / "second.tar.gz"

            self.assertEqual(build_deterministic_pyz(pyz1), build_deterministic_pyz(pyz2))
            self.assertEqual(build_deterministic_wheel(whl1), build_deterministic_wheel(whl2))
            self.assertEqual(build_deterministic_sdist(sd1), build_deterministic_sdist(sd2))

            with tarfile.open(sd1, mode="r:gz") as tf:
                names = tf.getnames()
                self.assertIn(f"starshield_forensics-{__version__}/starshield/__main__.py", names)
                for ti in tf.getmembers():
                    self.assertEqual(ti.uid, 0)
                    self.assertEqual(ti.gid, 0)
                    self.assertEqual(ti.uname, "")
                    self.assertEqual(ti.gname, "")
                    self.assertEqual(int(ti.mtime), FIXED_EPOCH)

    def test_08_missing_active_sstables_manifestless_lost_utf16_0xff_and_store_record_cap(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)

            # 1. Partial acquisition missing MANIFEST-referenced active SSTable -> LIVENESS_INDETERMINATE + caveat
            partial_dir = td / "partial_store"
            partial_dir.mkdir()
            sst5 = build_leveldb_sstable(
                [(b"k_del", 10, 1, b'{"id":"mA","from":"8:live:u","content":"deleted in missing L0"}')]
            )
            (partial_dir / "000005.ldb").write_bytes(sst5)
            ik_p = pack_internal_key(b"k_del", 10, 1)
            ve_partial = build_version_edit(
                comparator="idb_cmp1",
                new_files=[
                    (1, 5, len(sst5), ik_p, ik_p),
                    (0, 7, 256, ik_p, ik_p),  # 000007.ldb missing from disk!
                ],
            )
            (partial_dir / "MANIFEST-000002").write_bytes(encode_leveldb_log_record(REC_FULL, ve_partial))
            (partial_dir / "CURRENT").write_text("MANIFEST-000002\n", encoding="utf-8")

            st_part = parse_leveldb_store(partial_dir, redact=False)
            self.assertTrue(st_part["active_tier_has_unreadable_or_corrupted_regions"])
            self.assertIsNotNone(st_part["liveness_caveat"])
            self.assertGreaterEqual(st_part["corrupted_blocks_or_frames_count"], 1)
            self.assertEqual(st_part["live_active_records_count"], 0)
            self.assertEqual(st_part["liveness_indeterminate_records_count"], 1)
            self.assertEqual(st_part["recovered_records"][0]["retention_state"], "LIVENESS_INDETERMINATE")
            self.assertEqual(inspect_chromium_storage_path(partial_dir)["feasibility_verdict"], "PARTIAL")
            st_part_masked = parse_leveldb_store(partial_dir, redact=True)
            self.assertNotIn("000007", json.dumps(st_part_masked))

            # 1b. Missing MANIFEST-referenced active WAL (`log_number=9`) -> LIVENESS_INDETERMINATE + zero masked file-num leak
            miss_wal_dir = td / "missing_active_wal"
            miss_wal_dir.mkdir()
            (miss_wal_dir / "000005.ldb").write_bytes(sst5)
            ve_mwal = build_version_edit(
                comparator="leveldb.BytewiseComparator",
                log_number=9,
                next_file_number=10,
                last_sequence=20,
                new_files=[(1, 5, len(sst5), ik_p, ik_p)],
            )
            (miss_wal_dir / "MANIFEST-000002").write_bytes(encode_leveldb_log_record(REC_FULL, ve_mwal))
            (miss_wal_dir / "CURRENT").write_text("MANIFEST-000002\n", encoding="utf-8")
            st_mwal = parse_leveldb_store(miss_wal_dir, redact=True)
            self.assertTrue(st_mwal["active_tier_has_unreadable_or_corrupted_regions"])
            self.assertIsNotNone(st_mwal["liveness_caveat"])
            self.assertGreaterEqual(st_mwal["corrupted_blocks_or_frames_count"], 1)
            self.assertEqual(st_mwal["live_active_records_count"], 0)
            self.assertEqual(st_mwal["liveness_indeterminate_records_count"], 1)
            self.assertNotIn("000009", json.dumps(st_mwal))
            self.assertEqual(inspect_chromium_storage_path(miss_wal_dir)["feasibility_verdict"], "PARTIAL")

            # 2. MANIFEST-less store with `lost/` orphans: `lost/` never becomes LIVE_ACTIVE or suppresses root
            no_man_dir = td / "no_manifest_with_lost"
            (no_man_dir / "lost").mkdir(parents=True)
            (no_man_dir / "000002.ldb").write_bytes(
                build_leveldb_sstable(
                    [
                        (b"k1", 10, 1, b'{"id":"root_m1","from":"8:live:u","content":"root active 1"}'),
                        (b"k2", 10, 1, b'{"id":"root_m2","from":"8:live:u","content":"root active 2"}'),
                    ]
                )
            )
            (no_man_dir / "lost" / "000009.ldb").write_bytes(
                build_leveldb_sstable(
                    [
                        (b"k1", 20, 1, b'{"id":"lost_m1","from":"8:live:u","content":"orphan newer seq"}'),
                        (b"k2", 20, 0, b""),
                        (b"k3", 20, 1, b'{"id":"lost_only","from":"8:live:u","content":"only in lost"}'),
                    ]
                )
            )
            st_nm = parse_leveldb_store(no_man_dir, redact=False)
            nm_by_id = {r["message_id"]: r for r in st_nm["recovered_records"]}
            self.assertEqual(nm_by_id["root_m1"]["retention_state"], "LIVE_ACTIVE")
            self.assertEqual(nm_by_id["root_m2"]["retention_state"], "LIVE_ACTIVE")
            self.assertFalse(nm_by_id["root_m2"]["superseded_by_tombstone"])
            self.assertEqual(nm_by_id["lost_m1"]["retention_state"], "TOMBSTONED_HISTORICAL_RECOVERED")
            self.assertEqual(nm_by_id["lost_only"]["retention_state"], "TOMBSTONED_HISTORICAL_RECOVERED")

            # 3. 0x00 + UTF-16LE starting with low byte 0xFF (`U+4EFF` '仿', `U+5BFF` '寿') + 1-char LocalStorage key
            utf16_fang = b"\x00" + "仿冒客服索要验证码".encode("utf-16-le")
            utf16_shou = b"\x00" + "寿险理赔异常链接".encode("utf-16-le")
            self.assertFalse(is_blink_v8_serialized_value(utf16_fang))
            self.assertFalse(is_blink_v8_serialized_value(utf16_shou))
            dom_dir = td / "dom_0xff_lowbyte"
            dom_dir.mkdir()
            (dom_dir / "000001.ldb").write_bytes(
                build_leveldb_sstable(
                    [
                        (b"_https://app.example\x00\x01c", 1, 1, utf16_fang),
                        (b"_https://app.example\x00\x01note", 2, 1, utf16_shou),
                    ]
                )
            )
            st_dom = parse_leveldb_store(dom_dir, schema_mode="auto", redact=False)
            self.assertEqual(st_dom["blink_v8_non_json_values_skipped"], 0)
            self.assertEqual(st_dom["recovered_records_count"], 2)
            dom_by_id = {r["message_id"]: r["cached_content"] for r in st_dom["recovered_records"]}
            self.assertIn("c", dom_by_id)
            self.assertNotIn("\x01", dom_by_id["c"])
            self.assertIn("仿冒客服", dom_by_id["c"])
            self.assertIn("寿险理赔", dom_by_id["note"])

            # 4. Store recovered-record cap + `recovered_records_truncated` flag
            cap_dir = td / "record_cap_store"
            cap_dir.mkdir()
            many_ops = [
                (b"k_" + str(i).encode("ascii"), i + 1, 1, f'{{"id":"m{i}","from":"8:live:u","content":"x"}}'.encode())
                for i in range(12)
            ]
            (cap_dir / "000001.ldb").write_bytes(build_leveldb_sstable(many_ops))
            with mock.patch("starshield.leveldb_sstable.MAX_STORE_RECOVERED_RECORDS", 5):
                st_capped = parse_leveldb_store(cap_dir, redact=False)
            self.assertEqual(st_capped["recovered_records_count"], 5)
            self.assertTrue(st_capped["recovered_records_truncated"])

            # 5. Hardlinked multi-directory precheck finishes rapidly with single-pass generic fallback count
            hl_root = td / "hl_precheck"
            base_sst = build_leveldb_sstable(
                [(b"custom_k", 1, 1, b'{"custom_flag":"enabled","port":8080}')],
                compress=True,
            )
            src_sst = td / "seed.ldb"
            src_sst.write_bytes(base_sst)
            for idx_d in range(8):
                sub_d = hl_root / f"sub_{idx_d:02d}"
                sub_d.mkdir(parents=True)
                os.link(src_sst, sub_d / "000001.ldb")
            pre_hl = inspect_chromium_storage_path(hl_root, schema_mode="auto")
            self.assertEqual(pre_hl["feasibility_verdict"], "PARTIAL")
            self.assertEqual(pre_hl["generic_json_records_available"], 8)

    def test_09_ioc_linear_scaling_adjacent_ibans_uk_sort_card_and_vault_link_dotdot(self) -> None:
        import time

        from starshield.mcp_server import MCP_TOOLS

        # 1. Adjacent IBANs, UK postcode before IBAN, RF + trailing date/words, UK sort+account vs Luhn card, BIC stopwords
        adj = extract_validated_iocs(
            "Payee: London SW19 5AE IBAN gb82 west 1234 5698 7654 32 GB33 BUKB 2020 1555 5555 55",
            redact=False,
        )
        self.assertEqual(adj["mod97_validated_ibans"], ["GB82WEST12345698765432", "GB33BUKB20201555555555"])

        for suf in ("due 30 Nov", "due 01 Dec", "on 2026", "by 5pm", "inv 1234", "ASAP 12"):
            rf_res = extract_validated_iocs(f"Please pay ref RF18 5390 0754 7034 {suf}", redact=False)
            self.assertEqual(rf_res["iso11649_creditor_references"], ["RF18539007547034"])

        uk_luhn = extract_validated_iocs("Sort code 40-00-02 31926819", redact=False)
        self.assertEqual(uk_luhn["luhn_validated_cards"], [])
        self.assertEqual(uk_luhn["unvalidated_card_candidates"], [])
        self.assertEqual(len(uk_luhn["context_paired_uk_accounts"]), 1)
        self.assertEqual(uk_luhn["context_paired_uk_accounts"][0]["sort_code"], "40-00-02")
        self.assertEqual(uk_luhn["context_paired_uk_accounts"][0]["account_number"], "31926819")

        for bic_fp_text in ("SWIFT MESSAGES queue", "swift recovery plan", "swift: progress update"):
            self.assertEqual(extract_validated_iocs(bic_fp_text, redact=False)["validated_swift_bics"], [])

        # 2. Sub-second O(N log N) span scaling & O(N) hyphen-chain scaling (`GB00-...` / `RF00-...`),
        #    plus card recovery adjacent to claimed date/IBAN and leading quantity prefix
        t0 = time.perf_counter()
        dense_text = "GB82WEST12345698765432,DEUTDEFF;123456789 " * 6000
        dense_res = extract_validated_iocs(dense_text, redact=False)
        self.assertLess(time.perf_counter() - t0, 2.0)
        self.assertEqual(dense_res["mod97_validated_ibans"], ["GB82WEST12345698765432"])

        t_hyph = time.perf_counter()
        self.assertEqual(extract_validated_iocs("GB00-" * 25000 + "GB00", redact=False)["mod97_validated_ibans"], [])
        self.assertEqual(
            extract_validated_iocs("RF00-" * 25000 + "RF00", redact=False)["iso11649_creditor_references"], []
        )
        self.assertLess(time.perf_counter() - t_hyph, 2.0)

        c_date = extract_validated_iocs("card 4111 1111 1111 1111 01-12-26", redact=False)
        self.assertEqual(c_date["luhn_validated_cards"], ["4111111111111111"])
        self.assertEqual(c_date["unpaired_uk_sort_codes"], ["01-12-26"])

        c_iban45 = extract_validated_iocs("IBAN GB22 WEST 1234 5698 7654 45 4111 1111 1111 1111", redact=False)
        self.assertEqual(c_iban45["mod97_validated_ibans"], ["GB22WEST12345698765445"])
        self.assertEqual(c_iban45["luhn_validated_cards"], ["4111111111111111"])

        c_qty = extract_validated_iocs("qty 45 4111 1111 1111 1111", redact=False)
        self.assertEqual(c_qty["luhn_validated_cards"], ["4111111111111111"])
        self.assertEqual(c_qty["unvalidated_card_candidates"], [])

        c_ib_ccy = extract_validated_iocs("IBAN GB82WEST12345698765432-GBP", redact=False)
        self.assertEqual(c_ib_ccy["mod97_validated_ibans"], ["GB82WEST12345698765432"])

        # 3. Triage skips `clientmessageid` as Luhn card, scans >140 fields, and merges `messages` + `conversations`
        triage_msg: dict[str, object] = {
            "clientmessageid": "4740235624843217002",
            "content": "ok see you tomorrow",
        }
        for idx_f in range(150):
            triage_msg[f"f_{idx_f:03d}"] = f"val_{idx_f}"
        triage_msg["zz_beneficiary_iban"] = "GB82WEST12345698765432"
        hybrid_payload = {
            "messages": [triage_msg],
            "conversations": [{"MessageList": [{"id": "c2", "content": "Backup GB33BUKB20201555555555"}]}],
        }
        tri_res = triage_exported_chatsvc_json(hybrid_payload, redact=False)
        self.assertEqual(tri_res["messages_present_in_input"], 2)
        self.assertFalse(tri_res["structured_field_scan_truncated"])
        self.assertEqual(tri_res["corpus_validated_iocs"]["luhn_validated_cards"], [])
        self.assertEqual(
            tri_res["corpus_validated_iocs"]["mod97_validated_ibans"],
            ["GB82WEST12345698765432", "GB33BUKB20201555555555"],
        )

        # 4. Vault `link/..` symlink traversal, numbered LevelDB sibling guard, and non-tokenizing subcommand guard
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            ev = td / "evidence"
            (ev / "sub").mkdir(parents=True)
            (td / "safe").mkdir()
            (ev / "000003.log").write_bytes(
                encode_leveldb_log_record(
                    REC_FULL,
                    build_writebatch(1, [(1, b"k", b'{"id":"1","from":"8:live:u","content":"hi"}')]),
                )
            )
            (td / "safe" / "link").symlink_to(ev / "sub")

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    cli_main(["--vault-file", str(td / "safe" / "link" / ".." / "v2.json"), "parse-leveldb-store", str(ev)]),
                    2,
                )
                self.assertEqual(
                    cli_main(["--vault-file", str(ev / "v3.json"), "parse-leveldb-log", str(ev / "000003.log")]),
                    2,
                )
                self.assertEqual(
                    cli_main(["--vault-file", str(td / "safe" / "v4.json"), "demo"]),
                    2,
                )
            self.assertFalse((ev / "v2.json").exists())
            self.assertFalse((ev / "v3.json").exists())

        # 5. MCP `tools/list` uses 8-hex `XXXXXXXX` placeholders; 5000-digit & duplicate Content-Length rejected
        for tool_def in MCP_TOOLS:
            self.assertNotIn("_XXXX_", tool_def["description"])

        huge_cl_out = io.BytesIO()
        self.assertEqual(
            run_mcp_stdio_server(
                instream=io.BytesIO(b"Content-Length: " + (b"9" * 5000) + b"\r\n\r\n{}"),
                outstream=huge_cl_out,
            ),
            0,
        )
        self.assertIn(b"-32700", huge_cl_out.getvalue())

        dup_cl_out = io.BytesIO()
        ping_b = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        dup_frame = f"Content-Length: {len(ping_b)}\r\nContent-Length: 9999\r\n\r\n".encode("ascii") + ping_b
        self.assertEqual(
            run_mcp_stdio_server(instream=io.BytesIO(dup_frame), outstream=dup_cl_out),
            0,
        )
        self.assertIn(b"-32600", dup_cl_out.getvalue())


if __name__ == "__main__":
    unittest.main()
