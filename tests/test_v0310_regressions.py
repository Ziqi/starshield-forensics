#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Permanent Regression Suite for `starshield-forensics v0.3.10` (`tests/test_v0310_regressions.py`).

Covers operational resilience, evidentiary accuracy, and container bounds:
  1. Extreme ISO-8601 timezone boundary timestamps (`0001-01-01T00:00:00+01:00`,
     `9999-12-31T23:59:59-01:00`) handled without `OverflowError` across CLI and MCP,
     plus catch-all exception scrubbing without Traceback leakage or MCP process exit.
  2. Unwritable `--vault-file` path resilience in MCP (`vault_persist_warning` emitted,
     response preserved, server stays alive across subsequent RPC calls) and bounded
     single-level `save_vault_atomic` parent creation.
  3. `shred-vault` mandatory `starshield-token-vault/v1` + 4-hex `session_tag` verification
     before overwriting/unlinking (preventing accidental destruction of non-vault files)
     plus `_write_all` loop handling short OS writes.
  4. `extract_currency_amounts` support for ungrouped amounts (`USD 9500`, `GBP 18400.00`,
     `$12345`), European dot-grouped comma-decimal amounts (`€1.000,00`, `EUR 12.500,50`),
     and anti-truncation lookahead.
  5. PDF `incremental_revision_count` lexical `%%EOF` scanner skipping `raw_stream_spans`,
     balanced literal strings `(...)`, hex strings `<...>`, and mid-line `%` comments.
  6. LevelDB `WriteBatch` per-operation `leveldb_sequence_number` progression (`seq + idx`)
     across value puts and `kTypeDeletion` tombstones alongside `leveldb_batch_sequence_number`.
  7. `auto` schema mode routing generic `id` + `content` + `amount` records to `b2b_portal_json`
     rather than `chatsvc`, and keeping `recovered_chatsvc_records_count` strictly scoped to
     `schema_detected == "chatsvc"`.
  8. `precheck` refusing `GO` whenever any `.ldb`/`.sst` file exists (even without 48-byte
     footer magic) or when `MAX_PRECHECK_SCAN_FILES` truncates directory traversal.
  9. PNG `MAX_TOTAL_ICC_DECOMPRESSED_BYTES` (32 MiB) cumulative `iCCP` decompression cap.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from starshield.cli import (  # noqa: E402
    build_synthetic_leveldb_wal_bytes,
    main as cli_main,
    parse_strict_utc_ts,
)
from starshield.image_containers import (  # noqa: E402
    PNG_MAGIC,
    _build_synthetic_icc_bytes,
    inspect_image_container,
)
from starshield.leveldb_log import (  # noqa: E402
    REC_FULL,
    build_writebatch,
    encode_leveldb_log_record,
    inspect_chromium_storage_path,
    parse_leveldb_wal,
)
from starshield.mcp_server import run_mcp_stdio_server  # noqa: E402
from starshield.pdf_containers import (  # noqa: E402
    build_synthetic_incremental_pdf,
    inspect_pdf_container,
)
from starshield.pseudonymizer import (  # noqa: E402
    SessionPseudonymizer,
    _write_all,
    extract_currency_amounts,
    shred_vault_file,
)


class TestV0310Regressions(unittest.TestCase):
    def test_01_extreme_timezone_overflow_and_catchall_masking_cli_and_mcp(self) -> None:
        self.assertIsNone(parse_strict_utc_ts("0001-01-01T00:00:00+01:00"))
        self.assertIsNone(parse_strict_utc_ts("9999-12-31T23:59:59-01:00"))

        with tempfile.TemporaryDirectory() as tmpdir:
            payload = {
                "messages": [
                    {
                        "id": "ext_ts_1",
                        "from": "8:live:sender_01",
                        "composetime": "0001-01-01T00:00:00+01:00",
                        "deletetime": "9999-12-31T23:59:59-01:00",
                        "edittime": "0001-01-01T00:30:00+02:00",
                        "content": "Wire USD 9500 to GB82WEST12345698765432",
                    }
                ],
                "timestamp_pairs": [
                    {
                        "label": "overflow_pair",
                        "start_utc": "0001-01-01T00:00:00+01:00",
                        "end_utc": "9999-12-31T23:59:59-01:00",
                    }
                ],
            }
            json_path = Path(tmpdir) / "CANARY_OVERFLOW_CASE.json"
            json_path.write_text(json.dumps(payload), encoding="utf-8")

            for cli_args in (
                ["triage-json", str(json_path)],
                ["--pseudonymize", "triage-json", str(json_path)],
                ["corroborate-timestamps", str(json_path)],
            ):
                out_b, err_b = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out_b), contextlib.redirect_stderr(err_b):
                    rc = cli_main(cli_args)
                self.assertEqual(rc, 0)
                self.assertEqual(err_b.getvalue(), "")
                self.assertNotIn("Traceback", out_b.getvalue())
                self.assertNotIn("--unredacted", out_b.getvalue())

            # MCP server must handle extreme timestamps and survive unexpected RuntimeError
            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "starshield_triage_json", "arguments": {"json_path": str(json_path)}},
                },
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            ]
            in_b = b"\n".join(json.dumps(r).encode("utf-8") for r in reqs) + b"\n"
            out_s = io.BytesIO()
            self.assertEqual(run_mcp_stdio_server(redact=True, instream=io.BytesIO(in_b), outstream=out_s), 0)
            resps = [json.loads(line) for line in out_s.getvalue().decode("utf-8").strip().splitlines()]
            self.assertEqual(len(resps), 2)
            self.assertFalse(resps[0]["result"]["isError"])
            self.assertEqual(resps[1]["result"], {})

            # Simulate unexpected internal RuntimeError to verify catch-all scrubbing in CLI & MCP
            with mock.patch("starshield.cli.triage_exported_chatsvc_json", side_effect=RuntimeError("SECRET_PATH_99")):
                err_catch = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_catch):
                    rc_err = cli_main(["triage-json", str(json_path)])
                self.assertEqual(rc_err, 2)
                self.assertNotIn("Traceback", err_catch.getvalue())
                self.assertNotIn("SECRET_PATH_99", err_catch.getvalue())

            with mock.patch(
                "starshield.mcp_server.triage_exported_chatsvc_json",
                side_effect=RuntimeError("SECRET_MCP_PATH_88"),
            ):
                out_err_s = io.BytesIO()
                self.assertEqual(run_mcp_stdio_server(redact=True, instream=io.BytesIO(in_b), outstream=out_err_s), 0)
                err_resps = [json.loads(line) for line in out_err_s.getvalue().decode("utf-8").strip().splitlines()]
                self.assertEqual(len(err_resps), 2)
                self.assertTrue(err_resps[0]["result"]["isError"])
                self.assertNotIn("SECRET_MCP_PATH_88", json.dumps(err_resps))
                self.assertEqual(err_resps[1]["result"], {})

    def test_02_mcp_unwritable_vault_preserves_response_and_stays_alive(self) -> None:
        pseudo = SessionPseudonymizer(session_tag="A1B2")
        with tempfile.TemporaryDirectory() as tmpdir:
            # Missing multi-level parent must fail cleanly with OSError (no blind mkdir parents=True)
            deep_missing = Path(tmpdir) / "nonexistent_parent_a" / "nested_b" / "vault.json"
            with self.assertRaises(OSError):
                pseudo.save_vault_atomic(deep_missing)

            # Single-level missing subdir under an existing writable parent is created with 0700
            single_sub = Path(tmpdir) / "private_vault_dir" / "vault.json"
            pseudo.assign("IBAN", "GB82WEST12345698765432")
            pseudo.save_vault_atomic(single_sub)
            self.assertTrue(single_sub.is_file())

            # MCP server with unwritable vault path must emit response + warning and keep serving ping
            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_validate_financial_iocs",
                        "arguments": {"text": "Pay USD 9500 to GB82WEST12345698765432"},
                    },
                },
                {"jsonrpc": "2.0", "id": 11, "method": "ping"},
            ]
            in_b = b"\n".join(json.dumps(r).encode("utf-8") for r in reqs) + b"\n"
            out_s = io.BytesIO()
            rc = run_mcp_stdio_server(
                redact=True,
                vault_file=deep_missing,
                instream=io.BytesIO(in_b),
                outstream=out_s,
            )
            self.assertEqual(rc, 0)
            lines = [json.loads(line) for line in out_s.getvalue().decode("utf-8").strip().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertFalse(lines[0]["result"]["isError"])
            self.assertIn("vault_persist_warning", lines[0]["result"])
            self.assertNotIn("nonexistent_parent_a", json.dumps(lines[0]))
            ioc_body = json.loads(lines[0]["result"]["content"][0]["text"])
            self.assertEqual(ioc_body["extracted_currency_amounts"], ["USD 9500"])
            self.assertEqual(lines[1]["result"], {})

    def test_03_shred_vault_rejects_non_vault_evidence_and_handles_short_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence_txt = Path(tmpdir) / "important_case_evidence.txt"
            original_bytes = b"CRITICAL ORIGINAL EVIDENCE DO NOT OVERWRITE OR DELETE\n"
            evidence_txt.write_bytes(original_bytes)

            fake_json = Path(tmpdir) / "case_export.json"
            fake_json_bytes = json.dumps({"messages": [{"id": "1", "content": "keep me"}]}).encode("utf-8")
            fake_json.write_bytes(fake_json_bytes)

            empty_file = Path(tmpdir) / "empty.json"
            empty_file.write_bytes(b"")

            for non_vault, expected_content in (
                (evidence_txt, original_bytes),
                (fake_json, fake_json_bytes),
                (empty_file, b""),
            ):
                with self.assertRaises(ValueError) as ctx:
                    shred_vault_file(non_vault)
                self.assertIn("starshield-token-vault/v1", str(ctx.exception))
                self.assertTrue(non_vault.exists())
                self.assertEqual(non_vault.read_bytes(), expected_content)

                err_b = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_b):
                    rc = cli_main(["shred-vault", "--vault", str(non_vault)])
                self.assertEqual(rc, 2)
                self.assertIn("starshield-token-vault/v1", err_b.getvalue())
                self.assertTrue(non_vault.exists())
                self.assertEqual(non_vault.read_bytes(), expected_content)

            # Verify `_write_all` loops cleanly when os.write performs partial 7-byte writes
            part_file = Path(tmpdir) / "partial_write_check.bin"
            real_write = os.write

            def _short_write(fd: int, data: bytes | memoryview) -> int:
                return real_write(fd, bytes(data)[:7])

            fd = os.open(str(part_file), os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
            try:
                payload = b"0123456789ABCDEF" * 5
                with mock.patch("starshield.pseudonymizer.os.write", side_effect=_short_write):
                    _write_all(fd, payload)
            finally:
                os.close(fd)
            self.assertEqual(part_file.read_bytes(), payload)

    def test_04_currency_amount_ungrouped_european_and_anti_truncation(self) -> None:
        sample = (
            "Transfer USD 9500 or GBP 18400.00, then USD 9,500.00 and €1.000,00 "
            "plus $12345 and EUR 12.500,50."
        )
        self.assertEqual(
            extract_currency_amounts(sample),
            ["USD 9500", "GBP 18400.00", "USD 9,500.00", "€1.000,00", "$12345", "EUR 12.500,50"],
        )
        # Malformed 3-digit comma decimal must NOT truncate to '€1'
        self.assertEqual(extract_currency_amounts("Malformed €1.000,000 token"), [])

    def test_05_pdf_incremental_revision_count_ignores_streams_strings_and_comments(self) -> None:
        # 1. Stream body containing two `%%EOF` sequences + 1 real trailer `%%EOF`
        stream_body = b"q BT (hello) Tj ET\n%%EOF\nembedded %%EOF payload\nQ"
        pdf_stream_eof = (
            b"%PDF-1.4\n"
            + f"1 0 obj\n<< /Length {len(stream_body)} >>\nstream\n".encode("ascii")
            + stream_body
            + b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        res1 = inspect_pdf_container(pdf_stream_eof, "stream_eof.pdf")
        self.assertTrue(res1["valid_container"])
        self.assertEqual(res1["container_errors"], [])
        self.assertEqual(res1["incremental_revision_count"], 1)
        self.assertFalse(res1["has_multiple_revisions"])
        self.assertEqual(len(res1["eof_offsets"]), 1)

        # 2. `/Producer (saved as %%EOF already)` + comment `% note %%EOF` + hex `<2525454F46>` + 1 real `%%EOF`
        pdf_str_eof = (
            b"%PDF-1.4\n"
            b"% comment mentioning %%EOF in middle of line\n"
            b"1 0 obj\n<< /Producer (saved as %%EOF already \\(inner %%EOF\\)) /Title <2525454F46> >>\nendobj\n"
            b"trailer\n<< /Info 1 0 R >>\n%%EOF\n"
        )
        res2 = inspect_pdf_container(pdf_str_eof, "string_eof.pdf")
        self.assertTrue(res2["valid_container"])
        self.assertEqual(res2["container_errors"], [])
        self.assertEqual(res2["incremental_revision_count"], 1)
        self.assertFalse(res2["has_multiple_revisions"])
        self.assertEqual(len(res2["eof_offsets"]), 1)

        # 3. Genuine 2-revision incremental PDF still counts 2 revisions
        two_rev = build_synthetic_incremental_pdf()
        res3 = inspect_pdf_container(two_rev, "two_rev.pdf")
        self.assertTrue(res3["valid_container"])
        self.assertEqual(res3["incremental_revision_count"], 2)
        self.assertTrue(res3["has_multiple_revisions"])

        # 4. Adversarial unclosed '(' injected between revisions flags unterminated string & trailer mismatch
        first_eof_end = two_rev.index(b"%%EOF\n") + 6
        adv_unclosed_rev = two_rev[:first_eof_end] + b"(\n" + two_rev[first_eof_end:]
        res4 = inspect_pdf_container(adv_unclosed_rev, "adv_unclosed_rev.pdf")
        self.assertFalse(res4["valid_container"])
        err_reasons = " | ".join(e["reason"] for e in res4["container_errors"])
        self.assertIn("Unterminated PDF literal string", err_reasons)
        self.assertIn("Structural trailer mismatch", err_reasons)

    def test_06_writebatch_per_operation_sequence_numbers_with_tombstone(self) -> None:
        m1 = json.dumps({"id": "m1", "from": "8:live:u1", "composetime": "2025-03-18T10:00:00Z", "content": "a"}).encode(
            "utf-8"
        )
        m2 = json.dumps({"id": "m2", "from": "8:live:u1", "composetime": "2025-03-18T10:01:00Z", "content": "b"}).encode(
            "utf-8"
        )
        wb = build_writebatch(
            50,
            [
                (1, b"idb:k1", m1),
                (0, b"idb:k_deleted", b""),
                (1, b"idb:k3", m2),
            ],
        )
        parsed = parse_leveldb_wal(encode_leveldb_log_record(REC_FULL, wb))
        self.assertEqual(parsed["corrupted_frames_count"], 0)
        self.assertEqual(parsed["recovered_records_count"], 2)
        r0, r1 = parsed["recovered_records"]
        self.assertEqual(r0["leveldb_batch_sequence_number"], 50)
        self.assertEqual(r0["leveldb_sequence_number"], 50)
        self.assertEqual(r1["leveldb_batch_sequence_number"], 50)
        self.assertEqual(r1["leveldb_sequence_number"], 52)

    def test_07_auto_schema_invoice_classification_and_chatsvc_count(self) -> None:
        inv_bytes = json.dumps({"id": "inv-1", "content": "please pay", "amount": "USD 10.00"}).encode("utf-8")
        slack_bytes = json.dumps({"client_msg_id": "s1", "text": "hello", "user": "U1", "ts": "1.0"}).encode("utf-8")
        wb = build_writebatch(100, [(1, b"k_inv", inv_bytes), (1, b"k_slk", slack_bytes)])
        parsed = parse_leveldb_wal(encode_leveldb_log_record(REC_FULL, wb), schema_mode="auto")
        self.assertEqual(parsed["recovered_records_count"], 2)
        self.assertEqual(parsed["recovered_chatsvc_records_count"], 0)
        self.assertEqual(
            [r["schema_detected"] for r in parsed["recovered_records"]],
            ["b2b_portal_json", "slack_web"],
        )

        # Adding one genuine chatsvc record increments recovered_chatsvc_records_count to 1 (not 3)
        chat_bytes = json.dumps(
            {"id": "c1", "from": "8:live:alice", "composetime": "2025-03-18T12:00:00Z", "content": "ack"}
        ).encode("utf-8")
        wb3 = build_writebatch(200, [(1, b"k1", inv_bytes), (1, b"k2", slack_bytes), (1, b"k3", chat_bytes)])
        parsed3 = parse_leveldb_wal(encode_leveldb_log_record(REC_FULL, wb3), schema_mode="auto")
        self.assertEqual(parsed3["recovered_records_count"], 3)
        self.assertEqual(parsed3["recovered_chatsvc_records_count"], 1)

    def test_08_precheck_unverified_ldb_and_scan_cap_never_return_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = Path(tmpdir) / "chromium_store"
            store.mkdir()
            (store / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())
            # 64-byte .ldb file WITHOUT LevelDB SSTable footer magic
            (store / "000005.ldb").write_bytes(b"\x00" * 64)

            rep = inspect_chromium_storage_path(store, redact=True)
            self.assertEqual(rep["compacted_sstable_files_detected"], 1)
            self.assertEqual(rep["verified_leveldb_sstables_count"], 0)
            self.assertEqual(rep["carvable_json_records_count"], 2)
            self.assertEqual(rep["feasibility_verdict"], "PARTIAL")

            # Verify MAX_PRECHECK_SCAN_FILES cap stops traversal and downgrades GO -> PARTIAL
            capped_dir = Path(tmpdir) / "capped_store"
            capped_dir.mkdir()
            (capped_dir / "000001.log").write_bytes(build_synthetic_leveldb_wal_bytes())
            for i in range(5):
                (capped_dir / f"extra_{i}.txt").write_bytes(b"pad")
            with mock.patch("starshield.leveldb_log.MAX_PRECHECK_SCAN_FILES", 3):
                rep_cap = inspect_chromium_storage_path(capped_dir, redact=True)
            self.assertTrue(rep_cap["scan_capped_at_max_files"])
            self.assertEqual(rep_cap["feasibility_verdict"], "PARTIAL")

    def test_09_png_cumulative_32mib_iccp_decompression_budget(self) -> None:
        def make_chunk(ctype: bytes, data: bytes) -> bytes:
            crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

        ihdr = make_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        idat = make_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        iend = make_chunk(b"IEND", b"")

        # Each iCCP payload decompresses to ~12 MiB (<= 16 MiB single-chunk limit),
        # so 3 chunks = ~36 MiB > 32 MiB cumulative budget!
        base_icc = _build_synthetic_icc_bytes("Display P3", "APPL")
        padded_12mib = base_icc + (b"\x00" * (12 * 1024 * 1024))
        comp_12mib = zlib.compress(padded_12mib, level=1)
        iccp_chunks = b"".join(
            make_chunk(b"iCCP", f"Prof{idx}".encode("ascii") + b"\x00\x00" + comp_12mib)
            for idx in range(4)
        )
        png_bomb = PNG_MAGIC + ihdr + iccp_chunks + idat + iend

        res = inspect_image_container(png_bomb, "multi_iccp_bomb.png")
        self.assertFalse(res["valid_container"])
        self.assertEqual(len(res["icc_profiles"]), 2)
        self.assertTrue(
            any("Cumulative PNG iCCP decompression exceeded 32 MiB" in e["reason"] for e in res["container_errors"])
        )

        # 2. 40 chunks each >16 MiB single-chunk cap (16 MiB + 4 KiB): failed chunks MUST still
        # deduct from cumulative 32 MiB budget and halt after chunk 2 (never inflating 640 MiB).
        comp_over_16mib = zlib.compress(b"\x00" * (16 * 1024 * 1024 + 4096), level=1)
        over_chunks = b"".join(
            make_chunk(b"iCCP", f"Ov{idx}".encode("ascii") + b"\x00\x00" + comp_over_16mib)
            for idx in range(40)
        )
        png_over_bomb = PNG_MAGIC + ihdr + over_chunks + idat + iend
        real_decompressobj = zlib.decompressobj
        with mock.patch("starshield.image_containers.zlib.decompressobj", wraps=real_decompressobj) as spy_dobj:
            res_over = inspect_image_container(png_over_bomb, "over16_x40_bomb.png")
        self.assertFalse(res_over["valid_container"])
        self.assertEqual(spy_dobj.call_count, 2)
        self.assertTrue(
            any(
                "Cumulative PNG iCCP decompression exceeded 32 MiB" in e["reason"]
                for e in res_over["container_errors"]
            )
        )

        # 3. Exact 32 MiB boundary (2 x 16 MiB valid ICC payloads) succeeds, while +1 byte overflows
        exact_16mib_icc = base_icc + (b"\x00" * (16 * 1024 * 1024 - len(base_icc)))
        comp_exact_16mib = zlib.compress(exact_16mib_icc, level=1)
        two_exact = (
            make_chunk(b"iCCP", b"Ex0\x00\x00" + comp_exact_16mib)
            + make_chunk(b"iCCP", b"Ex1\x00\x00" + comp_exact_16mib)
        )
        res_exact = inspect_image_container(PNG_MAGIC + ihdr + two_exact + idat + iend, "exact_32mib.png")
        self.assertTrue(res_exact["valid_container"])
        self.assertEqual(len(res_exact["icc_profiles"]), 2)

        one_extra = make_chunk(b"iCCP", b"Ex2\x00\x00" + zlib.compress(b"X"))
        res_plus_one = inspect_image_container(
            PNG_MAGIC + ihdr + two_exact + one_extra + idat + iend,
            "plus_one_32mib.png",
        )
        self.assertFalse(res_plus_one["valid_container"])
        self.assertTrue(
            any(
                "Cumulative PNG iCCP decompression exceeded 32 MiB" in e["reason"]
                for e in res_plus_one["container_errors"]
            )
        )

        # 4. Mid-stream corrupt zlib chunks after 10 MiB partial output still charge budget
        comp_10mib_sync = zlib.compressobj(level=1)
        valid_prefix = comp_10mib_sync.compress(b"\x00" * (10 * 1024 * 1024)) + comp_10mib_sync.flush(zlib.Z_SYNC_FLUSH)
        corrupt_10mib = valid_prefix + b"\xff\xff\xff\xff\xff\xff"
        corrupt_chunks = b"".join(
            make_chunk(b"iCCP", f"Cr{idx}".encode("ascii") + b"\x00\x00" + corrupt_10mib)
            for idx in range(6)
        )
        with mock.patch("starshield.image_containers.zlib.decompressobj", wraps=real_decompressobj) as spy_corrupt:
            res_corrupt = inspect_image_container(PNG_MAGIC + ihdr + corrupt_chunks + idat + iend, "corrupt_mid.png")
        self.assertFalse(res_corrupt["valid_container"])
        self.assertLessEqual(spy_corrupt.call_count, 4)
        self.assertTrue(
            any(
                "Cumulative PNG iCCP decompression exceeded 32 MiB" in e["reason"]
                for e in res_corrupt["container_errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()
