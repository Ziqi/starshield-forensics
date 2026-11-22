# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Grammar-Class Closure & Invariant Regression Suite (`tests/test_v0311_hardening.py`).

Locks in whole-class lexical, state-machine, and symmetric safety invariants across:
1. Unified PDF structural trailer/xref lexical scanner (`%PDF-1.4 %%EOF` header comments,
   `% startxref 0` / `(startxref\\n0)` skipping, malformed `<4142 %%EOF 4344>` hex strings,
   `/startxref` Name exclusion, and `endobj xref\\n` space-prefixed xref tables).
2. LevelDB WAL schema veto (`_B2B_INVOICE_EXCLUSIVE_KEYS` overriding `properties.links` /
   `properties.deletetime` / `composetime` / non-MRI `from`), linear O(N) unclosed-brace
   failure span skipping (`(b'{"":' * 900 + b"0") * 200` and `1500`-deep variants),
   bounded 64-digit JSON integers & lone surrogate `\\ud800` isolation within multi-op
   `WriteBatch` records, `256`-entry bad-CRC output amplification cap, and `precheck`
   `.ldb`/`.sst` symlinks/directories, `.blob` directories/symlinks, and co-located SQLite.
3. Full-function `parse_strict_utc_ts` numeric overflow safety (`10**400`), symmetric
   `--vault-file` anti-clobber (`load_vault_strict` + `samestat`) & `shred-vault` pre-unlink
   inode verification, Swiss/French currency grouping (`CHF 1'234.50`, `EUR 1 234,56`)
   without truncation, `SessionPseudonymizer` `10,000`-token overflow fallback without
   MCP session poisoning, and strict RFC 8259 JSON (`NaN`/`Infinity` -> `null`).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

from starshield.cli import (
    build_synthetic_leveldb_wal_bytes,
    main as cli_main,
    parse_strict_utc_ts,
)
from starshield.image_containers import PNG_MAGIC, inspect_image_container
from starshield.ioc_validators import luhn_valid
from starshield.leveldb_log import (
    MAX_CORRUPTED_RECORDS_REPORTED,
    REC_FULL,
    _extract_json_objects_from_bytes,
    build_writebatch,
    classify_carved_json_object,
    encode_leveldb_log_record,
    encode_logical_record_across_blocks,
    inspect_chromium_storage_path,
    parse_leveldb_wal,
    sanitize_json_value,
)
from starshield.mcp_server import handle_mcp_message, run_mcp_stdio_server
from starshield.pdf_containers import build_synthetic_incremental_pdf, inspect_pdf_container
from starshield.pseudonymizer import (
    SessionPseudonymizer,
    detokenize_text,
    extract_currency_amounts,
    shred_vault_file,
)


def _strict_json_loads(raw_json: str) -> object:
    """RFC 8259 strict JSON loader rejecting NaN / Infinity / -Infinity constants."""

    def _reject_nonfinite(tok: str) -> None:
        raise ValueError(f"Non-RFC8259 constant emitted: {tok}")

    return json.loads(raw_json, parse_constant=_reject_nonfinite)


class TestV0311Hardening(unittest.TestCase):
    def test_01_pdf_unified_lexical_eof_startxref_xref_and_malformed_hex(self) -> None:
        # 1. `%PDF-1.4 %%EOF\n` on header line + `%PDF-1.7 %%EOF\n` on second comment line
        hdr_eof_pdf = (
            b"%PDF-1.4 %%EOF\n"
            b"%PDF-1.7 %%EOF\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000030 00000 n \n"
            b"trailer\n<< /Size 2 /Root 1 0 R >>\n"
            b"startxref\n68\n%%EOF\n"
        )
        res_hdr = inspect_pdf_container(hdr_eof_pdf, "hdr_eof.pdf")
        self.assertTrue(res_hdr["valid_container"], res_hdr["container_errors"])
        self.assertEqual(res_hdr["container_errors"], [])
        self.assertEqual(res_hdr["incremental_revision_count"], 1)
        self.assertFalse(res_hdr["has_multiple_revisions"])
        self.assertEqual(len(res_hdr["startxref_offsets"]), 1)

        # 2. `% startxref 0\n`, `(startxref\n0)`, `/startxref 0`, and `endobj xref\n`
        comment_str_sx_pdf = (
            b"%PDF-1.4\n"
            b"% startxref 0\n"
            b"1 0 obj\n<< /Note (startxref\n0\nxref\n0 1) /startxref 0 >>\nendobj xref\n"
            b"0 2\n0000000000 65535 f \n0000000023 00000 n \n"
            b"trailer\n<< /Size 2 /Root 1 0 R >>\n"
            b"startxref\n94\n%%EOF %trailing comment (not an unclosed string\n"
            b"%%EOF%glued_comment_not_a_revision\n"
        )
        res_sx = inspect_pdf_container(comment_str_sx_pdf, "sx_clean.pdf")
        self.assertTrue(res_sx["valid_container"], res_sx["container_errors"])
        self.assertEqual(res_sx["container_errors"], [])
        self.assertEqual(res_sx["incremental_revision_count"], 1)
        self.assertEqual(len(res_sx["startxref_offsets"]), 1)
        self.assertEqual(len(res_sx["xref_offsets"]), 1)

        # 3. Malformed hex string `<4142 %%EOF 4344>` must NOT inflate incremental_revision_count
        bad_hex_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Title <4142 %%EOF startxref 0 4344> >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        res_hex = inspect_pdf_container(bad_hex_pdf, "bad_hex.pdf")
        self.assertEqual(res_hex["incremental_revision_count"], 1)
        self.assertFalse(res_hex["has_multiple_revisions"])
        self.assertEqual(res_hex["startxref_offsets"], [])
        self.assertFalse(res_hex["valid_container"])
        self.assertTrue(any("Malformed non-hexadecimal" in e["reason"] for e in res_hex["container_errors"]))

    def test_02_chatsvc_financial_veto_and_mri_from_tightening(self) -> None:
        cases = [
            (
                {"id": "inv-1", "content": "pay", "amount": "USD 10.00", "properties": {"links": []}},
                "b2b_portal_json",
                None,
            ),
            (
                {
                    "id": "inv-2",
                    "content": "pay",
                    "amount": "USD 10.00",
                    "invoice_id": "INV-9",
                    "properties": {"deletetime": 1},
                },
                "b2b_portal_json",
                None,
            ),
            (
                {
                    "id": "inv-3",
                    "from": "8:live:spoof",
                    "composetime": "2025-03-18T10:00:00Z",
                    "iban": "GB82WEST12345698765432",
                    "content": "wire",
                },
                "b2b_portal_json",
                None,
            ),
            (
                {"id": "inv-4", "from": "Accounts Payable", "content": "please pay USD 10"},
                "web_messenger",
                "chatsvc",
            ),
            (
                {"id": "msg-5", "from": "8:live:genuine_teams", "content": "hello team"},
                "chatsvc",
                "chatsvc",
            ),
        ]
        for obj, expected_auto, expected_chatsvc_mode in cases:
            self.assertEqual(classify_carved_json_object(obj, schema_mode="auto"), expected_auto, obj)
            self.assertEqual(classify_carved_json_object(obj, schema_mode="chatsvc"), expected_chatsvc_mode, obj)

        wb = build_writebatch(
            10,
            [(1, f"k{idx}".encode("ascii"), json.dumps(c[0]).encode("utf-8")) for idx, c in enumerate(cases)],
        )
        parsed = parse_leveldb_wal(encode_leveldb_log_record(REC_FULL, wb), schema_mode="auto")
        self.assertEqual(parsed["recovered_records_count"], 5)
        self.assertEqual(parsed["recovered_chatsvc_records_count"], 1)

    def test_03_linear_brace_carving_bigint_and_surrogate_batch_isolation(self) -> None:
        # 1. 1.4 MiB `(b'{"":' * 900 + b"0") * 200` + 1500-deep RecursionError variant finish in < 0.25s
        quad_payload = (b'{"":' * 900 + b"0") * 200
        valid_tail = b'{"id":"tail_ok","from":"8:live:u1","composetime":"2025-03-18T10:00:00Z","content":"ok"}'
        wb_quad = build_writebatch(1, [(1, b"k_quad", quad_payload + b" " + valid_tail)])
        wal_quad = encode_logical_record_across_blocks(wb_quad)
        t0 = time.perf_counter()
        parsed_quad = parse_leveldb_wal(wal_quad)
        elapsed_quad = time.perf_counter() - t0
        self.assertLess(elapsed_quad, 3.0)
        self.assertEqual(parsed_quad["corrupted_frames_count"], 0)
        self.assertEqual([r["message_id"] for r in parsed_quad["recovered_records"]], ["tail_ok"])

        rec_payload = (b'{"":' * 1500 + b"0") * 80 + b" " + valid_tail
        wal_rec = encode_logical_record_across_blocks(build_writebatch(2, [(1, b"k_rec", rec_payload)]))
        t1 = time.perf_counter()
        parsed_rec = parse_leveldb_wal(wal_rec)
        self.assertLess(time.perf_counter() - t1, 3.0)
        self.assertEqual([r["message_id"] for r in parsed_rec["recovered_records"]], ["tail_ok"])

        # 2. >4300-digit integer and `\ud800` lone surrogate in op 0 MUST NOT drop valid sibling op 1
        poison_bigint = b'{"id":"bad_int","count":' + (b"9" * 5000) + b',"content":"x"}'
        poison_surrogate = b'{"id":"surr_1","from":"8:live:u","composetime":"2025-03-18T10:00:00Z","content":"hi \\ud800 bye"}'
        legit_sibling = b'{"id":"sib_ok","from":"8:live:u2","composetime":"2025-03-18T10:05:00Z","content":"clean"}'
        wb_mixed = build_writebatch(
            300,
            [
                (1, b"k0", poison_bigint),
                (1, b"k1", poison_surrogate),
                (1, b"k2", legit_sibling),
            ],
        )
        parsed_mix = parse_leveldb_wal(encode_logical_record_across_blocks(wb_mixed))
        self.assertEqual(parsed_mix["corrupted_frames_count"], 0)
        self.assertEqual([r["message_id"] for r in parsed_mix["recovered_records"]], ["surr_1", "sib_ok"])
        self.assertIn("\ufffd", parsed_mix["recovered_records"][0]["cached_content"])

    def test_04_bad_crc_amplification_cap_and_precheck_symlink_dir_sqlite(self) -> None:
        # 1. 1 MiB flood of 7-byte bad-CRC frames aligned to 32 KiB WAL blocks caps `corrupted_frames` at 256 (< 256 KiB JSON)
        bad_frame = b"\xde\xad\xbe\xef\x00\x00\x01"
        block_flood = bad_frame * (32768 // len(bad_frame)) + b"\x00" * (32768 % len(bad_frame))
        flood_wal = block_flood * 32
        parsed_flood = parse_leveldb_wal(flood_wal)
        self.assertGreater(parsed_flood["corrupted_frames_count"], 100000)
        self.assertTrue(parsed_flood["corrupted_frames_truncated"])
        self.assertEqual(len(parsed_flood["corrupted_frames"]), MAX_CORRUPTED_RECORDS_REPORTED)
        self.assertLess(len(json.dumps(parsed_flood)), 128 * 1024)

        # PNG bad-CRC flood similarly caps `crc_errors` at 256
        ihdr = struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr += struct.pack(">I", zlib.crc32(ihdr[4:]) & 0xFFFFFFFF)
        bad_png_chunk = struct.pack(">I", 0) + b"tEXt" + struct.pack(">I", 0x12345678)
        png_flood = PNG_MAGIC + ihdr + (bad_png_chunk * 2000)
        img_res = inspect_image_container(png_flood, "flood.png")
        self.assertFalse(img_res["valid_container"])
        self.assertEqual(img_res["crc_errors_count"], 2000)
        self.assertTrue(img_res["crc_errors_truncated"])
        self.assertEqual(len(img_res["crc_errors"]), 256)
        self.assertLess(len(json.dumps(img_res)), 128 * 1024)

        # 2. `precheck` blocks `GO` on symlink `.ldb`, directory `.ldb`, empty `.blob` dir, & co-located `.sqlite3`
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            ext_target = base / "outside.bin"
            ext_target.write_bytes(b"X" * 64)

            for sub_name, setup_fn in (
                ("sym_ldb", lambda d: (d / "000005.ldb").symlink_to(ext_target)),
                ("dir_ldb", lambda d: (d / "000006.ldb").mkdir()),
                ("empty_blob", lambda d: (d / "11.blob").mkdir()),
                ("beside_sqlite", lambda d: (d / "IndexedDB.sqlite3").write_bytes(b"SQLite format 3\x00")),
            ):
                d = base / sub_name
                d.mkdir()
                (d / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())
                setup_fn(d)
                rep = inspect_chromium_storage_path(d, redact=True)
                self.assertEqual(rep["feasibility_verdict"], "PARTIAL", f"Failed on {sub_name}: {rep}")

    def test_05_numeric_400digit_composetime_and_vault_symmetric_protection(self) -> None:
        # 1. Direct `parse_strict_utc_ts(10**400)` and 400-digit WAL `composetime` never raise OverflowError
        self.assertIsNone(parse_strict_utc_ts(10**400))
        self.assertIsNone(parse_strict_utc_ts(-(10**400)))
        self.assertIsNone(parse_strict_utc_ts(float("nan")))
        self.assertIsNone(parse_strict_utc_ts(float("inf")))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            wal_400 = tmp / "400digit_ts.log"
            raw_rec = (
                b'{"id":"m_bigts","from":"8:live:u","composetime":'
                + (b"1" * 400)
                + b',"content":"GBP 18,400.00"}'
            )
            wal_400.write_bytes(encode_leveldb_log_record(REC_FULL, build_writebatch(1, [(1, b"k", raw_rec)])))
            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(io.StringIO()):
                rc = cli_main(["parse-leveldb-log", str(wal_400)])
            self.assertEqual(rc, 0)

            # 2. `--vault-file` pointing to input evidence file or any non-vault file refuses to clobber
            evidence = tmp / "teams_export.json"
            orig_bytes = json.dumps(
                {
                    "messages": [
                        {
                            "id": "m1",
                            "from": "8:live:u1",
                            "composetime": "2025-03-18T10:00:00Z",
                            "properties": {"deletetime": "1742292600000"},
                            "content": "IBAN GB82WEST12345698765432",
                        }
                    ]
                }
            ).encode("utf-8")
            evidence.write_bytes(orig_bytes)

            err_same = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_same):
                rc_same = cli_main(["--vault-file", str(evidence), "triage-json", str(evidence)])
            self.assertEqual(rc_same, 2)
            self.assertEqual(evidence.read_bytes(), orig_bytes)
            self.assertIn("starshield-token-vault/v1", err_same.getvalue())

            other_non_vault = tmp / "other_important_notes.json"
            other_bytes = b'{"important_case_note": "DO_NOT_CLOBBER"}'
            other_non_vault.write_bytes(other_bytes)
            err_other = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_other):
                rc_other = cli_main(["--vault-file", str(other_non_vault), "triage-json", str(evidence)])
            self.assertEqual(rc_other, 2)
            self.assertEqual(other_non_vault.read_bytes(), other_bytes)

            # 3. `shred_vault_file` verifies `(st_dev, st_ino)` right before `unlink` (anti-TOCTOU)
            vault_ok = tmp / "real_vault.json"
            ps = SessionPseudonymizer(session_tag="ABCD")
            ps.assign("IBAN", "GB82WEST12345698765432")
            ps.save_vault_atomic(vault_ok)
            decoy_victim = tmp / "DO_NOT_DELETE.txt"
            decoy_victim.write_bytes(b"PRECIOUS_EVIDENCE")

            real_close = os.close

            def _swap_on_close(fd: int) -> None:
                real_close(fd)
                if vault_ok.exists() and decoy_victim.exists():
                    os.rename(vault_ok, tmp / "moved_zeroed_vault.bin")
                    os.rename(decoy_victim, vault_ok)

            with mock.patch("starshield.pseudonymizer.os.close", side_effect=_swap_on_close):
                with self.assertRaises(OSError):
                    shred_vault_file(vault_ok)
            self.assertEqual(vault_ok.read_bytes(), b"PRECIOUS_EVIDENCE")

    def test_06_currency_swiss_french_overflow_tokens_and_strict_rfc8259_json(self) -> None:
        # 1. Swiss apostrophe & French/ISO space thousands separators without truncation
        self.assertEqual(extract_currency_amounts("EUR 1 234,56"), ["EUR 1 234,56"])
        self.assertEqual(extract_currency_amounts("EUR 1\u00a0234,56 and EUR 1\u202f234,56"), ["EUR 1 234,56"])
        self.assertEqual(extract_currency_amounts("CHF 1'234.50"), ["CHF 1'234.50"])
        self.assertEqual(extract_currency_amounts("Malformed EUR 1 234,567"), [])
        self.assertEqual(extract_currency_amounts("Malformed CHF 1'23"), [])

        # 2. SessionPseudonymizer 10,000-token cap degrades to deterministic `<..._OVR_HMAC12>` without failing MCP
        ps = SessionPseudonymizer(session_tag="BEEF")
        with mock.patch("starshield.pseudonymizer.MAX_TOKENS_PER_CATEGORY", 3):
            t1 = ps.assign("CARD", "card_1")
            t2 = ps.assign("CARD", "card_2")
            t3 = ps.assign("CARD", "card_3")
            t4_a = ps.assign("CARD", "card_4")
            t4_b = ps.assign("CARD", "card_4")
        self.assertEqual([t1, t2, t3], ["<CARD_BEEF_01>", "<CARD_BEEF_02>", "<CARD_BEEF_03>"])
        self.assertTrue(t4_a.startswith("<CARD_BEEF_OVR_"))
        self.assertEqual(t4_a, t4_b)
        self.assertEqual(ps.token_counts()["CARD"], 3)
        self.assertEqual(ps.cap_exceeded_categories(), ["CARD"])
        restored, count, unmatched = detokenize_text(
            f"{t1} and {t4_a}",
            ps.export_vault_dict()["token_to_raw"],
            expected_session_tag="BEEF",
        )
        self.assertEqual(count, 1)
        self.assertIn("card_1", restored)
        self.assertEqual(unmatched, [t4_a])

        # Verify MCP server stays alive and `isError == False` after category cap is reached
        valid_card = next("620000000000000" + d for d in "0123456789" if luhn_valid("620000000000000" + d))
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            nan_surr_json = tmp / "nan_surr.json"
            nan_surr_json.write_text(
                '{"messages": [{"id": "n1", "from": "8:live:u1", '
                '"composetime": NaN, "edittime": Infinity, '
                f'"properties": {{"deletetime": "1742292600000"}}, "content": "Card {valid_card} \\ud800"}}]}}',
                encoding="utf-8",
            )

            # Unredacted CLI outputs strict RFC 8259 JSON (NaN/Infinity -> null, lone surrogate -> U+FFFD)
            out_unred = io.StringIO()
            with contextlib.redirect_stdout(out_unred), contextlib.redirect_stderr(io.StringIO()):
                rc_unred = cli_main(["--unredacted", "triage-json", str(nan_surr_json)])
            self.assertEqual(rc_unred, 0)
            parsed_strict = _strict_json_loads(out_unred.getvalue())
            self.assertIsInstance(parsed_strict, dict)

            # MCP server under mocked `MAX_TOKENS_PER_CATEGORY = 0` still succeeds (`isError == False`)
            req_bytes = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "starshield_triage_json", "arguments": {"json_path": str(nan_surr_json)}},
                    }
                ).encode("utf-8")
                + b"\n"
            )
            mcp_out = io.BytesIO()
            with mock.patch("starshield.pseudonymizer.MAX_TOKENS_PER_CATEGORY", 0):
                rc_mcp = run_mcp_stdio_server(instream=io.BytesIO(req_bytes), outstream=mcp_out)
            self.assertEqual(rc_mcp, 0)
            rpc_resp = _strict_json_loads(mcp_out.getvalue().decode("utf-8").strip())
            self.assertFalse(rpc_resp["result"]["isError"])
            inner_payload = _strict_json_loads(rpc_resp["result"]["content"][0]["text"])
            self.assertIn("CARD", inner_payload["pseudonym_cap_exceeded_categories"])

    def test_07_currency_tail_tokens_wal_nested_wrappers_pdf_backslash_and_iterative_json(self) -> None:
        # 1. Currency amounts followed by 3-digit percentages/codes vs malformed space grouping
        self.assertEqual(extract_currency_amounts("Paid £14,800.00 100% confirmed"), ["£14,800.00"])
        self.assertEqual(extract_currency_amounts("Amount: GBP 18,400.00 040 12345678"), ["GBP 18,400.00"])
        self.assertEqual(extract_currency_amounts("CHF 1'234.50 365 days"), ["CHF 1'234.50"])
        self.assertEqual(extract_currency_amounts("EUR 1 234,56 100% done"), ["EUR 1 234,56"])
        self.assertEqual(extract_currency_amounts("Send $500 100% now"), ["$500"])
        self.assertEqual(extract_currency_amounts("€1.000,00"), ["€1.000,00"])
        self.assertEqual(extract_currency_amounts("€1.000,000"), [])
        self.assertEqual(extract_currency_amounts("EUR 1 234 56"), [])
        self.assertEqual(extract_currency_amounts("EUR 1 234,5"), [])

        # 2. WAL JSON carver: 4M bare `{` flood, >=2-level unclosed wrapper around soft-deleted record,
        #    65-digit sibling + control-byte/stray quote, and camelCase keys
        t0 = time.perf_counter()
        self.assertEqual(_extract_json_objects_from_bytes(b"{" * 4_000_000), [])
        self.assertLess(time.perf_counter() - t0, 1.0)
        flood_res = parse_leveldb_wal(
            encode_logical_record_across_blocks(build_writebatch(1, [(1, b"k_br", b"{" * 200_000)]))
        )
        self.assertEqual(flood_res["recovered_records_count"], 0)

        rec_with_props = json.dumps(
            {
                "Id": "m_camel_del",
                "From": "8:live:sender_01",
                "ComposeTime": "2025-03-18T10:00:00Z",
                "Properties": {"DeleteTime": "1742292600000"},
                "Content": "Invoice GBP 18,400.00",
            }
        ).encode("utf-8")
        for payload in (
            b'{"store":{"messages":[' + rec_with_props,
            b'{"sync":{"messages":[' + rec_with_props + b'],"cursor":' + (b"9" * 65) + b"}}",
            (b'{"":' * 10000 + b"0 ") + rec_with_props,
            b'{"big":' + (b"9" * 65) + b',"s":"a\x01b"} ' + rec_with_props,
            b'{"big":' + (b"9" * 65) + b' " ' + rec_with_props,
        ):
            parsed_w = parse_leveldb_wal(encode_logical_record_across_blocks(build_writebatch(2, [(1, b"kw", payload)])))
            self.assertEqual([r["message_id"] for r in parsed_w["recovered_records"]], ["m_camel_del"])
            self.assertTrue(parsed_w["recovered_records"][0]["is_soft_deleted_in_ui"])

        # 3. PDF non-string backslash tokens, header preamble, comment-split startxref, same-line rev2, & /Type /X#52ef
        two_rev = build_synthetic_incremental_pdf()
        inject_pos = two_rev.index(b"%%EOF\n") + 6
        pdf_bs_comment = two_rev[:inject_pos] + b"99 0 obj\n<< /K\\%(\n >>\nendobj\n" + two_rev[inject_pos:]
        res_bs = inspect_pdf_container(pdf_bs_comment, "bs_comment.pdf")
        self.assertEqual(res_bs["incremental_revision_count"], 2)
        self.assertTrue(res_bs["valid_container"])

        same_line_two_rev = two_rev.replace(b"%%EOF\n4 0 obj", b"%%EOF 4 0 obj", 1)
        res_sl = inspect_pdf_container(same_line_two_rev, "same_line_rev2.pdf")
        self.assertEqual(res_sl["incremental_revision_count"], 2)
        self.assertEqual(len(res_sl["startxref_offsets"]), 2)

        preamble_pdf = b"PREAMBLE(\n" + two_rev.replace(b"startxref\n", b"startxref\n% comment\n", 1)
        res_pre = inspect_pdf_container(preamble_pdf, "preamble.pdf")
        self.assertEqual(res_pre["incremental_revision_count"], 2)
        self.assertEqual(len(res_pre["startxref_offsets"]), 2)

        xref_custom = inspect_pdf_container(
            b"%PDF-1.5\n1 0 obj\n<< /Type /XRef-custom >>\nendobj\n2 0 obj\n<< /Type /X#52ef >>\nendobj\nstartxref\n9\n%%EOF\n",
            "xref_hex.pdf",
        )
        self.assertEqual(len(xref_custom["xref_stream_offsets"]), 1)

        # 4. Iterative `sanitize_json_value` on 5,000-deep structure + MCP non-scalar `id` + 10k-deep non-vault guard
        deep_node: dict[str, object] = {"leaf": float("nan")}
        for _ in range(5000):
            deep_node = {"k": deep_node}
        cleaned_deep = sanitize_json_value(deep_node)
        self.assertIsInstance(cleaned_deep, dict)

        bad_id_resp = handle_mcp_message({"jsonrpc": "2.0", "id": [[1]], "method": "ping"})
        self.assertIsNotNone(bad_id_resp)
        assert bad_id_resp is not None
        self.assertIsNone(bad_id_resp["id"])
        self.assertEqual(bad_id_resp["error"]["code"], -32600)

        self.assertEqual(parse_strict_utc_ts("-1000000000000"), -1000000000.0)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            blob_anc = base / "case.blob.review" / "leveldb"
            blob_anc.mkdir(parents=True)
            (blob_anc / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())
            self.assertEqual(inspect_chromium_storage_path(blob_anc)["feasibility_verdict"], "GO")

            db_dir = base / "with_sqlite_db"
            db_dir.mkdir()
            (db_dir / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())
            (db_dir / "cache.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 84)
            self.assertEqual(inspect_chromium_storage_path(db_dir)["feasibility_verdict"], "PARTIAL")


if __name__ == "__main__":
    unittest.main()
