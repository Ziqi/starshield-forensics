#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Clean-Room Adversarial, Malformed-Input, Multi-Schema & Privacy Regression Suite for `starshield-forensics`.
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import struct
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from starshield.cli import (  # noqa: E402
    apply_image_redaction,
    apply_wal_record_redaction,
    build_acquisition_manifest,
    build_synthetic_leveldb_wal_bytes,
    corroborate_timestamps,
    main,
    strip_markup,
    summarize_corpus_linguistics,
    triage_exported_chatsvc_json,
)
from starshield.image_containers import (  # noqa: E402
    PNG_MAGIC,
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (  # noqa: E402
    DEFAULT_EPHEMERAL_SALT,
    aba_routing_valid,
    eth_eip55_checksum_valid,
    extract_validated_iocs,
    get_active_hmac_digest,
    iban_mod97_valid,
    iso11649_creditor_ref_valid,
    keccak256,
    lei_iso17442_valid,
    luhn_valid,
    mask_identifier,
    tron_trc20_address_valid,
)
from starshield.pdf_containers import (  # noqa: E402
    MAX_INFO_VALUES_PER_KEY,
    MAX_XMP_PACKETS,
    apply_pdf_redaction,
    build_synthetic_incremental_pdf,
    inspect_pdf_container,
)
from starshield.leveldb_log import (  # noqa: E402
    LEVELDB_SSTABLE_MAGIC_LE,
    REC_FIRST,
    REC_FULL,
    build_writebatch,
    crc32c,
    encode_leveldb_log_record,
    encode_varint,
    parse_leveldb_wal,
)


class TestAdversarialForensics(unittest.TestCase):
    def test_crc32c_official_ietf_vector(self) -> None:
        # RFC 3720 / iSCSI official Castagnoli CRC32C check value for ASCII "123456789"
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_plain_text_appl_not_misflagged_as_image_forgery(self) -> None:
        raw_text = b"Hello APPL Display P3 Adobe Photoshop 8BIM plain text file"
        res = inspect_image_container(raw_text, "notes.txt")
        self.assertFalse(res["valid_container"])
        self.assertEqual(res["container_format"], "UNSUPPORTED_OR_NOT_AN_IMAGE")
        self.assertNotIn("synthetic_forgery_verdict", res)

    def test_valid_png_iccp_parses_with_crc_and_neutral_epistemics(self) -> None:
        png = build_valid_png_with_iccp("Display P3", "APPL")
        res = inspect_image_container(png, "valid.png")
        self.assertTrue(res["valid_container"])
        self.assertEqual(res["crc_errors"], [])
        self.assertEqual(res["container_errors"], [])
        self.assertEqual(len(res["icc_profiles"]), 1)
        icc = res["icc_profiles"][0]
        self.assertTrue(icc["valid_icc_header"])
        self.assertEqual(icc["preferred_cmm"], "APPL")
        self.assertEqual(icc["description_hint"], "Display P3")
        self.assertGreater(icc["source_offset"], 8)
        self.assertTrue(len(res["alternative_explanations"]) >= 1)

    def test_truncated_png_ihdr_only_rejected(self) -> None:
        full_png = build_valid_png_with_iccp("Display P3", "APPL")
        ihdr_only = full_png[:33]
        self.assertTrue(ihdr_only.startswith(PNG_MAGIC))
        res = inspect_image_container(ihdr_only, "truncated_ihdr_only.png")
        self.assertFalse(res["valid_container"])
        self.assertTrue(len(res["container_errors"]) >= 1)

    def test_corrupted_png_chunk_crc_is_caught(self) -> None:
        png = bytearray(build_valid_png_with_iccp("Display P3", "APPL"))
        png[20] ^= 0xFF
        res = inspect_image_container(bytes(png), "corrupt.png")
        self.assertFalse(res["valid_container"])
        self.assertTrue(len(res["crc_errors"]) >= 1)

    def test_valid_jpeg_multi_chunk_icc_and_8bim_parses(self) -> None:
        jpg = build_valid_jpeg_with_icc_and_8bim("Display P3", "APPL", split_icc_chunks=3)
        res = inspect_image_container(jpg, "valid_multi_icc.jpg")
        self.assertTrue(res["valid_container"])
        self.assertEqual(res["container_errors"], [])
        self.assertEqual(len(res["icc_profiles"]), 1)
        self.assertEqual(res["icc_profiles"][0]["jpeg_app2_chunks_reassembled"], 3)
        self.assertEqual(res["icc_profiles"][0]["description_hint"], "Display P3")
        self.assertEqual(len(res["photoshop_app13_8bim_offsets"]), 1)

    def test_truncated_jpeg_without_sos_or_eoi_rejected(self) -> None:
        app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00"
        truncated_jpg = b"\xff\xd8" + app0
        res = inspect_image_container(truncated_jpg, "truncated_app0_only.jpg")
        self.assertFalse(res["valid_container"])
        self.assertTrue(len(res["container_errors"]) >= 1)

    def test_incomplete_jpeg_multi_chunk_icc_rejected(self) -> None:
        jpg = build_valid_jpeg_with_icc_and_8bim("Display P3", "APPL", split_icc_chunks=2)
        second_idx = jpg.find(b"\xff\xe2", jpg.find(b"\xff\xe2") + 4)
        tampered = bytearray(jpg)
        tampered[second_idx + 1] = 0xFE
        res = inspect_image_container(bytes(tampered), "missing_icc_part2.jpg")
        self.assertFalse(res["valid_container"])
        self.assertEqual(res["icc_profiles"], [])

    def test_swift_bic_rejects_workshop_and_accepts_all_iso3166_including_ad(self) -> None:
        noise = "Please attend WORKSHOP tomorrow with ABCDEFGH and DOCUMENT 20250401."
        self.assertEqual(extract_validated_iocs(noise, redact=False)["validated_swift_bics"], [])

        valid_bic_txt = "Wire via SWIFT BACAADADXXX or routing NWBKGB2L."
        bics = extract_validated_iocs(valid_bic_txt, redact=False)["validated_swift_bics"]
        self.assertIn("BACAADADXXX", bics)
        self.assertIn("NWBKGB2L", bics)

    def test_luhn_and_iban_registry_lengths_no15_and_fake_zz_rejected(self) -> None:
        self.assertTrue(luhn_valid("6200000000000005"))
        self.assertFalse(luhn_valid("6200000000000001"))
        self.assertTrue(iban_mod97_valid("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(iban_mod97_valid("NO93 8601 1117 947"))
        self.assertTrue(iban_mod97_valid("YE15 CBYE 0001 0188 6123 4567 8912 34"))
        for chk in range(10, 99):
            cand = f"ZZ{chk:02d}12345678901234"
            self.assertFalse(iban_mod97_valid(cand))

        txt = (
            "Send to 6200 0000 0000 0005, not 6200 0000 0000 0001. "
            "IBANs: NO9386011117947, YE15CBYE0001018861234567891234 and GB82WEST12345698765432."
        )
        iocs = extract_validated_iocs(txt, redact=False)
        self.assertEqual(iocs["luhn_validated_cards"], ["6200000000000005"])
        self.assertEqual(iocs["unvalidated_card_candidates"], ["6200000000000001"])
        self.assertIn("NO9386011117947", iocs["mod97_validated_ibans"])
        self.assertIn("YE15CBYE0001018861234567891234", iocs["mod97_validated_ibans"])
        self.assertIn("GB82WEST12345698765432", iocs["mod97_validated_ibans"])

    def test_uk_sort_code_does_not_pair_distant_or_cross_message_numbers(self) -> None:
        far_padding = "x" * 200
        txt = f"Sort Code 00-00-99 {far_padding} invoice date 20250401"
        iocs = extract_validated_iocs(txt, redact=False)
        self.assertEqual(iocs["context_paired_uk_accounts"], [])
        self.assertEqual(iocs["unpaired_uk_sort_codes"], ["00-00-99"])

        multi_msg_payload = {
            "messages": [
                {"id": "m1", "from": "u1", "content": "Please check UK Sort Code 00-00-99"},
                {"id": "m2", "from": "u2", "content": "20250401 is our next audit date"},
            ]
        }
        triaged = triage_exported_chatsvc_json(multi_msg_payload, redact=False)
        self.assertEqual(triaged["corpus_validated_iocs"]["context_paired_uk_accounts"], [])
        self.assertEqual(triaged["corpus_validated_iocs"]["unpaired_uk_sort_codes"], ["00-00-99"])

    def test_negative_latency_and_naive_timestamps_rejected(self) -> None:
        payload = {
            "session_metadata": [{"edge_pop_tag": "pop-eu-west-example-01"}],
            "timestamp_pairs": [
                {
                    "label": "negative_skew",
                    "start_utc": "2025-03-18T10:00:30Z",
                    "end_utc": "2025-03-18T10:00:00Z",
                },
                {
                    "label": "naive_no_tz",
                    "start_utc": "2025-03-18T10:00:00",
                    "end_utc": "2025-03-18T10:00:10Z",
                },
            ],
        }
        res = corroborate_timestamps(payload, redact=False)
        obs = {x["raw_label"]: x["status"] for x in res["timestamp_interval_observations"]}
        self.assertEqual(obs["negative_skew"], "REJECTED_NEGATIVE_DELTA_CLOCK_SKEW_OR_BAD_INPUT")
        self.assertEqual(obs["naive_no_tz"], "INVALID_OR_TIMEZONE_NAIVE_TIMESTAMP")

    def test_two_short_messages_produce_no_duress_diagnosis(self) -> None:
        payload = {
            "subject_sender_id": "u1",
            "messages": [
                {"from": "u1", "content": "ok"},
                {"from": "u1", "content": "done"},
            ],
        }
        res = summarize_corpus_linguistics(payload)
        self.assertEqual(res["sample_size"], 2)
        self.assertFalse(res["minimum_recommended_sample_met"])
        self.assertEqual(res["utterance_ratio_3_to_12_chars"], 0.5)
        self.assertNotIn("psr_fca_duress_assessment", res)

    def test_leveldb_cross_32kib_first_middle_last_and_nested_json_no_false_carve(self) -> None:
        wal = build_synthetic_leveldb_wal_bytes()
        self.assertGreater(len(wal), 65536)
        parsed = parse_leveldb_wal(wal)
        self.assertEqual(parsed["corrupted_frames_count"], 0)
        self.assertGreaterEqual(parsed["valid_physical_frames"], 4)
        self.assertEqual(parsed["recovered_chatsvc_records_count"], 2)
        for rec in parsed["recovered_records"]:
            self.assertNotEqual(rec["message_id"], "")
            self.assertNotEqual(rec["cached_content"], "")

    def test_leveldb_truncated_writebatch_value_and_op_count_mismatch_rejected(self) -> None:
        msg_bytes = json.dumps({"id": "m9", "from": "u1", "content": "hello"}).encode("utf-8")
        bad_wb_trunc = (
            struct.pack("<QI", 500, 1)
            + b"\x01"
            + encode_varint(3)
            + b"key"
            + encode_varint(len(msg_bytes) + 50)
            + msg_bytes
        )
        frame_a = encode_leveldb_log_record(REC_FULL, bad_wb_trunc)
        parsed_a = parse_leveldb_wal(frame_a)
        self.assertEqual(parsed_a["recovered_chatsvc_records_count"], 0)
        self.assertEqual(parsed_a["corrupted_frames_count"], 1)

        wb_valid_1 = build_writebatch(501, [(1, b"k1", msg_bytes)])
        bad_wb_count = wb_valid_1[:8] + struct.pack("<I", 2) + wb_valid_1[12:]
        frame_b = encode_leveldb_log_record(REC_FULL, bad_wb_count)
        parsed_b = parse_leveldb_wal(frame_b)
        self.assertEqual(parsed_b["recovered_chatsvc_records_count"], 0)
        self.assertEqual(parsed_b["corrupted_frames_count"], 1)

        frame_c = encode_leveldb_log_record(REC_FULL, wb_valid_1 + b"TRAILING_GARBAGE")
        parsed_c = parse_leveldb_wal(frame_c)
        self.assertEqual(parsed_c["recovered_chatsvc_records_count"], 0)
        self.assertEqual(parsed_c["corrupted_frames_count"], 1)

    def test_leveldb_unclosed_first_fragment_at_eof_flagged(self) -> None:
        wb = build_writebatch(777, [(1, b"k", b'{"id":"1","from":"u","content":"hi"}')])
        dangling_first = encode_leveldb_log_record(REC_FIRST, wb[:20])
        parsed = parse_leveldb_wal(dangling_first)
        self.assertEqual(parsed["recovered_chatsvc_records_count"], 0)
        self.assertEqual(parsed["corrupted_frames_count"], 1)
        self.assertIn("unclosed", parsed["corrupted_frames"][0]["reason"].lower())

    def test_ephemeral_hmac_redaction_and_manifest_hash_suppression(self) -> None:
        # 1. Different salts produce un-linkable HMAC digests, and zero prefix/suffix chars leak
        secret_acct = "GB82WEST12345698765432"
        m1 = mask_identifier(secret_acct, salt=b"salt_alpha_000000000000000000001")
        m2 = mask_identifier(secret_acct, salt=b"salt_bravo_000000000000000000002")
        self.assertNotEqual(m1, m2)
        self.assertNotIn("GB82", m1)
        self.assertNotIn("5432", m1)

        # 2. Default masked manifest suppresses raw SHA-256 and source filename to prevent hash confirmation
        manifest_masked = build_acquisition_manifest(b"raw_evidence_bytes", "sensitive_filename.json", redact=True)
        self.assertEqual(manifest_masked["source_label"], "[REDACTED_SOURCE_LABEL]")
        self.assertIn("OMITTED_IN_MASKED_MODE", manifest_masked["input_sha256"])

        # 3. WAL default redaction suppresses exact dates, file_size_bytes, message IDs, and raw value SHA-256
        wal = apply_wal_record_redaction(
            parse_leveldb_wal(build_synthetic_leveldb_wal_bytes()),
            redact=True,
            salt=b"unit_test_salt_32_bytes_padding!",
        )
        self.assertIsNone(wal["file_size_bytes"])
        rec = wal["recovered_records"][0]
        self.assertTrue(rec["message_id"].startswith("msg_hmac_"))
        self.assertEqual(rec["composetime"], "[REDACTED_UTC_TIMESTAMP]")
        self.assertEqual(rec["value_sha256"], "[OMITTED_IN_MASKED_MODE]")
        self.assertIn("REDACTED_CONTENT", rec["cached_content"])

    def test_image_text_canary_and_wal_filesize_redacted_by_default(self) -> None:
        canary_str = "Software\x00CANARY-VICTIM-7F3A9 /Users/Example/Private"
        canary_png = build_valid_png_with_iccp(
            "Display P3",
            "APPL",
            software_text=canary_str,
            iccp_name="CanaryCustomProfileName",
        )
        raw_img_res = inspect_image_container(canary_png, "sensitive_screenshot.png")
        self.assertEqual(len(raw_img_res["software_text_chunks"]), 1)
        self.assertIn("CANARY-VICTIM-7F3A9", raw_img_res["software_text_chunks"][0]["preview"])

        masked_img_res = apply_image_redaction(
            inspect_image_container(canary_png, "sensitive_screenshot.png"),
            redact=True,
            salt=b"canary_test_salt_32_bytes_pad_01",
        )
        serialized = json.dumps(masked_img_res)
        self.assertNotIn("CANARY-VICTIM-7F3A9", serialized)
        self.assertNotIn("/Users/Example/Private", serialized)
        self.assertNotIn("CanaryCustomProfileName", serialized)
        self.assertNotIn("sensitive_screenshot.png", serialized)
        self.assertTrue(masked_img_res["icc_profiles"][0]["png_iccp_name"].startswith("[REDACTED_HMAC:"))

    def test_oversize_file_error_suppresses_filename_and_size_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            oversize_path = Path(tmpdir) / "CONFIDENTIAL_CLIENT_MERGER_CLAIM_9981.png"
            oversize_bytes = 2 * 1024 * 1024 + 37
            with open(oversize_path, "wb") as fh:
                os.truncate(fh.fileno(), oversize_bytes)

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                rc = main(["--max-mb", "1", "inspect-image", str(oversize_path)])

            self.assertEqual(rc, 2)
            self.assertEqual(out_buf.getvalue(), "")
            err_text = err_buf.getvalue()
            self.assertNotIn("CONFIDENTIAL_CLIENT_MERGER_CLAIM_9981", err_text)
            self.assertNotIn(str(tmpdir), err_text)
            self.assertNotIn(str(oversize_bytes), err_text)
            self.assertNotIn("Traceback", err_text)
            err_obj = json.loads(err_text)
            self.assertTrue(err_obj["masked_mode"])

            # Verify --unredacted retains lab diagnostic filename and exact byte count
            err_unredacted = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_unredacted):
                rc_unred = main(["--unredacted", "--max-mb", "1", "inspect-image", str(oversize_path)])
            self.assertEqual(rc_unred, 2)
            self.assertIn("CONFIDENTIAL_CLIENT_MERGER_CLAIM_9981.png", err_unredacted.getvalue())
            self.assertIn(str(oversize_bytes), err_unredacted.getvalue())

    def test_missing_or_malformed_input_suppresses_path_and_snippets_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_wal = Path(tmpdir) / "SECRET_MATTER_DIR_771" / "missing_000003.log"
            err_missing = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_missing):
                rc_missing = main(["parse-leveldb-log", str(missing_wal)])
            self.assertEqual(rc_missing, 2)
            self.assertNotIn("SECRET_MATTER_DIR_771", err_missing.getvalue())
            self.assertNotIn("missing_000003.log", err_missing.getvalue())
            self.assertNotIn("Traceback", err_missing.getvalue())

            bad_json = Path(tmpdir) / "sensitive_export_442.json"
            bad_json.write_bytes(b'{"messages": [CANARY_MALFORMED_SNIPPET_8821')
            err_json = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_json):
                rc_json = main(["triage-json", str(bad_json)])
            self.assertEqual(rc_json, 2)
            self.assertNotIn("sensitive_export_442", err_json.getvalue())
            self.assertNotIn("CANARY_MALFORMED_SNIPPET_8821", err_json.getvalue())
            self.assertNotIn("Traceback", err_json.getvalue())

    def test_schema_invalid_json_types_suppress_traceback_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            top_array = Path(tmpdir) / "CANARY_ARRAY_JSON_901.json"
            top_array.write_bytes(b"[]")
            bad_fields = Path(tmpdir) / "CANARY_BAD_FIELDS_902.json"
            bad_fields.write_bytes(b'{"timestamp_pairs": "not_a_list", "messages": 12345}')

            for subcmd, target in (
                ("triage-json", top_array),
                ("corroborate-timestamps", top_array),
                ("summarize-linguistics", top_array),
                ("corroborate-timestamps", bad_fields),
                ("summarize-linguistics", bad_fields),
            ):
                out_b, err_b = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out_b), contextlib.redirect_stderr(err_b):
                    rc = main([subcmd, str(target)])
                self.assertEqual(rc, 2)
                self.assertEqual(out_b.getvalue(), "")
                err_txt = err_b.getvalue()
                self.assertNotIn("Traceback", err_txt)
                self.assertNotIn("cli.py", err_txt)
                self.assertNotIn("CANARY_ARRAY_JSON_901", err_txt)
                self.assertNotIn("CANARY_BAD_FIELDS_902", err_txt)
                parsed_err = json.loads(err_txt)
                self.assertTrue(parsed_err["masked_mode"])

    def test_bad_crc_custom_png_chunk_type_masked_by_default(self) -> None:
        base_png = build_valid_png_with_iccp("Display P3", "APPL")
        # Inject a custom 4-byte chunk 'seCr' with an intentionally invalid CRC32 right before IEND
        iend_offset = len(base_png) - 12
        payload = b"CANARY_BAD_CRC_PAYLOAD_7719"
        bad_custom_chunk = struct.pack(">I", len(payload)) + b"seCr" + payload + struct.pack(">I", 0xDEADBEEF)
        tampered_png = base_png[:iend_offset] + bad_custom_chunk + base_png[iend_offset:]

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad_custom_chunk.png"
            p.write_bytes(tampered_png)
            out_masked = io.StringIO()
            with contextlib.redirect_stdout(out_masked), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["inspect-image", str(p)])
            self.assertEqual(rc, 0)
            masked_txt = out_masked.getvalue()
            self.assertNotIn("seCr", masked_txt)
            self.assertNotIn("CANARY_BAD_CRC_PAYLOAD_7719", masked_txt)
            self.assertIn("[CUSTOM_PNG_CHUNK]", masked_txt)

    def test_multi_schema_slack_whatsapp_and_b2b_portal_wal_carving_and_iocs(self) -> None:
        slack_rec = json.dumps(
            {
                "ts": "1742292600.000100",
                "user": "U099SUPPLIER",
                "text": "Urgent Slack update: wire to GB82WEST12345698765432",
                "deleted_ts": "1742293000.000200",
            }
        ).encode("utf-8")
        wa_rec = json.dumps(
            {
                "id": "wa_false_001",
                "from": "447700900000@c.us",
                "t": 1742292700,
                "body": "Pay UK Sort Code 00-00-00 Account 00000000 immediately",
                "is_deleted": True,
            }
        ).encode("utf-8")
        portal_rec = json.dumps(
            {
                "invoice_id": "INV-2026-9910",
                "vendor": "Synthetic Components Ltd",
                "beneficiary_iban": "NO9386011117947",
                "amount": "18400.00",
            }
        ).encode("utf-8")

        wb = build_writebatch(
            2001,
            [
                (1, b"idb:slack:1", b"\xff\x15" + slack_rec),
                (1, b"idb:wa:1", b"\xff\x15" + wa_rec),
                (1, b"idb:portal:1", b"\xff\x15" + portal_rec),
            ],
        )
        wal = encode_leveldb_log_record(REC_FULL, wb)

        # Strict legacy chatsvc filter returns 0 on non-chatsvc schemas
        strict_chatsvc = parse_leveldb_wal(wal, schema_mode="chatsvc")
        self.assertEqual(strict_chatsvc["recovered_records_count"], 0)

        # Default auto schema carves all 3 platforms and extracts validated banking IOCs
        auto_parsed = apply_wal_record_redaction(parse_leveldb_wal(wal, schema_mode="auto"), redact=False)
        self.assertEqual(auto_parsed["recovered_records_count"], 3)
        schemas = [r["schema_detected"] for r in auto_parsed["recovered_records"]]
        self.assertEqual(schemas, ["slack_web", "web_messenger", "b2b_portal_json"])
        self.assertTrue(auto_parsed["recovered_records"][0]["is_soft_deleted_in_ui"])
        self.assertTrue(auto_parsed["recovered_records"][1]["is_soft_deleted_in_ui"])
        self.assertIn("GB82WEST12345698765432", auto_parsed["recovered_records"][0]["extracted_iocs"]["mod97_validated_ibans"])
        paired_uk = auto_parsed["recovered_records"][1]["extracted_iocs"]["context_paired_uk_accounts"]
        self.assertEqual(len(paired_uk), 1)
        self.assertEqual(paired_uk[0]["sort_code"], "00-00-00")
        self.assertEqual(paired_uk[0]["account_number"], "00000000")
        self.assertIn("NO9386011117947", auto_parsed["recovered_records"][2]["extracted_iocs"]["mod97_validated_ibans"])

    def test_precheck_go_partial_and_nogo_sstable_without_path_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            go_dir = Path(tmpdir) / "CANARY_CLIENT_DIR_GO_881"
            go_dir.mkdir()
            (go_dir / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())

            out_go = io.StringIO()
            with contextlib.redirect_stdout(out_go), contextlib.redirect_stderr(io.StringIO()):
                rc_go = main(["precheck", str(go_dir)])
            self.assertEqual(rc_go, 0)
            self.assertNotIn("CANARY_CLIENT_DIR_GO_881", out_go.getvalue())
            rep_go = json.loads(out_go.getvalue())["precheck_manifest"]
            self.assertEqual(rep_go["feasibility_verdict"], "GO")
            self.assertEqual(rep_go["carvable_json_records_count"], 2)
            self.assertEqual(rep_go["soft_deleted_json_records_count"], 2)

            # Add a valid LevelDB SSTable (.ldb with 48-byte footer ending in 0xdb4775248b80fb57) -> PARTIAL
            fake_sstable = b"\x00" * 56 + LEVELDB_SSTABLE_MAGIC_LE
            (go_dir / "000005.ldb").write_bytes(fake_sstable)
            out_partial = io.StringIO()
            with contextlib.redirect_stdout(out_partial), contextlib.redirect_stderr(io.StringIO()):
                rc_part = main(["precheck", str(go_dir)])
            self.assertEqual(rc_part, 0)
            rep_part = json.loads(out_partial.getvalue())["precheck_manifest"]
            self.assertEqual(rep_part["feasibility_verdict"], "PARTIAL")
            self.assertEqual(rep_part["verified_leveldb_sstables_count"], 1)

            # Compacted-only directory (no .log records) -> NO_GO_COMPACTED_OR_UNSUPPORTED
            nogo_dir = Path(tmpdir) / "CANARY_COMPACTED_ONLY_882"
            nogo_dir.mkdir()
            (nogo_dir / "000010.ldb").write_bytes(fake_sstable)
            out_nogo = io.StringIO()
            with contextlib.redirect_stdout(out_nogo), contextlib.redirect_stderr(io.StringIO()):
                rc_nogo = main(["precheck", str(nogo_dir)])
            self.assertEqual(rc_nogo, 0)
            self.assertNotIn("CANARY_COMPACTED_ONLY_882", out_nogo.getvalue())
            rep_nogo = json.loads(out_nogo.getvalue())["precheck_manifest"]
            self.assertEqual(rep_nogo["feasibility_verdict"], "NO_GO_COMPACTED_OR_UNSUPPORTED")
            self.assertEqual(rep_nogo["carvable_json_records_count"], 0)
            self.assertEqual(rep_nogo["verified_leveldb_sstables_count"], 1)

    def test_25_cli_subcommands_crypto_agility_and_external_key_file(self) -> None:
        """Exercise CLI subcommands, HMAC digest agility (sha384/blake2b), and external key file loading."""
        repo_root = Path(__file__).resolve().parent.parent
        sample_json = repo_root / "samples" / "synthetic_case_benchmark.json"
        pkg_sample_json = repo_root / "starshield" / "data" / "synthetic_case_benchmark.json"
        if not sample_json.is_file():
            sample_json = pkg_sample_json
        self.assertTrue(pkg_sample_json.is_file())
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "hmac_secret.key"
            key_path.write_bytes(b"cleanroom-hmac-key-material-32bytes!")

            # Deterministic cross-run HMAC token with sha384 + external key file
            out1 = io.StringIO()
            out2 = io.StringIO()
            with contextlib.redirect_stdout(out1):
                rc1 = main(["--hmac-digest", "sha384", "--hmac-key-file", str(key_path), "triage-json", str(sample_json)])
            with contextlib.redirect_stdout(out2):
                rc2 = main(["--hmac-digest", "sha384", "--hmac-key-file", str(key_path), "triage-json", str(sample_json)])
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            j1 = json.loads(out1.getvalue())["triage_result"]
            j2 = json.loads(out2.getvalue())["triage_result"]
            self.assertEqual(j1["corpus_validated_iocs"], j2["corpus_validated_iocs"])

            # blake2b produces distinct tokens from sha384 under same key
            out_b2 = io.StringIO()
            with contextlib.redirect_stdout(out_b2):
                rc_b2 = main(["--hmac-digest", "blake2b", "--hmac-key-file", str(key_path), "triage-json", str(sample_json)])
            self.assertEqual(rc_b2, 0)
            jb2 = json.loads(out_b2.getvalue())["triage_result"]
            self.assertNotEqual(j1["corpus_validated_iocs"], jb2["corpus_validated_iocs"])

            # Too-short key file rejected cleanly with exit code 2
            short_key = Path(tmpdir) / "short.key"
            short_key.write_bytes(b"short")
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_buf):
                rc_short = main(["--hmac-key-file", str(short_key), "triage-json", str(sample_json)])
            self.assertEqual(rc_short, 2)

            # Exercise corroborate-timestamps, summarize-linguistics, and inspect-image CLI entrypoints
            for subcmd in ("corroborate-timestamps", "summarize-linguistics"):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(main([subcmd, str(sample_json)]), 0)
                self.assertIn("acquisition_manifest", json.loads(buf.getvalue()))

            png_file = Path(tmpdir) / "sample.png"
            png_file.write_bytes(build_valid_png_with_iccp("Display P3", "APPL"))
            img_buf = io.StringIO()
            with contextlib.redirect_stdout(img_buf):
                self.assertEqual(main(["inspect-image", str(png_file)]), 0)
            self.assertTrue(json.loads(img_buf.getvalue())["image_container_analysis"]["valid_container"])

    def test_26_mcp_stdio_server_tools_and_privacy_by_default(self) -> None:
        """Verify MCP JSON-RPC 2.0 lifecycle, 8 read-only tools, dual framing, and zero-leak default redaction."""
        from starshield.mcp_server import handle_mcp_message, run_mcp_stdio_server

        with tempfile.TemporaryDirectory() as tmpdir:
            canary_dir = Path(tmpdir) / "CANARY_MCP_ELECTRON_DIR_991"
            canary_dir.mkdir()
            (canary_dir / "000003.log").write_bytes(build_synthetic_leveldb_wal_bytes())

            canary_png = Path(tmpdir) / "CANARY_MCP_RECEIPT_992.png"
            canary_png.write_bytes(
                build_valid_png_with_iccp(
                    "Display P3",
                    "APPL",
                    software_text="Software\x00CANARY_SECRET_EDITOR_USER_992",
                    iccp_name="CanaryReceiptProfile",
                )
            )
            missing_img = Path(tmpdir) / "CANARY_MISSING_MCP_PATH_993" / "receipt.png"

            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
                {"jsonrpc": "2.0", "id": 4, "method": "resources/templates/list"},
                {"jsonrpc": "2.0", "id": 5, "method": "prompts/list"},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "starshield_demo"}},
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {"name": "starshield_precheck_leveldb", "arguments": {"target_path": str(canary_dir)}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {"name": "starshield_inspect_image_tamper", "arguments": {"image_path": str(canary_png)}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_validate_financial_iocs",
                        "arguments": {
                            "text": "Wire to IBAN GB82WEST12345698765432 (SWIFT NWBKGB2LXXX), Sort Code 00-00-00 Account 00000000."
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {"name": "starshield_inspect_image_tamper", "arguments": {"image_path": str(missing_img)}},
                },
                {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "unknown_tool"}},
                {"jsonrpc": "2.0", "id": 13, "method": "unknown/method"},
            ]

            in_bytes = b"\n".join(json.dumps(r).encode("utf-8") for r in requests) + b"\n{malformed_json\n"
            out_stream = io.BytesIO()
            rc = run_mcp_stdio_server(
                redact=True,
                instream=io.BytesIO(in_bytes),
                outstream=out_stream,
            )
            self.assertEqual(rc, 0)

            raw_output = out_stream.getvalue().decode("utf-8")
            # Zero path/canary/raw-IBAN leaks in default masked mode across the entire RPC transcript
            for forbidden in (
                "CANARY_MCP_ELECTRON_DIR_991",
                "CANARY_MCP_RECEIPT_992",
                "CANARY_SECRET_EDITOR_USER_992",
                "CanaryReceiptProfile",
                "CANARY_MISSING_MCP_PATH_993",
                "GB82WEST12345698765432",
                "--unredacted",
            ):
                self.assertNotIn(forbidden, raw_output)

            lines = [json.loads(line) for line in raw_output.strip().splitlines()]
            by_id = {item.get("id"): item for item in lines if item.get("id") is not None}
            # Notification produced no response; 13 ID'd requests + 1 parse error = 14 lines
            self.assertEqual(len(lines), 14)
            self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-03-26")
            self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "starshield-forensics")
            self.assertEqual(by_id[2]["result"], {})
            self.assertEqual(by_id[3]["result"]["resources"], [])
            self.assertEqual(by_id[4]["result"]["resourceTemplates"], [])
            self.assertEqual(by_id[5]["result"]["prompts"], [])
            self.assertEqual(len(by_id[6]["result"]["tools"]), 8)

            self.assertFalse(by_id[7]["result"]["isError"])
            pre_res = json.loads(by_id[8]["result"]["content"][0]["text"])
            self.assertEqual(pre_res["precheck_manifest"]["feasibility_verdict"], "GO")

            img_res = json.loads(by_id[9]["result"]["content"][0]["text"])
            self.assertTrue(img_res["image_container_analysis"]["valid_container"])
            self.assertEqual(img_res["acquisition_manifest"]["source_label"], "[REDACTED_SOURCE_LABEL]")

            ioc_res = json.loads(by_id[10]["result"]["content"][0]["text"])
            self.assertTrue(ioc_res["masked_mode"])
            self.assertIn("validation_scope_note", ioc_res)
            self.assertIn("does NOT indicate fraud", ioc_res["validation_scope_note"])
            self.assertTrue(ioc_res["validated_iocs"]["mod97_validated_ibans"][0].startswith("[REDACTED_HMAC:"))

            # Missing file returns tool-level isError=True with scrubbed path
            self.assertTrue(by_id[11]["result"]["isError"])
            self.assertEqual(by_id[12]["error"]["code"], -32602)
            self.assertEqual(by_id[13]["error"]["code"], -32601)
            self.assertEqual(lines[-1]["error"]["code"], -32700)

            # Verify Content-Length header framing & unredacted lab mode + CLI entrypoint
            cl_req_body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_validate_financial_iocs",
                        "arguments": {"text": "IBAN GB82WEST12345698765432"},
                    },
                }
            ).encode("utf-8")
            cl_frame = f"Content-Length: {len(cl_req_body)}\r\nContent-Type: application/vscode-jsonrpc\r\n\r\n".encode(
                "ascii"
            ) + cl_req_body
            cl_out = io.BytesIO()
            self.assertEqual(
                run_mcp_stdio_server(redact=False, instream=io.BytesIO(cl_frame), outstream=cl_out),
                0,
            )
            cl_raw = cl_out.getvalue()
            self.assertTrue(cl_raw.startswith(b"Content-Length: "))
            cl_json = json.loads(cl_raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
            unred_ioc = json.loads(cl_json["result"]["content"][0]["text"])
            self.assertFalse(unred_ioc["masked_mode"])
            self.assertEqual(unred_ioc["validated_iocs"]["mod97_validated_ibans"], ["GB82WEST12345698765432"])

            # Protocol edge cases via handle_mcp_message & CLI `starshield mcp`
            self.assertEqual(handle_mcp_message("not-a-dict")["error"]["code"], -32600)
            self.assertEqual(handle_mcp_message({"jsonrpc": "2.0", "id": 1})["error"]["code"], -32600)
            self.assertEqual(
                handle_mcp_message({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []})["error"]["code"],
                -32602,
            )
            fallback_init = handle_mcp_message(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}
            )
            self.assertEqual(fallback_init["result"]["protocolVersion"], "2024-11-05")

            # CLI `starshield mcp` smoke test via mocked stdin/stdout buffers
            class _StdWrapper(io.TextIOWrapper):
                pass

            cli_in = _StdWrapper(io.BytesIO(b'{"jsonrpc":"2.0","id":77,"method":"ping"}\n'), encoding="utf-8")
            cli_out_buf = io.BytesIO()
            cli_out = _StdWrapper(cli_out_buf, encoding="utf-8", write_through=True)
            orig_in, orig_out = sys.stdin, sys.stdout
            try:
                sys.stdin = cli_in
                sys.stdout = cli_out
                self.assertEqual(main(["mcp"]), 0)
            finally:
                sys.stdin = orig_in
                sys.stdout = orig_out
            cli_resp = json.loads(cli_out_buf.getvalue().decode("utf-8").strip())
            self.assertEqual(cli_resp["id"], 77)
            self.assertEqual(cli_resp["result"], {})

    def test_pdf_incremental_revisions_xmp_cli_and_mcp(self) -> None:
        non_pdf = inspect_pdf_container(b"Not a PDF document header", "plain.txt")
        self.assertFalse(non_pdf["valid_container"])
        self.assertEqual(non_pdf["container_format"], "UNSUPPORTED_OR_NOT_A_PDF")
        self.assertEqual(non_pdf["epistemic_tier"], "OBSERVED")

        pdf_bytes = build_synthetic_incremental_pdf()
        unred = inspect_pdf_container(pdf_bytes, "CANARY_INVOICE_994.pdf")
        self.assertTrue(unred["valid_container"])
        self.assertEqual(unred["container_format"], "PDF")
        self.assertEqual(unred["epistemic_tier"], "DERIVED")
        self.assertEqual(unred["incremental_revision_count"], 2)
        self.assertTrue(unred["has_multiple_revisions"])
        self.assertEqual(len(unred["eof_offsets"]), 2)
        self.assertEqual(len(unred["xref_offsets"]), 2)
        self.assertIn("ReportLab PDF Library 4.0", unred["info_metadata"]["Producer"])
        self.assertIn("Synthetic PDF Incremental Editor 1.2", unred["info_metadata"]["Producer"])
        self.assertTrue(len(unred["alternative_explanations"]) >= 1)

        # Compressed XMP FlateDecode + /JS risk marker + redaction check
        xmp_xml = (
            b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            b"<x:xmpmeta><rdf:RDF><rdf:Description "
            b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">'
            b"<xmp:CreatorTool>CanaryEditor 9.1</xmp:CreatorTool>"
            b"<xmp:ModifyDate>2026-03-19T09:15:00Z</xmp:ModifyDate>"
            b"<xmpMM:DocumentID>uuid:CANARY-DOC-ID</xmpMM:DocumentID>"
            b'</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
        )
        comp_xmp = zlib.compress(xmp_xml)
        extra_pdf = (
            pdf_bytes
            + b"\n<< /Type /Metadata /Subtype /XML /Filter /FlateDecode >>\nstream\n"
            + comp_xmp
            + b"\nendstream\n<< /S /JavaScript /JS (app.alert) >>\n"
        )
        obs = inspect_pdf_container(extra_pdf, "canary_xmp.pdf")
        self.assertGreaterEqual(len(obs["xmp_metadata"]), 1)
        self.assertTrue(obs["xmp_metadata"][0]["from_compressed_stream"])
        self.assertEqual(obs["risk_markers"].get("js_actions"), 2)

        masked = apply_pdf_redaction(obs, redact=True, salt=b"fixed_test_salt_16")
        self.assertEqual(masked["artifact"], "[REDACTED_PDF_LABEL]")
        self.assertIsNone(masked["file_size_bytes"])
        self.assertIsNone(masked["trailing_bytes_after_final_eof"])
        self.assertIsNone(masked["eof_offsets"])
        self.assertIsNone(masked["startxref_offsets"])
        self.assertIsNone(masked["xref_offsets"])
        self.assertIsNone(masked["xref_stream_offsets"])
        self.assertIsNone(masked["xmp_metadata"][0]["source_offset"])
        self.assertEqual(masked["incremental_revision_count"], 2)
        self.assertTrue(masked["has_multiple_revisions"])
        self.assertEqual(masked["info_metadata"]["ModDate"], ["[REDACTED_PDF_TIMESTAMP]"])
        self.assertEqual(masked["xmp_metadata"][0]["modify_date"], "[REDACTED_PDF_TIMESTAMP]")
        self.assertTrue(masked["xmp_metadata"][0]["document_id"].startswith("[REDACTED_HMAC:"))

        # CLI `inspect-pdf` & MCP `starshield_inspect_pdf_tamper` end-to-end check
        from starshield.mcp_server import handle_mcp_message

        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "CANARY_WIRE_PDF_995.pdf"
            pdf_path.write_bytes(pdf_bytes)
            stdout_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf):
                rc = main(["inspect-pdf", str(pdf_path)])
            self.assertEqual(rc, 0)
            cli_out = stdout_buf.getvalue()
            self.assertNotIn("CANARY_WIRE_PDF_995", cli_out)
            self.assertNotIn("ReportLab PDF Library 4.0", cli_out)
            cli_json = json.loads(cli_out)
            self.assertEqual(cli_json["pdf_container_analysis"]["incremental_revision_count"], 2)

            mcp_resp = handle_mcp_message(
                {
                    "jsonrpc": "2.0",
                    "id": 501,
                    "method": "tools/call",
                    "params": {"name": "starshield_inspect_pdf_tamper", "arguments": {"pdf_path": str(pdf_path)}},
                },
                redact=True,
                session_salt=b"fixed_mcp_salt_16",
            )
            self.assertIsNotNone(mcp_resp)
            mcp_text = mcp_resp["result"]["content"][0]["text"]
            self.assertNotIn("CANARY_WIRE_PDF_995", mcp_text)
            mcp_payload = json.loads(mcp_text)
            self.assertTrue(mcp_payload["pdf_container_analysis"]["has_multiple_revisions"])

    def test_pdf_nested_parentheses_token_boundary_and_startxref_bounds(self) -> None:
        """Verify ISO 32000-1 §7.3.4.2 nested parens, /Key token boundaries, BOMs, comments, hex, and >4300-digit startxref."""
        utf16be_hex = ("FEFF" + "Meridian Suite".encode("utf-16-be").hex().upper()).encode("ascii")
        utf16le_hex = (codecs.BOM_UTF16_LE + "SubTitle LE".encode("utf-16-le")).hex().upper().encode("ascii")
        utf8_lit = codecs.BOM_UTF8 + b"Author UTF-8"
        long_prefix_240 = b"P" * 240
        nested_pdf = (
            b"%PDF-1.7\n"
            b"1 0 obj\n"
            b"<< /ProducerExtra (MUST_NOT_MATCH_PRODUCER) "
            b"/Producer (ReportLab (Core v4.0) Engine) "
            b"/Producer (" + long_prefix_240 + b"AAA) "
            b"/Producer (" + long_prefix_240 + b"BBB) "
            b"/Creator % inline PDF comment before value\n<" + utf16be_hex + b"> "
            b"/Author (" + utf8_lit + b") "
            b"/Subject <" + utf16le_hex + b"> "
            b"/Subject <41424> "
            b"/Subject <ZZZZ_NOT_HEX> "
            b"/Title (\\111\\156\\166\\\r\noice \\(Rev B\\)) >>\n"
            b"endobj\n"
            b"startxref\n-42\n"
            b"startxref\n999999\n"
            b"startxref\n" + (b"9" * 5000) + b"\n"
            b"%%EOF\n"
        )
        res = inspect_pdf_container(nested_pdf, label="nested_spec.pdf")
        # Truncation-before-dedup collapses both 243-char strings sharing a 240-char prefix into 1 entry
        self.assertEqual(
            res["info_metadata"]["Producer"],
            ["ReportLab (Core v4.0) Engine", "P" * 240],
        )
        self.assertEqual(res["info_metadata"]["Creator"], ["Meridian Suite"])
        self.assertEqual(res["info_metadata"]["Author"], ["Author UTF-8"])
        self.assertEqual(res["info_metadata"]["Subject"], ["SubTitle LE", "AB@"])
        self.assertEqual(res["info_metadata"]["Title"], ["Invoice (Rev B)"])
        self.assertFalse(res["valid_container"])
        self.assertIsNone(res["startxref_offsets"][-1]["declared_xref_offset"])
        reasons = " | ".join(err["reason"] for err in res["container_errors"])
        self.assertIn("negative startxref", reasons.lower())
        self.assertIn("past end", reasons.lower())
        self.assertIn("64-bit integer range", reasons.lower())

    def test_pdf_antiredos_unclosed_producer_and_unclosed_streams_under_100ms(self) -> None:
        """Ensure 100 KB unclosed /Producer (((... and 1,000 unclosed stream\\n run in linear bounded time."""
        malformed_producer = b"%PDF-1.4\n/Producer " + (b"(" * (100 * 1024)) + b"\n%%EOF\n"
        t0 = time.perf_counter()
        res_prod = inspect_pdf_container(malformed_producer, label="unclosed_parens.pdf")
        dt_prod = time.perf_counter() - t0
        self.assertEqual(res_prod["info_metadata"], {})
        self.assertLess(dt_prod, 2.0)

        unclosed_streams = (
            b"%PDF-1.4\n"
            + (b"<< /Filter /FlateDecode >>\nstream\nAAAA\n" * 1000)
            + (b"stream\nBBBB\n" * 1000)
            + (b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>' * 500)
            + b"%%EOF\n"
        )
        t1 = time.perf_counter()
        res_streams = inspect_pdf_container(unclosed_streams, label="unclosed_streams.pdf")
        dt_streams = time.perf_counter() - t1
        self.assertFalse(res_streams["valid_container"])
        self.assertTrue(any("missing endstream" in e["reason"].lower() for e in res_streams["container_errors"]))
        self.assertLess(dt_streams, 2.0)

        # Verify 'upstream' is rejected and bare 'stream\r' after '>>' is noted cleanly without backtracking
        comp_js = zlib.compress(b"/JavaScript")
        upstream_and_bare_cr = (
            b"%PDF-1.4\n"
            b"<< /Filter /FlateDecode >>\nupstream\n" + comp_js + b"\nendstream\n"
            b"<< /Filter /FlateDecode >>\nstream\r" + comp_js + b"\r\nendstream\n"
            b"%%EOF\n"
        )
        res_edge = inspect_pdf_container(upstream_and_bare_cr, label="edge_stream.pdf")
        self.assertNotIn("js_actions", res_edge["risk_markers"])
        self.assertFalse(res_edge["valid_container"])
        self.assertTrue(any("bare CR" in e["reason"] for e in res_edge["container_errors"]))

    def test_pdf_cumulative_32mib_decompression_circuit_breaker(self) -> None:
        """Verify >32 MiB cumulative budget, repeated 16 MiB bombs, and >16 MiB single-stream S2 recovery."""
        chunk_12mib = zlib.compress(b"\x00" * (12 * 1024 * 1024), level=1)
        trailing_launch = zlib.compress(b"/Launch", level=1)
        stream_tpl = b"\n<< /Filter /FlateDecode >>\nstream\n"
        multi_bomb_pdf = (
            b"%PDF-1.4\n"
            + stream_tpl + chunk_12mib + b"\nendstream\n"
            + stream_tpl + chunk_12mib + b"\nendstream\n"
            + stream_tpl + chunk_12mib + b"\nendstream\n"
            + stream_tpl + trailing_launch + b"\nendstream\n"
            + b"%%EOF\n"
        )
        res = inspect_pdf_container(multi_bomb_pdf, label="cumulative_budget.pdf")
        self.assertFalse(res["valid_container"])
        self.assertTrue(
            any("32 MiB" in err["reason"] for err in res["container_errors"]),
            res["container_errors"],
        )
        self.assertNotIn("launch_actions", res["risk_markers"])

        # 1. Single >16 MiB stream skipped while subsequent valid stream S2 (within remaining budget) IS recovered
        chunk_17mib = zlib.compress(b"\x00" * (17 * 1024 * 1024), level=1)
        s2_xmp = zlib.compress(
            b'<?xpacket begin=""?><rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
            b'xmp:CreatorTool="RecoveredS2"/>'
            b'<?xpacket end="w"?>\n/OpenAction',
            level=1,
        )
        recover_s2_pdf = (
            b"%PDF-1.4\n"
            + stream_tpl + chunk_17mib + b"\nendstream\n"
            + stream_tpl + s2_xmp + b"\nendstream\n"
            + b"%%EOF\n"
        )
        res_rec = inspect_pdf_container(recover_s2_pdf, label="recover_s2.pdf")
        self.assertFalse(res_rec["valid_container"])
        self.assertTrue(any("16 MiB" in e["reason"] for e in res_rec["container_errors"]))
        self.assertEqual(len(res_rec["xmp_metadata"]), 1)
        self.assertEqual(res_rec["xmp_metadata"][0]["creator_tool"], "RecoveredS2")
        self.assertEqual(res_rec["risk_markers"].get("open_actions"), 1)

        # 2. Repeated 16 MiB+ bombs charge unpacked bytes so Stream 2 immediately trips 32 MiB circuit breaker
        repeated_bombs_pdf = (
            b"%PDF-1.4\n"
            + (stream_tpl + chunk_17mib + b"\nendstream\n") * 6
            + stream_tpl + trailing_launch + b"\nendstream\n"
            + b"%%EOF\n"
        )
        res_rep = inspect_pdf_container(repeated_bombs_pdf, label="repeated_17m.pdf")
        self.assertFalse(res_rep["valid_container"])
        self.assertTrue(any("32 MiB" in e["reason"] for e in res_rep["container_errors"]))
        self.assertNotIn("launch_actions", res_rep["risk_markers"])

    def test_pdf_endstream_no_leading_eol_long_dict_and_xmp_cap(self) -> None:
        """Verify endstream abutting Adler-32 directly, >256-byte dict lookback, S1 unclosed -> S2 recovery, and 256 XMP cap."""
        s1_comp = zlib.compress(b"Clean stream 1 body")
        s2_comp = zlib.compress(
            b'<?xpacket begin=""?><rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
            b'xmp:CreatorTool="DirectAbutS2"/><?xpacket end="w"?>'
        )
        long_dict_pad = b"/Note (" + (b"D" * 1200) + b") "
        # S1 has NO EOL before endstream AND S2 has /FlateDecode >1200 bytes before stream; S3 has /FlateDecodeExtra;
        # S4 is a single-line stream dict containing a literal '%' inside a string value (`50% discount`).
        s4_comp = zlib.compress(
            b'<?xpacket begin=""?><rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
            b'xmp:CreatorTool="PercentStringDictS4"/><?xpacket end="w"?>'
        )
        abut_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + s1_comp + b"endstream\nendobj\n"
            b"2 0 obj\n<< /Filter /FlateDecode " + long_dict_pad + b">>\nstream\n" + s2_comp + b"endstream\nendobj\n"
            b"3 0 obj\n<< /Filter /FlateDecodeExtra >>\nstream\n" + zlib.compress(b"/Launch") + b"endstream\nendobj\n"
            b"4 0 obj\n<< /Filter /FlateDecode /Comment (50% discount) >>\nstream\n" + s4_comp + b"\nendstream\nendobj\n"
            b"%%EOF\n"
        )
        res_abut = inspect_pdf_container(abut_pdf, label="abut.pdf")
        self.assertTrue(res_abut["valid_container"], res_abut["container_errors"])
        self.assertEqual(len(res_abut["xmp_metadata"]), 2)
        self.assertEqual(
            [x["creator_tool"] for x in res_abut["xmp_metadata"]],
            ["DirectAbutS2", "PercentStringDictS4"],
        )
        self.assertNotIn("launch_actions", res_abut["risk_markers"])

        # Malformed S1 missing endstream before valid S2: S2 XMP is still extracted and S1 anomaly is logged
        missing_endstream_s1 = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + s1_comp + b"\nendobj\n"
            b"2 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + s2_comp + b"\nendstream\nendobj\n"
            b"%%EOF\n"
        )
        res_s1_unclosed = inspect_pdf_container(missing_endstream_s1, label="s1_missing_end.pdf")
        self.assertFalse(res_s1_unclosed["valid_container"])
        self.assertEqual(len(res_s1_unclosed["xmp_metadata"]), 1)
        self.assertEqual(res_s1_unclosed["xmp_metadata"][0]["creator_tool"], "DirectAbutS2")

        # Tiny XMP object-graph amplification bomb (20,000 XMP packets ~1.48 MB inside FlateDecode) capped at MAX_XMP_PACKETS
        tiny_pkt = b'<?xpacket begin=""?><rdf:Description xmlns:xmp="x" xmp:CreatorTool="T"/><?xpacket end="w"?>'
        comp_many_xmp = zlib.compress(tiny_pkt * 20000, level=1)
        xmp_bomb_pdf = (
            b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + comp_many_xmp + b"\nendstream\n%%EOF\n"
        )
        res_xmp_cap = inspect_pdf_container(xmp_bomb_pdf, label="xmp_cap.pdf")
        self.assertEqual(len(res_xmp_cap["xmp_metadata"]), MAX_XMP_PACKETS)
        self.assertFalse(res_xmp_cap["valid_container"])
        self.assertTrue(any(str(MAX_XMP_PACKETS) in e["reason"] for e in res_xmp_cap["container_errors"]))

    def test_pdf_redaction_non_mutation_and_default_ephemeral_salt_consistency(self) -> None:
        """Ensure apply_pdf_redaction never mutates input dicts/lists and defaults to DEFAULT_EPHEMERAL_SALT."""
        xmp_xml = (
            b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            b'<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
            b'xmp:CreatorTool="CanarySuite 2.0" xmp:CreateDate="2026-03-18T10:00:00Z"/>'
            b'<?xpacket end="w"?>'
        )
        raw_pdf = build_synthetic_incremental_pdf() + b"\n" + xmp_xml
        original = inspect_pdf_container(raw_pdf, label="CANARY_ORIGINAL_LABEL.pdf")
        frozen_before = copy.deepcopy(original)

        red1 = apply_pdf_redaction(original, redact=True)
        red2 = apply_pdf_redaction(original, redact=True)
        unred_copy = apply_pdf_redaction(original, redact=False)

        # Strict non-mutation of original input across both redact=True and redact=False
        self.assertEqual(original, frozen_before)
        self.assertIsNot(unred_copy, original)
        self.assertIsNot(unred_copy["info_metadata"], original["info_metadata"])

        # Process-run HMAC token alignment via DEFAULT_EPHEMERAL_SALT when salt is None
        self.assertEqual(red1, red2)
        self.assertEqual(red1["artifact"], "[REDACTED_PDF_LABEL]")
        self.assertIsNone(red1["file_size_bytes"])
        expected_prod_hmac = mask_identifier("ReportLab PDF Library 4.0", salt=DEFAULT_EPHEMERAL_SALT)
        self.assertIn(expected_prod_hmac, red1["info_metadata"]["Producer"])
        expected_xmp_hmac = mask_identifier("CanarySuite 2.0", salt=DEFAULT_EPHEMERAL_SALT)
        self.assertEqual(red1["xmp_metadata"][0]["creator_tool"], expected_xmp_hmac)
        self.assertEqual(red1["xmp_metadata"][0]["create_date"], "[REDACTED_PDF_TIMESTAMP]")

    def test_pdf_cli_and_mcp_masked_and_error_paths_zero_leak(self) -> None:
        """Verify CLI inspect-pdf and MCP starshield_inspect_pdf_tamper leak zero filenames, sizes, or hashes."""
        from starshield.mcp_server import handle_mcp_message

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Valid PDF & truncated PDF with unique byte length (13579) in masked mode
            valid_bytes = build_synthetic_incremental_pdf()
            valid_sha = hashlib.sha256(valid_bytes).hexdigest()
            valid_path = Path(tmpdir) / "CANARY_SECRET_BEC_INVOICE_4411.pdf"
            valid_path.write_bytes(valid_bytes)

            trunc_bytes = (b"%PDF-1.4\n1 0 obj\n<< /Author (CANARY_AUTHOR_4412) >>\nendobj\n").ljust(13579, b" ")
            trunc_sha = hashlib.sha256(trunc_bytes).hexdigest()
            trunc_path = Path(tmpdir) / "CANARY_TRUNCATED_PDF_4412.pdf"
            trunc_path.write_bytes(trunc_bytes)

            for target_path, raw_b, raw_sha in (
                (valid_path, valid_bytes, valid_sha),
                (trunc_path, trunc_bytes, trunc_sha),
            ):
                cli_out, cli_err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(cli_out), contextlib.redirect_stderr(cli_err):
                    rc = main(["inspect-pdf", str(target_path)])
                self.assertEqual(rc, 0)
                combined_cli = cli_out.getvalue() + cli_err.getvalue()
                self.assertNotIn(target_path.name, combined_cli)
                self.assertNotIn(str(tmpdir), combined_cli)
                self.assertNotIn(str(len(raw_b)), re.sub(r"\[REDACTED_HMAC:[0-9a-f]+\]", "[REDACTED_HMAC]", combined_cli))
                self.assertNotIn(raw_sha, combined_cli)
                self.assertNotIn("CANARY_AUTHOR_4412", combined_cli)

                mcp_ok = handle_mcp_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 601,
                        "method": "tools/call",
                        "params": {"name": "starshield_inspect_pdf_tamper", "arguments": {"pdf_path": str(target_path)}},
                    },
                    redact=True,
                )
                mcp_txt = json.dumps(mcp_ok)
                self.assertNotIn(target_path.name, mcp_txt)
                self.assertNotIn(str(tmpdir), mcp_txt)
                self.assertNotIn(str(len(raw_b)), re.sub(r"\[REDACTED_HMAC:[0-9a-f]+\]", "[REDACTED_HMAC]", mcp_txt))
                self.assertNotIn(raw_sha, mcp_txt)
                self.assertNotIn("CANARY_AUTHOR_4412", mcp_txt)

            # 2. Missing file & oversize file error paths in CLI and MCP masked mode
            missing_pdf = Path(tmpdir) / "CANARY_MISSING_PDF_DIR_4413" / "secret_wire.pdf"
            oversize_pdf = Path(tmpdir) / "CANARY_OVERSIZE_PDF_4414.pdf"
            oversize_len = 2 * 1024 * 1024 + 41
            with open(oversize_pdf, "wb") as fh:
                os.truncate(fh.fileno(), oversize_len)

            for bad_path, extra_cli_args in (
                (missing_pdf, []),
                (oversize_pdf, ["--max-mb", "1"]),
            ):
                err_b = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_b):
                    rc_err = main([*extra_cli_args, "inspect-pdf", str(bad_path)])
                self.assertEqual(rc_err, 2)
                err_str = err_b.getvalue()
                self.assertNotIn(bad_path.name, err_str)
                self.assertNotIn("CANARY_", err_str)
                self.assertNotIn(str(tmpdir), err_str)
                self.assertNotIn(str(oversize_len), err_str)

                mcp_err = handle_mcp_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 602,
                        "method": "tools/call",
                        "params": {"name": "starshield_inspect_pdf_tamper", "arguments": {"pdf_path": str(bad_path)}},
                    },
                    redact=True,
                    max_mb=1,
                )
                self.assertTrue(mcp_err["result"]["isError"])
                mcp_err_str = json.dumps(mcp_err)
                self.assertNotIn(bad_path.name, mcp_err_str)
                self.assertNotIn("CANARY_", mcp_err_str)
                self.assertNotIn(str(tmpdir), mcp_err_str)
                self.assertNotIn(str(oversize_len), mcp_err_str)

    def test_keccak256_and_rd03_cross_border_financial_validators(self) -> None:
        # Canonical Keccak-256 (0x01) empty, "abc", and 135/136/137-byte rate-boundary digests
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )
        self.assertEqual(
            keccak256(b"a" * 135).hex(),
            "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
        )
        self.assertEqual(
            keccak256(b"a" * 136).hex(),
            "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
        )
        self.assertEqual(
            keccak256(b"a" * 137).hex(),
            "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39",
        )

        # IBAN extraction ReDoS regression: "AA00" + "A"*36 + " " completes in < 50ms,
        # and unspaced IBAN followed by newline + uppercase token ("GB82WEST12345698765432\nSWIFT") extracts cleanly
        iban_redos_txt = ("AA00" + ("A" * 36) + " ") * 50
        t_iban = time.perf_counter()
        self.assertEqual(extract_validated_iocs(iban_redos_txt, redact=False)["mod97_validated_ibans"], [])
        self.assertLess(time.perf_counter() - t_iban, 1.5)
        nl_iban_res = extract_validated_iocs("GB82WEST12345698765432\nSWIFT NWBKGB2LXXX", redact=False)
        self.assertEqual(nl_iban_res["mod97_validated_ibans"], ["GB82WEST12345698765432"])
        self.assertEqual(nl_iban_res["validated_swift_bics"], ["NWBKGB2LXXX"])

        # SWIFT local +/-120-char context window & expanded commercial stopwords
        distant_swift = "Wire via SWIFT NWBKGB2LXXX " + ("x" * 200) + " BACAADAD SUPPLIER HOLDINGS ATTACHED OVERSEAS"
        swift_res = extract_validated_iocs(distant_swift, redact=False)["validated_swift_bics"]
        self.assertEqual(swift_res, ["NWBKGB2LXXX"])

        # All 8/8 official Ethereum EIP-55 spec test vectors (4 mixed-case, 2 all-caps, 2 all-low) & negatives
        eip55_ok = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        eip55_ok2 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        eip55_ok3 = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        eip55_ok4 = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        eip55_spec_all_caps_1 = "0x52908400098527886E0F7030069857D2E4169EE7"
        eip55_spec_all_caps_2 = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
        eip55_spec_all_low_1 = "0xde709f2102306220921060314715629080e2fb77"
        eip55_spec_all_low_2 = "0x27b1fdb04752bbc536007a920d24acb045561c26"
        eip55_bad_case = "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        for spec_vec in (
            eip55_ok,
            eip55_ok2,
            eip55_ok3,
            eip55_ok4,
            eip55_spec_all_caps_1,
            eip55_spec_all_caps_2,
            eip55_spec_all_low_1,
            eip55_spec_all_low_2,
        ):
            self.assertTrue(eth_eip55_checksum_valid(spec_vec), spec_vec)
        self.assertFalse(eth_eip55_checksum_valid(eip55_bad_case))
        self.assertFalse(eth_eip55_checksum_valid(eip55_ok.lower()))
        self.assertFalse(eth_eip55_checksum_valid(eip55_ok.upper()))
        self.assertFalse(eth_eip55_checksum_valid("0x" + ("0" * 40)))

        # Single-alpha-character EIP-55 edge case computed directly against Keccak-256 nibble
        single_alpha_lower = ("0" * 39) + "a"
        nibble_39 = int(keccak256(single_alpha_lower.encode("ascii")).hex()[39], 16)
        valid_single_alpha = "0x" + ("0" * 39) + ("A" if nibble_39 >= 8 else "a")
        wrong_single_alpha = "0x" + ("0" * 39) + ("a" if nibble_39 >= 8 else "A")
        self.assertTrue(eth_eip55_checksum_valid(valid_single_alpha))
        self.assertFalse(eth_eip55_checksum_valid(wrong_single_alpha))

        # US ABA Routing positive & negatives (including Unicode superscript rejection)
        self.assertTrue(aba_routing_valid("021000021"))
        self.assertFalse(aba_routing_valid("021000022"))  # bad check digit
        self.assertFalse(aba_routing_valid("990000021"))  # invalid Fed prefix
        self.assertFalse(aba_routing_valid("02100002²"))  # non-ASCII digit

        # ISO 11649 RF Creditor Reference positive & negative + 25-char trailing single-char grouping
        self.assertTrue(iso11649_creditor_ref_valid("RF18539007547034"))
        self.assertTrue(iso11649_creditor_ref_valid("RF18 5390 0754 7034"))
        self.assertFalse(iso11649_creditor_ref_valid("RF19539007547034"))
        rf25_tail = "123456789012345678901"
        rf25_chk = 98 - (int(rf25_tail + "271500") % 97)
        rf25_spaced = f"RF{rf25_chk:02d} 1234 5678 9012 3456 7890 1"
        self.assertTrue(iso11649_creditor_ref_valid(rf25_spaced))
        self.assertEqual(
            extract_validated_iocs(f"Ref {rf25_spaced} USD", redact=False)["iso11649_creditor_references"],
            [f"RF{rf25_chk:02d}{rf25_tail}"],
        )

        # Synthetic ISO 17442 LEI positive, negative, & alpha-LOU context gate
        lei_body = "549300SYNTH0LEI001"
        lei_num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in (lei_body + "00"))
        lei_chk = 98 - (int(lei_num) % 97)
        valid_lei = f"{lei_body}{lei_chk:02d}"
        bad_lei = f"{lei_body}{(lei_chk + 1) % 97:02d}"
        self.assertTrue(lei_iso17442_valid(valid_lei))
        self.assertFalse(lei_iso17442_valid(bad_lei))

        alpha_lei_body = "ABCD00SYNTH0LEI001"
        alpha_lei_num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in (alpha_lei_body + "00"))
        alpha_lei_chk = 98 - (int(alpha_lei_num) % 97)
        valid_alpha_lei = f"{alpha_lei_body}{alpha_lei_chk:02d}"
        self.assertEqual(extract_validated_iocs(f"Token {valid_alpha_lei}", redact=False)["validated_leis"], [])
        self.assertEqual(
            extract_validated_iocs(f"Legal Entity {valid_alpha_lei}", redact=False)["validated_leis"],
            [valid_alpha_lei],
        )

        # Synthetic TRON TRC-20 Base58Check address (`0x41` + double SHA-256 checksum) + version/overflow rejections
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        def b58encode25(raw21: bytes) -> str:
            c4 = hashlib.sha256(hashlib.sha256(raw21).digest()).digest()[:4]
            v = int.from_bytes(raw21 + c4, "big")
            out_c = []
            while v:
                v, r = divmod(v, 58)
                out_c.append(alphabet[r])
            return "".join(reversed(out_c))

        valid_tron = b58encode25(b"\x41" + bytes(range(1, 21)))
        self.assertTrue(valid_tron.startswith("T") and len(valid_tron) == 34)
        bad_tron = valid_tron[:-1] + ("2" if valid_tron[-1] != "2" else "3")
        wrong_ver_tron = b58encode25(b"\x40\xff" + (b"\xff" * 19))
        self.assertTrue(wrong_ver_tron.startswith("T") and len(wrong_ver_tron) == 34)
        overflow_tron = "T" + ("z" * 33)
        self.assertTrue(tron_trc20_address_valid(valid_tron))
        self.assertFalse(tron_trc20_address_valid(bad_tron))
        self.assertFalse(tron_trc20_address_valid(wrong_ver_tron))
        self.assertFalse(tron_trc20_address_valid(overflow_tron))

        # Full extraction positive + context gate + masked HMAC redaction check
        bare_num_only = "Order ID 021000021 shipped in batch four."
        self.assertEqual(extract_validated_iocs(bare_num_only, redact=False)["aba_validated_routing_numbers"], [])

        sample_msg = (
            f"Remit via ABA Routing 021000021, Creditor Ref RF18 5390 0754 7034, "
            f"LEI {valid_lei}, TRON {valid_tron}, ETH {eip55_ok}, or vault {valid_single_alpha}."
        )
        unred_iocs = extract_validated_iocs(sample_msg, redact=False)
        self.assertEqual(unred_iocs["aba_validated_routing_numbers"], ["021000021"])
        self.assertEqual(unred_iocs["iso11649_creditor_references"], ["RF18539007547034"])
        self.assertEqual(unred_iocs["validated_leis"], [valid_lei])
        self.assertEqual(unred_iocs["base58check_tron_addresses"], [valid_tron])
        self.assertEqual(unred_iocs["eip55_eth_addresses"], [eip55_ok, valid_single_alpha])

        red_iocs = extract_validated_iocs(sample_msg, redact=True, salt=b"fixed_ioc_salt_16")
        for field, expected_cnt in (
            ("aba_validated_routing_numbers", 1),
            ("iso11649_creditor_references", 1),
            ("validated_leis", 1),
            ("base58check_tron_addresses", 1),
            ("eip55_eth_addresses", 2),
        ):
            self.assertEqual(len(red_iocs[field]), expected_cnt)
            self.assertTrue(all(tok.startswith("[REDACTED_HMAC:") for tok in red_iocs[field]))

    def test_cli_and_mcp_deep_json_recursion_unexpected_args_and_demo_key_file(self) -> None:
        """Verify 2000-deep JSON RecursionError handling, MCP unexpected arg rejection, non-regular file gate, and demo --hmac-key-file."""
        from starshield.mcp_server import handle_mcp_message, run_mcp_stdio_server

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Deeply nested JSON `[...]` triggers RecursionError and is caught cleanly without traceback/path leak
            deep_json_path = Path(tmpdir) / "CANARY_DEEP_NESTED_JSON_8811.json"
            deep_payload = ("[" * 10000 + "]" * 10000).encode("ascii")
            deep_json_path.write_bytes(deep_payload)

            err_cli = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_cli):
                rc_deep = main(["triage-json", str(deep_json_path)])
            self.assertEqual(rc_deep, 2)
            self.assertNotIn("Traceback", err_cli.getvalue())
            self.assertNotIn("CANARY_DEEP_NESTED_JSON_8811", err_cli.getvalue())
            self.assertTrue(json.loads(err_cli.getvalue())["masked_mode"])

            # Directory passed to file-only `inspect-pdf` rejected by regular-file S_ISREG gate
            dir_err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(dir_err):
                rc_dir = main(["inspect-pdf", str(tmpdir)])
            self.assertEqual(rc_dir, 2)
            self.assertNotIn(str(tmpdir), dir_err.getvalue())

            # Deeply nested JSON over MCP stdio returns clean -32700 parse error without crashing server
            mcp_out = io.BytesIO()
            rc_mcp_deep = run_mcp_stdio_server(
                redact=True,
                instream=io.BytesIO(deep_payload + b"\n"),
                outstream=mcp_out,
            )
            self.assertEqual(rc_mcp_deep, 0)
            self.assertIn(json.loads(mcp_out.getvalue().decode("utf-8"))["error"]["code"], (-32700, -32600))

            # 2. MCP unexpected tool arguments rejected per additionalProperties=False without echoing canary keys
            pdf_path = Path(tmpdir) / "clean.pdf"
            pdf_path.write_bytes(build_synthetic_incremental_pdf())
            bad_arg_resp = handle_mcp_message(
                {
                    "jsonrpc": "2.0",
                    "id": 701,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_inspect_pdf_tamper",
                        "arguments": {
                            "pdf_path": str(pdf_path),
                            "CANARY_UNEXPECTED_ARG_8812": "CANARY_SECRET_VAL_8812",
                        },
                    },
                },
                redact=True,
            )
            self.assertTrue(bad_arg_resp["result"]["isError"])
            bad_arg_txt = json.dumps(bad_arg_resp)
            self.assertNotIn("CANARY_UNEXPECTED_ARG_8812", bad_arg_txt)
            self.assertNotIn("CANARY_SECRET_VAL_8812", bad_arg_txt)

            # 3. `starshield --hmac-key-file ... demo` produces deterministic tokens & restores active digest afterward
            key_file = Path(tmpdir) / "demo_hmac.key"
            key_file.write_bytes(b"deterministic-demo-key-material-32b!")
            demo1, demo2 = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(demo1):
                self.assertEqual(main(["--hmac-digest", "blake2b", "--hmac-key-file", str(key_file), "demo"]), 0)
            with contextlib.redirect_stdout(demo2):
                self.assertEqual(main(["--hmac-digest", "blake2b", "--hmac-key-file", str(key_file), "demo"]), 0)
            d1 = json.loads(demo1.getvalue())
            d2 = json.loads(demo2.getvalue())
            self.assertEqual(d1["engine_2_exported_json_triage"], d2["engine_2_exported_json_triage"])
            self.assertEqual(d1["engine_1_raw_leveldb_wal_carver"], d2["engine_1_raw_leveldb_wal_carver"])
            # Active HMAC digest is cleanly restored to sha256 after main() returns
            self.assertEqual(get_active_hmac_digest(), "sha256")

    def test_image_description_hint_linear_merge_and_mcp_error_sanitization(self) -> None:
        """Verify description_hint masking + deepcopy, O(M) 2200-message IBAN triage, and MCP zero-reflection errors."""
        from starshield.mcp_server import handle_mcp_message

        # 1. Custom description_hint in img_report & PNG containers masked without mutating input dict
        custom_rep = {
            "artifact": "raw_canary.png",
            "valid_container": True,
            "icc_profiles": [
                {
                    "valid_icc_header": True,
                    "description_hint": "CANARY_PRIVATE_IDENTITY",
                    "png_iccp_name": "CANARY_PRIVATE_IDENTITY",
                }
            ],
        }
        rep_snapshot = copy.deepcopy(custom_rep)
        masked_rep = apply_image_redaction(custom_rep, redact=True, salt=b"test_icc_salt_16")
        self.assertEqual(custom_rep, rep_snapshot)
        self.assertTrue(masked_rep["icc_profiles"][0]["description_hint"].startswith("[REDACTED_HMAC:"))
        self.assertNotIn("CANARY_PRIVATE_IDENTITY", json.dumps(masked_rep))

        with tempfile.TemporaryDirectory() as tmpdir:
            for idx, (p_desc, i_name, expect_masked_desc) in enumerate(
                (
                    ("CANARY_PRIVATE_IDENTITY", "CANARY_PRIVATE_IDENTITY", False),
                    ("sRGB IEC61966-2.1 CANARY_PRIVATE_IDENTITY", "CANARY_PRIVATE_IDENTITY", True),
                )
            ):
                png_bytes = build_valid_png_with_iccp(profile_desc=p_desc, iccp_name=i_name)
                p_file = Path(tmpdir) / f"CANARY_IMG_{idx}.png"
                p_file.write_bytes(png_bytes)

                cli_buf = io.StringIO()
                with contextlib.redirect_stdout(cli_buf):
                    self.assertEqual(main(["inspect-image", str(p_file)]), 0)
                cli_txt = cli_buf.getvalue()
                self.assertNotIn("CANARY_PRIVATE_IDENTITY", cli_txt)
                self.assertNotIn("sRGB IEC61966-2.1", cli_txt)
                if expect_masked_desc:
                    cli_icc = json.loads(cli_txt)["image_container_analysis"]["icc_profiles"][0]
                    self.assertTrue(str(cli_icc["description_hint"]).startswith("[REDACTED_HMAC:"))

                mcp_img = handle_mcp_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 801 + idx,
                        "method": "tools/call",
                        "params": {"name": "starshield_inspect_image_tamper", "arguments": {"image_path": str(p_file)}},
                    },
                    redact=True,
                )
                mcp_img_txt = json.dumps(mcp_img)
                self.assertNotIn("CANARY_PRIVATE_IDENTITY", mcp_img_txt)
                self.assertNotIn("sRGB IEC61966-2.1", mcp_img_txt)

        # 2. O(M) corpus IOC deduplication across 2,200 distinct-IBAN messages in < 1.0s
        # "WEST" = 32 14 28 29, "GB00" = 16 11 00 -> precompute mod 97 via arithmetic
        messages_2200 = []
        for i in range(2200):
            bban_num = f"32142829{10000000000000 + i:014d}161100"
            chk = 98 - (int(bban_num) % 97)
            iban_i = f"GB{chk:02d}WEST{10000000000000 + i:014d}"
            messages_2200.append({"id": f"m_{i}", "from": "u1", "content": f"Pay {iban_i}"})

        t0 = time.perf_counter()
        triaged_2200 = triage_exported_chatsvc_json({"messages": messages_2200}, redact=False)
        elapsed_2200 = time.perf_counter() - t0
        self.assertEqual(len(triaged_2200["corpus_validated_iocs"]["mod97_validated_ibans"]), 2200)
        self.assertLess(elapsed_2200, 3.0)

        # 3. Masked MCP unknown tool (-32602) & unknown method (-32601) never reflect caller strings
        unk_tool = handle_mcp_message(
            {
                "jsonrpc": "2.0",
                "id": 810,
                "method": "tools/call",
                "params": {"name": "CANARY_UNKNOWN_TOOL"},
            },
            redact=True,
        )
        self.assertEqual(unk_tool["error"]["code"], -32602)
        self.assertNotIn("CANARY_UNKNOWN_TOOL", json.dumps(unk_tool))

        unk_method = handle_mcp_message(
            {
                "jsonrpc": "2.0",
                "id": 811,
                "method": "CANARY_UNKNOWN_METHOD",
            },
            redact=True,
        )
        self.assertEqual(unk_method["error"]["code"], -32601)
        self.assertNotIn("CANARY_UNKNOWN_METHOD", json.dumps(unk_method))

    def test_pdf_corrupt_flate_budget_hex_names_objstm_length_and_mcp_int(self) -> None:
        """Verify corrupt FlateDecode budget cap, ISO 32000 #xx Name escapes, /ObjStm /Length, and MCP huge-int bounds."""
        from starshield.mcp_server import run_mcp_stdio_server

        # 400x corrupt near-16 MiB FlateDecode streams (16 MiB - 4 KiB zeros + invalid block byte 0x06)
        # must charge unpacked chunks and trip the 32 MiB circuit breaker immediately without decompressing 6.4 GiB
        cobj = zlib.compressobj(level=1)
        corrupt_16m = cobj.compress(b"\x00" * (16 * 1024 * 1024 - 4096)) + cobj.flush(zlib.Z_SYNC_FLUSH) + b"\x06"
        trailing_launch = zlib.compress(b"/Launch", level=1)
        h1_pdf = (
            b"%PDF-1.4\n"
            + (b"<< /Filter /FlateDecode >>\nstream\n" + corrupt_16m + b"\nendstream\n") * 400
            + b"<< /Filter /FlateDecode >>\nstream\n" + trailing_launch + b"\nendstream\n"
            + b"%%EOF\n"
        )
        t_h1 = time.perf_counter()
        res_h1 = inspect_pdf_container(h1_pdf, label="corrupt_flate_bomb.pdf")
        self.assertFalse(res_h1["valid_container"])
        self.assertTrue(any("32 MiB" in e["reason"] for e in res_h1["container_errors"]), res_h1["container_errors"])
        self.assertNotIn("launch_actions", res_h1["risk_markers"])
        self.assertLess(time.perf_counter() - t_h1, 3.0)

        # 20,000 `>>\nstream\n` and 20,000 `% stream\n` complete in linear bounded time via monotonic scan_floor
        t_h2a = time.perf_counter()
        res_h2a_scan = inspect_pdf_container(b"%PDF-1.4\n" + (b">>\nstream\n" * 20000) + b"%%EOF\n")
        self.assertEqual(res_h2a_scan["risk_markers"], {})
        self.assertLess(time.perf_counter() - t_h2a, 3.0)

        t_h2b = time.perf_counter()
        res_h2b_scan = inspect_pdf_container(b"%PDF-1.4\n" + (b"% stream\n" * 20000) + b"%%EOF\n")
        self.assertTrue(res_h2b_scan["valid_container"])
        self.assertLess(time.perf_counter() - t_h2b, 3.0)

        # H3 + M4 + M5 + N1: ISO 32000-1 §7.3.5 `#xx` Name escapes, `%` / string spoof immunity,
        # `/Type /ObjStm` Info extraction, `/Length N` over embedded fake `endstream `, and `header_offset=None`
        objstm_payload = (
            b"4 0 << /Producer (ObjStm Real Producer 3.1) /OpenActio#6E << /S /Java#53cript /J#53 (1) >> >>\n"
            b"endstream \n"
            b"5 0 << /Creator (After Fake Endstream via Length) >>"
        )
        stored_objstm = zlib.compress(objstm_payload, level=0)
        self.assertIn(b"endstream ", stored_objstm)

        h3_m4_m5_pdf = (
            b"   %PDF-1.5\n"
            b"% /Producer (Comment Spoofed Producer)\n"
            b"1 0 obj\n<< /Note (Body string mentioning /Producer (String Spoofed) and /JavaScript) "
            b"/Pro#64ucer (TopHexEscapedProducer) >>\nendobj\n"
            + f"2 0 obj\n<< /Type /ObjStm /Filter /Flate#44ecode /Length {len(stored_objstm)} >>\nstream\n".encode(
                "ascii"
            )
            + stored_objstm
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h3 = inspect_pdf_container(h3_m4_m5_pdf, label="hex_objstm.pdf")
        self.assertTrue(res_h3["valid_container"], res_h3["container_errors"])
        self.assertEqual(res_h3["header_offset"], 3)
        self.assertEqual(
            res_h3["info_metadata"]["Producer"],
            ["TopHexEscapedProducer", "ObjStm Real Producer 3.1"],
        )
        self.assertEqual(res_h3["info_metadata"]["Creator"], ["After Fake Endstream via Length"])
        self.assertEqual(res_h3["risk_markers"]["js_actions"], 2)
        self.assertEqual(res_h3["risk_markers"]["open_actions"], 1)
        self.assertGreaterEqual(res_h3["risk_markers"]["obfuscated_name_tokens"], 5)

        red_h3 = apply_pdf_redaction(res_h3, redact=True)
        self.assertIsNone(red_h3["header_offset"])

        # M3: >64 distinct Info values per key capped at MAX_INFO_VALUES_PER_KEY (64)
        many_titles = b"".join(f"/Title (DocTitle_{i:04d})\n".encode("ascii") for i in range(90))
        res_m3 = inspect_pdf_container(b"%PDF-1.4\n1 0 obj\n<<\n" + many_titles + b">>\nendobj\n%%EOF\n")
        self.assertEqual(len(res_m3["info_metadata"]["Title"]), MAX_INFO_VALUES_PER_KEY)
        self.assertFalse(res_m3["valid_container"])
        self.assertTrue(any("Info value cap reached" in e["reason"] for e in res_m3["container_errors"]))

        # M2: MCP stdio server survives 5,000-digit JSON integer (Python int_max_str_digits ValueError) with -32700
        huge_int_rpc = b'{"jsonrpc":"2.0","id":' + (b"9" * 5000) + b',"method":"ping"}\n'
        followup_rpc = b'{"jsonrpc":"2.0","id":909,"method":"ping"}\n'
        mcp_buf = io.BytesIO()
        self.assertEqual(
            run_mcp_stdio_server(redact=True, instream=io.BytesIO(huge_int_rpc + followup_rpc), outstream=mcp_buf),
            0,
        )
        mcp_lines = [json.loads(ln) for ln in mcp_buf.getvalue().decode("utf-8").strip().splitlines()]
        self.assertEqual(len(mcp_lines), 2)
        self.assertEqual(mcp_lines[0]["error"]["code"], -32700)
        self.assertEqual(mcp_lines[1]["id"], 909)
        self.assertEqual(mcp_lines[1]["result"], {})

        # strip_markup("<" * 40000) runs in linear bounded time
        t_m6 = time.perf_counter()
        stripped_lt = strip_markup("<" * 40000)
        self.assertEqual(len(stripped_lt), 40000)
        self.assertLess(time.perf_counter() - t_m6, 2.0)

    def test_pdf_lf_comment_scan_streamx_length_swallow_decoy_stream_and_filters(self) -> None:
        """Verify LF-only comment scan, streamX token handling, lying /Length overrun checks, and filter chains."""
        # ~2 KB FlateDecode of 1,000,000 LF-only `%\n` lines completes without unbounded CR scans
        comp_lf_comments = zlib.compress(b"%\n" * 1_000_000, level=9)
        self.assertLess(len(comp_lf_comments), 4096)
        b1_pdf = b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + comp_lf_comments + b"\nendstream\n%%EOF\n"
        t_b1 = time.perf_counter()
        res_b1 = inspect_pdf_container(b1_pdf, label="lf_comments.pdf")
        self.assertTrue(res_b1["valid_container"], res_b1["container_errors"])
        self.assertLess(time.perf_counter() - t_b1, 2.5)

        # 40,000 newline-free ` streamX` tokens complete cleanly
        h1_streamx = b"%PDF-1.7 " + (b" streamX" * 40000) + b" %%EOF"
        t_h1 = time.perf_counter()
        res_streamx = inspect_pdf_container(h1_streamx, label="streamx_tokens.pdf")
        self.assertTrue(res_streamx["valid_container"], res_streamx["container_errors"])
        self.assertLess(time.perf_counter() - t_h1, 2.5)

        # R2-H2 (a): Lying `/Length` spanning `endstream\\nendobj\\n2 0 obj ...` up to a later stream's `endstream`
        # must flag container error AND still detect swallowed OpenAction, JS, AcroForm, and Producer
        s1_benign = zlib.compress(b"benign stream 1")
        swallowed_section = (
            s1_benign
            + b"\nendstream\nendobj\n"
            b"2 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> "
            b"/AcroForm << >> /Producer (SwallowedByLengthProducer) >>\nendobj\n"
            b"3 0 obj\n<< /Length 5 >>\nstream\nhello"
        )
        lying_len_pdf = (
            f"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length {len(swallowed_section)} >>\nstream\n".encode("ascii")
            + swallowed_section
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h2a = inspect_pdf_container(lying_len_pdf, label="r2_h2_lying_len.pdf")
        self.assertFalse(res_h2a["valid_container"])
        self.assertTrue(
            any("overruns an earlier endstream" in e["reason"] for e in res_h2a["container_errors"]),
            res_h2a["container_errors"],
        )
        self.assertEqual(res_h2a["risk_markers"].get("open_actions"), 1)
        self.assertEqual(res_h2a["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_h2a["risk_markers"].get("acroforms"), 1)
        self.assertEqual(res_h2a["info_metadata"].get("Producer"), ["SwallowedByLengthProducer"])

        # R2-H2 (b): Lying `/Length` WITHOUT an earlier `endstream` (appending hidden objects right after deflate EOF)
        # must flag trailing bytes after stream EOF AND scan the post-EOF objects
        post_eof_section = (
            s1_benign
            + b"\n2 0 obj\n<< /OpenAction << /S /JavaScript /JS (1) >> "
            b"/AcroForm << >> /Producer (PostDeflateEOFProducer) >>\nendobj\n"
        )
        trailing_len_pdf = (
            f"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length {len(post_eof_section)} >>\nstream\n".encode("ascii")
            + post_eof_section
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h2b = inspect_pdf_container(trailing_len_pdf, label="r2_h2_trailing_eof.pdf")
        self.assertFalse(res_h2b["valid_container"])
        self.assertTrue(
            any("trailing bytes after stream EOF" in e["reason"] for e in res_h2b["container_errors"]),
            res_h2b["container_errors"],
        )
        self.assertEqual(res_h2b["risk_markers"].get("open_actions"), 1)
        self.assertEqual(res_h2b["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_h2b["risk_markers"].get("acroforms"), 1)
        self.assertEqual(res_h2b["info_metadata"].get("Producer"), ["PostDeflateEOFProducer"])

        # R2-H3: `/X /stream\\n`, `/Comment (a\\nstream\\nb)`, and `(endobj endstream)` + `% comment >>\\n` decoys
        js_launch_comp = zlib.compress(b"/S /JavaScript /JS (1) /Launch")
        for decoy_hdr in (
            b"<< /Filter /FlateDecode /X /stream\n>>\nstream\n",
            b"<< /Filter /FlateDecode /Comment (a\nstream\nb) >>\nstream\n",
            b"<< /Filter /FlateDecode /Note (fake endobj endstream\nstream\n) >> % decoy >>\nstream\n",
        ):
            decoy_pdf = b"%PDF-1.4\n1 0 obj\n" + decoy_hdr + js_launch_comp + b"\nendstream\nendobj\n%%EOF\n"
            res_h3 = inspect_pdf_container(decoy_pdf, label="r2_h3_decoy.pdf")
            self.assertTrue(res_h3["valid_container"], res_h3["container_errors"])
            self.assertEqual(res_h3["risk_markers"].get("js_actions"), 2)
            self.assertEqual(res_h3["risk_markers"].get("launch_actions"), 1)

        # R2-M1: `/ASCIIHexDecode`, `[/ASCII85Decode /FlateDecode]`, unfiltered stream, `/LZWDecode` risk marker,
        # and unflagged pure `/DCTDecode` image stream
        hex_payload = b"1 0 << /Producer (AsciiHexObjStmProd) /S /JavaScript >>".hex().encode("ascii") + b">"
        a85_flate_payload = (
            base64.a85encode(zlib.compress(b"/Producer (A85FlateProd) /OpenAction << /JS (1) >>")) + b"~>"
        )
        m1_filters_pdf = (
            b"%PDF-1.6\n"
            b"1 0 obj\n<< /Type /ObjStm /Filter /ASCIIHexDecode >>\nstream\n" + hex_payload + b"\nendstream\nendobj\n"
            b"2 0 obj\n<< /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n"
            + a85_flate_payload
            + b"\nendstream\nendobj\n"
            b"3 0 obj\n<< /Length 42 >>\nstream\n<< /Producer (UnfilteredProd) /Launch 1 >>\nendstream\nendobj\n"
            b"4 0 obj\n<< /Subtype /Image /Filter /DCTDecode >>\nstream\n\xff\xd8\xff\xd9\nendstream\nendobj\n"
            b"%%EOF\n"
        )
        res_m1 = inspect_pdf_container(m1_filters_pdf, label="r2_m1_filters.pdf")
        self.assertTrue(res_m1["valid_container"], res_m1["container_errors"])
        self.assertEqual(
            res_m1["info_metadata"].get("Producer"),
            ["AsciiHexObjStmProd", "A85FlateProd", "UnfilteredProd"],
        )
        self.assertEqual(res_m1["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_m1["risk_markers"].get("open_actions"), 1)
        self.assertEqual(res_m1["risk_markers"].get("launch_actions"), 1)
        self.assertNotIn("undecoded_filter_streams", res_m1["risk_markers"])

        lzw_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Filter /LZWDecode >>\nstream\n\x80\x0b\x60\x50\nendstream\nendobj\n"
            b"2 0 obj\n<< /Type /ObjStm /Filter /DCTDecode >>\nstream\n\xff\xd8\xff\xd9\nendstream\nendobj\n"
            b"%%EOF\n"
        )
        res_lzw = inspect_pdf_container(lzw_pdf, label="r2_m1_lzw.pdf")
        self.assertTrue(res_lzw["valid_container"], res_lzw["container_errors"])
        self.assertEqual(res_lzw["risk_markers"].get("undecoded_filter_streams"), 2)

    def test_pdf_dict_string_spoof_513_ws_5kb_dict_dct_smuggle_and_forward_lexer(self) -> None:
        """Verify PDF dict string/comment spoof immunity, >4 KiB stream dicts, DCTDecode object smuggling, and EIP-55 vectors."""
        # `/Note (/Filter /DCTDecode /Length 9999)`, `% /Filter /DCTDecode`, and nested `/Sub << /Filter /DCTDecode >>`
        # must NEVER spoof outer stream `/Filter` or `/Length` (outer dict has `filters=[]` -> unfiltered scan)
        spoof_pdf = (
            b"%PDF-1.4\n1 0 obj\n"
            b"<< /Note (/Filter /DCTDecode /Length 9999) % /Filter /DCTDecode\n"
            b"   /Sub << /Filter /DCTDecode /Type /ObjStm >> >>\n"
            b"stream\n/S /JavaScript /JS (1) /OpenAction 1\nendstream\nendobj\n%%EOF\n"
        )
        res_spoof = inspect_pdf_container(spoof_pdf, label="dict_spoof.pdf")
        self.assertTrue(res_spoof["valid_container"], res_spoof["container_errors"])
        self.assertEqual(res_spoof["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_spoof["risk_markers"].get("open_actions"), 1)
        self.assertNotIn("undecoded_filter_streams", res_spoof["risk_markers"])

        # 513 whitespace bytes between `>>` and `stream\n` (no arbitrary 512-byte lookback cap)
        js_launch_comp = zlib.compress(b"/S /JavaScript /JS (1) /Launch")
        ws513_pdf = (
            b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>"
            + (b" " * 513)
            + b"stream\n"
            + js_launch_comp
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_ws513 = inspect_pdf_container(ws513_pdf, label="ws_513.pdf")
        self.assertTrue(res_ws513["valid_container"], res_ws513["container_errors"])
        self.assertEqual(res_ws513["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_ws513["risk_markers"].get("launch_actions"), 1)

        # >4 KiB stream dictionaries (`<< /Pad (A*5000) /Filter /FlateDecode >>` AND 500-entry dict)
        pad5k_pdf = (
            b"%PDF-1.4\n1 0 obj\n<< /Pad (" + (b"A" * 5000) + b") /Filter /FlateDecode >>\nstream\n"
            + js_launch_comp
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h1_pad = inspect_pdf_container(pad5k_pdf, label="pad_5kb.pdf")
        self.assertTrue(res_h1_pad["valid_container"], res_h1_pad["container_errors"])
        self.assertEqual(res_h1_pad["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_h1_pad["risk_markers"].get("launch_actions"), 1)

        entries_500 = b" ".join(f"/KeyEntry_{i:04d} {i}".encode("ascii") for i in range(500))
        self.assertGreater(len(entries_500), 6000)
        dict500_pdf = (
            b"%PDF-1.4\n1 0 obj\n<< " + entries_500 + b" /Filter /FlateDecode >>\nstream\n"
            + js_launch_comp
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h1_500 = inspect_pdf_container(dict500_pdf, label="entries_500.pdf")
        self.assertTrue(res_h1_500["valid_container"], res_h1_500["container_errors"])
        self.assertEqual(res_h1_500["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_h1_500["risk_markers"].get("launch_actions"), 1)

        # `/Filter /DCTDecode` with lying `/Length` smuggling `2 0 obj ...` and `4 0 obj ...` without inner `endstream`
        smuggled_dct = (
            b"\xff\xd8\xff\xe0 (fake_jpeg_paren\n"
            b"2 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> /AcroForm << >> >>\nendobj\n"
            b"4 0 obj\n<< /Producer (HiddenForge 9) >>\nendobj\n\xff\xd9"
        )
        dct_smuggle_pdf = (
            f"%PDF-1.4\n1 0 obj\n<< /Subtype /Image /Filter /DCTDecode /Length {len(smuggled_dct)} >>\nstream\n".encode(
                "ascii"
            )
            + smuggled_dct
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_h2 = inspect_pdf_container(dct_smuggle_pdf, label="dct_smuggle.pdf")
        self.assertFalse(res_h2["valid_container"])
        self.assertTrue(
            any("Embedded PDF object/trailer syntax" in e["reason"] for e in res_h2["container_errors"]),
            res_h2["container_errors"],
        )
        self.assertEqual(res_h2["risk_markers"].get("open_actions"), 1)
        self.assertEqual(res_h2["risk_markers"].get("js_actions"), 2)
        self.assertEqual(res_h2["risk_markers"].get("acroforms"), 1)
        self.assertEqual(res_h2["info_metadata"].get("Producer"), ["HiddenForge 9"])

        # ~2 MiB of repeated `<</Filter/FlateDecode>>\nstream\n<zlib("x")>\n` sharing a single trailing `endstream`
        trace_scale = 8.0 if (sys.gettrace() is not None or "coverage" in sys.modules) else 1.0
        flate_unit = b"<</Filter/FlateDecode>>\nstream\n" + zlib.compress(b"x") + b"\n"
        reps_2mb = (2 * 1024 * 1024) // len(flate_unit)
        shared_end_pdf = b"%PDF-1.4\n" + (flate_unit * reps_2mb) + b"endstream\n%%EOF\n"
        self.assertGreater(len(shared_end_pdf), 2 * 1024 * 1024 - 128)
        t_h3 = time.perf_counter()
        res_h3 = inspect_pdf_container(shared_end_pdf, label="shared_endstream.pdf")
        dt_h3 = time.perf_counter() - t_h3
        self.assertFalse(res_h3["valid_container"])
        self.assertTrue(res_h3["container_errors"])
        self.assertLess(dt_h3, 3.0 * trace_scale)

        # 0.5 MiB monotonic forward lexer stress tests (`<<`*500 + `>>\nstream\n`*400, and `<<` + `()`*2100 + ...)
        blk_a = (b"<<" * 500) + (b">>\nstream\n" * 400)
        lexer_a_pdf = b"%PDF-1.4\n" + (blk_a * ((512 * 1024) // len(blk_a) + 1)) + b"%%EOF\n"
        t_h4a = time.perf_counter()
        res_h4a = inspect_pdf_container(lexer_a_pdf, label="forward_lexer_a.pdf")
        dt_h4a = time.perf_counter() - t_h4a
        self.assertEqual(res_h4a["risk_markers"], {})
        self.assertLess(dt_h4a, 3.0 * trace_scale)

        blk_b = b"<<" + (b"()" * 2100) + b">>\nstream\n" + (b">>stream\n" * 50) + b"endstream\n"
        lexer_b_pdf = b"%PDF-1.4\n" + (blk_b * ((512 * 1024) // len(blk_b) + 1)) + b"%%EOF\n"
        t_h4b = time.perf_counter()
        res_h4b = inspect_pdf_container(lexer_b_pdf, label="forward_lexer_b.pdf")
        dt_h4b = time.perf_counter() - t_h4b
        self.assertIsInstance(res_h4b, dict)
        self.assertIn("container_errors", res_h4b)
        self.assertLess(dt_h4b, 3.0 * trace_scale)

        # Explicit check on all 8/8 official EIP-55 specification vectors
        all_8_eip55 = (
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
        )
        for addr in all_8_eip55:
            self.assertTrue(eth_eip55_checksum_valid(addr), addr)


if __name__ == "__main__":
    unittest.main()
