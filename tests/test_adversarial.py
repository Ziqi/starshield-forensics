#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clean-Room Adversarial, Malformed-Input, Multi-Schema & Privacy Regression Suite for `starshield-forensics` v0.3.6.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from starshield.cli import (
    apply_image_redaction,
    apply_wal_record_redaction,
    build_acquisition_manifest,
    build_synthetic_leveldb_wal_bytes,
    corroborate_timestamps,
    main,
    summarize_corpus_linguistics,
    triage_exported_chatsvc_json,
)
from starshield.image_containers import (
    PNG_MAGIC,
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (
    extract_validated_iocs,
    iban_mod97_valid,
    luhn_valid,
    mask_identifier,
)
from starshield.leveldb_log import (
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

            # Compacted-only directory (no .log records) -> NO_GO_COMPACTED_OR_UNSUPPORTED (£0 fee)
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
        sample_json = Path(__file__).resolve().parent.parent / "samples" / "synthetic_case_benchmark.json"
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


if __name__ == "__main__":
    unittest.main()
