#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Regression & Security Invariant Suite for `starshield-forensics v0.3.11` (`tests/test_v039_upgrades.py`).

Covers:
  1. PDF lexical & stream-tracker edge-case regressions (stray `(`, unclosed dict before `/FlateDecode`,
     and linear complexity on shared-`endstream` inputs).
  2. Structural MCP Airlock (ZERO free-text pass-through, ZERO `--unredacted` prompt hints):
     withholds `cached_content` / `cached_plaintext` while emitting numeric currency amounts and
     4-hex session-fingerprinted + country-tagged placeholders (`<IBAN_GB_9F3A_01>`, `<TRC20_9F3A_01>`,
     `<ENTITY_9F3A_01>`).
  3. Cross-case anti-collision `detokenize` check (foreign `session_tag` left unexpanded & flagged),
     `0600` `O_NOFOLLOW` atomic vault creation, `starshield shred-vault` overwrite+unlink, and
     one-way MCP airlock (neither `detokenize` nor `shred-vault` exposed over MCP).
  4. `starshield demo` keyed-HMAC schema backward-compatibility lock (`[REDACTED_HMAC:...]`).
  5. Repo-wide banned-phrase hygiene, version parity (`0.3.11`), relative Markdown link closure,
     REUSE SPDX compliance, and pure Python `>= 3.10` stdlib AST gate.
"""

from __future__ import annotations

import ast
import copy
import io
import json
import os
import re
import stat
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

_REPO_ROOT_STR = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT_STR not in sys.path:
    sys.path.insert(0, _REPO_ROOT_STR)

from starshield import __version__  # noqa: E402
from starshield.cli import (  # noqa: E402
    apply_wal_record_redaction,
    build_demo_report,
    build_synthetic_leveldb_wal_bytes,
    main as cli_main,
)
from starshield.ioc_validators import VALIDATION_SCOPE_NOTE, aba_routing_valid  # noqa: E402
from starshield.leveldb_log import inspect_chromium_storage_path, parse_leveldb_wal  # noqa: E402
from starshield.mcp_server import MCP_TOOLS, run_mcp_stdio_server  # noqa: E402
from starshield.pdf_containers import inspect_pdf_container  # noqa: E402
from starshield.pseudonymizer import (  # noqa: E402
    SessionPseudonymizer,
    detokenize_text,
    extract_currency_amounts,
    load_vault_strict,
    shred_vault_file,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestV039Upgrades(unittest.TestCase):
    def test_version_and_zero_commercial_or_stale_strings(self) -> None:
        stale_ver = ".".join(("0", "3", "6"))
        banned_fee = " ".join(("pilot", "fee"))
        self.assertEqual(__version__, "0.3.11")
        for py_file in (REPO_ROOT / "starshield").glob("*.py"):
            src = py_file.read_text(encoding="utf-8")
            self.assertIn("SPDX-License-Identifier: MIT", src, f"Missing SPDX in {py_file.name}")
            self.assertNotIn(stale_ver, src, f"Stale version found in {py_file.name}")
            self.assertNotIn(banned_fee, src.lower(), f"Commercial residue in {py_file.name}")

        with tempfile.TemporaryDirectory() as tmp:
            empty_dir = Path(tmp) / "empty_store"
            empty_dir.mkdir()
            pre = inspect_chromium_storage_path(empty_dir, redact=True)
            self.assertEqual(pre["tool_version"], "starshield-forensics/0.3.11")
            self.assertIn("Chrome 156+", pre["intake_guidance"])
            self.assertNotIn(banned_fee, json.dumps(pre).lower())

    def test_forensic_focus_demo_schema_backward_compatibility(self) -> None:
        """Ensure `starshield demo` keeps `[REDACTED_HMAC:...]` & `[REDACTED_CONTENT]` without CLI bypass hints."""
        demo = build_demo_report(redact=True)
        rec = demo["engine_1_raw_leveldb_wal_carver"]["recovered_records"][1]
        self.assertTrue(rec["sender_mri"].startswith("[REDACTED_HMAC:"))
        self.assertEqual(rec["cached_content"], "[REDACTED_CONTENT]")
        self.assertNotIn("--unredacted", json.dumps(demo))
        self.assertTrue(rec["extracted_iocs"]["luhn_validated_cards"][0].startswith("[REDACTED_HMAC:"))
        self.assertTrue(rec["extracted_iocs"]["mod97_validated_ibans"][0].startswith("[REDACTED_HMAC:"))

    def test_pure_stdlib_ast_imports(self) -> None:
        if hasattr(sys, "stdlib_module_names"):
            allowed_roots = set(sys.stdlib_module_names) | {"starshield"}
        else:
            import sysconfig

            stdlib_dir = Path(sysconfig.get_paths()["stdlib"])
            dynload_dir = stdlib_dir / "lib-dynload"
            dyn_stdlib = (
                {p.stem for p in stdlib_dir.glob("*.py")}
                | {p.name for p in stdlib_dir.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}
                | ({p.name.split(".")[0] for p in dynload_dir.glob("*.so")} if dynload_dir.is_dir() else set())
            )
            allowed_roots = set(sys.builtin_module_names) | dyn_stdlib | {"__future__", "starshield"}
        for py_file in (REPO_ROOT / "starshield").glob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        self.assertIn(root, allowed_roots, f"Non-stdlib import {root} in {py_file.name}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    root = node.module.split(".")[0]
                    self.assertIn(root, allowed_roots, f"Non-stdlib import {root} in {py_file.name}")

    def test_pdf_stray_paren_resync_in_lexical_scanner(self) -> None:
        for stray_prefix in (b"%PDF-1.4\n(\n", b"%PDF-1.4\n(\\(\n"):
            raw = (
                stray_prefix
                + b"1 0 obj\n<< /Producer (Acrobat Distiller 24.0) /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n"
                b"endobj\n%%EOF\n"
            )
            res = inspect_pdf_container(raw, label="stray_paren.pdf")
            self.assertIn("Acrobat Distiller 24.0", res["info_metadata"].get("Producer", []))
            self.assertGreaterEqual(res["risk_markers"]["js_actions"], 1)
            self.assertGreaterEqual(res["risk_markers"]["open_actions"], 1)
            self.assertTrue(res["container_errors"], "Expected lexical error for stray '('")

    def test_pdf_stray_paren_and_unclosed_dict_before_flate_stream(self) -> None:
        payload = b"<< /Producer (HiddenObjStmProd) /S /JavaScript /JS (1) >>"
        comp = zlib.compress(payload, level=0)
        self.assertIn(b")", comp)

        pdf_a = (
            b"%PDF-1.5\n(\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n"
            + comp
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        res_a = inspect_pdf_container(pdf_a, label="unclosed_paren_a.pdf")
        self.assertIn("HiddenObjStmProd", res_a["info_metadata"].get("Producer", []))
        self.assertGreaterEqual(res_a["risk_markers"]["js_actions"], 1)

        pdf_b = (
            b"%PDF-1.5\n(\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n"
            + comp
            + b"\nendstream\n%%EOF\n"
        )
        res_b = inspect_pdf_container(pdf_b, label="unclosed_paren_b.pdf")
        self.assertIn("HiddenObjStmProd", res_b["info_metadata"].get("Producer", []))
        self.assertGreaterEqual(res_b["risk_markers"]["js_actions"], 1)
        self.assertTrue(res_b["container_errors"])

        pdf_c = (
            b"%PDF-1.5\n<<\n<< /Filter /FlateDecode >>\nstream\n"
            + comp
            + b"\nendstream\n%%EOF\n"
        )
        res_c = inspect_pdf_container(pdf_c, label="unclosed_dict_c.pdf")
        self.assertTrue(
            any("without resolvable enclosing dictionary" in e["reason"] for e in res_c["container_errors"])
        )
        self.assertGreaterEqual(res_c["risk_markers"]["undecoded_filter_streams"], 1)

    def test_pdf_shared_endstream_linear_complexity(self) -> None:
        unit = b"<< /Length 1000000 >>\nstream\nx\n"
        k = 40000
        raw = (
            b"%PDF-1.4\n"
            + (unit * k)
            + (b"endstreamX " * 4000)
            + b"\nendstream\nendobj\n%%EOF\n"
        )
        trace_scale = 8.0 if (sys.gettrace() is not None or "coverage" in sys.modules) else 1.0
        t0 = time.perf_counter()
        res = inspect_pdf_container(raw, label="shared_endstream_linear.pdf")
        elapsed = time.perf_counter() - t0
        self.assertTrue(res["valid_container"])
        self.assertLess(elapsed, 3.0 * trace_scale, f"Shared-endstream scan took {elapsed:.3f}s")

    def test_us_treasury_aba_prefix_and_wal_redaction_immutability(self) -> None:
        self.assertTrue(aba_routing_valid("000000204"))
        self.assertFalse(aba_routing_valid("000000000"))

        wal_raw = build_synthetic_leveldb_wal_bytes()
        wal_parsed = parse_leveldb_wal(wal_raw)
        snap = copy.deepcopy(wal_parsed)
        red = apply_wal_record_redaction(wal_parsed, redact=True, salt=None)
        self.assertEqual(wal_parsed, snap, "apply_wal_record_redaction mutated caller dict in-place")
        self.assertIsNone(red["file_size_bytes"])
        self.assertEqual(red["ioc_validation_scope_note"], VALIDATION_SCOPE_NOTE)

    def test_session_fingerprinted_tokens_cross_case_guard_and_shred_vault(self) -> None:
        pseudo = SessionPseudonymizer(session_tag="9F3A", session_id="ss_9f3a_test01")
        msg_1 = (
            "Wire GBP 18,400.00 to GB82WEST12345698765432 or TRC20 "
            "TYzVpTxq4B6s9cXMUUV5NCaZ3YCKz6UzfM via SWIFT NWBKGB2LXXX."
        )
        msg_2 = "Second hop EUR 5,200.00 from GB82WEST12345698765432 to NO9386011117947."

        iocs_1 = pseudo.pseudonymize_iocs_from_text(msg_1)
        iocs_2 = pseudo.pseudonymize_iocs_from_text(msg_2)
        self.assertEqual(iocs_1["mod97_validated_ibans"], ["<IBAN_GB_9F3A_01>"])
        self.assertEqual(iocs_1["base58check_tron_addresses"], ["<TRC20_9F3A_01>"])
        self.assertEqual(iocs_1["validated_swift_bics"], ["<BIC_GB_9F3A_01>"])
        # Multi-hop consistency + ISO country visibility: GB stays _01, NO becomes _02
        self.assertEqual(
            iocs_2["mod97_validated_ibans"],
            ["<IBAN_GB_9F3A_01>", "<IBAN_NO_9F3A_02>"],
        )
        self.assertEqual(extract_currency_amounts(msg_1), ["GBP 18,400.00"])
        self.assertEqual(extract_currency_amounts(msg_2), ["EUR 5,200.00"])

        with tempfile.TemporaryDirectory() as tmp:
            vault_path = Path(tmp) / "vault_case_a.json"
            pseudo.save_vault_atomic(vault_path)
            self.assertEqual(stat.S_IMODE(os.stat(vault_path).st_mode), 0o600)

            sym_path = Path(tmp) / "sym_vault.json"
            sym_path.symlink_to(vault_path)
            with self.assertRaises(OSError):
                pseudo.save_vault_atomic(sym_path)
            with self.assertRaises(OSError):
                load_vault_strict(sym_path)
            with self.assertRaises(OSError):
                shred_vault_file(sym_path)

            # Single-pass non-recursive detokenization + foreign session_tag (`C41D`) isolation!
            mapping, v_tag = load_vault_strict(vault_path)
            self.assertEqual(v_tag, "9F3A")
            mapping["<TEST_9F3A_01>"] = "<IBAN_GB_9F3A_01>"
            draft = "Hop: <TEST_9F3A_01> -> <IBAN_GB_9F3A_01> -> <IBAN_NO_9F3A_02> (foreign: <IBAN_GB_C41D_01>)"
            restored, count, unmatched = detokenize_text(draft, mapping, expected_session_tag=v_tag)
            self.assertEqual(count, 3)
            self.assertEqual(unmatched, ["<IBAN_GB_C41D_01>"])
            self.assertEqual(
                restored,
                "Hop: <IBAN_GB_9F3A_01> -> GB82WEST12345698765432 -> NO9386011117947 (foreign: <IBAN_GB_C41D_01>)",
            )

            # CLI round-trip (`triage-json --vault-file` -> `detokenize` -> `shred-vault`)
            chat_json = Path(tmp) / "CANARY_SECRET_EXPORT.json"
            chat_json.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "id": "m1",
                                "from": "8:orgid:actor_alpha",
                                "composetime": "2025-03-18T10:00:00Z",
                                "deletetime": "2025-03-18T10:05:00Z",
                                "content": "CANARY_PROSE_SECRET_991 Send GBP 18,400.00 to GB82WEST12345698765432",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            cli_vault = Path(tmp) / "cli_vault.json"
            buf_out = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = buf_out
                rc = cli_main(["--vault-file", str(cli_vault), "triage-json", str(chat_json)])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            triage_json = json.loads(buf_out.getvalue())
            triage_str = buf_out.getvalue()
            # Free-form chat prose & `--unredacted` prompt hint MUST NOT appear in structural mode!
            self.assertNotIn("CANARY_PROSE_SECRET_991", triage_str)
            self.assertNotIn("GB82WEST12345698765432", triage_str)
            self.assertNotIn("actor_alpha", triage_str)
            self.assertNotIn("--unredacted", triage_str)
            tag = triage_json["pseudonym_session_tag"]
            self.assertRegex(tag, r"^[0-9A-F]{4}$")
            rec0 = triage_json["triage_result"]["soft_deleted_records"][0]
            self.assertEqual(rec0["extracted_currency_amounts"], ["GBP 18,400.00"])
            self.assertEqual(rec0["extracted_iocs"]["mod97_validated_ibans"], [f"<IBAN_GB_{tag}_01>"])
            self.assertEqual(rec0["sender_mri"], f"<ENTITY_{tag}_01>")

            detok_buf = io.StringIO()
            try:
                sys.stdout = detok_buf
                rc2 = cli_main(
                    [
                        "detokenize",
                        "--vault",
                        str(cli_vault),
                        "--text",
                        f"<ENTITY_{tag}_01> -> <IBAN_GB_{tag}_01> vs <IBAN_GB_FFFF_01>",
                    ]
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc2, 0)
            detok_res = json.loads(detok_buf.getvalue())
            self.assertEqual(
                detok_res["detokenized_text"],
                "8:orgid:actor_alpha -> GB82WEST12345698765432 vs <IBAN_GB_FFFF_01>",
            )
            self.assertEqual(detok_res["unmatched_or_foreign_tokens"], ["<IBAN_GB_FFFF_01>"])
            self.assertIn("cross_session_warning", detok_res)

            # Shred vault file and verify removal + explicit SSD/CoW best-effort disclaimer
            shred_buf = io.StringIO()
            try:
                sys.stdout = shred_buf
                rc3 = cli_main(["shred-vault", "--vault", str(cli_vault)])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc3, 0)
            self.assertFalse(cli_vault.exists())
            shred_out = json.loads(shred_buf.getvalue())
            self.assertEqual(shred_out["erasure_guarantee"], "best_effort_logical_overwrite_and_unlink_only")
            self.assertIn("does NOT guarantee unrecoverable physical block erasure", shred_out["filesystem_caveat"])

            help_buf = io.StringIO()
            try:
                sys.stdout = help_buf
                with self.assertRaises(SystemExit) as cm:
                    cli_main(["shred-vault", "--help"])
                self.assertEqual(cm.exception.code, 0)
            finally:
                sys.stdout = old_stdout
            self.assertIn("best-effort", help_buf.getvalue().lower())

    def test_mcp_structural_airlock_withholds_prose_and_blocks_detokenize_exposure(self) -> None:
        by_name = {t["name"]: t for t in MCP_TOOLS}
        self.assertIn("starshield_parse_leveldb_log", by_name)
        self.assertIn("starshield_triage_json", by_name)
        self.assertFalse(any("detoken" in name.lower() or "shred" in name.lower() for name in by_name))
        self.assertTrue(
            by_name["starshield_inspect_image_tamper"]["description"].startswith(
                "CONTAINER STRUCTURE OBSERVATION ONLY"
            )
        )
        self.assertTrue(
            by_name["starshield_inspect_pdf_tamper"]["description"].startswith(
                "CONTAINER STRUCTURE OBSERVATION ONLY"
            )
        )
        self.assertIn(VALIDATION_SCOPE_NOTE, by_name["starshield_validate_financial_iocs"]["description"])

        with tempfile.TemporaryDirectory() as tmp:
            wal_file = Path(tmp) / "CANARY_MCP_WAL_PATH.log"
            wal_file.write_bytes(build_synthetic_leveldb_wal_bytes())
            json_file = Path(tmp) / "CANARY_MCP_JSON_PATH.json"
            json_file.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "id": "m9",
                                "from": "user:impersonated_supplier_01",
                                "composetime": "2025-03-18T11:00:00Z",
                                "deletetime": "2025-03-18T11:02:00Z",
                                "content": "CANARY_INJECTION_PROSE_777 Re-confirming USD 9,500.00 to GB82WEST12345698765432.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            mcp_vault = Path(tmp) / "mcp_vault.json"

            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_parse_leveldb_log",
                        "arguments": {"log_path": str(wal_file)},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "starshield_triage_json",
                        "arguments": {"json_path": str(json_file)},
                    },
                },
            ]
            in_stream = io.BytesIO(b"\n".join(json.dumps(r).encode("utf-8") for r in reqs) + b"\n")
            out_stream = io.BytesIO()
            rc = run_mcp_stdio_server(
                redact=True,
                vault_file=mcp_vault,
                instream=in_stream,
                outstream=out_stream,
            )
            self.assertEqual(rc, 0)
            transcript = out_stream.getvalue().decode("utf-8")
            for secret_str in (
                "CANARY_MCP_WAL_PATH",
                "CANARY_MCP_JSON_PATH",
                "CANARY_INJECTION_PROSE_777",
                "Updated UK Faster Payments",
                "GB82WEST12345698765432",
                "NO9386011117947",
                "6200000000000005",
                "impersonated_supplier_01",
                "--unredacted",
            ):
                self.assertNotIn(secret_str, transcript)

            lines = [json.loads(line) for line in transcript.strip().splitlines()]
            wal_payload = json.loads(lines[0]["result"]["content"][0]["text"])
            json_payload = json.loads(lines[1]["result"]["content"][0]["text"])
            s_tag = wal_payload["pseudonym_session_tag"]
            self.assertTrue(re.fullmatch(r"[0-9A-F]{4}", s_tag))

            wal_ibans = wal_payload["leveldb_wal_analysis"]["recovered_records"][1]["extracted_iocs"][
                "mod97_validated_ibans"
            ]
            json_ibans = json_payload["triage_result"]["soft_deleted_records"][0]["extracted_iocs"][
                "mod97_validated_ibans"
            ]
            self.assertEqual(wal_ibans, [f"<IBAN_GB_{s_tag}_01>", f"<IBAN_NO_{s_tag}_02>"])
            self.assertEqual(json_ibans, [f"<IBAN_GB_{s_tag}_01>"])
            self.assertEqual(
                json_payload["triage_result"]["soft_deleted_records"][0]["extracted_currency_amounts"],
                ["USD 9,500.00"],
            )
            self.assertTrue(mcp_vault.exists())

    def test_sdist_packaged_data_and_readme_hygiene(self) -> None:
        """Enforce repo-wide banned-phrase hygiene, relative link closure, and standalone fixture fallback."""
        repo_root = Path(__file__).resolve().parent.parent
        pkg_sample = repo_root / "starshield" / "data" / "synthetic_case_benchmark.json"
        manifest_in = repo_root / "MANIFEST.in"
        self.assertTrue(pkg_sample.is_file())
        self.assertTrue(manifest_in.is_file())
        manifest_txt = manifest_in.read_text(encoding="utf-8")
        self.assertIn("recursive-include samples *.json", manifest_txt)
        self.assertIn("recursive-include tests *.py", manifest_txt)
        self.assertIn("recursive-include scripts *.py", manifest_txt)

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(["triage-json", str(pkg_sample)])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        self.assertIn("triage_result", json.loads(buf.getvalue()))

        # Construct forbidden substrings dynamically so raw `rg` across `tests/` also stays 0-hit
        banned_phrases = (
            " ".join(("EU", "CRA", "Aligned")),
            " ".join(("ISO", "17025", "Aligned")),
            "%20".join(("EU", "CRA", "Aligned")),
            "%20".join(("ISO", "17025", "Aligned")),
            "".join(("物理", "隔离")),
            "-".join(("coercive", "extortion")),
            " ".join(("payment-dispute", "compliance")),
            " ".join(("Establishes", "an", "Industry", "Standard")),
            " ".join(("Chrome", "150+")),
            " ".join(("£0", "fee")),
            "_".join(("accounts", "payable")),
            bytes.fromhex("6b696d695f616e645f6f707573").decode("ascii"),
        )
        scan_targets: list[Path] = []
        for top_name in (
            "README.md",
            "README.zh-CN.md",
            "SECURITY.md",
            "VALIDATION_REPORT_FSR_ISO17025.md",
            "SECURITY_ASSURANCE_CASE.md",
            "SECURITY-INSIGHTS.yml",
            "CITATION.cff",
            "CONTRIBUTING.md",
            "GOVERNANCE.md",
            "funding.json",
        ):
            p = repo_root / top_name
            if p.is_file():
                scan_targets.append(p)
        for sub_dir in ("benchmark", "starshield", "tests", "scripts"):
            d = repo_root / sub_dir
            if d.is_dir():
                scan_targets.extend(
                    sorted(f for f in d.rglob("*") if f.is_file() and f.suffix in {".py", ".md", ".json"})
                )

        for target_file in scan_targets:
            content = target_file.read_text(encoding="utf-8")
            for phrase in banned_phrases:
                self.assertNotIn(
                    phrase,
                    content,
                    f"Banned phrase {phrase!r} found in {target_file.relative_to(repo_root)}",
                )

        readme_en = (repo_root / "README.md").read_text(encoding="utf-8")
        readme_zh = (repo_root / "README.zh-CN.md").read_text(encoding="utf-8")
        for doc in (readme_en, readme_zh):
            self.assertIn("Chrome 156+", doc)

        # Verify zero dead relative file links across packaged Markdown docs
        link_re = re.compile(r"\]\(([^)]+)\)")
        for md_rel in ("README.md", "README.zh-CN.md", "SECURITY.md", "benchmark/README.md"):
            md_path = repo_root / md_rel
            if not md_path.is_file():
                continue
            md_txt = md_path.read_text(encoding="utf-8")
            for m in link_re.finditer(md_txt):
                href = m.group(1).strip()
                if not href or href.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                rel_part = href.split("#", 1)[0]
                if not rel_part:
                    continue
                resolved = (md_path.parent / rel_part).resolve()
                self.assertTrue(
                    resolved.exists(),
                    f"Dead relative link {href!r} in {md_rel} -> {resolved}",
                )


if __name__ == "__main__":
    unittest.main()
