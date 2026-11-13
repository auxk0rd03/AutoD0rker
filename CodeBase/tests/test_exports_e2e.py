"""End-to-End polyglot integration test & simulation suite for AutoDorker.

Tests:
- Python Gate 1/2 AST analyzers (esprima, pyyaml, lxml)
- Ephemeral local HTTP server with real exposures + low-entropy honeypots + Soft-404s
- Real compiled Rust `bin/dork_spider` + Python `py_engine` + POSIX `scripts/*.sh`
- Real compiled Go `bin/gateway` HTTP loopback server, SSRF blocking, batch scan,
  HTMX partials, SVG telemetry, .MD, .DOCX, and Batch ZIP archive generation.
"""

from __future__ import annotations

import http.server
import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from docx import Document

from py_engine.ast_analyzer import (
    calculate_shannon_entropy,
    verify_html_dom_ast,
    verify_js_ast_secret,
    verify_json_ast,
    verify_scan_findings_in_db,
    verify_yaml_ast,
)
from py_engine.report_docx import write_docx_report
from py_engine.report_md import write_markdown_report
from py_engine.svg_telemetry import render_svg_telemetry

CODEBASE_DIR = Path(__file__).resolve().parent.parent
DORKSET_CSV = CODEBASE_DIR.parent / "Docs" / "DorkSet.csv"
BIN_SPIDER = CODEBASE_DIR / "bin" / "dork_spider"
BIN_GATEWAY = CODEBASE_DIR / "bin" / "gateway"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _SyntheticTargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(self, code: int, ctype: str, body: str, extra_headers: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self._send(
                200,
                "text/html; charset=utf-8",
                (
                    "<html><head><title>Target Portal</title></head><body>"
                    "<a href='/configs/'>Configs</a>"
                    "<a href='/login'>Login</a>"
                    "<a href='/blog/index-of'>Blog</a>"
                    "<a href='/secrets.yaml'>Honeypot YAML</a>"
                    "<a href='/prod.yaml'>Prod YAML</a>"
                    "<a href='/soft404/admin.php'>Soft404</a>"
                    "<script src='/app.js'></script>"
                    "</body></html>"
                ),
            )
        elif path == "/configs/":
            self._send(
                200,
                "text/html; charset=utf-8",
                (
                    "<html><head><title>Index of /configs</title></head><body>"
                    "<h1>Index of /configs</h1>"
                    "<pre><a href='../'>Parent Directory</a>\n"
                    "<a href='configmap.yaml'>configmap.yaml</a>\n"
                    "<a href='proftpd.conf'>proftpd.conf</a></pre></body></html>"
                ),
            )
        elif path == "/login":
            self._send(
                200,
                "text/html; charset=utf-8",
                (
                    "<html><head><title>UAT Portal Login</title></head><body>"
                    "<form action='/auth/login' method='post'>"
                    "<input type='text' name='user'/><input type='password' name='pass'/>"
                    "</form></body></html>"
                ),
            )
        elif path == "/blog/index-of":
            self._send(
                200,
                "text/html; charset=utf-8",
                (
                    "<html><head><title>Index of Best Practices</title></head><body>"
                    "<article><p>Never expose configmap.yaml or smb.conf publicly.</p></article>"
                    "</body></html>"
                ),
            )
        elif path == "/app.js":
            self._send(
                200,
                "application/javascript",
                (
                    "// Commented secret: aws_access_key_id = '" "AKIA" "9X4K2M8P3Q7R5T1W'\n"
                    "const notice = 'Missing aws_access_key_id parameter';\n"
                    "import('./chunks/admin.js');\n"
                ),
            )
        elif path == "/chunks/admin.js":
            self._send(200, "application/javascript", "console.log('admin chunk loaded');")
        elif path == "/secrets.yaml":
            self._send(
                200,
                "text/yaml",
                "aws_access_key_id: AKIAXXXXXXXXXXXXXXXX\naws_secret_access_key: changeme123456\n",
            )
        elif path == "/prod.yaml":
            self._send(
                200,
                "text/yaml",
                "kind: ConfigMap\naws_access_key_id: " "AKIA" "9X4K2M8P3Q7R5T1W\n",
            )
        elif path == "/soft404/admin.php" or path.startswith("/_adk_404_probe_"):
            code = 200 if path == "/soft404/admin.php" else 404
            self._send(
                code,
                "text/html; charset=utf-8",
                "<html><head><title>404 Not Found</title></head><body><div class='err'><h1>Page Not Found</h1><p>Resource missing.</p></div></body></html>",
            )
        else:
            self._send(
                404,
                "text/html; charset=utf-8",
                "<html><head><title>404 Not Found</title></head><body><div class='err'><h1>Page Not Found</h1><p>Resource missing.</p></div></body></html>",
            )


class TestAutoDorkerPythonAndE2E(unittest.TestCase):
    server: http.server.ThreadingHTTPServer
    server_thread: threading.Thread
    target_port: int

    @classmethod
    def setUpClass(cls) -> None:
        cls.target_port = _free_loopback_port()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", cls.target_port), _SyntheticTargetHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_python_ast_and_entropy_analyzers(self) -> None:
        # JS AST should ignore comments and reject low-entropy placeholders, while accepting real secrets
        synth_key = "AKIA" + "9X4K2M8P3Q7R5T1W"
        js_src = f"""
        // const aws_access_key_id = "{synth_key}";
        const placeholderKey = "YOUR_API_KEY_HERE";
        const aws_access_key_id = "{synth_key}";
        """
        res = verify_js_ast_secret(js_src)
        self.assertTrue(res["parsed"])
        self.assertEqual(len(res["verified_secrets"]), 1)
        self.assertEqual(res["verified_secrets"][0]["key"], "aws_access_key_id")
        self.assertGreaterEqual(res["verified_secrets"][0]["entropy_bps"], 300)
        self.assertGreaterEqual(res["suppressed_low_entropy"], 1)

        # YAML & JSON AST checks
        ok_y, keys_y = verify_yaml_ast("kind: ConfigMap\nmetadata:\n  name: prod\n")
        self.assertTrue(ok_y)
        self.assertIn("kind", keys_y)
        self.assertFalse(verify_yaml_ast("<!DOCTYPE html><html><body>404</body></html>")[0])
        self.assertTrue(verify_json_ast('{"status": "ok"}')[0])
        self.assertFalse(verify_json_ast("not json")[0])

        # HTML DOM checks
        ok_dir, _ = verify_html_dom_ast(
            "<html><head><title>Index of /</title></head><body><pre><a href='../'>..</a><a href='a.conf'>a.conf</a></pre></body></html>",
            "dir_index",
        )
        self.assertTrue(ok_dir)
        bad_dir, _ = verify_html_dom_ast(
            "<html><head><title>Index of concepts</title></head><body><p>Blog</p></body></html>",
            "dir_index",
        )
        self.assertFalse(bad_dir)
        self.assertGreater(calculate_shannon_entropy("AKIA" + "9X4K2M8P3Q7R5T1W"), 3.0)

    def test_end_to_end_pipeline_reports_and_gateway(self) -> None:
        self.assertTrue(BIN_SPIDER.exists(), f"Missing {BIN_SPIDER}; run ./dev.sh build")
        self.assertTrue(BIN_GATEWAY.exists(), f"Missing {BIN_GATEWAY}; run ./dev.sh build")

        with tempfile.TemporaryDirectory(prefix="adk_e2e_") as tmp_str:
            tmp = Path(tmp_str)
            db_path = tmp / "test_state.db"
            out_dir = tmp / "Output"
            out_dir.mkdir(parents=True, exist_ok=True)
            harvest_dir = tmp / "harvest"
            harvest_dir.mkdir(mode=0o700)

            # 1. Seed 295 DorkSet rules
            ing = subprocess.run(
                [str(BIN_SPIDER), "--ingest-csv", str(DORKSET_CSV), "--db", str(db_path)],
                cwd=str(CODEBASE_DIR),
                capture_output=True,
                text=True,
                check=True,
            )
            ing_json = json.loads(ing.stdout)
            self.assertEqual(ing_json["ingested"], 295)

            # 2. Run Rust spider against synthetic mock HTTP target
            target_url = f"http://127.0.0.1:{self.target_port}/"
            scan = subprocess.run(
                [
                    str(BIN_SPIDER),
                    "--scan",
                    "--target",
                    target_url,
                    "--batch-id",
                    "E2E-BATCH-1",
                    "--batch-index",
                    "1",
                    "--depth",
                    "2",
                    "--allow-local",
                    "--keep-harvest",
                    "--harvest-dir",
                    str(harvest_dir),
                    "--db",
                    str(db_path),
                    "--out-rel",
                    "Output/Targ001",
                    "--json",
                ],
                cwd=str(CODEBASE_DIR),
                capture_output=True,
                text=True,
                check=True,
            )
            scan_json = json.loads(scan.stdout)
            scan_id = int(scan_json["scan_id"])
            self.assertGreaterEqual(scan_json["verified_count"], 2)
            self.assertGreaterEqual(scan_json["ast_fp_dropped"], 1)
            self.assertGreaterEqual(scan_json["entropy_fp_dropped"], 1)
            self.assertGreaterEqual(scan_json["soft404_fp_dropped"], 1)

            # 3. Stage-2 Python AST confirmation
            py_res = verify_scan_findings_in_db(str(db_path), scan_id, str(harvest_dir))
            self.assertGreaterEqual(py_res["confirmed"], 2)
            self.assertEqual(py_res["ast_rejected"], 0)

            # 4. Generate SVG telemetry, .MD, and .DOCX
            svg = render_svg_telemetry(str(db_path), scan_id=scan_id)
            self.assertIn("<svg", svg)
            self.assertIn("VERIFIED TP", svg)

            targ1 = out_dir / "Targ001"
            md_file = write_markdown_report(str(db_path), scan_id, str(targ1 / f"autodorker_triage_scan_{scan_id}.md"))
            docx_file = write_docx_report(str(db_path), scan_id, str(targ1 / f"AutoDorker_Enterprise_Report_{scan_id}.docx"))

            md_text = md_file.read_text(encoding="utf-8")
            self.assertIn("1. Document Control & Engagement Metadata", md_text)
            self.assertIn("Sec-Ch-Ua", md_text)
            self.assertNotIn("AKIAXXXXXXXXXXXXXXXX", md_text)
            self.assertNotIn("/blog/index-of", md_text)
            self.assertNotIn("/soft404/admin.php", md_text)

            parsed_doc = Document(str(docx_file))
            full_doc_txt = "\n".join(p.text for p in parsed_doc.paragraphs)
            self.assertIn("Document Control", full_doc_txt)
            self.assertGreaterEqual(len(parsed_doc.tables), 3)

            # 5. Boot real Go Gateway on isolated loopback port and test HTTP / HTMX / SSRF / ZIP
            gw_port = _free_loopback_port()
            backup_dir = tmp / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            gw_env = {
                **os.environ,
                "AUTODORKER_BIND_ADDR": f"127.0.0.1:{gw_port}",
                "AUTODORKER_DB_PATH": str(db_path),
                "AUTODORKER_OUTPUT_DIR": str(out_dir),
                "AUTODORKER_BACKUP_DIR": str(backup_dir),
                "AUTODORKER_DORKSET_PATH": str(DORKSET_CSV),
            }
            gw_proc = subprocess.Popen(
                [str(BIN_GATEWAY)],
                cwd=str(CODEBASE_DIR),
                env=gw_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                base_gw = f"http://127.0.0.1:{gw_port}"
                # Wait for listener readiness
                for _ in range(30):
                    try:
                        with urllib.request.urlopen(base_gw + "/telemetry/status", timeout=2) as resp:
                            if resp.status == 200:
                                break
                    except Exception:
                        threading.Event().wait(0.1)

                # Dashboard HTML & CSP header verification
                with urllib.request.urlopen(base_gw + "/", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    csp = resp.headers.get("Content-Security-Policy", "")
                    self.assertIn("script-src 'self'", csp)
                    body = resp.read().decode("utf-8")
                    self.assertIn("SYS.01 // AUTODORKER", body)
                    self.assertIn("/static/js/htmx.min.js", body)

                # HTMX mode switch partial
                with urllib.request.urlopen(base_gw + "/ui/input-mode?mode=batch", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn("url1,url2,url3", resp.read().decode("utf-8"))

                # SSRF blocking test (169.254.169.254 even with local_staging=on)
                ssrf_req = urllib.request.Request(
                    base_gw + "/api/scan",
                    data=urllib.parse.urlencode({"target_urls": "http://169.254.169.254/latest", "local_staging": "on"}).encode(),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx_err:
                    urllib.request.urlopen(ssrf_req, timeout=5)
                self.assertEqual(ctx_err.exception.code, 400)
                ctx_err.exception.close()

                # Live multi-URL POST /api/scan pipeline (Go -> Rust -> Python AST -> Export -> Backup)
                multi_payload = urllib.parse.urlencode({
                    "target_urls": f"http://127.0.0.1:{self.target_port}/, http://127.0.0.1:{self.target_port}/configs/",
                    "stealth_present": "1",
                    "stealth_mode": "on",
                    "local_staging": "on",
                    "engagement_id": "CN-AUDIT-2026-E2E",
                }).encode()
                scan_req = urllib.request.Request(base_gw + "/api/scan", data=multi_payload, method="POST")
                with urllib.request.urlopen(scan_req, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    hx_trig = resp.headers.get("HX-Trigger", "")
                    self.assertEqual(hx_trig, "scanStarted")
                    self.assertIn("PIPELINE RUNNING", resp.read().decode("utf-8"))

                # Poll /panels/findings until both Targ001 and Targ002 artifacts exist
                for _ in range(60):
                    if (out_dir / "Targ002").is_dir() and any((out_dir / "Targ002").glob("*.docx")):
                        break
                    threading.Event().wait(0.2)

                self.assertTrue((out_dir / "Targ001").is_dir(), "Expected Targ001 artifact directory")
                self.assertTrue((out_dir / "Targ002").is_dir(), "Expected Targ002 artifact directory")

                # Verify /panels/findings HTMX OOB rendering & /panels/svg-telemetry
                with urllib.request.urlopen(base_gw + "/panels/findings", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    htmx_frag = resp.read().decode("utf-8")
                    self.assertIn('hx-swap-oob="innerHTML"', htmx_frag)
                    self.assertIn("kpi-verified-tp", htmx_frag)

                with urllib.request.urlopen(base_gw + "/panels/svg-telemetry", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn("<svg", resp.read().decode("utf-8"))

                # Verify Batch ZIP now contains both Targ001 and Targ002
                with urllib.request.urlopen(base_gw + "/api/export/batch-zip", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    zdata = resp.read()
                    with zipfile.ZipFile(io.BytesIO(zdata), "r") as zf:
                        names = zf.namelist()
                        self.assertTrue(any(n.startswith("Targ001/") and n.endswith(".md") for n in names))
                        self.assertTrue(any(n.startswith("Targ001/") and n.endswith(".docx") for n in names))
                        self.assertTrue(any(n.startswith("Targ002/") and n.endswith(".md") for n in names))
                        self.assertTrue(any(n.startswith("Targ002/") and n.endswith(".docx") for n in names))

                # Export .MD and .DOCX for latest scan
                with urllib.request.urlopen(f"{base_gw}/api/export/md/latest", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn("CN-AUDIT-2026-E2E", resp.read().decode("utf-8"))

                with urllib.request.urlopen(f"{base_gw}/api/export/docx/latest", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertGreater(len(resp.read()), 2000)
            finally:
                gw_proc.terminate()
                gw_proc.wait(timeout=5)
                if gw_proc.stdout:
                    gw_proc.stdout.close()
                if gw_proc.stderr:
                    gw_proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
