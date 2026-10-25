"""Local-only regression tests. No organizational targets or public providers are contacted."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import php_surface_audit as audit


class FakeResolver:
    backend = "local-test"
    def __init__(self, *args, **kwargs):
        pass
    def resolve(self, host):
        addresses = [host] if audit.is_ip(host) else ["127.0.0.1"] if host in ("app.test", "localhost") else []
        return {"host": host, "addresses": addresses, "cnames": [], "errors": [], "backend": self.backend}
    def reverse(self, address):
        return ["app.test"], ""


class FixtureHandler(BaseHTTPRequestHandler):
    mode = "php"
    requests_seen = []
    def log_message(self, *args):
        pass
    def version_string(self):
        return "Apache/2.4.62"
    def do_GET(self):
        self.__class__.requests_seen.append((self.path, self.headers.get("Host")))
        path = self.path.split("?")[0]
        if self.mode == "named-only" and not self.headers.get("Host", "").startswith("app.test"):
            return self.reply(403, "error code: 1003 Direct IP access not allowed Cloudflare",
                              {"Server": "cloudflare", "CF-Ray": "fixture"})
        if self.mode == "discovery" and path == "/":
            return self.reply(200, '<meta content="MediaWiki 1.43.0" name="generator">'
                '<script>const endpoint="relative.php";</script>',
                {"Refresh": "0; url=/refreshed.php", "Content-Location": "/canonical.php"})
        if self.mode == "discovery" and path in ("/relative.php", "/refreshed.php", "/canonical.php"):
            return self.reply(200, "Public service " + path, {"X-Powered-By": "PHP/8.4.27"})
        if self.mode.startswith("redirect-"):
            generic = "<title>Application shell</title><p>Generic shared content</p>"
            if path == "/":
                return self.reply(200, '<title>Redirect fixture</title><a href="/index.php">Home</a>')
            if self.mode == "redirect-404":
                if path.startswith("/final/"):
                    return self.reply(404, "<title>Not found</title>")
                if path.startswith("/canonical/"):
                    return self.reply(301, "", {"Location": "/final/" + path[len("/canonical/"):]})
                return self.reply(301, "", {"Location": "/canonical" + path})
            if self.mode == "redirect-generic-controls":
                if path in ("/index.php", "/shared"):
                    return self.reply(200, generic)
                return self.reply(302, "", {"Location": "/shared"})
            if self.mode == "redirect-valid":
                if path == "/index.php":
                    return self.reply(302, "", {"Location": "/real.php"})
                if path == "/real.php":
                    return self.reply(200, "<title>Customer portal</title><p>Distinct report page</p>")
            if self.mode == "redirect-loop" and path == "/index.php":
                return self.reply(301, "", {"Location": "/index.php"})
            return self.reply(404, "<title>Not found</title>")
        if self.mode == "soft404":
            return self.reply(200, '<title>Welcome</title><a href="/soft.php">Home</a><p>Generic application shell</p>')
        if path == "/":
            return self.reply(200, '<title>Fixture</title><a href="/area/index.php">Area</a>'
                '<a href="/restricted.php">Restricted</a><script src="/app.js"></script>'
                '<a href="https://outside.invalid/no.php">Outside</a>'
                '<a href="/logout.php">Logout</a><form action="/submit.php" method="post"></form>')
        if path == "/app.js":
            return self.reply(200, 'fetch("/api/status.php");', {"Content-Type": "application/javascript"})
        if path == "/api/status.php":
            return self.reply(200, '{"status":"ok"}', {"Content-Type": "application/json",
                                                       "X-Powered-By": "PHP/8.3.35"})
        if path == "/area/index.php":
            return self.reply(200, "<title>Customer area</title><p>Distinct application page</p>")
        if path == "/hidden/report.php":
            return self.reply(200, "<title>Report</title><p>Public report landing page</p>")
        if path == "/robots.txt":
            return self.reply(200, "User-agent: *\nDisallow: /hidden/report.php", {"Content-Type": "text/plain"})
        if path == "/sitemap.xml":
            return self.reply(200, '<?xml version="1.0"?><urlset><url><loc>http://' +
                              self.headers["Host"] + "/hidden/report.php</loc></url></urlset>",
                              {"Content-Type": "application/xml"})
        if path == "/restricted.php":
            return self.reply(403, "<title>Access denied</title>")
        return self.reply(404, "<title>Not found</title><p>The requested page does not exist.</p>")
    def reply(self, status, body, headers=None):
        raw = body.encode("utf8")
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        headers = headers or {}
        if "Content-Type" not in headers:
            self.send_header("Content-Type", "text/html")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (OSError, ssl.SSLError):
            pass


@contextlib.contextmanager
def server(mode="php", tls=False):
    handler = type("Handler", (FixtureHandler,), {"mode": mode, "requests_seen": []})
    service = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    cert_tmp = None
    if tls:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            from datetime import datetime, timedelta, timezone
        except ImportError:
            service.server_close()
            raise unittest.SkipTest("Optional cryptography is needed only to create the local TLS fixture")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.test")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("app.test")]), critical=False)
            .sign(key, hashes.SHA256()))
        cert_tmp = tempfile.TemporaryDirectory()
        cert_path, key_path = Path(cert_tmp.name)/"cert.pem", Path(cert_tmp.name)/"key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        service.sni_names = []
        context.set_servername_callback(lambda sock, name, ctx: service.sni_names.append(name))
        service.socket = context.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        yield service, handler
    finally:
        service.shutdown()
        service.server_close()
        if cert_tmp:
            cert_tmp.cleanup()


def run_audit(service, tls=False, host="127.0.0.1", max_requests=70):
    scheme = "https" if tls else "http"
    target = audit.parse_target("{}://{}:{}/".format(scheme, host, service.server_port))
    config = audit.Config(timeout=1, target_seconds=15, max_requests=max_requests,
                         max_pages=35, max_depth=2, max_ips=1, rps=50)
    temp = tempfile.TemporaryDirectory()
    engine = audit.Auditor(config, FakeResolver(), audit.Scope([target], config),
                          audit.RateLimiter(50), temp.name)
    result = engine.audit(target)
    return result, temp


class ParsingAndRules(unittest.TestCase):
    def test_mixed_targets_preserve_path_case_and_ipv6(self):
        self.assertEqual(audit.parse_target("192.0.2.10").host, "192.0.2.10")
        self.assertEqual(audit.parse_target("PORTAL.Example.org").host, "portal.example.org")
        self.assertIn("/Area/INDEX.PHP", audit.parse_target("https://example.org/Area/INDEX.PHP").urls[0])
        self.assertEqual(audit.parse_target("2001:db8::1").host, "2001:db8::1")
        self.assertIn("[2001:db8::1]", audit.parse_target("2001:db8::1").urls[0])
        with self.assertRaises(ValueError):
            audit.parse_target("https://user:pass@example.org/")
        with self.assertRaises(ValueError):
            audit.parse_target("example.org/private")
        self.assertIsNone(audit.parse_target("# comment"))
    def test_versions_are_not_binary_cve_verdicts(self):
        self.assertIn("BEFORE_FIX", audit.version_assessment("8.3.35"))
        self.assertIn("NOT_INDEPENDENTLY_VERIFIED", audit.version_assessment("8.3.36"))
        self.assertIn("LEGACY", audit.version_assessment("7.4.33"))
        self.assertIn("INCOMPLETE", audit.version_assessment("8.3"))
        self.assertIn("NONFINAL", audit.version_assessment("8.5.12RC1"))
    def test_weak_apache_and_nginx_not_runtime_confirmation(self):
        apache = {"url":"http://app.test/", "headers":[("Server","Apache")], "body":""}
        nginx = dict(apache, headers=[("Server","nginx")])
        self.assertEqual(audit.detect_evidence(apache)[0]["strength"], "weak")
        self.assertEqual(audit.detect_evidence(nginx), [])
    def test_header_on_error_and_cookie_name_only(self):
        r = {"url":"http://app.test/no.php", "status":404, "headers":[
            ("X-Powered-By","PHP/8.4.27"), ("Set-Cookie","PHPSESSID=SECRET; HttpOnly")], "body":""}
        evidence = audit.detect_evidence(r)
        self.assertEqual(evidence[0]["version"], "8.4.27")
        self.assertNotIn("SECRET", json.dumps(evidence))
    def test_soft404_variable_path_and_incomplete_controls(self):
        a = {"url":"http://app.test/index.php","status":200,"headers":[],"body":"No page /index.php"}
        b = {"url":"http://app.test/rand.php","status":200,"headers":[],"body":"No page /rand.php"}
        self.assertTrue(audit.generic_match(a,b))
        b["body_truncated"] = True
        self.assertIsNone(audit.generic_match(a,b))
    def test_html_and_csv_output_escape_untrusted_values(self):
        self.assertEqual(audit.csv_safe("=1+1"), "'=1+1")
        self.assertNotIn("\x1b", audit.clean("\x1b[31mtest"))
    def test_phpinfo_requires_structure_not_just_tutorial_words(self):
        r = {"url":"http://app.test/", "headers":[("Content-Type","text/html")],
             "body":"<p>PHP Version 8.3.35 Server API Loaded Configuration File</p>"}
        self.assertFalse(any(e["kind"] == "PHPINFO_REPORT" for e in audit.detect_evidence(r)))
        r["body"] = "<h1>PHP Version 8.3.35</h1><table><tr><td>Server API</td><td>Loaded Configuration File</td></tr></table>"
        self.assertTrue(any(e["kind"] == "PHPINFO_REPORT" for e in audit.detect_evidence(r)))

    def test_javascript_and_robots_links(self):
        r = {"url":"http://app.test/a.js","headers":[("Content-Type","application/javascript")],
             "body":'fetch("/api/info.php");'}
        self.assertIn(("http://app.test/api/info.php","javascript"), audit.extract_links(r)[0])
        r.update(url="http://app.test/robots.txt",body="Disallow: /hidden/info.php")
        self.assertIn(("http://app.test/hidden/info.php","robots"), audit.extract_links(r)[0])

    def test_generators_are_attribute_order_independent_and_not_php_versions(self):
        for product in ("MediaWiki", "TYPO3", "PrestaShop", "Moodle", "DokuWiki", "phpBB", "Roundcube"):
            with self.subTest(product=product):
                record = {"url": "http://app.test/", "headers": [],
                          "body": '<meta content="{} 1.43.0" name="generator">'.format(product)}
                evidence = audit.detect_evidence(record)
                self.assertTrue(any(e["kind"] == "PHP_APPLICATION_GENERATOR" for e in evidence))
                self.assertTrue(all(e["strength"] == "indicator" and not e["version"] for e in evidence))

    def test_application_headers_preserve_runtime_uncertainty(self):
        for key, value in (("X-Generator", "Drupal 11"), ("X-Powered-By", "Nette Framework"),
                           ("Server", "FrankenPHP"), ("X-Drupal-Cache", "HIT"),
                           ("X-Magento-Cache-Debug", "MISS")):
            with self.subTest(key=key, value=value):
                evidence = audit.detect_evidence({"url": "http://app.test/", "headers": [(key, value)], "body": ""})
                self.assertTrue(evidence)
                self.assertTrue(all(e["strength"] == "indicator" and not e["version"] for e in evidence))

    def test_cookie_patterns_exclude_generic_session_names_and_values(self):
        for name in ("MoodleSession", "roundcube_sessid", "CakePHP", "PrestaShop-" + "a" * 32,
                     "SESS" + "b" * 32, "phpbb3_abcd_sid"):
            record = {"url": "http://app.test/", "body": "", "headers": [("Set-Cookie", name + "=PRIVATE_VALUE; Secure")]}
            evidence = audit.detect_evidence(record)
            self.assertTrue(evidence, name)
            self.assertNotIn("PRIVATE_VALUE", json.dumps(evidence))
        record["headers"] = [("Set-Cookie", "session_for_some_other_software=PRIVATE_VALUE")]
        self.assertFalse(audit.detect_evidence(record))

    def test_product_names_in_articles_and_generic_csrf_cookies_are_not_evidence(self):
        record = {"url": "http://app.test/", "headers": [("Set-Cookie", "XSRF-TOKEN=abc")],
                  "body": "<p>Compare Laravel, Symfony, Moodle and MediaWiki.</p>"}
        self.assertFalse(audit.detect_evidence(record))

    def test_inline_and_relative_javascript_endpoints_and_header_links(self):
        record = {"url": "http://app.test/area/", "headers": [("Refresh", '0; url="/refresh.php"'),
                  ("Location", "/redirect.php"), ("Content-Location", "/canonical.php")],
                  "body": '<base href="/app/"><script>$.get("status.php"); const u="\\/api\\/info.php";</script>'}
        links = {url for url, _ in audit.extract_links(record)[0]}
        self.assertTrue({"http://app.test/app/status.php", "http://app.test/api/info.php",
                         "http://app.test/refresh.php", "http://app.test/redirect.php",
                         "http://app.test/canonical.php"}.issubset(links))


class LocalIntegration(unittest.TestCase):
    def tearDown(self):
        audit.STOP.clear()
    def test_cli_handles_unicode_paths_with_ascii_output_encoding(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "\u05d1\u05d3\u05d9\u05e7\u05d4"
            output.mkdir()
            targets = output / "targets.txt"
            targets.write_text("https://user:pass@invalid.example/", encoding="utf-8")
            environment = dict(os.environ, PYTHONIOENCODING="ascii:strict")
            completed = subprocess.run([sys.executable, str(Path(audit.__file__)), "--targets", str(targets),
                                        "--output", str(output)], env=environment, capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("ascii", errors="replace"))
            self.assertTrue(next(output.glob("run_*/report.html"), None))
    def test_additional_discovery_reaches_live_routes(self):
        with server("discovery") as (service, handler):
            result, temp = run_audit(service)
            with temp:
                paths = {p for p, _ in handler.requests_seen}
                self.assertTrue({"/relative.php", "/refreshed.php", "/canonical.php"}.issubset(paths))
                self.assertEqual(result["php"], "EXPLICIT_PHP_REPORT")
                self.assertEqual([v["version"] for v in result["versions"]], ["8.4.27"])
                self.assertLessEqual(result["requests"], 70)

    def test_strict_scope_blocks_unlisted_names_even_at_same_ip(self):
        with server("named-only") as (service, handler), tempfile.TemporaryDirectory() as folder:
            target = audit.parse_target("http://127.0.0.1:{}/".format(service.server_port))
            config = audit.Config(strict_scope=True, rps=50, timeout=1)
            engine = audit.Auditor(config, FakeResolver(), audit.Scope([target], config), audit.RateLimiter(50), folder)
            result = engine.audit(target)
            self.assertFalse(any(host.startswith("app.test") for _, host in handler.requests_seen))
            self.assertTrue(any(n["state"] == "OUT_OF_SCOPE_STRICT_HOST_POLICY" for n in result["candidate_names"]))

    def test_strict_scope_allows_declared_domain_at_input_ip(self):
        with server("named-only") as (service, handler), tempfile.TemporaryDirectory() as folder:
            target = audit.parse_target("http://127.0.0.1:{}/".format(service.server_port))
            config = audit.Config(strict_scope=True, scope_domains=("app.test",), rps=50, timeout=1)
            engine = audit.Auditor(config, FakeResolver(), audit.Scope([target], config), audit.RateLimiter(50), folder)
            result = engine.audit(target)
            self.assertTrue(any(host.startswith("app.test") for _, host in handler.requests_seen))
            self.assertEqual(result["php"], "EXPLICIT_PHP_REPORT")

    def test_bulk_scheduler_bounds_pending_work_and_batches_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            targets = Path(folder) / "targets.txt"
            targets.write_text("\n".join("http://app.test/{}".format(i) for i in range(17)))
            pending_sizes = []
            report_sizes = []
            real_wait = audit.futures.wait
            def tracked_wait(pending, **kwargs):
                pending_sizes.append(len(pending))
                return real_wait(pending, **kwargs)
            def fake_audit(engine, target):
                return {"target_id": audit.digest(target.original)[:12], "target": target.original,
                        "availability": "HTTP_RESPONDING", "php": "NO_PHP_EVIDENCE",
                        "versions": [], "requests": 1, "coverage": "LIMITED"}
            with patch.object(audit, "Resolver", FakeResolver), \
                 patch.object(audit.Auditor, "audit", fake_audit), \
                 patch.object(audit.futures, "wait", tracked_wait), \
                 patch.object(audit, "save_reports", side_effect=lambda run, results, metadata: report_sizes.append(len(results))), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = audit.main(["--targets", str(targets), "--output", folder,
                                 "--workers", "2", "--report-every", "5"])
            self.assertEqual(rc, 0)
            self.assertTrue(pending_sizes)
            self.assertLessEqual(max(pending_sizes), 4)
            self.assertEqual(report_sizes, [1, 5, 10, 15, 17])
            run = next(Path(folder).glob("run_*"))
            lines = (run / "results.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 17)
            self.assertEqual(len({json.loads(line)["target_id"] for line in lines}), 17)

    def test_interruption_retains_finished_jobs_and_lists_unscheduled_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            targets = Path(folder) / "targets.txt"
            inputs = ["http://app.test/{}".format(i) for i in range(17)]
            targets.write_text("\n".join(inputs))
            final = {}
            def fake_audit(engine, target):
                audit.STOP.wait(2)
                return {"target_id": audit.digest(target.original)[:12], "target": target.original}
            def save(run, results, metadata):
                final.update(results=list(results), metadata=dict(metadata))
            with patch.object(audit, "Resolver", FakeResolver), \
                 patch.object(audit.Auditor, "audit", fake_audit), \
                 patch.object(audit.futures, "wait", side_effect=KeyboardInterrupt), \
                 patch.object(audit, "save_reports", save), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = audit.main(["--targets", str(targets), "--output", folder, "--workers", "2"])
            self.assertEqual(rc, 130)
            self.assertTrue(final["metadata"]["interrupted"])
            finished = {r["target"] for r in final["results"]}
            not_started = set(final["metadata"]["not_started_targets"])
            self.assertTrue(finished)
            self.assertFalse(finished & not_started)
            self.assertEqual(finished | not_started, set(inputs))
            run = next(Path(folder).glob("run_*"))
            self.assertEqual(len((run / "results.jsonl").read_text().splitlines()), len(finished))
    def test_crawl_js_php_route_and_non_submission(self):
        with server() as (service, handler):
            result, temp = run_audit(service)
            with temp:
                self.assertEqual(result["php"], "EXPLICIT_PHP_REPORT", result["notes"])
                self.assertIn("8.3.35", [v["version"] for v in result["versions"]])
                states = {p["url"].split(":")[-1].split("/",1)[-1]:p["state"] for p in result["php_paths"]}
                self.assertIn("DISTINCT_PHP_ROUTE", states.values())
                self.assertTrue(any(p["state"] == "ACCESS_RESTRICTED_EXISTENCE_UNPROVEN" for p in result["php_paths"]))
                paths = [p for p,h in handler.requests_seen]
                self.assertIn("/api/status.php", paths)
                self.assertIn("/hidden/report.php", paths)
                self.assertNotIn("/logout.php", paths)
                self.assertNotIn("/submit.php", paths)
                self.assertFalse(any("outside.invalid" in h for p,h in handler.requests_seen))
                for row in result["observations"]:
                    self.assertTrue((Path(temp.name)/row["evidence_file"]).is_file())
    def test_soft404_never_becomes_verified_php_route(self):
        with server("soft404") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                self.assertIn(result["php"], ("WEAK_PHP_SUSPICION", "PHP_INDICATORS"))
                self.assertTrue(result["php_paths"])
                self.assertTrue(all(p["state"] != "DISTINCT_PHP_ROUTE" for p in result["php_paths"]))
    def test_ip_denial_recovers_through_verified_dns_name(self):
        with server("named-only") as (service, handler):
            result, temp = run_audit(service)
            with temp:
                self.assertTrue(any(n["kind"] == "CLOUDFLARE_DIRECT_IP_DENIED" for n in result["notes"]))
                self.assertEqual(result["php"], "EXPLICIT_PHP_REPORT")
                self.assertTrue(any(h.startswith("app.test") for p,h in handler.requests_seen))
    def test_tls_certificate_names_and_sni_binding(self):
        with server("named-only", tls=True) as (service, _handler):
            config = audit.Config(timeout=2)
            r = audit.network_fetch("https://app.test:{}/".format(service.server_port),
                                    "127.0.0.1", config, time.monotonic()+8)
            self.assertEqual(r["status"], 200, r)
            self.assertIn("app.test", r["certificate_names"])
            self.assertIn("app.test", service.sni_names)
            strict = dataclasses_replace(config, verify_tls=True)
            r = audit.network_fetch("https://app.test:{}/".format(service.server_port),
                                    "127.0.0.1", strict, time.monotonic()+8)
            self.assertEqual(r["tcp"], "OPEN")
            self.assertEqual(r["tls"], "ERROR")
    def test_request_budget_is_visible_and_enforced(self):
        with server() as (service, _handler):
            result, temp = run_audit(service, max_requests=2)
            with temp:
                self.assertLessEqual(result["requests"], 2)
                self.assertEqual(result["scan_state"], "REQUEST_BUDGET_REACHED")
                self.assertEqual(result["coverage"], "LIMITED")
    def test_cli_creates_all_reports_and_retains_invalid_inputs(self):
        with server() as (service, _handler), tempfile.TemporaryDirectory() as folder:
            targets = Path(folder)/"targets.txt"
            targets.write_text("http://127.0.0.1:{}/\nhttps://user:password@bad.invalid/\n".format(service.server_port))
            with patch.object(audit, "Resolver", FakeResolver), contextlib.redirect_stdout(io.StringIO()):
                rc = audit.main(["--targets",str(targets),"--output",folder,
                    "--rps","50","--max-ips","1","--timeout","1","--target-seconds","15"])
            self.assertEqual(rc, 0)
            run = next(Path(folder).glob("run_*"))
            for name in ("summary.csv","php_evidence.csv","dns_candidates.csv","php_paths.csv",
                         "report.html","results.json","results.jsonl","run.json"):
                self.assertTrue((run/name).is_file(), name)
            data = json.loads((run/"results.json").read_text())
            self.assertEqual(len(data["metadata"]["invalid_inputs"]), 1)
            self.assertEqual(data["targets"][0]["php"], "EXPLICIT_PHP_REPORT")
            report = (run/"report.html").read_text(encoding="utf8")
            self.assertIn('lang="en"', report)
            self.assertIn('dir="ltr"', report)
            self.assertNotRegex(report, r"[\u0590-\u05ff]")

def dataclasses_replace(instance, **kwargs):
    import dataclasses
    return dataclasses.replace(instance, **kwargs)


class RedirectRegression(unittest.TestCase):
    def tearDown(self):
        audit.STOP.clear()

    def test_canonical_redirects_to_404_never_produce_strong_route_evidence(self):
        with server("redirect-404") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                self.assertFalse(any(e["kind"] == "DISTINCT_PHP_ROUTE" for e in result["evidence"]))
                redirects = [p for p in result["php_paths"] if p["status"] == 301]
                self.assertTrue(redirects)
                self.assertTrue(all(p["state"] == "REDIRECT_TO_NOT_FOUND_OR_MASKED" for p in redirects))
                self.assertTrue(all(p["final_status"] == 404 for p in redirects))
                self.assertTrue(any([h["status"] for h in p["redirect_chain"]] == [301,301,404]
                                    for p in redirects))

    def test_redirected_controls_compare_the_terminal_generic_response(self):
        with server("redirect-generic-controls") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                candidates = [p for p in result["php_paths"] if p["url"].endswith("/index.php")]
                self.assertTrue(candidates)
                self.assertTrue(all(p["state"] == "GENERIC_RESPONSE_EXISTENCE_UNPROVEN" for p in candidates))
                self.assertFalse(any(e["kind"] == "DISTINCT_PHP_ROUTE" for e in result["evidence"]))

    def test_redirect_to_real_php_route_only_promotes_terminal_success(self):
        with server("redirect-valid") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                routes = [e for e in result["evidence"] if e["kind"] == "DISTINCT_PHP_ROUTE"]
                self.assertTrue(routes)
                self.assertTrue(all(e["url"].endswith("/real.php") for e in routes))
                self.assertFalse(any(p["status"] in audit.REDIRECT_CODES and p["state"] == "DISTINCT_PHP_ROUTE"
                                     for p in result["php_paths"]))

    def test_redirect_loop_is_unresolved_not_evidence(self):
        with server("redirect-loop") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                paths = [p for p in result["php_paths"] if p["url"].endswith("/index.php")]
                self.assertTrue(any(p.get("redirect_resolution") == "REDIRECT_LOOP" for p in paths))
                self.assertFalse(any(e["kind"] == "DISTINCT_PHP_ROUTE" for e in result["evidence"]))

    def make_job(self, folder):
        target = audit.parse_target("http://app.test/index.php")
        config = audit.Config(timeout=1, target_seconds=15)
        engine = audit.Auditor(config, FakeResolver(), audit.Scope([target], config),
                               audit.RateLimiter(50), folder)
        return audit.Job(engine, target)

    def test_same_host_https_redirect_preserves_explicit_connection_ip(self):
        with tempfile.TemporaryDirectory() as folder:
            job = self.make_job(folder)
            first = {"id":"first", "url":"http://app.test/index.php", "connect_ip":"192.0.2.10",
                     "status":301, "headers":[("Location","https://app.test/index.php")]}
            final = dict(first, id="final", url="https://app.test/index.php", status=404, headers=[])
            with patch.object(job, "fetch", return_value=final) as fetch, \
                 patch.object(job, "resolve", side_effect=AssertionError("Must preserve pinned address")):
                terminal, trace, state = job.follow_redirects(first, "test")
            self.assertEqual(terminal["status"], 404)
            self.assertEqual(state, "FINAL_RESPONSE")
            fetch.assert_called_once_with("https://app.test/index.php", "192.0.2.10", "test")

    def test_unresolved_or_restricted_controls_cannot_promote_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            job = self.make_job(folder)
            candidate = {"id":"candidate", "url":"http://app.test/index.php", "connect_ip":"127.0.0.1",
                         "status":200, "headers":[], "body":"Distinct candidate"}
            denied = dict(candidate, id="control", url="http://app.test/random.php", status=403,
                          access_state="HTTP_ACCESS_RESTRICTED", body="Denied")
            with patch.object(job, "controls_for", return_value=[denied, denied]):
                job.validate_php_path(candidate, "test")
            self.assertEqual(job.paths[0]["state"], "CONTROL_CHECK_INCOMPLETE")
            self.assertFalse(job.evidence)

    def test_external_redirect_is_not_fetched_or_promoted(self):
        with tempfile.TemporaryDirectory() as folder:
            job = self.make_job(folder)
            candidate = {"id":"candidate", "url":"http://app.test/index.php", "connect_ip":"127.0.0.1",
                         "status":302, "headers":[("Location","https://outside.invalid/index.php")]}
            with patch.object(job, "fetch", side_effect=AssertionError("Out-of-scope request")):
                job.validate_php_path(candidate, "test")
            self.assertEqual(job.paths[0]["state"], "REDIRECT_UNRESOLVED_EXISTENCE_UNPROVEN")
            self.assertFalse(job.evidence)

    def test_saved_chain_ambiguous_or_missing_is_unresolved(self):
        initial = {"id":"a", "url":"http://app.test/index.php", "connect_ip":"127.0.0.1",
                   "status":301, "headers":[("Location","https://app.test/index.php")]}
        final = dict(initial, id="b", url="https://app.test/index.php", status=404, headers=[])
        self.assertIsNone(audit.saved_redirect_chain(initial,[initial])[0])
        self.assertIsNone(audit.saved_redirect_chain(initial,[initial,final,dict(final,id="c")])[0])
        self.assertEqual(audit.saved_redirect_chain(initial,[initial,final])[0]["status"],404)

    def test_offline_repair_recomputes_without_php_claim_and_keeps_valid_2xx_route(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            observation = {"id":"legacy-1", "url":"http://app.test/index.php", "connect_ip":"127.0.0.1",
                           "status":301, "headers":[("Location","https://app.test/index.php")]}
            final = dict(observation, id="legacy-2", url="https://app.test/index.php", status=404, headers=[])
            bad = {"kind":"DISTINCT_PHP_ROUTE", "strength":"strong", "url":observation["url"],
                   "connect_ip":"127.0.0.1", "request_id":"legacy-1", "detail":"Legacy error", "version":""}
            base = {"target":"app.test", "target_id":"legacy", "availability":"HTTP_RESPONDING",
                    "http_statuses":[301,404], "php":"STRONG_PHP_INDICATORS", "versions":[],
                    "action":"PHP_REVIEW_REQUIRED", "coverage":"LIMITED", "scan_state":"COMPLETED_WITHIN_CONFIGURED_LIMITS",
                    "requests":2, "elapsed_seconds":0, "cve_verdict":"NOT_EXPLOIT_TESTED_VENDOR_PATCH_STATUS_UNVERIFIED",
                    "evidence":[bad], "observations":[observation,final], "php_paths":[{
                        "url":observation["url"], "connect_ip":"127.0.0.1", "source":"directory_index_convention",
                        "status":301, "state":"DISTINCT_PHP_ROUTE", "request_id":"legacy-1"}],
                    "notes":[], "candidate_names":[]}
            good = json.loads(json.dumps(base))
            good["target_id"] = "valid"
            good["evidence"].append(dict(bad, request_id="valid-1",url="https://app.test/real.php", detail="Valid terminal route"))
            good["observations"].append(dict(final, id="valid-1",url="https://app.test/real.php",status=200))
            audit.save_reports(source,[base,good],{"started":audit.now(),"dns_backend":"unused","config":{}})
            with contextlib.redirect_stdout(io.StringIO()):
                repaired = audit.repair_run(source)
            data = json.loads((repaired/"results.json").read_text())
            self.assertEqual(data["targets"][0]["php"],"NO_PHP_EVIDENCE")
            self.assertEqual(data["targets"][0]["action"],"IDENTIFICATION_REVIEW_REQUIRED")
            self.assertEqual(data["targets"][1]["php"],"STRONG_PHP_INDICATORS")
            self.assertEqual([e["request_id"] for e in data["targets"][1]["evidence"]],["valid-1"])
            self.assertEqual(data["metadata"]["repair"]["removed_redirect_signals"],2)

    def test_offline_repair_preserves_original_and_independent_php_evidence(self):
        with server("redirect-404") as (service, _handler):
            result, temp = run_audit(service)
            with temp:
                source = Path(temp.name)
                path = next(p for p in result["php_paths"] if p["status"] == 301)
                result["evidence"].append({"strength":"strong", "kind":"DISTINCT_PHP_ROUTE",
                    "url":path["url"], "connect_ip":path["connect_ip"], "version":"",
                    "request_id":path["request_id"], "detail":"Historical buggy redirect promotion"})
                observation = next(r for r in result["observations"] if r["id"] == path["request_id"])
                result["evidence"].append({"strength":"explicit", "kind":"PHP_HEADER",
                    "url":path["url"], "connect_ip":path["connect_ip"], "version":"8.3.35",
                    "request_id":path["request_id"], "detail":"Independent PHP banner on redirect"})
                path["state"] = "DISTINCT_PHP_ROUTE"
                metadata = {"started":audit.now(), "dns_backend":"local-test", "config":{}}
                audit.save_reports(source,[result],metadata)
                originals = {f.name:f.read_bytes() for f in source.iterdir() if f.is_file()}
                with patch.object(audit,"network_fetch",side_effect=AssertionError("Offline must not connect")), \
                     patch.object(audit,"Resolver",side_effect=AssertionError("Offline must not resolve")), \
                     contextlib.redirect_stdout(io.StringIO()):
                    rc = audit.main(["--repair-run",str(source)])
                self.assertEqual(rc,0)
                repaired = next(source.glob("repaired_v1_0_1_*"))
                updated = json.loads((repaired/"results.json").read_text())
                self.assertEqual(updated["metadata"]["repair"]["removed_redirect_signals"],1)
                self.assertEqual(updated["metadata"]["repair"]["network_requests"],0)
                target = updated["targets"][0]
                self.assertEqual(target["php"],"EXPLICIT_PHP_REPORT")
                self.assertTrue(any(e["kind"] == "PHP_HEADER" for e in target["evidence"]))
                self.assertFalse(any(e["kind"] == "DISTINCT_PHP_ROUTE" for e in target["evidence"]))
                self.assertEqual(target["versions"][0]["version"],"8.3.35")
                fixed_path = next(p for p in target["php_paths"] if p["request_id"] == path["request_id"])
                self.assertEqual(fixed_path["final_status"],404)
                self.assertEqual(fixed_path["state"],"REDIRECT_TO_NOT_FOUND_OR_MASKED")
                self.assertIn("final_status",(repaired/"php_paths.csv").read_text(encoding="utf-8-sig"))
                for name,contents in originals.items():
                    self.assertEqual((source/name).read_bytes(),contents,name)
                for obs in target["observations"]:
                    self.assertTrue((repaired/obs["evidence_file"]).is_file())

if __name__ == "__main__":
    unittest.main(verbosity=2)
