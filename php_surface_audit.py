#!/usr/bin/env python3
"""PHP Surface Audit - evidence-driven PHP discovery, not an exploit validator."""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import csv
import dataclasses
import difflib
import gzip
import hashlib
import html
import http.client
from html.parser import HTMLParser
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, unquote, quote
from urllib.request import Request, urlopen
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

VERSION = "1.1.0"
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
         (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
REFERENCES = {
    "php": "https://www.php.net/archive/2026.php#2026-10-21-5",
    "ncsc": "https://github.com/NCSC-NL/php2shell",
    "48243": "https://www.tenable.com/plugins/nessus/48243",
    "369483": "https://www.tenable.com/plugins/nessus/369483",
    "fingerprinting": "https://owasp.org/www-project-web-security-testing-guide/",
}
PHP_EXT = re.compile(r"\.(?:php\d*|phtml)(?:/|$)", re.I)
SKIP_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|gz|exe|dmg)(?:$|\?)", re.I)
ACTION_PATH = re.compile(r"(?:^|[/_?&=-])(?:logout|logoff|signout|delete|remove|destroy|unsubscribe|checkout|purchase|sendmail)(?:$|[/_?&=.-])", re.I)
PHP_VERSION = re.compile(r"\bPHP(?:\s+Version)?[ /:=-]+(\d+\.\d+(?:\.\d+)?(?:[-+~._a-zA-Z0-9]*)?)", re.I)
STOP = threading.Event()
PRINT_LOCK = threading.Lock()
BROWSER_LOCK = threading.Lock()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def clean(value, limit=300):
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value)).strip()
    return text[:limit] + ("..." if len(text) > limit else "")

def configure_console():
    # Redirected Windows consoles may use an encoding that cannot print a path/target.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

def digest(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()

def host_key(value):
    value = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return value.encode("idna").decode("ascii").lower()

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def authority(host, port=None):
    text = "[" + host + "]" if ":" in host else host
    return text + (":" + str(port) if port else "")

def normalize_url(url):
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("Only HTTP(S) URLs with a host are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not accepted")
    host = host_key(parts.hostname)
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    netloc = authority(host, port if port not in (None, 80 if parts.scheme == "http" else 443) else None)
    if re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError("Whitespace/control characters in a target")
    return urlunsplit((parts.scheme.lower(), netloc, quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"), quote(parts.query, safe="/%?:@!$&'()*+,;=-._~[]"), ""))

@dataclasses.dataclass
class Target:
    original: str
    host: str
    urls: list
    line: int = 0

def parse_target(text, ports=(80, 443), line=0):
    text = text.strip().lstrip("\ufeff")
    if not text or text.startswith("#"):
        return None
    if "://" in text:
        url = normalize_url(text)
        return Target(text, host_key(urlsplit(url).hostname), [url], line)
    if is_ip(text):
        host, explicit_port = host_key(text), None
    else:
        parts = urlsplit("//" + text)
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("Use a full HTTP(S) URL when supplying a path")
        if parts.username is not None or not parts.hostname:
            raise ValueError("Invalid target")
        host, explicit_port = host_key(parts.hostname), parts.port
        if not is_ip(host) and not re.fullmatch(r"[a-z0-9_.-]+", host):
            raise ValueError("Invalid DNS name")
    urls = []
    for port in ((explicit_port,) if explicit_port is not None else ports):
        if not 1 <= port <= 65535:
            raise ValueError("Invalid port")
        scheme = "https" if port in (443, 8443, 9443) else "http"
        urls.append(normalize_url("{}://{}/".format(scheme, authority(host, port))))
    return Target(text, host, urls, line)

def version_assessment(version):
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return "INCOMPLETE_VERSION_REQUIRES_REVIEW"
    ver = tuple(map(int, match.groups()))
    if re.search(r"(?:alpha|beta|rc|dev)", version[match.end():], re.I):
        return "NONFINAL_BUILD_REQUIRES_REVIEW"
    fixed = FIXED.get(ver[:2])
    if fixed:
        return ("REPORTED_VERSION_BEFORE_FIX_BACKPORT_UNKNOWN" if ver < fixed
                else "REPORTED_VERSION_AT_OR_AFTER_FIX_NOT_INDEPENDENTLY_VERIFIED")
    return ("LEGACY_BRANCH_VENDOR_PATCH_STATUS_UNKNOWN" if ver[:2] < (8, 2)
            else "BRANCH_NOT_IN_RULESET_REQUIRES_REVIEW")

class Resolver:
    """dnspython is optional; the system resolver is a documented fallback."""
    def __init__(self, timeout=4, nameservers=()):
        self.timeout, self.cache, self.lock = timeout, {}, threading.Lock()
        self.backend = "system"
        try:
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
            self.resolver.lifetime = timeout
            self.resolver.timeout = min(2, timeout)
            self.resolver.use_search_by_default = False
            if nameservers:
                self.resolver.nameservers = list(nameservers)
            self.backend = "dnspython"
        except ImportError:
            self.resolver = None
            if nameservers:
                raise ValueError("--resolver requires dnspython")

    def resolve(self, host):
        if is_ip(host):
            return {"host": host, "addresses": [host], "cnames": [], "errors": [], "backend": self.backend}
        with self.lock:
            cached = self.cache.get(host)
        if cached is not None:
            return cached
        data = {"host": host, "addresses": [], "cnames": [], "errors": [], "backend": self.backend}
        if self.resolver:
            for typ in ("A", "AAAA", "CNAME"):
                try:
                    answer = self.resolver.resolve(host + ".", typ, lifetime=self.timeout)
                    if typ == "CNAME":
                        data["cnames"].extend(str(x.target).rstrip(".") for x in answer)
                    else:
                        data["addresses"].extend(str(x) for x in answer)
                    canonical = str(answer.canonical_name).rstrip(".")
                    if canonical != host:
                        data["cnames"].append(canonical)
                except Exception as exc:
                    data["errors"].append("{}: {}".format(typ, clean(exc)))
        else:
            try:
                data["addresses"] = [x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
            except OSError as exc:
                data["errors"].append(clean(exc))
            data["errors"].append("CNAME enumeration unavailable; install dnspython. System DNS timeout is OS-controlled.")
        data["addresses"] = sorted(set(data["addresses"]), key=lambda x: (":" in x, x))
        data["cnames"] = sorted(set(data["cnames"]))
        with self.lock:
            self.cache[host] = data
        return data

    def reverse(self, address):
        try:
            if self.resolver:
                import dns.reversename
                qname = dns.reversename.from_address(address)
                return [str(x.target).rstrip(".") for x in self.resolver.resolve(qname, "PTR", lifetime=self.timeout)], ""
            return [socket.gethostbyaddr(address)[0]], ""
        except Exception as exc:
            return [], clean(exc)

class RateLimiter:
    def __init__(self, rps):
        self.interval, self.lock, self.next = 1.0 / rps, threading.Lock(), {}

    def wait(self, key, deadline):
        with self.lock:
            current = time.monotonic()
            slot = max(current, self.next.get(key, current))
            self.next[key] = slot + self.interval
        delay = slot - time.monotonic()
        if time.monotonic() + max(0, delay) >= deadline:
            raise TimeoutError("Target time budget exhausted before the request")
        if delay > 0 and STOP.wait(delay):
            raise InterruptedError("Interrupted")

def decode_certificate(der):
    if not der:
        return [], "No peer certificate received"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", encoding="ascii", delete=False) as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
            name = handle.name
        try:
            decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
            if not decoder:
                return [], "Certificate name decoder unavailable on this Python implementation"
            cert = decoder(name)
        finally:
            os.unlink(name)
        names = [value for typ, value in cert.get("subjectAltName", ()) if typ == "DNS"]
        names.extend(value for rdn in cert.get("subject", ()) for key, value in rdn if key == "commonName")
        return sorted(set(clean(x, 253).lower().rstrip(".") for x in names)), ""
    except Exception as exc:
        return [], "Certificate decode: " + clean(exc)

class DeadlineReader(io.RawIOBase):
    """Enforce a total socket-read deadline, including HTTP header trickles."""
    def __init__(self, sock, deadline, timeout):
        self.sock, self.deadline, self.timeout = sock, deadline, timeout
    def readable(self):
        return True
    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Request total deadline exceeded")
        self.sock.settimeout(min(self.timeout, remaining))
        return self.sock.recv_into(buffer)

class ResponseSocket:
    def __init__(self, sock, deadline, timeout):
        self.sock, self.deadline, self.timeout = sock, deadline, timeout
    def makefile(self, *args, **kwargs):
        return io.BufferedReader(DeadlineReader(self.sock, self.deadline, self.timeout))

def network_fetch(url, address, config, deadline, method="GET"):
    record = {"url": url, "connect_ip": address, "method": method, "time": now(),
              "tcp": "NOT_TESTED", "tls": "N/A", "tls_verification": "not_applicable",
              "status": None, "reason": "", "headers": [], "body": "", "body_truncated": False,
              "certificate_names": [], "certificate_error": "", "error": "", "stage": "TCP"}
    sock = response = None
    started = time.monotonic()
    try:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        request_deadline = min(deadline, started + config.timeout * 3)
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Target time budget exhausted")
        sock = socket.create_connection((address, port), timeout=min(config.timeout, remaining))
        record["tcp"], record["local_ip"] = "OPEN", sock.getsockname()[0]
        if parts.scheme == "https":
            record["stage"] = "TLS"
            context = ssl.create_default_context()
            if not config.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            sock.settimeout(min(config.timeout, max(.01, request_deadline - time.monotonic())))
            sock = context.wrap_socket(sock, server_hostname=parts.hostname)
            record["tls"] = sock.version()
            record["tls_verification"] = "verified" if config.verify_tls else "disabled_for_diagnostics"
            record["certificate_names"], record["certificate_error"] = decode_certificate(sock.getpeercert(binary_form=True))
        record["stage"] = "HTTP"
        request_path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        headers = ["{} {} HTTP/1.1".format(method, request_path), "Host: " + parts.netloc,
                   "User-Agent: PHP-Surface-Audit/" + VERSION, "Accept: */*",
                   "Accept-Encoding: identity", "Connection: close", "", ""]
        sock.settimeout(min(config.timeout, max(.01, request_deadline - time.monotonic())))
        sock.sendall("\r\n".join(headers).encode("ascii"))
        response = http.client.HTTPResponse(ResponseSocket(sock, request_deadline, config.timeout), method=method)
        response.begin()
        record["status"], record["reason"] = response.status, clean(response.reason)
        record["headers"] = list(response.getheaders())
        chunks, size = [], 0
        while method != "HEAD" and size <= config.max_body:
            chunk = response.read1(min(32768, config.max_body + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
        record["body_truncated"] = len(body) > config.max_body
        body = body[:config.max_body]
        encoding = next((v for k, v in record["headers"] if k.lower() == "content-encoding"), "").lower()
        if encoding == "gzip":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                    decoded = stream.read(config.max_body + 1)
                record["body_truncated"] |= len(decoded) > config.max_body
                body = decoded[:config.max_body]
            except (OSError, EOFError) as exc:
                record["decode_error"] = clean(exc)
        elif encoding not in ("", "identity"):
            record["decode_error"] = "Unsupported content encoding: " + clean(encoding)
        record["bytes_read"] = size
        content_type = next((v for k, v in record["headers"] if k.lower() == "content-type"), "")
        charset = re.search(r"charset\s*=\s*[\"']?([a-zA-Z0-9_-]+)", content_type)
        try:
            record["body"] = body.decode(charset.group(1) if charset else "utf-8", errors="replace")
        except LookupError:
            record["body"] = body.decode("utf-8", errors="replace")
        record["stage"] = "COMPLETE"
    except (OSError, ValueError, http.client.HTTPException, UnicodeError) as exc:
        if record["stage"] == "TCP":
            record["tcp"] = ("TIMEOUT" if isinstance(exc, (TimeoutError, socket.timeout))
                             else "REFUSED" if isinstance(exc, ConnectionRefusedError) else "ERROR")
        if record["stage"] == "TLS":
            record["tls"] = "ERROR"
        record["error"] = type(exc).__name__ + ": " + clean(exc)
    finally:
        if response:
            response.close()
        if sock:
            sock.close()
        record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return record

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.base = [], [], ""
        self.generators, self.scripts, self.in_script = [], [], False
        self.title, self.in_title = "", False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and attrs.get("href"):
            self.base = attrs["href"]
        if tag == "title":
            self.in_title = True
        if tag == "script":
            self.in_script = True
        if tag == "meta" and attrs.get("name", "").lower() == "generator":
            self.generators.append(attrs.get("content", ""))
        if tag == "form" and attrs.get("action"):
            self.forms.append({"action": attrs["action"], "method": attrs.get("method", "GET").upper()})
        if tag != "form":
            for key in ("href", "src", "data-src"):
                if attrs.get(key):
                    self.links.append((attrs[key], tag))
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*(.+)", attrs.get("content", ""), re.I)
            if match:
                self.links.append((match.group(1).strip("'\" "), "meta"))
    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "script":
            self.in_script = False
    def handle_data(self, data):
        if self.in_title:
            self.title += data
        if self.in_script:
            self.scripts.append(data)

def header(record, name):
    return ", ".join(str(v) for k, v in record.get("headers", ()) if k.lower() == name.lower())

def extract_links(record):
    base, content = record["url"], record["body"]
    links, parser = [], LinkParser()
    try:
        parser.feed(content)
    except Exception:
        pass
    document_base = urljoin(base, parser.base) if parser.base else base
    links.extend((urljoin(document_base, v), tag) for v, tag in parser.links)
    links.extend((urljoin(document_base, item["action"]), "form:" + item["method"]) for item in parser.forms)
    ctype = header(record, "content-type").lower()
    javascript = "javascript" in ctype or urlsplit(base).path.lower().endswith(".js")
    for script in ([content] if javascript else parser.scripts):
        script = script.replace(r"\/", "/")
        for value in re.findall(r"""["'\x60]([^"'\x60\s<>\\]{1,1800})["'\x60]""", script):
            # Relative PHP endpoints also occur in XHR/jQuery/config objects.
            if value.startswith(("http://", "https://", "//", "/", "./", "../")) or PHP_EXT.search(value.split("?", 1)[0]):
                try:
                    links.append((urljoin(document_base, html.unescape(value)), "javascript"))
                except ValueError:
                    pass
        for value in re.findall(r"\b(?:fetch|axios\.(?:get|head))\s*\(\s*['\"]([^'\"]+)['\"]", script):
            links.append((urljoin(document_base, value), "javascript"))
    if "javascript" in ctype or urlsplit(base).path.lower().endswith(".js"):
        for value in re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)", content):
            if not value.startswith("data:"):
                links.append((urljoin(base, value), "source_map_reference"))
    if "xml" in ctype or urlsplit(base).path.lower().endswith(".xml"):
        try:
            if "<!DOCTYPE" not in content.upper() and "<!ENTITY" not in content.upper():
                root = ET.fromstring(content)
                links.extend((node.text.strip(), "sitemap") for node in root.iter()
                             if node.tag.rsplit("}", 1)[-1] == "loc" and node.text)
        except ET.ParseError:
            pass
    if urlsplit(base).path.lower().endswith("/robots.txt"):
        for line in content.splitlines():
            match = re.match(r"\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)", line, re.I)
            if match and "*" not in match.group(1) and "$" not in match.group(1):
                links.append((urljoin(base, match.group(1)), "robots"))
    for key, value in record["headers"]:
        if key.lower() == "link":
            links.extend((urljoin(base, x), "http-link") for x in re.findall(r"<([^>]+)>", value))
        elif key.lower() in ("location", "content-location"):
            links.append((urljoin(base, value), "http-" + key.lower()))
        elif key.lower() == "refresh":
            match = re.search(r"url\s*=\s*(.+)", value, re.I)
            if match:
                links.append((urljoin(base, match.group(1).strip("'\" ")), "http-refresh"))
    return links, clean(parser.title), parser.forms

def normalized_body(record):
    text = html.unescape(record.get("body", "")).lower()
    path = urlsplit(record.get("url", "")).path
    for value in (path.lower(), html.escape(path).lower(), unquote(path).lower()):
        if value and value != "/":
            text = text.replace(value, "<requested-path>")
    text = re.sub(r"\b[0-9a-f]{12,}\b|\b\d{6,}\b", "<variable>", text)
    text = re.sub(r"([?&](?:csrf|token|nonce)[^=]*=)[^&\"'\s<>]+", r"\1<variable>", text)
    return re.sub(r"\s+", " ", text).strip()

def generic_match(candidate, control):
    if any(r.get("error") or r.get("decode_error") or r.get("body_truncated") for r in (candidate, control)):
        return None
    if candidate.get("status") is None or control.get("status") is None:
        return None
    if candidate.get("status") != control.get("status"):
        return False
    loc_a, loc_b = header(candidate, "location"), header(control, "location")
    if loc_a or loc_b:
        return urljoin(candidate["url"], loc_a) == urljoin(control["url"], loc_b)
    if candidate.get("body", "") == control.get("body", ""):
        return True
    a, b = normalized_body(candidate), normalized_body(control)
    if a == b:
        return True
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a[:6000] + a[-2000:], b[:6000] + b[-2000:], autojunk=True).ratio() >= .94

def waf_state(record):
    text, server = record.get("body", "").lower(), header(record, "server").lower()
    if re.search(r"(?:error\s*(?:code)?\s*[:#]?\s*1003|direct ip access not allowed)", text) and ("cloudflare" in server or "cloudflare" in text or header(record, "cf-ray")):
        return "CLOUDFLARE_DIRECT_IP_DENIED"
    if ("cf-chl-" in text or "challenge-platform" in text) and ("cloudflare" in server or header(record, "cf-ray")):
        return "CLOUDFLARE_CHALLENGE"
    if record.get("status") == 429:
        return "RATE_LIMITED"
    return "HTTP_ACCESS_RESTRICTED" if record.get("status") in (401, 403) else ""

def is_text_response(record):
    ctype = header(record, "content-type").lower()
    return not ctype or any(x in ctype for x in ("text/", "json", "xml", "javascript", "html"))

def detect_evidence(record):
    """Return observations, not an exploitability verdict."""
    found = []
    def add(kind, strength, detail, version=""):
        found.append({"kind": kind, "strength": strength, "detail": clean(detail, 500),
                      "version": version, "url": record["url"],
                      "connect_ip": record.get("connect_ip", ""), "request_id": record.get("id", "")})
    products = r"WordPress|Drupal|Joomla!?|Magento|MediaWiki|TYPO3|PrestaShop|Moodle|DokuWiki|phpBB|Roundcube|Laravel|Symfony|CakePHP|Nette|ThinkPHP|FrankenPHP"
    for key, value in record.get("headers", []):
        if key.lower() in ("server", "x-powered-by", "x-generator"):
            match = PHP_VERSION.search(value)
            if match:
                add("PHP_HEADER", "explicit", key + ": " + value, match.group(1))
            elif re.search(r"\bPHP\b", value, re.I):
                add("PHP_HEADER", "explicit", key + ": " + value)
            if re.search(r"\b(?:" + products + r")\b", value, re.I):
                add("PHP_APPLICATION_HEADER", "indicator", key + ": " + value + "; application/runtime association, not execution proof")
        if key.lower() in ("x-drupal-cache", "x-drupal-dynamic-cache", "x-magento-cache-debug"):
            add("PHP_APPLICATION_HEADER", "indicator", key + ": " + value + "; may be served by a cache/proxy")
        if key.lower() == "set-cookie":
            name = value.split("=", 1)[0].strip()
            if (name.lower() in ("phpsessid", "laravel_session", "ci_session", "cakephp", "moodlesession", "roundcube_sessid")
                    or re.fullmatch(r"(?:S?SESS|PrestaShop-)[0-9a-f]{32}|phpbb[0-9a-z]*_[0-9a-z]+_(?:sid|u|k)", name, re.I)):
                add("PHP_ECOSYSTEM_COOKIE", "indicator", "Cookie name: " + name)
    server = header(record, "server")
    if re.search(r"\b(?:Apache|LiteSpeed|OpenLiteSpeed)\b", server, re.I):
        add("COMPATIBLE_WEB_SERVER", "weak", "PHP-capable web server reported; PHP is not established: " + server)
    body = record.get("body", "")
    if not is_text_response(record):
        return found
    lower = body.lower()
    parser = LinkParser()
    try:
        parser.feed(body)
    except Exception:
        pass
    for generator in parser.generators:
        if re.search(r"\b(?:" + products + r")\b", generator, re.I):
            add("PHP_APPLICATION_GENERATOR", "indicator", "HTML generator: " + generator + "; a static copy/proxy remains possible")
    plain = html.unescape(re.sub(r"<[^>]{0,500}>", " ", body))
    structured_phpinfo = bool(re.search(r"<h[12][^>]*>\s*PHP Version\s+\d", body, re.I) or re.search(r"^PHP Version\s*=>\s*\d", body, re.M))
    if structured_phpinfo and all(x in lower for x in ("php version", "server api", "loaded configuration file")):
        match = PHP_VERSION.search(plain)
        add("PHPINFO_REPORT", "explicit", "Structured PHP environment report exposed",
            match.group(1) if match else "")
    if re.search(r"\bPHP (?:Warning|Fatal error|Notice|Parse error|Deprecated):", plain, re.I) or (
        re.search(r"\b(?:Warning|Fatal error|Parse error)\b", plain) and
        re.search(r"\.php\b.{0,120}\bon line\s+\d+", plain, re.I)):
        add("PHP_RUNTIME_DIAGNOSTIC", "explicit", "PHP-style runtime diagnostic exposed; inspect saved response")
    ctype = header(record, "content-type").lower()
    if body.lstrip().startswith("<?php") and "html" not in ctype:
        add("PHP_SOURCE_ARTIFACT", "strong", "Response begins with PHP source; runtime execution is not established")
    signatures = {
        "WordPress": [r"wp-content/", r"wp-includes/", r"""name=["']generator["'][^>]+wordpress"""],
        "Drupal": [r"drupalsettings", r"/core/misc/drupal", r"""name=["']generator["'][^>]+drupal"""],
        "Joomla": [r"""name=["']generator["'][^>]+joomla""", r"/media/system/js/", r"joomla\.jtext"],
        "Magento": [r"x-magento-init", r"mage/cookies", r"magento_", r"static/version\d+/frontend/"],
    }
    for product, rules in signatures.items():
        matches = [rule for rule in rules if re.search(rule, lower)]
        if matches:
            add("PHP_APPLICATION_" + product.upper(), "strong" if len(matches) >= 2 else "indicator",
                "{} signatures: {}. A static copy/proxy remains possible.".format(product, len(matches)))
    return found


@dataclasses.dataclass
class Config:
    timeout: float = 4
    target_seconds: float = 90
    max_requests: int = 70
    max_pages: int = 35
    max_depth: int = 2
    max_body: int = 524288
    max_hosts: int = 8
    max_ips: int = 4
    rps: float = 2
    workers: int = 4
    report_every: int = 25
    verify_tls: bool = False
    strict_scope: bool = False
    headless: bool = False
    archives: bool = False
    ct: bool = False
    shodan: bool = False
    ports: tuple = (80, 443)
    scope_domains: tuple = ()
    resolver: tuple = ()
    output: str = ""
    verbose: bool = False

class Scope:
    def __init__(self, targets, config):
        self.exact_hosts = {t.host for t in targets}
        self.ips = {t.host for t in targets if is_ip(t.host)}
        self.domains = tuple(config.scope_domains)
    def declared(self, host):
        return host in self.exact_hosts or any(host == d or host.endswith("." + d) for d in self.domains)

class Auditor:
    def __init__(self, config, resolver, scope, limiter, run_dir):
        self.config, self.resolver, self.scope, self.limiter = config, resolver, scope, limiter
        self.run_dir = Path(run_dir)

    def audit(self, target):
        with PRINT_LOCK:
            print("[START] " + clean(target.original), flush=True)
        job = Job(self, target)
        try:
            job.run()
        except Exception as exc:
            job.note("INTERNAL_ERROR", type(exc).__name__ + ": " + clean(exc))
            job.state = "ERROR"
        return job.finish()

class Job:
    def __init__(self, auditor, target):
        self.a = auditor
        self.c, self.target = auditor.config, target
        self.started, self.deadline = time.monotonic(), time.monotonic() + auditor.config.target_seconds
        self.id = digest(target.original)[:12]
        self.records, self.evidence, self.candidates, self.notes = [], [], {}, []
        self.paths, self.dns, self.forms, self.discovered = [], [], [], []
        self.cache, self.controls, self.evidence_keys = {}, {}, set()
        self.bindings, self.binding_keys = [], set()
        self.state, self.request_count, self.pages = "COMPLETED_WITHIN_CONFIGURED_LIMITS", 0, 0
        self.headless_state = "DISABLED"
        self.providers = {}
        self.notified = set()
        if self.a.resolver.backend == "system":
            self.note("DNS_BACKEND_LIMIT", "CNAME enumeration is unavailable and OS DNS may exceed the target deadline; install optional dnspython")
        self.dir = self.a.run_dir / "evidence" / self.id
        self.dir.mkdir(parents=True, exist_ok=True)

    def note(self, kind, detail):
        item = {"kind": kind, "detail": clean(detail, 700)}
        if item not in self.notes:
            self.notes.append(item)

    def available(self):
        if STOP.is_set():
            self.state = "INTERRUPTED"
            return False
        if time.monotonic() >= self.deadline:
            self.state = "TIME_BUDGET_REACHED"
            return False
        if self.request_count >= self.c.max_requests:
            self.state = "REQUEST_BUDGET_REACHED"
            return False
        return True

    def add_evidence(self, item):
        key = (item["kind"], item.get("url"), item.get("connect_ip"), item.get("detail"))
        if key not in self.evidence_keys:
            self.evidence_keys.add(key)
            self.evidence.append(item)
            notice = (item["strength"], item.get("version") or item["kind"])
            if item["strength"] in ("explicit", "strong") and notice not in self.notified:
                self.notified.add(notice)
                with PRINT_LOCK:
                    print("[SIGNAL] {} | {} | {} | {}".format(clean(self.target.original), item["strength"].upper(), item["kind"], clean(item["url"])), flush=True)

    def observe(self, record):
        for item in detect_evidence(record):
            self.add_evidence(item)
        if record.get("body_truncated"):
            self.note("BODY_TRUNCATED", record["url"])
        for error_key in ("error", "decode_error", "certificate_error"):
            if record.get(error_key):
                self.note(error_key.upper(), record["url"] + ": " + record[error_key])
        if is_text_response(record) and record.get("body"):
            links, _title, _forms = extract_links(record)
            current_host = urlsplit(record["url"]).hostname
            for linked_url, linked_source in links[:300]:
                try:
                    linked = urlsplit(linked_url)
                    if linked.hostname == current_host and PHP_EXT.search(linked.path):
                        self.add_evidence({"kind": "PHP_ROUTE_REFERENCE", "strength": "indicator",
                            "detail": "Unverified same-host PHP-like URL in " + linked_source + ": " + clean(linked_url),
                            "version": "", "url": record["url"], "connect_ip": record.get("connect_ip", ""),
                            "request_id": record["id"]})
                except ValueError:
                    pass
        for name in record.get("certificate_names", []):
            self.candidate(name, "TLS certificate", record.get("connect_ip", ""))
        state = waf_state(record)
        if state:
            record["access_state"] = state
            self.note(state, record["url"])
        location = header(record, "location")
        if location:
            try:
                host = urlsplit(urljoin(record["url"], location)).hostname
                if host:
                    self.candidate(host, "HTTP redirect", record.get("connect_ip", ""))
            except ValueError:
                pass
        path = self.dir / (record["id"] + ".json")
        record["evidence_file"] = str(path.relative_to(self.a.run_dir)).replace(os.sep, "/")
        path.write_text(json.dumps(record, indent=2, ensure_ascii=True), encoding="utf-8")

    def fetch(self, url, ip, purpose, method="GET"):
        try:
            url = normalize_url(url)
        except ValueError as exc:
            self.note("URL_REJECTED", str(exc))
            return None
        key = (url, ip, method)
        if key in self.cache:
            return self.cache[key]
        if not self.available():
            return None
        try:
            self.a.limiter.wait(ip, self.deadline)
        except (TimeoutError, InterruptedError) as exc:
            self.note("SCHEDULER_STOP", str(exc))
            self.available()
            return None
        self.request_count += 1
        record = network_fetch(url, ip, self.c, self.deadline, method)
        record["id"] = "{}-{:04d}".format(self.id, self.request_count)
        record["purpose"] = purpose
        self.records.append(record)
        self.cache[key] = record
        self.observe(record)
        if self.c.verbose:
            with PRINT_LOCK:
                print("  {} {} via {} => TCP={} HTTP={} {}".format(
                    method, clean(url, 180), ip, record["tcp"], record["status"] or "-",
                    record.get("access_state", "")), flush=True)
        if record.get("status") == 429:
            # A bounded pause; never immediately retry an overloaded endpoint.
            STOP.wait(min(2, max(0, self.deadline - time.monotonic())))
        return record

    def candidate(self, name, source, related_ip=""):
        try:
            name = host_key(name)
        except (ValueError, UnicodeError):
            return
        if is_ip(name):
            return
        if len(self.candidates) >= 200 and name not in self.candidates:
            self.note("CANDIDATE_LIMIT", "At most 200 discovered DNS names are retained per target")
            return
        item = self.candidates.setdefault(name, {"name": name, "sources": [], "related_ips": [],
                                                 "addresses": [], "state": "DISCOVERED"})
        if source not in item["sources"]:
            item["sources"].append(source)
        if related_ip and related_ip not in item["related_ips"]:
            item["related_ips"].append(related_ip)

    def resolve(self, host):
        data = self.a.resolver.resolve(host)
        if not any(x["host"] == host for x in self.dns):
            self.dns.append(data)
        return data

    def allowed_name(self, host):
        if self.a.scope.declared(host):
            return True
        if self.c.strict_scope:
            return False
        item = self.candidates.get(host, {})
        return bool(set(item.get("addresses", [])) & self.a.scope.ips)

    def add_binding(self, url, ip, route):
        key = (url, ip)
        if key not in self.binding_keys:
            self.binding_keys.add(key)
            item = {"url": url, "connect_ip": ip, "route": route}
            self.bindings.append(item)
            return item
        return None

    def provider_get(self, endpoint, provider):
        if not self.available():
            return None
        # Provider requests never contain credentials in saved URLs or output.
        self.providers[provider] = "REQUESTED"
        try:
            request = Request(endpoint, headers={"User-Agent": "PHP-Surface-Audit/" + VERSION,
                                                  "Accept": "application/json"})
            with urlopen(request, timeout=min(self.c.timeout, max(.1, self.deadline - time.monotonic()))) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                self.providers[provider] = "TRUNCATED_RESPONSE_NOT_PARSED"
                return None
            data = json.loads(raw)
            self.providers[provider] = "COMPLETED"
            return data
        except Exception as exc:
            # Do not include provider exception text: it may echo a URL/API key.
            self.providers[provider] = "FAILED_" + type(exc).__name__
            return None

    def passive_discovery(self):
        if self.c.shodan:
            api_key = os.getenv("SHODAN_API_KEY", "")
            if not api_key:
                self.providers["Shodan"] = "SKIPPED_NO_SHODAN_API_KEY"
            elif is_ip(self.target.host) and ipaddress.ip_address(self.target.host).is_global:
                data = self.provider_get("https://api.shodan.io/shodan/host/{}?{}".format(
                    self.target.host, urlencode({"key": api_key})), "Shodan")
                if isinstance(data, dict):
                    for name in data.get("hostnames", []):
                        self.candidate(name, "Shodan historical observation", self.target.host)
        if self.c.ct and not is_ip(self.target.host):
            data = self.provider_get("https://crt.sh/?" + urlencode(
                {"q": self.target.host, "output": "json"}), "Certificate Transparency")
            if isinstance(data, list):
                for item in data[:500]:
                    for name in str(item.get("name_value", "")).splitlines():
                        self.candidate(name, "Certificate Transparency")
        if self.c.archives and not is_ip(self.target.host):
            endpoint = "https://web.archive.org/cdx/search/cdx?" + urlencode({
                "url": self.target.host + "/*", "output": "json", "filter": "statuscode:200",
                "fl": "original", "collapse": "urlkey", "limit": 100})
            data = self.provider_get(endpoint, "Wayback CDX")
            if isinstance(data, list):
                for row in data[1:]:
                    if row and isinstance(row[0], str):
                        self.discovered.append({"url": row[0], "source": "historical_archive", "depth": 1})

    def discover_bindings(self):
        data = self.resolve(self.target.host)
        addresses = data["addresses"][:self.c.max_ips]
        if len(data["addresses"]) > len(addresses):
            self.note("IP_LIMIT", "Not all resolved IPs were probed; increase --max-ips")
        if not addresses:
            self.note("DNS_NO_ADDRESS", self.target.host)
        if is_ip(self.target.host):
            names, error = self.a.resolver.reverse(self.target.host)
            if error:
                self.note("PTR_LOOKUP", error)
            for name in names:
                self.candidate(name, "PTR", self.target.host)
        for ip in addresses:
            for url in self.target.urls:
                self.add_binding(url, ip, "DIRECT_IP" if is_ip(self.target.host) else "DNS_NAME_AT_RESOLVED_IP")
                self.fetch(url, ip, "initial_probe")
        for record in list(self.records):
            if record.get("status") is not None and is_text_response(record):
                links, _, _ = extract_links(record)
                for link, _source in links[:100]:
                    try:
                        if urlsplit(link).hostname:
                            self.candidate(urlsplit(link).hostname, "Initial page link")
                    except ValueError:
                        pass
        self.passive_discovery()
        self.expand_candidates()
        if is_ip(self.target.host) and not any(x["state"] == "IN_SCOPE_PROBED" for x in self.candidates.values()):
            self.note("DNS_SITE_IDENTITY_UNRESOLVED", "No usable in-scope DNS name was verified for this IP. IP-only responses do not cover named virtual hosts.")

    def expand_candidates(self):
        # Process names discovered by certificates/redirects, without unbounded recursion.
        processed = {name for name, item in self.candidates.items() if item["state"] != "DISCOVERED"}
        admitted = sum(item["state"] == "IN_SCOPE_PROBED" for item in self.candidates.values())
        for _round in range(2):
            names = [name for name in self.candidates if name not in processed]
            for name in names:
                if not self.available():
                    break
                processed.add(name)
                item = self.candidates[name]
                if "*" in name:
                    item["state"] = "WILDCARD_NOT_EXPANDED"
                    continue
                if self.c.strict_scope and not self.a.scope.declared(name):
                    item["state"] = "OUT_OF_SCOPE_STRICT_HOST_POLICY"
                    continue
                if admitted >= self.c.max_hosts:
                    item["state"] = "HOST_LIMIT_NOT_PROBED"
                    self.note("HOST_LIMIT", "Increase --max-hosts to examine additional candidate names")
                    continue
                resolved = self.resolve(name)
                item["addresses"] = resolved["addresses"]
                if not resolved["addresses"] and not (self.a.scope.declared(name) and set(item["related_ips"]) & self.a.scope.ips):
                    item["state"] = "NO_CURRENT_DNS_ADDRESS"
                    continue
                if not resolved["addresses"]:
                    self.note("NAMED_BINDING_WITHOUT_DNS", name + ": testing the declared name only at its explicitly supplied, observed IP association")
                if not self.a.scope.declared(name) and not (set(resolved["addresses"]) & self.a.scope.ips):
                    item["state"] = "OUT_OF_SCOPE_OR_UNVERIFIED_ASSOCIATION"
                    continue
                item["state"] = "IN_SCOPE_PROBED"
                admitted += 1
                associated = list(resolved["addresses"])
                # Retain explicit original-IP/name bindings only for in-scope, discovered names.
                associated += [ip for ip in item["related_ips"] if ip in self.a.scope.ips]
                for ip in list(dict.fromkeys(associated))[:self.c.max_ips]:
                    for seed in self.target.urls:
                        parts = urlsplit(seed)
                        new_url = urlunsplit((parts.scheme, authority(name, parts.port), "/", "", ""))
                        if self.add_binding(new_url, ip, "DISCOVERED_DNS_AT_ASSOCIATED_IP"):
                            self.fetch(new_url, ip, "named_site_probe")

    def controls_for(self, record):
        parts = urlsplit(record["url"])
        directory = parts.path.rsplit("/", 1)[0] + "/"
        key = (parts.scheme, parts.netloc, record["connect_ip"], directory)
        if key not in self.controls:
            token = "surface-check-" + uuid.uuid4().hex[:12]
            controls = []
            for suffix in ("", ".php"):
                url = urlunsplit((parts.scheme, parts.netloc, directory + token + suffix, "", ""))
                controls.append(self.fetch(url, record["connect_ip"], "nonexistent_path_control"))
            self.controls[key] = controls
        return self.controls[key]

    def follow_redirects(self, record, purpose):
        """Resolve in-scope redirect chains without treating redirection as PHP evidence."""
        current = record
        trace = []
        seen = set()
        for _hop in range(6):
            trace.append({"request_id": current["id"], "url": current["url"],
                          "connect_ip": current["connect_ip"], "status": current.get("status"),
                          "location": header(current, "location")})
            if current.get("status") not in (301, 302, 303, 307, 308):
                return current, trace, "FINAL_RESPONSE"
            key = (current["url"], current["connect_ip"])
            if key in seen:
                return None, trace, "REDIRECT_LOOP"
            seen.add(key)
            if len(trace) >= 6:
                return None, trace, "REDIRECT_LIMIT"
            location = header(current, "location")
            if not location:
                return None, trace, "REDIRECT_WITHOUT_LOCATION"
            try:
                next_url = normalize_url(urljoin(current["url"], location))
                old_host = host_key(urlsplit(current["url"]).hostname)
                new_host = host_key(urlsplit(next_url).hostname)
            except (ValueError, UnicodeError):
                return None, trace, "INVALID_REDIRECT_LOCATION"
            if ACTION_PATH.search(unquote(urlsplit(next_url).path + "?" + urlsplit(next_url).query)):
                self.note("ACTION_URL_NOT_FETCHED", next_url)
                return None, trace, "REDIRECT_ACTION_NOT_FETCHED"
            if urlsplit(next_url).query:
                return None, trace, "REDIRECT_QUERY_REQUIRES_REVIEW"
            if new_host == old_host:
                address = current["connect_ip"]
            else:
                self.candidate(new_host, "Redirect validation", current["connect_ip"])
                if not self.allowed_name(new_host):
                    return None, trace, "REDIRECT_OUT_OF_SCOPE_OR_UNVERIFIED"
                addresses = self.resolve(new_host)["addresses"]
                if not addresses:
                    return None, trace, "REDIRECT_DNS_UNRESOLVED"
                address = addresses[0]
            current = self.fetch(next_url, address, purpose)
            if current is None:
                return None, trace, "REDIRECT_REQUEST_NOT_COMPLETED"
        return None, trace, "REDIRECT_LIMIT"

    def validate_php_path(self, record, source):
        if not PHP_EXT.search(urlsplit(record["url"]).path):
            return
        item = {"url": record["url"], "connect_ip": record["connect_ip"], "source": source,
                "status": record.get("status"), "state": "UNRESOLVED",
                "request_id": record["id"], "controls": [], "redirect_chain": []}
        if record.get("status") is None:
            item["state"] = "REQUEST_FAILED"
        elif record.get("status") in (404, 410):
            item["state"] = "NOT_FOUND_OR_MASKED"
        elif record.get("status") in (301, 302, 303, 307, 308):
            final, trace, resolution = self.follow_redirects(record, "php_route_redirect_validation")
            item["redirect_chain"] = trace
            item["final_url"] = final["url"] if final else ""
            item["final_status"] = final.get("status") if final else None
            item["redirect_resolution"] = resolution
            if final is None or final.get("status") is None:
                item["state"] = "REDIRECT_UNRESOLVED_EXISTENCE_UNPROVEN"
            elif final["status"] in (404, 410):
                item["state"] = "REDIRECT_TO_NOT_FOUND_OR_MASKED"
            elif final.get("access_state"):
                item["state"] = "REDIRECT_TO_ACCESS_RESTRICTED_EXISTENCE_UNPROVEN"
            else:
                item["state"] = "REDIRECT_TARGET_RESPONDED_ORIGINAL_PATH_UNPROVEN"
                # Evaluate an actual terminal PHP-like route separately, never the initial 3xx.
                if PHP_EXT.search(urlsplit(final["url"]).path):
                    self.validate_php_path(final, "redirect_terminal_response")
        elif record.get("access_state"):
            item["state"] = "ACCESS_RESTRICTED_EXISTENCE_UNPROVEN"
        else:
            controls = self.controls_for(record)
            terminal_controls = []
            control_ids = []
            for control in controls:
                if control is None:
                    terminal_controls.append(None)
                    continue
                terminal, trace, _resolution = self.follow_redirects(control, "control_redirect_validation")
                if terminal and (terminal.get("access_state") or terminal.get("status", 0) is None
                                 or terminal.get("status", 0) >= 500):
                    terminal = None
                terminal_controls.append(terminal)
                control_ids.extend(hop["request_id"] for hop in trace)
            item["controls"] = list(dict.fromkeys(control_ids))
            comparisons = [generic_match(record, control) if control else None
                           for control in terminal_controls]
            if len(comparisons) != 2 or any(value is None for value in comparisons):
                item["state"] = "CONTROL_CHECK_INCOMPLETE"
            elif any(comparisons):
                item["state"] = "GENERIC_RESPONSE_EXISTENCE_UNPROVEN"
            elif record["status"] in (200, 201, 202, 203, 204):
                item["state"] = "DISTINCT_PHP_ROUTE"
                self.add_evidence({"kind": "DISTINCT_PHP_ROUTE", "strength": "strong",
                    "detail": "Terminal successful PHP-like response differs from resolved same-directory controls; physical file/execution not proven",
                    "version": "", "url": record["url"], "connect_ip": record["connect_ip"],
                    "request_id": record["id"]})
            else:
                item["state"] = "DISTINCT_ERROR_RESPONSE_REQUIRES_REVIEW"
        if not any(path["request_id"] == item["request_id"] and path["source"] == source
                   for path in self.paths):
            self.paths.append(item)

    def usable_link(self, url, source):
        try:
            url = normalize_url(url)
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return None
        if source.startswith("form:"):
            self.forms.append({"url": url, "source": source, "state": "RECORDED_NOT_SUBMITTED"})
            return None
        # Keep discovered paths, omit query values to reduce duplicate/state-changing requests.
        url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        if ACTION_PATH.search(unquote(parts.path + "?" + parts.query)):
            self.note("ACTION_URL_NOT_FETCHED", url)
            return None
        if SKIP_EXT.search(parts.path):
            return None
        if not self.allowed_name(host_key(parts.hostname)):
            self.candidate(parts.hostname, "Crawl link (not yet validated)")
            return None
        return url

    def crawl(self, binding):
        if not self.available():
            return
        root = self.fetch(binding["url"], binding["connect_ip"], "initial_probe")
        if not root or root["status"] is None:
            return
        if root.get("access_state") in ("CLOUDFLARE_DIRECT_IP_DENIED", "CLOUDFLARE_CHALLENGE", "RATE_LIMITED"):
            # Other name/IP/scheme bindings are still tested; this binding remains limited.
            return
        parts = urlsplit(root["url"])
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        queue = [(root["url"], 0, "seed"), (origin + "robots.txt", 0, "standard_discovery"),
                 (origin + "sitemap.xml", 0, "standard_discovery")]
        queue += [(item["url"], item["depth"], item["source"]) for item in self.discovered
                  if urlsplit(item["url"]).hostname == parts.hostname]
        seen, same_origin_count = set(), 0
        while queue and self.available():
            queue.sort(key=lambda x: (0 if PHP_EXT.search(urlsplit(x[0]).path) else
                                      1 if urlsplit(x[0]).path.endswith(".js") else 2, x[1]))
            url, depth, source = queue.pop(0)
            url = self.usable_link(url, source)
            if not url or url in seen:
                continue
            seen.add(url)
            if self.pages >= self.c.max_pages:
                self.note("PAGE_LIMIT", "Crawl stopped at --max-pages")
                break
            candidate = urlsplit(url)
            if host_key(candidate.hostname) == host_key(parts.hostname):
                ip = binding["connect_ip"]
            elif (candidate.scheme, candidate.netloc) != (parts.scheme, parts.netloc):
                host = host_key(candidate.hostname)
                self.candidate(host, "Crawl link")
                if not any(host_key(urlsplit(b["url"]).hostname) == host for b in self.bindings):
                    continue
                resolved = self.resolve(host)
                addresses = resolved["addresses"][:1]
                if not addresses:
                    continue
                ip = addresses[0]
            else:
                ip = binding["connect_ip"]
            record = self.fetch(url, ip, "crawl:" + source)
            self.pages += 1
            same_origin_count += 1
            if not record or record["status"] is None:
                continue
            self.validate_php_path(record, source)
            if not is_text_response(record) or record.get("access_state") or record["status"] >= 400:
                continue
            links, title, forms = extract_links(record)
            record["title"] = title
            if depth < self.c.max_depth:
                for link, link_source in links[:300]:
                    candidate_url = self.usable_link(link, link_source)
                    if candidate_url:
                        queue.append((candidate_url, depth + 1, link_source))
            elif links:
                self.note("DEPTH_LIMIT", "Some discovered links were not visited beyond --depth")
            redirect = header(record, "location")
            if redirect:
                queue.insert(0, (urljoin(record["url"], redirect), depth, "redirect"))
            # A single directory-index convention probe is derived from server/app evidence.
            if depth == 0 and urlsplit(url).path.endswith("/"):
                queue.append((urljoin(url, "index.php"), depth + 1, "directory_index_convention"))
        if same_origin_count == 0:
            self.note("CRAWL_NO_PAGES", binding["url"])

    def browser_enrichment(self):
        if not self.c.headless:
            return
        # Only declared DNS names: browser DNS must not escape an IP-only scope.
        eligible = [b for b in self.bindings if not is_ip(urlsplit(b["url"]).hostname)
                    and self.a.scope.declared(host_key(urlsplit(b["url"]).hostname))]
        if not eligible:
            self.headless_state = "SKIPPED_NO_DECLARED_DNS_TARGET"
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.headless_state = "SKIPPED_PLAYWRIGHT_NOT_INSTALLED"
            self.note("HEADLESS_UNAVAILABLE", "Install optional Playwright and Chromium to enable browser enrichment")
            return
        with BROWSER_LOCK:
            if not self.available():
                self.headless_state = "SKIPPED_BUDGET"
                return
            seed = eligible[0]["url"]
            seen_responses = []
            allowed_hosts = {host_key(urlsplit(b["url"]).hostname) for b in eligible}
            def route_request(route):
                request = route.request
                parts = urlsplit(request.url)
                if (request.method not in ("GET", "HEAD") or parts.scheme not in ("http", "https")
                    or not parts.hostname or host_key(parts.hostname) not in allowed_hosts
                    or ACTION_PATH.search(unquote(parts.path + "?" + parts.query))
                    or request.resource_type in ("image", "media", "font") or not self.available()):
                    route.abort()
                    return
                try:
                    addresses = self.resolve(host_key(parts.hostname))["addresses"]
                    if not addresses:
                        route.abort()
                        return
                    self.a.limiter.wait(addresses[0], self.deadline)
                    self.request_count += 1
                    route.continue_()
                except Exception:
                    route.abort()
            browser = None
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    context = browser.new_context(ignore_https_errors=not self.c.verify_tls,
                                                   service_workers="block")
                    context.route("**/*", route_request)
                    page = context.new_page()
                    page.on("response", lambda response: seen_responses.append(response))
                    page.goto(seed, wait_until="domcontentloaded",
                              timeout=int(min(15, max(1, self.deadline - time.monotonic())) * 1000))
                    page.wait_for_timeout(750)
                    dom = page.content()[:self.c.max_body]
                    synthetic = {"url": page.url, "connect_ip": "BROWSER_DNS_ROUTE_UNVERIFIED",
                                 "headers": [], "body": dom, "id": self.id + "-browser-dom"}
                    synthetic.update({"time": now(), "tcp": "OPEN", "status": None, "purpose": "browser_dom", "method": "GET", "body_truncated": len(dom) >= self.c.max_body})
                    self.records.append(synthetic)
                    self.observe(synthetic)
                    links, _, _ = extract_links(synthetic)
                    for url, source in links:
                        candidate_url = self.usable_link(url, source)
                        if candidate_url:
                            self.discovered.append({"url": candidate_url, "depth": 1, "source": "browser_dom"})
                    for browser_index, response in enumerate(seen_responses[:50], 1):
                        try:
                            if host_key(urlsplit(response.url).hostname) not in allowed_hosts:
                                continue
                            record = {"id": self.id + "-browser-" + str(browser_index),
                                      "url": response.url, "connect_ip": "BROWSER_DNS_ROUTE_UNVERIFIED",
                                      "method": response.request.method, "status": response.status,
                                      "headers": list(response.all_headers().items()), "body": "",
                                      "time": now(), "tcp": "OPEN", "purpose": "browser_response"}
                            # Header evidence is collected here; discovered paths are probed by the normal engine.
                            self.records.append(record)
                            self.observe(record)
                            if response.request.method in ("GET", "HEAD"):
                                candidate_url = self.usable_link(response.url, "browser_network")
                                if candidate_url:
                                    self.discovered.append({"url": candidate_url, "depth": 1, "source": "browser_network"})
                        except Exception as exc:
                            self.note("BROWSER_RESPONSE_ERROR", type(exc).__name__)
                    context.close()
                    browser.close()
                    browser = None
                self.headless_state = "COMPLETED_DNS_ROUTE_ONLY"
                self.note("BROWSER_SCOPE", "Browser enrichment is limited to declared DNS hosts; external resources and non-read requests are blocked")
            except Exception as exc:
                self.headless_state = "ERROR"
                self.note("HEADLESS_ERROR", clean(exc))
                if browser:
                    try:
                        browser.close()
                    except Exception:
                        pass

    def run(self):
        self.discover_bindings()
        if not self.c.headless and any(re.search(r'<(?:div|main)[^>]+id=["\'](?:root|app|__next)["\']', r.get("body", ""), re.I) for r in self.records):
            self.note("HEADLESS_RECOMMENDED", "JavaScript application shell found; browser enrichment was not enabled")
        self.browser_enrichment()
        examined = set()
        for _round in range(3):
            pending = [b for b in self.bindings if (b["url"], b["connect_ip"]) not in examined]
            if not pending or not self.available():
                break
            for binding in pending:
                if not self.available():
                    break
                examined.add((binding["url"], binding["connect_ip"]))
                self.crawl(binding)
            self.expand_candidates()

    def finish(self):
        strengths = {item["strength"] for item in self.evidence}
        php = ("EXPLICIT_PHP_REPORT" if "explicit" in strengths else
               "STRONG_PHP_INDICATORS" if "strong" in strengths else
               "PHP_INDICATORS" if "indicator" in strengths else
               "WEAK_PHP_SUSPICION" if "weak" in strengths else "NO_PHP_EVIDENCE")
        versions = sorted({item["version"] for item in self.evidence if item.get("version")})
        if len(versions) > 1:
            self.note("MULTIPLE_VERSION_REPORTS", "Preserve all versions; verify mixed backends, stale responses or misleading banners")
        remaining_names = sum(n["state"] == "DISCOVERED" for n in self.candidates.values())
        if remaining_names:
            self.note("UNEXAMINED_DISCOVERED_NAMES", str(remaining_names) + " discovered names were not fully evaluated within the configured rounds/budgets")
        status_codes = sorted({r["status"] for r in self.records if r.get("status") is not None})
        tcp = any(r.get("tcp") == "OPEN" for r in self.records)
        availability = "HTTP_RESPONDING" if status_codes else "TCP_ONLY" if tcp else "NO_SUCCESSFUL_CONNECTION"
        limitations = [n for n in self.notes if n["kind"] not in ("PTR_LOOKUP",)]
        if not self.records:
            self.note("NO_HTTP_OBSERVATIONS", "No request result was obtained; inspect DNS/provider/budget errors")
            limitations = list(self.notes)
        result = {
            "target": self.target.original, "target_host": self.target.host, "target_id": self.id,
            "time": now(), "availability": availability, "http_statuses": status_codes,
            "php": php, "versions": [{"version": v, "assessment": version_assessment(v)} for v in versions],
            "action": "PHP_REVIEW_REQUIRED" if strengths else "IDENTIFICATION_REVIEW_REQUIRED",
            "cve_verdict": "NOT_EXPLOIT_TESTED_VENDOR_PATCH_STATUS_UNVERIFIED",
            "scan_state": self.state, "coverage": "LIMITED" if limitations or self.state != "COMPLETED_WITHIN_CONFIGURED_LIMITS" else "COMPLETED_CONFIGURED_CHECKS",
            "requests": self.request_count, "pages": self.pages,
            "elapsed_seconds": round(time.monotonic() - self.started, 2),
            "headless": self.headless_state, "providers": self.providers, "dns": self.dns,
            "bindings": self.bindings, "candidate_names": list(self.candidates.values()),
            "evidence": self.evidence, "php_paths": self.paths, "forms": self.forms,
            "notes": self.notes,
            "observations": [{k: v for k, v in r.items() if k != "body"} for r in self.records],
        }
        (self.dir / "target.json").write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
        return result


def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text

def write_csv(path, columns, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([csv_safe(value) for value in row])

def report_html(results, metadata):
    esc = lambda value: html.escape(str(value), quote=True)
    counts = {"targets": len(results),
              "http": sum(x["availability"] == "HTTP_RESPONDING" for x in results),
              "explicit": sum(x["php"] == "EXPLICIT_PHP_REPORT" for x in results),
              "suspected": sum(x["php"] not in ("NO_PHP_EVIDENCE", "EXPLICIT_PHP_REPORT") for x in results),
              "limited": sum(x["coverage"] == "LIMITED" for x in results)}
    rows, details = [], []
    for item in results:
        versions = ", ".join(v["version"] for v in item["versions"]) or "Not disclosed"
        signal = item["php"] != "NO_PHP_EVIDENCE"
        badge = "explicit" if item["php"] == "EXPLICIT_PHP_REPORT" else "suspect" if signal else "unknown"
        rows.append(
            '<tr data-signal="{}" data-limited="{}"><td><a href="#{}">{}</a></td>'
            '<td>{}</td><td><span class="badge {}">{}</span></td><td>{}</td>'
            '<td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                "yes" if signal else "no", "yes" if item["coverage"] == "LIMITED" else "no",
                esc(item["target_id"]), esc(item["target"]), esc(item["availability"]),
                badge, esc(item["php"]), esc(versions), esc(item["http_statuses"]),
                esc(item["requests"]), esc(item["coverage"])))
        evidence_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(e["strength"]), esc(e["kind"]), esc(e["url"]), esc(e["connect_ip"]), esc(e["detail"]))
            for e in item["evidence"])
        path_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(p["url"]), esc(p["connect_ip"]), esc(p["state"]), esc(p["source"]),
                esc(p.get("final_url", "")), esc(p.get("final_status", "")))
            for p in item["php_paths"])
        observation_rows = "".join(
            '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">JSON</a></td></tr>'.format(
                esc(r["url"]), esc(r.get("connect_ip", "")), esc(r.get("tcp", "")),
                esc(r.get("status") or "-"), esc(r.get("access_state", "")),
                esc(r.get("error", "")), esc(r.get("evidence_file", "")))
            for r in item["observations"])
        notes = "".join("<li><b>{}</b>: {}</li>".format(esc(n["kind"]), esc(n["detail"])) for n in item["notes"])
        candidates = "".join("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            esc(n["name"]), esc(", ".join(n["sources"])), esc(", ".join(n["addresses"])), esc(n["state"]))
            for n in item["candidate_names"])
        version_rows = "".join("<li>{}: {}</li>".format(esc(v["version"]), esc(v["assessment"])) for v in item["versions"])
        details.append(
            '<section id="{}"><h2>{}</h2><p>{} | {} | {} requests | {} seconds</p>'
            '<p><b>Action:</b> {} <b>CVE assessment:</b> {}</p>'
            '<details open><summary>PHP evidence ({})</summary><div class="scroll"><table>'
            '<thead><tr><th>Strength</th><th>Method</th><th>URL</th><th>Connection</th><th>Evidence</th></tr></thead>'
            '<tbody>{}</tbody></table></div></details>'
            '<details><summary>PHP path validation ({})</summary><div class="scroll"><table>'
            '<thead><tr><th>URL</th><th>Connection</th><th>Validation</th><th>Discovery source</th><th>Final URL</th><th>Final HTTP</th></tr></thead><tbody>{}</tbody></table></div></details>'
            '<details><summary>Observed versions</summary><ul>{}</ul></details>'
            '<details><summary>DNS candidate names ({})</summary><div class="scroll"><table>'
            '<thead><tr><th>Name</th><th>Sources</th><th>Current addresses</th><th>State</th></tr></thead><tbody>{}</tbody></table></div></details>'
            '<details><summary>Request observations ({})</summary><div class="scroll"><table>'
            '<thead><tr><th>URL</th><th>Connection</th><th>TCP</th><th>HTTP</th><th>Access state</th><th>Error</th><th>Evidence</th></tr></thead>'
            '<tbody>{}</tbody></table></div></details>'
            '<details open><summary>Coverage and errors ({})</summary><ul>{}</ul></details>'
            '<p><a href="evidence/{}/target.json">Full target record</a></p></section>'.format(
                esc(item["target_id"]), esc(item["target"]), esc(item["availability"]),
                esc(item["php"]), item["requests"], item["elapsed_seconds"],
                esc(item["action"]), esc(item["cve_verdict"]), len(item["evidence"]), evidence_rows,
                len(item["php_paths"]), path_rows, version_rows or "<li>No version disclosed</li>",
                len(item["candidate_names"]), candidates, len(item["observations"]), observation_rows,
                len(item["notes"]), notes or "<li>No additional coverage limits reported</li>", esc(item["target_id"])))
    cards = "".join('<div class="card"><strong>{}</strong><span>{}</span></div>'.format(value, key.title())
                    for key, value in counts.items())
    references = "".join('<li><a href="{}">{}</a></li>'.format(esc(url), esc(key)) for key, url in REFERENCES.items())
    template = """<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP Surface Audit</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#dbe6f3;font:15px/1.55 system-ui,Arial,sans-serif}
main{max-width:1550px;margin:auto;padding:32px}h1{font-size:34px;margin:0}h2{font-size:23px}
p{color:#a7b8cf}a{color:#80c9ff}header{padding-bottom:18px}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.card{background:#131f33;border:1px solid #293b55;border-radius:12px;padding:15px 24px;min-width:130px}.card strong{display:block;font-size:30px;color:#fff}.card span{color:#a7b8cf}
section{background:#101b2c;border:1px solid #293b55;border-radius:12px;padding:20px;margin:22px 0;scroll-margin-top:14px}
.scroll{overflow:auto;max-height:600px;border:1px solid #293b55;border-radius:8px;margin:10px 0}
table{border-collapse:separate;border-spacing:0;width:100%;min-width:900px}th,td{padding:11px 13px;text-align:left;vertical-align:top;border-bottom:1px solid #26364e;overflow-wrap:anywhere}
thead th{position:sticky;top:0;background:#1b2c45;z-index:1}tbody tr:nth-child(even){background:#142137}
.badge{display:inline-block;font-size:12px;padding:4px 7px;border-radius:5px;white-space:nowrap}.explicit{background:#164b43;color:#a8f5d3}.suspect{background:#4a3b19;color:#ffe2a0}.unknown{background:#2b3547;color:#c4d1e4}
.controls{display:flex;gap:18px;flex-wrap:wrap;align-items:center;padding:14px;background:#142137;border-radius:8px}
input[type=search]{background:#0b1220;color:#fff;border:1px solid #46617f;padding:10px;border-radius:6px;min-width:250px}
summary{cursor:pointer;font-weight:600;padding:10px 0}li{margin:6px 0}code{color:#b3dcff}footer{margin:30px 0;color:#9bb0cc}
</style></head><body><main>
<header><h1>PHP Surface Audit</h1><p>Evidence-driven discovery of PHP indicators, exposed version reports, DNS identities and coverage gaps.</p>
<p>Run: __RUN__ | Scanner: __VERSION__ | DNS backend: __DNS__</p></header>
<div class="cards">__CARDS__</div>
<div class="controls"><input id="search" type="search" placeholder="Filter targets, versions, or status">
<label><input id="signals" type="checkbox"> PHP signals only</label>
<label><input id="limited" type="checkbox"> Limited coverage only</label></div>
<div class="scroll"><table id="targets"><thead><tr><th>Target</th><th>Availability</th><th>PHP classification</th><th>Versions reported</th><th>HTTP</th><th>Requests</th><th>Coverage</th></tr></thead><tbody>__ROWS__</tbody></table></div>
<p>Every PHP signal requires organizational review. A compatible web server alone is a weak suspicion. Missing evidence is not evidence of absence. Version comparisons do not verify vendor backports or exploitability.</p>
__DETAILS__
<details><summary>Run configuration</summary><pre>__CONFIG__</pre></details>
<footer><h2>Reference material</h2><ul>__REFS__</ul></footer>
</main><script>
function filterRows(){var q=document.getElementById('search').value.toLowerCase();
document.querySelectorAll('#targets tbody tr').forEach(function(row){
row.hidden=!(row.textContent.toLowerCase().includes(q)&&
(!document.getElementById('signals').checked||row.dataset.signal==='yes')&&
(!document.getElementById('limited').checked||row.dataset.limited==='yes'));});}
document.querySelectorAll('.controls input').forEach(function(el){el.addEventListener('input',filterRows);});
</script></body></html>"""
    for key, value in {
        "__RUN__": esc(metadata["started"]), "__VERSION__": esc(VERSION),
        "__DNS__": esc(metadata["dns_backend"]), "__CARDS__": cards, "__ROWS__": "".join(rows),
        "__DETAILS__": "".join(details), "__CONFIG__": esc(json.dumps(metadata["config"], indent=2)),
        "__REFS__": references,
    }.items():
        template = template.replace(key, value)
    return template

def save_reports(run_dir, results, metadata):
    run_dir = Path(run_dir)
    (run_dir / "results.json").write_text(json.dumps(
        {"metadata": metadata, "targets": results}, indent=2, ensure_ascii=True), encoding="utf-8")
    (run_dir / "report.html").write_text(report_html(results, metadata), encoding="utf-8")
    write_csv(run_dir / "summary.csv",
        ["target", "availability", "php", "versions", "http_statuses", "action", "coverage", "scan_state", "requests", "elapsed_seconds"],
        [[r["target"], r["availability"], r["php"], "; ".join(v["version"] for v in r["versions"]),
          "; ".join(map(str, r["http_statuses"])), r["action"], r["coverage"], r["scan_state"],
          r["requests"], r["elapsed_seconds"]] for r in results])
    write_csv(run_dir / "php_evidence.csv",
        ["target", "strength", "kind", "url", "connect_ip", "version", "detail", "request_id"],
        [[r["target"], e["strength"], e["kind"], e["url"], e["connect_ip"], e.get("version", ""), e["detail"], e["request_id"]]
         for r in results for e in r["evidence"]])
    write_csv(run_dir / "dns_candidates.csv",
        ["target", "name", "sources", "addresses", "state"],
        [[r["target"], n["name"], "; ".join(n["sources"]), "; ".join(n["addresses"]), n["state"]]
         for r in results for n in r["candidate_names"]])
    write_csv(run_dir / "php_paths.csv",
        ["target", "url", "connect_ip", "discovery_source", "status", "validation", "request_id",
         "final_url", "final_status", "redirect_resolution"],
        [[r["target"], p["url"], p["connect_ip"], p["source"], p["status"], p["state"], p["request_id"],
          p.get("final_url", ""), p.get("final_status", ""), p.get("redirect_resolution", "")]
         for r in results for p in r["php_paths"]])

REDIRECT_CODES = (301, 302, 303, 307, 308)

def saved_redirect_chain(record, observations):
    """Trace saved observations only; missing/ambiguous hops stay unresolved."""
    current, trace, seen = record, [], set()
    for _ in range(6):
        trace.append({"request_id": current["id"], "url": current["url"],
                      "connect_ip": current.get("connect_ip", ""), "status": current.get("status"),
                      "location": header(current, "location")})
        if current.get("status") not in REDIRECT_CODES:
            return current, trace, "FINAL_SAVED_RESPONSE"
        key = (current["url"], current.get("connect_ip"))
        if key in seen:
            return None, trace, "SAVED_REDIRECT_LOOP"
        seen.add(key)
        location = header(current, "location")
        if not location:
            return None, trace, "SAVED_REDIRECT_WITHOUT_LOCATION"
        try:
            next_url = normalize_url(urljoin(current["url"], location))
        except (ValueError, UnicodeError):
            return None, trace, "SAVED_INVALID_REDIRECT_LOCATION"
        matches = [r for r in observations if r.get("url") == next_url]
        pinned = [r for r in matches if r.get("connect_ip") == current.get("connect_ip")]
        matches = pinned or matches
        if len(matches) != 1:
            return None, trace, "SAVED_HOP_MISSING_OR_AMBIGUOUS"
        current = matches[0]
    return None, trace, "SAVED_REDIRECT_LIMIT"

def repair_run(source):
    """Remove historical 3xx route promotions without making network requests."""
    source = Path(source).resolve()
    data = json.loads((source / "results.json").read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise ValueError("Expected a scanner results.json containing metadata and targets")
    results = data["targets"]
    removed_total = 0
    for result in results:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", result["target_id"]):
            raise ValueError("Invalid target ID in saved report")
        observations = result.get("observations", [])
        by_id = {r["id"]: r for r in observations}
        paths_by_id = {r["request_id"]: r for r in result.get("php_paths", [])}
        def was_redirect(evidence):
            record = by_id.get(evidence.get("request_id"), {})
            status = record.get("status", paths_by_id.get(evidence.get("request_id"), {}).get("status"))
            return evidence.get("kind") == "DISTINCT_PHP_ROUTE" and status in REDIRECT_CODES
        removed = [e for e in result["evidence"] if was_redirect(e)]
        result["evidence"] = [e for e in result["evidence"] if not was_redirect(e)]
        removed_total += len(removed)
        for item in result.get("php_paths", []):
            record = by_id.get(item.get("request_id"))
            if not record and item.get("status") in REDIRECT_CODES:
                record = {"id": item["request_id"], "url": item["url"], "connect_ip": item["connect_ip"],
                          "status": item["status"], "headers": []}
            if not record or record.get("status") not in REDIRECT_CODES:
                continue
            final, trace, resolution = saved_redirect_chain(record, observations)
            item.update(redirect_chain=trace, final_url=final["url"] if final else "",
                        final_status=final.get("status") if final else None,
                        redirect_resolution=resolution)
            if final is None or final.get("status") is None:
                state = "REDIRECT_UNRESOLVED_EXISTENCE_UNPROVEN"
            elif final["status"] in (404, 410):
                state = "REDIRECT_TO_NOT_FOUND_OR_MASKED"
            elif final.get("access_state") or final["status"] in (401, 403, 429):
                state = "REDIRECT_TO_ACCESS_RESTRICTED_EXISTENCE_UNPROVEN"
            else:
                state = "REDIRECT_TARGET_RESPONDED_ORIGINAL_PATH_UNPROVEN"
            item["state"] = state
        strengths = {e["strength"] for e in result["evidence"]}
        result["php"] = ("EXPLICIT_PHP_REPORT" if "explicit" in strengths else
                         "STRONG_PHP_INDICATORS" if "strong" in strengths else
                         "PHP_INDICATORS" if "indicator" in strengths else
                         "WEAK_PHP_SUSPICION" if "weak" in strengths else "NO_PHP_EVIDENCE")
        result["action"] = "PHP_REVIEW_REQUIRED" if strengths else "IDENTIFICATION_REVIEW_REQUIRED"
        result["versions"] = [{"version": v, "assessment": version_assessment(v)}
                              for v in sorted({e["version"] for e in result["evidence"] if e.get("version")})]
        result.setdefault("notes", []).append({
            "kind": "OFFLINE_REDIRECT_REPAIR",
            "detail": "{} erroneous DISTINCT_PHP_ROUTE redirect signals removed. No network requests. "
                      "Other historical findings/controls were not revalidated; rerun 1.0.1 for current identification.".format(len(removed))})
        result["coverage"] = "LIMITED"
        # The repaired directory is a child of the source; retain links to original evidence.
        for record in observations:
            evidence_file = record.get("evidence_file", "").replace("\\", "/")
            if evidence_file.startswith("evidence/") and ".." not in evidence_file.split("/"):
                record["evidence_file"] = "../" + evidence_file
            else:
                record["evidence_file"] = ""
    output = source / ("repaired_v1_0_1_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:6])
    output.mkdir()
    metadata = dict(data.get("metadata", {}))
    metadata.setdefault("started", now())
    metadata.setdefault("dns_backend", "not-used-offline")
    metadata.setdefault("config", {})
    metadata["scanner"] = VERSION
    metadata["repair"] = {"time": now(), "source_run": str(source), "removed_redirect_signals": removed_total,
                          "network_requests": 0, "scope": "Historical 3xx DISTINCT_PHP_ROUTE promotions only"}
    for result in results:
        directory = output / "evidence" / result["target_id"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "target.json").write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    (output / "run.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
    (output / "results.jsonl").write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in results), encoding="utf-8")
    save_reports(output, results, metadata)
    print("Offline repair: {} erroneous redirect signals removed; 0 network requests.".format(removed_total))
    print("Original run preserved. Open " + str(output / "report.html"))
    return output

def build_parser():
    parser = argparse.ArgumentParser(
        description="Adaptive PHP discovery with DNS/IP binding, crawling, evidence and honest coverage reporting.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=VERSION)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--targets", help="UTF-8 input file: one IP, DNS name or HTTP(S) URL per line")
    mode.add_argument("--repair-run", help="Offline repair of historical 3xx route false positives in an existing run; originals remain unchanged")
    parser.add_argument("--mode", choices=["adaptive"], default="adaptive", help="Evidence-driven adaptive discovery")
    parser.add_argument("--output", default="results", help="Parent output directory; each execution creates a unique run directory")
    parser.add_argument("--scope-domain", action="append", default=[], help="Additional organization-owned domain suffix allowed for discovered hosts; repeatable")
    parser.add_argument("--scope-file", help="Optional domain scope file, one suffix per line")
    parser.add_argument("--strict-scope", action="store_true", help="Only admit declared DNS names/domain suffixes; disable discovery admission based only on a shared input IP")
    parser.add_argument("--ports", default="80,443", help="Ports for bare inputs; explicit URLs keep their own port")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent input targets")
    parser.add_argument("--report-every", type=int, default=25, help="Refresh aggregate reports after this many completed targets; JSONL is always immediate")
    parser.add_argument("--rps", type=float, default=2, help="Maximum request starts per second per destination IP")
    parser.add_argument("--timeout", type=float, default=4, help="Per-operation timeout; requests also have a 3x timeout total deadline")
    parser.add_argument("--target-seconds", type=float, default=90, help="Time budget per target (system DNS can exceed this without dnspython)")
    parser.add_argument("--max-requests", type=int, default=70, help="Network request budget per target, including controls and browser requests")
    parser.add_argument("--max-pages", type=int, default=35, help="Maximum crawl pages per target across all bindings")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth; not a wordlist depth")
    parser.add_argument("--max-body", type=int, default=524288, help="Maximum response bytes retained/decompressed")
    parser.add_argument("--max-hosts", type=int, default=8, help="Maximum admitted discovered names per input target")
    parser.add_argument("--max-ips", type=int, default=4, help="Maximum addresses probed per DNS identity")
    parser.add_argument("--verify-tls", action="store_true", help="Require valid TLS certificates; default is diagnostic collection without verification")
    parser.add_argument("--resolver", action="append", default=[], help="DNS server IP; requires optional dnspython; repeatable")
    parser.add_argument("--headless", action="store_true", help="Add optional Playwright/Chromium DOM and GET network discovery for declared DNS hosts")
    parser.add_argument("--ct", action="store_true", help="Query public Certificate Transparency for DNS input targets")
    parser.add_argument("--archives", action="store_true", help="Query Wayback CDX for historical paths on DNS input targets")
    parser.add_argument("--shodan", action="store_true", help="Query Shodan host data for public IP inputs using SHODAN_API_KEY from the environment")
    parser.add_argument("--verbose", action="store_true", help="Print each request result as well as target summaries")
    return parser

def main(argv=None):
    configure_console()
    args = build_parser().parse_args(argv)
    if args.repair_run:
        try:
            repair_run(args.repair_run)
            return 0
        except (ValueError, KeyError, TypeError, OSError) as exc:
            print("ERROR: Offline repair failed: " + clean(exc), file=sys.stderr)
            return 2
    try:
        ports = tuple(dict.fromkeys(int(value.strip()) for value in args.ports.split(",")))
        if not ports or any(not 1 <= x <= 65535 for x in ports):
            raise ValueError("Ports must be between 1 and 65535")
        if not (1 <= args.workers <= 32 and 0 < args.rps <= 50 and .1 <= args.timeout <= 60):
            raise ValueError("Use workers 1-32, rps >0 to 50, and timeout 0.1-60")
        if not 1 <= args.report_every <= 100000:
            raise ValueError("Use --report-every between 1 and 100000")
        if not (1 <= args.target_seconds <= 3600 and 1 <= args.max_requests <= 10000
                and 1 <= args.max_pages <= 10000 and 0 <= args.depth <= 10
                and 1024 <= args.max_body <= 5_242_880 and 1 <= args.max_hosts <= 200
                and 1 <= args.max_ips <= 100):
            raise ValueError("Invalid crawl/budget settings; use --help")
        scope_domains = list(args.scope_domain)
        if args.scope_file:
            scope_domains += [line.strip() for line in Path(args.scope_file).read_text(encoding="utf-8-sig").splitlines()
                              if line.strip() and not line.lstrip().startswith("#")]
        scope_domains = tuple(host_key(d.lstrip("*.")) for d in scope_domains)
        config = Config(
            timeout=args.timeout, target_seconds=args.target_seconds, max_requests=args.max_requests,
            max_pages=args.max_pages, max_depth=args.depth, max_body=args.max_body,
            max_hosts=args.max_hosts, max_ips=args.max_ips, rps=args.rps, workers=args.workers,
            report_every=args.report_every,
            verify_tls=args.verify_tls, strict_scope=args.strict_scope,
            headless=args.headless, archives=args.archives, ct=args.ct,
            shodan=args.shodan, ports=ports, scope_domains=scope_domains,
            resolver=tuple(args.resolver), output=args.output, verbose=args.verbose)
        lines = Path(args.targets).read_text(encoding="utf-8-sig").splitlines()
        targets, invalid, seen = [], [], set()
        for number, line in enumerate(lines, 1):
            try:
                target = parse_target(line, ports, number)
                if target:
                    key = tuple(target.urls)
                    if key not in seen:
                        seen.add(key)
                        targets.append(target)
            except (ValueError, UnicodeError) as exc:
                invalid.append({"line": number, "input": clean(line), "error": clean(exc)})
        if not targets and not invalid:
            raise ValueError("No targets found in the input file")
        resolver = Resolver(config.timeout, config.resolver)
    except (ValueError, OSError) as exc:
        print("ERROR: " + clean(exc), file=sys.stderr)
        return 2
    run_dir = Path(args.output) / ("run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:6])
    run_dir.mkdir(parents=True, exist_ok=False)
    metadata = {"scanner": VERSION, "started": now(), "config": dataclasses.asdict(config),
                "dns_backend": resolver.backend, "invalid_inputs": invalid,
                "classification_policy": "All PHP indicators require review regardless of reported version",
                "cve_rules_reference_date": "2026-10-25", "references": REFERENCES}
    print("PHP Surface Audit {} | {} targets | DNS={} | TLS verification={}".format(
        VERSION, len(targets), resolver.backend, "ON" if config.verify_tls else "OFF (diagnostic)"), flush=True)
    print("Output: " + str(run_dir.resolve()), flush=True)
    if resolver.backend == "system":
        print("NOTE: Optional dnspython is missing; CNAME enumeration is unavailable and DNS timeouts are OS-controlled.", flush=True)
    for item in invalid:
        print("[INVALID line {}] {}: {}".format(item["line"], item["input"], item["error"]), flush=True)
    (run_dir / "run.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
    auditor = Auditor(config, resolver, Scope(targets, config), RateLimiter(config.rps), run_dir)
    results = []
    pool = futures.ThreadPoolExecutor(max_workers=config.workers)
    pending = {}
    scheduled_count = 0
    def refill():
        nonlocal scheduled_count
        while len(pending) < config.workers * 2 and scheduled_count < len(targets):
            target = targets[scheduled_count]
            pending[pool.submit(auditor.audit, target)] = target
            scheduled_count += 1
    interrupted = False
    try:
        with (run_dir / "results.jsonl").open("a", encoding="utf-8") as stream:
            refill()
            while pending:
                completed, _ = futures.wait(pending, return_when=futures.FIRST_COMPLETED)
                for future in completed:
                    result = future.result()
                    results.append(result)
                    stream.write(json.dumps(result, ensure_ascii=True) + "\n")
                    stream.flush()
                    del pending[future]
                    with PRINT_LOCK:
                        print("[{}/{}] {} | {} | {} | versions={} | requests={} | {}".format(
                            len(results), len(targets), clean(result["target"]), result["availability"],
                            result["php"], ",".join(v["version"] for v in result["versions"]) or "not disclosed",
                            result["requests"], result["coverage"]), flush=True)
                    if len(results) == 1 or len(results) % config.report_every == 0:
                        save_reports(run_dir, results, metadata)
                refill()
    except KeyboardInterrupt:
        interrupted = True
        STOP.set()
        print("\nStopping: in-flight requests will finish within their timeout.", flush=True)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        # Retain completed and interrupted worker results, including those not yielded above.
        known_ids = {r["target_id"] for r in results}
        with (run_dir / "results.jsonl").open("a", encoding="utf-8") as stream:
            for future, target in pending.items():
                if future.done() and not future.cancelled():
                    try:
                        result = future.result()
                    except Exception as exc:
                        metadata.setdefault("worker_errors", []).append({"target": target.original, "error": clean(exc)})
                        continue
                    if result["target_id"] not in known_ids:
                        results.append(result)
                        known_ids.add(result["target_id"])
                        stream.write(json.dumps(result, ensure_ascii=True) + "\n")
        metadata["finished"] = now()
        metadata["interrupted"] = interrupted
        metadata["not_started_targets"] = ([t.original for f, t in pending.items() if f.cancelled()]
                                           + [t.original for t in targets[scheduled_count:]])
        save_reports(run_dir, results, metadata)
    print("Finished: {} target records. Open {}".format(len(results), run_dir / "report.html"), flush=True)
    return 130 if interrupted else 0

if __name__ == "__main__":
    raise SystemExit(main())
