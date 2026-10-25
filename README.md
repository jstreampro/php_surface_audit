# PHP Surface Audit

Find externally visible PHP indicators across a list of IP addresses, DNS names and URLs. The scanner records HTTP evidence, reported versions, named virtual hosts and coverage gaps, then produces HTML, CSV and JSON reports for review.

Use it to build an inventory and prioritize PHP2Shell remediation. It does **not** confirm exploitability or verify that a vendor patch is installed. Scans use bounded HTTP GET requests; no exploit payloads, uploads or form submissions are sent. Run it only against assets you are authorized to assess.

## Quick start

Requires Python 3.9 or newer. The core scanner uses the Python standard library.

```sh
git clone https://github.com/jstreampro/php_surface_audit.git
cd php_surface_audit
cp targets.example.txt targets.txt
# Replace the example entries with your approved targets.
python3 php_surface_audit.py --targets targets.txt --verbose
```

On Windows PowerShell, use `Copy-Item targets.example.txt targets.txt` and `py` instead of `python3`.

Open `report.html` in the new directory printed by the scanner. [demo/report.html](demo/report.html) contains results from local test servers and can be downloaded and opened without running a scan.

For bounded DNS queries, CNAME enumeration and custom resolvers, install the optional DNS dependency:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python php_surface_audit.py --targets targets.txt --verbose
```

On Windows, the virtual environment interpreter is `.venv\Scripts\python.exe`. Without `dnspython`, the system resolver works, but its DNS timeouts are controlled by the OS and may exceed the target time budget.

## Targets and scope

The input file accepts one target per line. Blank lines and lines starting with `#` are ignored.

```text
192.0.2.10
portal.example.org
https://apps.example.org/customer/
http://portal.example.org:8080/
2001:db8::10
```

Bare hosts are checked on ports 80 and 443. Full URLs keep their scheme, port and starting path. Use `--ports 80,443,8080,8443` to change ports for bare inputs; this does not override full URLs. CIDR ranges and wildcard target expansion are not supported: supply an explicit asset list. Duplicate normalized target URLs are removed. URL credentials are rejected.

To include discovered names under approved organization domains:

```sh
python3 php_surface_audit.py --targets targets.txt --scope-domain example.org --strict-scope
```

Repeat `--scope-domain` for multiple organizations, or use `--scope-file scope.txt` with one domain suffix per line. Input hostnames are declared exactly as supplied. A suffix also permits its subdomains; do not use a public suffix such as `com`.

By default, a discovered DNS name can also be admitted when its current DNS addresses overlap an explicitly supplied input IP. This helps recover named virtual hosts from IP inventories. **Use `--strict-scope` on shared hosting or CDN addresses** to require a declared hostname or domain suffix instead. Sharing an IP does not establish organization ownership.

The scanner uses the site name for HTTP Host and TLS SNI while connecting to the recorded IP. PTR, certificate names, redirects and page links provide candidate identities. Wildcard certificates are recorded without guessing hostnames. CNAME relationships are recorded without automatically treating their targets as application names. IP-only scanning cannot enumerate every virtual host.

## Detection methods

- PHP declarations and versions in response headers, including error responses.
- PHP session and application cookie names; values are excluded from evidence summaries.
- Application headers, HTML generator metadata and page signatures. Coverage includes WordPress, Drupal, Joomla, Magento, MediaWiki, TYPO3, PrestaShop, Moodle, DokuWiki, phpBB, Roundcube and selected PHP frameworks.
- Structured `phpinfo()` output, PHP-style diagnostics and PHP source returned as text.
- PHP-like paths in HTML, form actions, inline/external JavaScript, robots.txt, sitemaps, HTTP Link/Location/Content-Location/Refresh headers and referenced source maps.
- A single `index.php` convention probe for each seed directory.
- Random same-directory extensionless and `.php` control requests to distinguish candidate routes from generic responses and soft 404s.

Discovery follows observed links within the configured scope, depth and request budget. It does not enumerate a directory wordlist. Form actions are recorded without being submitted. Discovered query values are stripped, and recognized action URLs are skipped. Explicit input URLs retain their query, so review them before scanning. GET endpoints can still have application side effects; action filtering is a heuristic.

### Interpreting results

| Classification | Meaning |
| --- | --- |
| `EXPLICIT_PHP_REPORT` | A response reports PHP, a PHP version, an environment report or a PHP-style diagnostic. Reports may be stale or misleading. |
| `STRONG_PHP_INDICATORS` | A distinct PHP-like route, multiple application signatures or a PHP source artifact. Runtime execution is unproven. |
| `PHP_INDICATORS` | An application header, generator, cookie, individual page marker or unverified same-host PHP-like URL. |
| `WEAK_PHP_SUSPICION` | A reported PHP-capable server such as Apache or LiteSpeed, without stronger evidence. |
| `NO_PHP_EVIDENCE` | Completed checks found no PHP evidence. This does not establish absence. |

A WordPress or MediaWiki version is never treated as a PHP version. Static copies, reverse proxies and cached headers can preserve application markers after an architecture change. A distinct `.php` response can come from a rewrite rule. A 401/403 or redirect alone does not prove a PHP file exists. Redirect chains and control responses are resolved before route comparisons; unresolved checks remain unproven.

Review `coverage`, `scan_state` and the target notes alongside the classification. WAF challenges, failed DNS lookups, restricted responses and exhausted budgets leave evidence gaps. Contradictory PHP version reports are retained.

## PHP2Shell version review

PHP2Shell refers to CVE-2026-109618 and CVE-2026-109619. The configured upstream fixed releases, checked against the [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) on **25 October 2026**, are:

| Branch | Fixed upstream release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Reported versions are compared within their own branch. Older branches, incomplete versions and prerelease builds require separate review. Distribution and appliance vendors may backport fixes without changing the upstream version number. The scanner cannot inspect installed packages, PHP worker state or vendor build metadata.

Treat detected PHP as an asset requiring verification. Confirm the running web PHP version and the package/vendor advisory, apply the appropriate update and restart affected workers. A recent banner does not produce a `SAFE` verdict, and missing external evidence does not produce a `NOT VULNERABLE` verdict. See [NCSC-NL's operational guidance](https://github.com/NCSC-NL/php2shell) for embedded products and vendor advisories.

## Larger inventories

Start with a small sample to establish request volume and coverage, then increase the target count:

```sh
python3 php_surface_audit.py --targets targets.txt --scope-file scope.txt --strict-scope --workers 8 --rps 2 --target-seconds 120 --max-requests 100 --max-pages 50 --report-every 50
```

`--workers` controls concurrent input targets. `--rps` limits request starts per destination IP across workers in the same process; there is no aggregate global rate limit. Separate scanner processes do not share this limit. The pending task queue is bounded to twice the worker count.

Each completed target is immediately flushed to `results.jsonl` and saved under `evidence/`. Aggregate HTML/CSV/JSON reports refresh after the first target, every `--report-every` targets (default 25), and at completion or Ctrl+C. Set `--report-every 1` for an update after every target. For very large inventories, split the input into batches: aggregate results remain in memory and HTML generation still grows with the number of observations.

| Control | Default |
| --- | --- |
| `--workers` | 4 |
| `--rps` | 2 requests/second/IP |
| `--timeout` | 4 seconds per socket operation |
| `--target-seconds` | 90 seconds per target |
| `--max-requests` | 70 requests per target, including controls and browser requests |
| `--max-pages` / `--depth` | 35 pages / depth 2 |
| `--max-body` | 524288 bytes per response |
| `--max-hosts` / `--max-ips` | 8 admitted discovered names / 4 addresses per identity |

HTTP reads also have a total deadline of three times `--timeout`, capped by the remaining target budget. Browser startup/shutdown and provider DNS may exceed that budget. TLS verification is disabled by default for diagnostic collection; add `--verify-tls` to require valid certificates. The normal target transport ignores HTTP proxy environment variables.

Use `--help` for all options. Exit status is 0 for a completed run, 2 for input/configuration errors, and 130 for interruption. Target-specific connection failures and invalid input lines are recorded in reports and do not by themselves make the process fail. Check result records when automating scans.

## Optional enrichment

### Browser discovery

```sh
.venv/bin/python -m pip install -r requirements-headless.txt
.venv/bin/python -m playwright install chromium
.venv/bin/python php_surface_audit.py --targets targets.txt --scope-domain example.org --strict-scope --headless
```

Playwright adds rendered DOM and browser GET/HEAD observations for the first eligible declared DNS binding per target. Non-read requests, recognized action URLs, third-party hosts, service workers, images, media and fonts are blocked. Some applications will not render fully. Missing dependencies are reported, and the core scan continues.

Browser observations use `BROWSER_DNS_ROUTE_UNVERIFIED`: browser routing is not pinned to a particular backend IP. Follow-up probes use the normal IP-aware transport. The browser does not solve WAF challenges.

### Public data providers

```sh
python3 php_surface_audit.py --targets targets.txt --ct --archives
```

| Option | Source and purpose |
| --- | --- |
| `--ct` | crt.sh Certificate Transparency names for DNS inputs. |
| `--archives` | Up to 100 historical URL rows per DNS input from Wayback CDX. |
| `--shodan` | Historical hostnames for public IP inputs; reads `SHODAN_API_KEY` from the environment. |

These providers are disabled by default. Enabling them sends the relevant target identity to an external provider. Historical data is not live PHP evidence; names and paths must pass current scope and action checks before probing. Provider calls are tracked separately from target HTTP requests and use urllib's proxy configuration. API availability and quotas vary. API keys are excluded from saved provider URLs and error text.

## Output

Each run creates `results/run_TIMESTAMP_ID/`:

| File | Contents |
| --- | --- |
| `report.html` | Searchable local report with PHP/coverage filters and evidence links. |
| `summary.csv` | One row per input target: availability, PHP classification, versions and coverage. |
| `php_evidence.csv` | Individual signals and sources. |
| `php_paths.csv` | Candidate paths, controls, redirect resolution and terminal status. |
| `dns_candidates.csv` | Discovered identities and admission decisions. |
| `results.json` / `results.jsonl` | Aggregate data / incrementally flushed target records. |
| `run.json` | Initial configuration and rejected input lines; final run metadata is in `results.json`. |
| `evidence/TARGET_ID/` | Saved HTTP observations and the complete target record. |

Response bodies are bounded; truncation and decoding failures are recorded. HTML escapes server-controlled text, and CSV formula prefixes are escaped. Raw evidence **can contain session cookies, private URLs, diagnostics and sensitive page content**. Store scan output privately and review it before sharing. The repository ignores normal results directories and local target/scope files.

Historical 1.0.0 redirect-route false positives can be repaired offline:

```sh
python3 php_surface_audit.py --repair-run results/run_TIMESTAMP_ID
```

This writes a new child directory, preserves the source and makes no network requests. Keep the repaired folder with its source for evidence links. Repair is limited to historical 3xx route promotions; a new scan is needed to apply current detection methods.

## Development

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m unittest discover -s . -p test_php_surface_audit.py -v
python3 scripts/generate_demo.py
```

Tests use loopback HTTP/TLS fixtures and mocked DNS, never organizational targets. `cryptography` is used only to generate the test TLS certificate; that fixture is skipped if it is unavailable. CI is configured for Linux and Windows. Optional live provider APIs and an actual Playwright browser are outside the local regression suite. See [VALIDATION.json](VALIDATION.json) and [CHANGELOG.md](CHANGELOG.md).
