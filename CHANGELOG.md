# Changelog

## 1.1.0 — 2026-10-25

- Detect PHP application headers and generator metadata, including applications that do not expose `.php` links.
- Recognize additional PHP ecosystem cookie names and narrow Drupal session-cookie matching to avoid generic session-name false positives.
- Discover relative PHP endpoints in inline and external JavaScript, including escaped URL slashes.
- Collect links from HTTP Location, Content-Location and Refresh headers.
- Add `--strict-scope` for inventories on shared hosting/CDN addresses.
- Bound pending target jobs to twice the worker count and add `--report-every` to reduce aggregate report rewrites on large inventories.
- Add regression coverage, a reproducible local demo, public usage documentation and Windows/Linux CI.
- Handle paths and target names that a redirected Windows console cannot encode.

## 1.0.1

- Stop promoting PHP-like redirect responses to distinct PHP route evidence.
- Resolve bounded in-scope redirects and compare terminal control responses.
- Add offline repair of historical 3xx route false positives while preserving original evidence.

## 1.0.0

- Initial adaptive PHP inventory scanner with IP/DNS bindings, crawl controls and HTML/CSV/JSON evidence reports.
