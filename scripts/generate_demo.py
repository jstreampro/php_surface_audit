"""Generate public demo output using loopback fixtures only."""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import php_surface_audit as audit
from test_php_surface_audit import FakeResolver, server


def main():
    audit.configure_console()
    destination = ROOT / "demo"
    destination.mkdir(exist_ok=True)
    config = audit.Config(timeout=1, target_seconds=15, max_ips=1, rps=50, strict_scope=True)
    results = []
    for mode in ("php", "discovery", "soft404", "redirect-404"):
        with server(mode) as (service, _):
            target = audit.parse_target("http://127.0.0.1:{}/".format(service.server_port))
            engine = audit.Auditor(config, FakeResolver(), audit.Scope([target], config),
                                   audit.RateLimiter(config.rps), destination)
            result = engine.audit(target)
            result["notes"].insert(0, {"kind": "LOCAL_DEMO_FIXTURE", "detail": mode + "; synthetic local server, no organizational assets contacted"})
            result["coverage"] = "LIMITED"
            target_file = destination / "evidence" / result["target_id"] / "target.json"
            target_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
            results.append(result)
    metadata = {"scanner": audit.VERSION, "started": audit.now(), "dns_backend": "LOCAL_TEST_FIXTURES",
                "config": {"demo": "Synthetic loopback fixtures only; no organizational assets contacted."}}
    audit.save_reports(destination, results, metadata)
    # Remove obsolete generated observations after successful regeneration.
    current_ids = {result["target_id"] for result in results}
    for directory in (destination / "evidence").iterdir():
        if directory.is_dir() and not directory.is_symlink() and re.fullmatch(r"[0-9a-f]{12}", directory.name) and directory.name not in current_ids:
            for observation in directory.glob("*.json"):
                observation.unlink()
            if not any(directory.iterdir()):
                try:
                    directory.rmdir()
                except OSError:
                    # OneDrive may retain an empty, read-only placeholder directory.
                    pass
    print("Demo: demo/report.html")


if __name__ == "__main__":
    main()
