"""Write the website address into an agent's SERVER_URL before a release build.

    python agents/ci/set_server_url.py device_monitoring_prototype/device_agent.py https://example.com

Only the release workflow runs this, on its own throwaway checkout. The address must be
HTTPS so the published apps never send enrollment tokens over plain HTTP.
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

PLACEHOLDER = '"__SERVER_URL__"'


def main(path, url):
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname or parts.path not in {"", "/"} \
            or parts.query or parts.fragment or parts.username or parts.password:
        raise SystemExit(f"DEVMONITOR_SERVER_URL must be an https:// origin, got {url!r}")
    origin = f"https://{parts.netloc}"
    source_path = Path(path)
    source = source_path.read_text(encoding="utf-8")
    if source.count(PLACEHOLDER) != 1:
        raise SystemExit(f"{path} must contain exactly one {PLACEHOLDER}")
    source_path.write_text(source.replace(PLACEHOLDER, json.dumps(origin)), encoding="utf-8")
    print(f"{path}: SERVER_URL = {origin}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
