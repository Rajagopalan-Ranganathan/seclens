"""Generate openapi.yaml from the FastAPI app without starting a server."""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from seclens.main import create_app

OUTPUT = Path(__file__).resolve().parents[1] / "openapi.yaml"


def main():
    app = create_app()
    spec = app.openapi()

    if HAS_YAML:
        text = yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
    else:
        text = json.dumps(spec, indent=2)

    if "--check" in sys.argv:
        if not OUTPUT.exists():
            print(f"FAIL: {OUTPUT} does not exist. Run `make openapi` to generate it.")
            sys.exit(1)
        current = OUTPUT.read_text()
        if current.strip() != text.strip():
            print(f"FAIL: {OUTPUT} is out of date. Run `make openapi` to regenerate.")
            sys.exit(1)
        print(f"OK: {OUTPUT} is up to date.")
        return

    OUTPUT.write_text(text)
    print(f"Written {OUTPUT}")


if __name__ == "__main__":
    main()
