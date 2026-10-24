#!/usr/bin/env python3
"""WezWordn patch 02 — main-process integration into the desktop fork.

Steps (all verified, fail-loud):
1. Copies the compiled WezWordnCore-TS (`core/dist/src/*.js`, built and
   tested before this patch runs) into `apps/desktop/src/wezwordn/core-js/`
   plus the hand-written `index.d.ts` surface declarations.
2. Copies `integration/wezwordn.main.ts` to `apps/desktop/src/wezwordn/`
   and the feature-window assets (html/preload/renderer) to
   `apps/desktop/src/wezwordn/ui/` (the CI workflow copies the UI assets
   next to the bundled main output after the webpack build).
3. Adds ONE side-effect import line to upstream `src/main.ts`, anchored on
   the MenuMain import which upstream main.ts carries verbatim.

No upstream file content is otherwise modified.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ANCHOR = 'import { MenuMain } from "./main/menu/menu.main";'
IMPORT_LINE = 'import "./wezwordn/wezwordn.main";'


def main(overlay: Path, upstream: Path) -> int:
    desktop = upstream / "apps" / "desktop"
    target_dir = desktop / "src" / "wezwordn"
    core_js_dir = target_dir / "core-js"
    ui_dir = target_dir / "ui"
    core_js_dir.mkdir(parents=True, exist_ok=True)
    ui_dir.mkdir(parents=True, exist_ok=True)

    dist_src = overlay / "core" / "dist" / "src"
    js_files = sorted(dist_src.glob("*.js"))
    if len(js_files) < 10:
        print(f"FAIL: expected >=10 compiled core files in {dist_src}, found {len(js_files)}")
        return 1
    for f in js_files:
        shutil.copy2(f, core_js_dir / f.name)
    print(f"copied {len(js_files)} core-js files")

    shutil.copy2(overlay / "integration" / "core-js-index.d.ts", core_js_dir / "index.d.ts")
    shutil.copy2(overlay / "integration" / "wezwordn.main.ts", target_dir / "wezwordn.main.ts")
    for name in ("wezwordn.html", "wezwordn-preload.js", "wezwordn-renderer.js"):
        shutil.copy2(overlay / "integration" / name, ui_dir / name)
    print("copied integration sources")

    main_ts = desktop / "src" / "main.ts"
    text = main_ts.read_text(encoding="utf-8")
    if text.count(ANCHOR) != 1:
        print(f"FAIL: anchor found x{text.count(ANCHOR)} in src/main.ts (expected x1)")
        return 1
    if IMPORT_LINE in text:
        print("FAIL: import line already present — patch applied twice?")
        return 1
    main_ts.write_text(text.replace(ANCHOR, ANCHOR + "\n" + IMPORT_LINE), encoding="utf-8")
    print("patched src/main.ts (side-effect import)")
    print("patch 02 OK")
    return 0


if __name__ == "__main__":
    overlay = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    upstream = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("upstream")
    sys.exit(main(overlay, upstream))
