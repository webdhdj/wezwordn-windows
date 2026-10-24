#!/usr/bin/env python3
"""WezWordn patch 01 — identity for the Bitwarden desktop fork (Windows).

Applies literal-anchor replacements to the upstream `apps/desktop` tree
(fetched fresh in CI). Every anchor must exist exactly once; the patch
fails loudly otherwise — no silent partial identity.

Changes:
- electron-builder.json: productName Bitwarden -> WezWordn,
  appId com.bitwarden.desktop -> com.wezcrypt.wezwordn,
  extraMetadata.name bitwarden -> wezwordn, copyright holder line,
  update feed URL -> wezcrypt.com placeholder (no upstream update feed —
  an unsigned fork must not pull Bitwarden's signed updates),
  AppX identity -> WezCrypt publisher display + wezwordndesktop app id.
- src/package.json (the built app's package.json — Electron derives the
  app name / userData path from it): productName, desktopName, author,
  homepage, description.
- apps/desktop/package.json: description only (build metadata).

Icons are NOT replaced by this patch: upstream's icon set stays until
wesam supplies a WezWordn .ico; that is declared, not hidden.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPLACEMENTS: dict[str, list[tuple[str, str]]] = {
    "apps/desktop/electron-builder.json": [
        ('"productName": "Bitwarden"', '"productName": "WezWordn"'),
        ('"appId": "com.bitwarden.desktop"', '"appId": "com.wezcrypt.wezwordn"'),
        ('"name": "bitwarden"', '"name": "wezwordn"'),
        (
            '"copyright": "Copyright © 2015-2026 Bitwarden Inc."',
            '"copyright": "Copyright © 2026 Wesam Majed — WezCrypt. Based on Bitwarden (GPL-3.0)."',
        ),
        (
            '"url": "https://artifacts.bitwarden.com/desktop"',
            '"url": "https://wezcrypt.com/wezwordn-updates"',
        ),
        ('"applicationId": "bitwardendesktop"', '"applicationId": "wezwordndesktop"'),
        ('"identityName": "8bitSolutionsLLC.bitwardendesktop"', '"identityName": "WezCrypt.wezwordndesktop"'),
        ('"publisherDisplayName": "Bitwarden Inc"', '"publisherDisplayName": "WezCrypt"'),
        # Unsigned-fork packaging: upstream win targets include "nsis-web"
        # and "appx". AppX needs a Store publisher certificate this fork
        # does not have; nsis-web downloads its installer payload pieces
        # from the configured publish feed (cut above). CI run #9
        # (2026-10-24) failed at the pack step after a fully green build;
        # the deterministic unsigned targets are nsis + portable, selected
        # here in the config itself instead of a fragile CLI override.
        ('"target": ["portable", "nsis-web", "appx"]', '"target": ["nsis", "portable"]'),
    ],
    "apps/desktop/src/package.json": [
        ('"productName": "Bitwarden"', '"productName": "WezWordn"'),
        ('"desktopName": "bitwarden.desktop"', '"desktopName": "wezwordn.desktop"'),
        (
            '"author": "Bitwarden Inc. <hello@bitwarden.com> (https://bitwarden.com)"',
            '"author": "Wesam Majed — WezCrypt (https://wezcrypt.com)"',
        ),
        ('"homepage": "https://bitwarden.com"', '"homepage": "https://wezcrypt.com"'),
    ],
    "apps/desktop/package.json": [
        (
            '"description": "A secure and free password manager for all of your devices."',
            '"description": "WezWordn — private offline-first password manager by Wesam Majed (WezCrypt). Based on Bitwarden desktop (GPL-3.0)."',
        ),
    ],
}


def main(root: Path) -> int:
    failures = 0
    for rel, pairs in REPLACEMENTS.items():
        path = root / rel
        if not path.exists():
            print(f"FAIL missing file: {rel}")
            failures += 1
            continue
        text = path.read_text(encoding="utf-8")
        for old, new in pairs:
            count = text.count(old)
            if count != 1:
                print(f"FAIL anchor x{count} (expected x1) in {rel}: {old[:70]}...")
                failures += 1
                continue
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")
        print(f"patched {rel}")
    if failures:
        print(f"patch 01 FAILED with {failures} anchor problem(s)")
        return 1
    print("patch 01 OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")))
