# WezWordn — Windows 11 Edition

**Developer:** Wesam Majed — WezCrypt (https://wezcrypt.com)
**Version:** 1.0.0 (WezWordn product versioning; upstream desktop base 2026.10.2)
**License:** GPL-3.0 (derived from Bitwarden clients — see `LICENSE_GPL.txt` upstream)

## What this is

The Windows edition of WezWordn, built the same way as the iOS edition:
an overlay repository that patches the official open-source
[bitwarden/clients](https://github.com/bitwarden/clients) desktop app
(`apps/desktop`, Electron 43, GPL-3.0) at build time — identity,
integration, no vendored upstream copy here.

Layout:

| Path | Role |
|---|---|
| `core/` | **WezWordnCore-TS** — TypeScript port of the Swift WezWordnCore, byte-compatible formats (WZEN v1, `.wezshare` v1, Emergency v1, WEZBACKUP v1). Zero runtime dependencies. **58 tests, all passing** via `npm test` in `core/`. |
| `integration/` | Electron main-process module (`wezwordn.main.ts`), feature-window page/preload/renderer, core type surface (`core-js-index.d.ts`). |
| `patches/` | `01-identity.py` (productName/appId/AppX identity → WezWordn / `com.wezcrypt.wezwordn`), `02-wezwordn-integration.py` (copies compiled core + integration, one anchored import in upstream `src/main.ts`). Both fail loudly on anchor drift; both were dry-run verified against the real upstream files. |
| `.github/workflows/windows-build.yml` | CI: core tests → `windows-latest` build → NSIS installer + portable `.exe` → in-build ProductName identity verification → artifacts. |

## Features on Windows (via the integration)

Everything below runs **locally in the main process** through IPC
(`wezwordn:*`), with a feature window opened by **Ctrl+Shift+W** or the
`--wezwordn` switch:

- **Encrypted Files (WZEN v1)** — same byte format as iOS; files encrypted
  on Windows open on iOS and vice versa. The 32-byte file key is wrapped
  by Electron `safeStorage` (**DPAPI** on Windows); if DPAPI is
  unavailable the feature disables itself rather than storing a
  plaintext key.
- **Local TOTP** — RFC 4226/6238, otpauth parsing.
- **Vault Health** — same checks/scoring as iOS.
- **Secure Sharing (`.wezshare`)** and **Emergency Recovery** — X25519 +
  HKDF-SHA256 + AES-256-GCM, formats identical to iOS. Recipient keypairs
  live in main-process memory for the session; export is explicit.
- **Local Data Vault + WEZBACKUP v1** — in the core (same as iOS),
  PBKDF2-HMAC-SHA256 210,000 iterations.

Upstream Bitwarden functionality (vault, sync, AutoFill via browser
extension native messaging, **Windows Hello** unlock via
`desktop_native`) is **unchanged upstream code** — WezWordn does not
re-implement or bypass it.

## Honest status (read before distributing)

- **Unsigned.** No code-signing certificate is configured, so the
  installer is unsigned and Windows SmartScreen will warn. Signing needs
  an EV/OV certificate in CI secrets; nothing here fakes it.
- **Not run on a physical Windows 11 machine by the developer of this
  overlay.** Verification = core tests (this repo), patch dry-runs
  against real upstream files, and the CI build on `windows-latest`
  including its executable identity check. First real install test is
  still owed, exactly like the iOS edition's on-device step.
- **Icons** remain upstream's until a WezWordn `.ico` set is supplied —
  declared in patch 01, not hidden.
- Local-layer crypto limits are the same documented ones as iOS
  (no Argon2id in the local layer; PBKDF2 for backups; see the iOS
  edition's `CRYPTOGRAPHY.md` — the algorithms and parameters are
  identical here by construction and by shared test vectors in
  `core/vectors/cross-platform.json`).

## Build it yourself

```powershell
# prerequisites: Node 24, Python 3.12, Rust stable (for desktop_native)
cd core; npm test            # builds dist/ and runs all tests
# fetch upstream, then:
python patches/01-identity.py <clients-tree>
python patches/02-wezwordn-integration.py . <clients-tree>
cd <clients-tree>; npm ci --ignore-scripts
cd apps/desktop; npm run build-native; npm run build
Copy-Item src/wezwordn/ui/* build/ -Force
npx electron-builder --win --x64 -p never --config.win.target='["nsis","portable"]'
```
