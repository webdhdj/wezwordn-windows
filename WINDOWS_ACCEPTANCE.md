# WezWordn Windows 1.0.0 — Acceptance Report

Date: 2026-10-24 (Asia/Riyadh). Grading states, same discipline as the iOS
edition: **مُتحقق** (verified here) / **مبني غير مُجرّب** (built, not
device-tested) / **محظور** (blocked).

| # | Item | State | Evidence |
|---|---|---|---|
| 1 | Upstream source identified & licensed | مُتحقق | bitwarden/clients `apps/desktop`, `@bitwarden/desktop` 2026.10.2, package license GPL-3.0, Electron 43.5.0, electron-builder win targets portable/nsis-web/appx (fetched live 2026-10-24) |
| 2 | WezWordnCore-TS implemented (8 modules mirrored) | مُتحقق | `core/src/` 12 modules incl. canonical-json + x25519-raw |
| 3 | Core tests actually run | مُتحقق | `npm test` in `core/`: **58 tests, 58 pass, 0 fail** (Node v24.22.1), re-run independently by the lead after the build agent finished, incl. clean rebuild |
| 4 | Format byte-compatibility with iOS | مُتحقق | WZEN sizes match Swift exactly (empty 25B, 100B→145B, 10,000B→10,225B); PBKDF2 KAT `120fb6cf…be17b`; RFC 6238 vectors ×18; RFC 7748 + RFC 5869 verified; `core/vectors/cross-platform.json` |
| 5 | Identity patch applies to real upstream files | مُتحقق | Dry-run of `01-identity.py` against freshly fetched upstream files: all anchors ×1, productName WezWordn / appId com.wezcrypt.wezwordn written |
| 6 | Integration patch applies | مُتحقق | Dry-run of `02-wezwordn-integration.py`: 12 core-js files + sources copied, import inserted at `src/main.ts:55` |
| 7 | Integration type/syntax sanity | مُتحقق (جزئيًا) | JS assets pass `node --check`; `wezwordn.main.ts` strict-checked against stubs — remaining diagnostics traced to sandbox-missing @types/node/electron (present in the real upstream build); handler params explicitly typed for upstream `noImplicitAny` |
| 8 | Full Windows build (installer .exe) | محظور → CI | No Windows in this environment. `.github/workflows/windows-build.yml` builds on `windows-latest` and fails the job unless produced .exe files report ProductName WezWordn. **No run has completed yet at the time of this report — no .exe is claimed or attached.** |
| 9 | Installed & run on Windows 11 | محظور | Needs a real Windows 11 machine / completed CI artifact install test |
| 10 | Windows Hello unlock | مبني غير مُجرّب | Untouched upstream (`MainBiometricsService` + `desktop_native`); not tested by us on hardware |
| 11 | Code signing / SmartScreen | محظور (مُعلن) | Unsigned by design until a certificate exists; CI sets `CSC_IDENTITY_AUTO_DISCOVERY=false` |
| 12 | WezWordn icon set (.ico) | محظور (مُعلن) | Upstream icons remain; declared in patch 01 and README |

## Known design limits (not defects)

- Feature window opens via Ctrl+Shift+W / `--wezwordn` — a deep menu
  integration into upstream's Angular settings is future work, the same
  phased approach the iOS edition used (settings entry first).
- Recipient private keys for sharing/recovery are session-memory only in
  the integration layer; persistent encrypted key storage is future work
  (on iOS this same gap is documented in FEATURE_MAPPING.md).
