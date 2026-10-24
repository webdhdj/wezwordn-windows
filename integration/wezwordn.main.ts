// WezWordn main-process integration for the Bitwarden desktop (Electron) fork.
//
// Scope — read before assuming more:
// - This module is imported for its side effects from upstream `src/main.ts`
//   (patch 02 adds one import line). On import it waits for `app.ready` and
//   then registers `wezwordn:*` IPC handlers backed by the real
//   WezWordnCore-TS build copied to `./core-js/` by patch 02.
// - It does NOT touch upstream vault, sync, auth, or biometrics code.
//   Windows Hello unlock stays exactly upstream's (MainBiometricsService /
//   desktop_native). What this module adds is the local-only feature set:
//   encrypted files (WZEN v1), local TOTP, vault health, secure sharing,
//   emergency recovery, and encrypted local backup (WEZBACKUP v1).
// - The local file-encryption key is stored through Electron `safeStorage`
//   (DPAPI-backed on Windows) when encryption is available. If safeStorage
//   is unavailable the module refuses to create a plaintext key file and
//   reports the feature as unavailable instead of silently weakening it.
// - Feature window: opened with the global shortcut Ctrl+Shift+W or the
//   `--wezwordn` command-line switch. Its page + preload are plain files
//   copied next to the bundled main output by the CI build step
//   (see .github/workflows/windows-build.yml), not webpack bundles.

import { createPrivateKey, createPublicKey, randomFillSync } from "crypto";
import type { KeyObject } from "crypto";
import * as fs from "fs";
import * as path from "path";

import { app, BrowserWindow, dialog, globalShortcut, ipcMain, safeStorage } from "electron";

import {
  analyzeVaultHealth,
  createRecoveryPackage,
  createSharePackage,
  decryptFile,
  encryptFile,
  exportSharePackage,
  generateX25519KeyPair,
  importSharePackage,
  openSharePackage,
  recoverVaultKey,
  totpRecordCurrentCode,
} from "./core-js/index.js";

const KEY_FILE = "wezwordn-file-key.dpapi";
const state = { window: null as BrowserWindow | null, recipientKeys: new Map<string, KeyObject>() };

function dataDir(): string {
  const dir = path.join(app.getPath("userData"), "WezWordn");
  fs.mkdirSync(path.join(dir, "EncryptedFiles"), { recursive: true });
  return dir;
}

function loadOrCreateFileKey(): Buffer {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error(
      "safeStorage (DPAPI) is unavailable on this system; encrypted-file features are disabled rather than storing a plaintext key.",
    );
  }
  const keyPath = path.join(dataDir(), KEY_FILE);
  if (fs.existsSync(keyPath)) {
    // safeStorage is string-based: the 32-byte key is stored base64-encoded,
    // DPAPI-encrypted by the OS on Windows.
    return Buffer.from(safeStorage.decryptString(fs.readFileSync(keyPath)), "base64");
  }
  const key = Buffer.alloc(32);
  randomFillSync(key);
  fs.writeFileSync(keyPath, safeStorage.encryptString(key.toString("base64")));
  return key;
}

function openFeaturesWindow(): void {
  if (state.window) {
    state.window.focus();
    return;
  }
  const win = new BrowserWindow({
    width: 980,
    height: 720,
    title: "WezWordn — Local Features",
    webPreferences: {
      preload: path.join(__dirname, "wezwordn-preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  state.window = win;
  win.on("closed", () => (state.window = null));
  void win.loadFile(path.join(__dirname, "wezwordn.html"));
}

app.whenReady().then(() => {
  globalShortcut.register("CommandOrControl+Shift+W", openFeaturesWindow);
  if (process.argv.includes("--wezwordn")) {
    openFeaturesWindow();
  }

  ipcMain.handle("wezwordn:open-window", () => openFeaturesWindow());

  // Recipient keypairs for sharing/recovery live in main-process memory for
  // the session only — never written to disk by this module. Exporting the
  // private key is the caller's explicit action (`wezwordn:key-export`).
  ipcMain.handle("wezwordn:keygen", () => {
    const pair = generateX25519KeyPair();
    const keyId = `key-${state.recipientKeys.size + 1}-${Date.now()}`;
    state.recipientKeys.set(keyId, pair.privateKey);
    return {
      keyId,
      publicKeyB64: (pair.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    };
  });

  ipcMain.handle("wezwordn:key-export", (_e: unknown, keyId: string) => {
    const priv = state.recipientKeys.get(keyId);
    if (!priv) {
      throw new Error("Unknown keyId for this session.");
    }
    return {
      privateKeyPkcs8B64: (priv.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
    };
  });

  ipcMain.handle("wezwordn:key-import", (_e: unknown, privateKeyPkcs8B64: string) => {
    const priv = createPrivateKey({
      key: Buffer.from(privateKeyPkcs8B64, "base64"),
      format: "der",
      type: "pkcs8",
    });
    const keyId = `key-${state.recipientKeys.size + 1}-${Date.now()}`;
    state.recipientKeys.set(keyId, priv);
    return {
      keyId,
      publicKeyB64: (createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    };
  });

  ipcMain.handle("wezwordn:encrypt-file", async () => {
    const picked = await dialog.showOpenDialog({ properties: ["openFile"] });
    if (picked.canceled || picked.filePaths.length === 0) {
      return { canceled: true };
    }
    const source = picked.filePaths[0];
    const dest = path.join(dataDir(), "EncryptedFiles", `${path.basename(source)}.wzen`);
    encryptFile(source, dest, loadOrCreateFileKey());
    return { canceled: false, storedAs: dest, size: fs.statSync(dest).size };
  });

  ipcMain.handle("wezwordn:decrypt-file", async (_e: unknown, storedPath: string) => {
    const picked = await dialog.showSaveDialog({ defaultPath: path.basename(storedPath).replace(/\.wzen$/, "") });
    if (picked.canceled || !picked.filePath) {
      return { canceled: true };
    }
    decryptFile(storedPath, picked.filePath, loadOrCreateFileKey());
    return { canceled: false, writtenTo: picked.filePath };
  });

  ipcMain.handle("wezwordn:list-files", () => {
    const dir = path.join(dataDir(), "EncryptedFiles");
    return fs
      .readdirSync(dir)
      .filter((n) => n.endsWith(".wzen"))
      .map((n) => ({ name: n, fullPath: path.join(dir, n), size: fs.statSync(path.join(dir, n)).size }));
  });

  ipcMain.handle("wezwordn:totp-now", (_e: unknown, recordJson: string) => {
    const record = JSON.parse(recordJson);
    return { code: totpRecordCurrentCode(record), remaining: 30 - (Math.floor(Date.now() / 1000) % 30) };
  });

  ipcMain.handle("wezwordn:health", (_e: unknown, itemsJson: string) => analyzeVaultHealth(JSON.parse(itemsJson)));

  ipcMain.handle("wezwordn:share-create", (_e: unknown, itemJson: string, recipientPublicKeyB64: string) => {
    // Recipient public keys travel as base64 SPKI DER, the same encoding the
    // core's x25519-raw helpers produce/consume.
    const pub = createPublicKey({ key: Buffer.from(recipientPublicKeyB64, "base64"), format: "der", type: "spki" });
    const pkg = createSharePackage(JSON.parse(itemJson), pub);
    return { packageJson: exportSharePackage(pkg), fingerprint: pkg.fingerprint };
  });

  ipcMain.handle("wezwordn:share-open", (_e: unknown, packageJson: string, keyId: string) => {
    const priv = state.recipientKeys.get(keyId);
    if (!priv) {
      throw new Error("No in-memory recipient key for this session; import or generate one first.");
    }
    return openSharePackage(importSharePackage(packageJson), priv);
  });

  ipcMain.handle("wezwordn:recovery-create", (_e: unknown, vaultKeyHex: string, recipientPublicKeyB64: string, ownerLabel: string) => {
    const pub = createPublicKey({ key: Buffer.from(recipientPublicKeyB64, "base64"), format: "der", type: "spki" });
    const pkg = createRecoveryPackage(Buffer.from(vaultKeyHex, "hex"), pub, ownerLabel ?? "");
    return pkg;
  });

  ipcMain.handle("wezwordn:recovery-open", (_e: unknown, pkgJson: string, keyId: string) => {
    const priv = state.recipientKeys.get(keyId);
    if (!priv) {
      throw new Error("No in-memory recipient key for this session.");
    }
    return recoverVaultKey(JSON.parse(pkgJson), priv).toString("hex");
  });
});
