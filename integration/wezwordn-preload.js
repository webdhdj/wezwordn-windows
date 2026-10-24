// WezWordn features-window preload. Exposes a narrow, argument-checked
// bridge to the main-process `wezwordn:*` handlers. No Node access leaks
// into the page: contextIsolation stays on, and every method is one IPC
// invoke with JSON-compatible values only.
"use strict";
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("wezwordn", {
  encryptFile: () => ipcRenderer.invoke("wezwordn:encrypt-file"),
  decryptFile: (storedPath) => ipcRenderer.invoke("wezwordn:decrypt-file", storedPath),
  listFiles: () => ipcRenderer.invoke("wezwordn:list-files"),
  totpNow: (recordJson) => ipcRenderer.invoke("wezwordn:totp-now", recordJson),
  health: (itemsJson) => ipcRenderer.invoke("wezwordn:health", itemsJson),
  keygen: () => ipcRenderer.invoke("wezwordn:keygen"),
  keyExport: (keyId) => ipcRenderer.invoke("wezwordn:key-export", keyId),
  keyImport: (pkcs8B64) => ipcRenderer.invoke("wezwordn:key-import", pkcs8B64),
  shareCreate: (itemJson, recipientPublicKeyB64) =>
    ipcRenderer.invoke("wezwordn:share-create", itemJson, recipientPublicKeyB64),
  shareOpen: (packageJson, keyId) => ipcRenderer.invoke("wezwordn:share-open", packageJson, keyId),
  recoveryCreate: (vaultKeyHex, recipientPublicKeyB64, ownerLabel) =>
    ipcRenderer.invoke("wezwordn:recovery-create", vaultKeyHex, recipientPublicKeyB64, ownerLabel),
  recoveryOpen: (pkgJson, keyId) => ipcRenderer.invoke("wezwordn:recovery-open", pkgJson, keyId),
});
