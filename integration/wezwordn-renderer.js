"use strict";
const $ = (id) => document.getElementById(id);
const show = (id, value) => {
  $(id).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
};
const guard = (id, fn) => async () => {
  try {
    await fn();
  } catch (e) {
    show(id, "خطأ: " + (e && e.message ? e.message : String(e)));
  }
};

$("btn-enc").onclick = guard("files-out", async () => {
  show("files-out", await window.wezwordn.encryptFile());
  await refreshFiles();
});
async function refreshFiles() {
  const files = await window.wezwordn.listFiles();
  $("files").innerHTML = "";
  if (!files.length) {
    $("files").textContent = "لا توجد ملفات مشفرة بعد.";
    return;
  }
  for (const f of files) {
    const row = document.createElement("div");
    row.textContent = `${f.name} — ${f.size} B `;
    const b = document.createElement("button");
    b.textContent = "فك التشفير…";
    b.onclick = guard("files-out", async () => show("files-out", await window.wezwordn.decryptFile(f.fullPath)));
    row.appendChild(b);
    $("files").appendChild(row);
  }
}
$("btn-list").onclick = () => refreshFiles();
refreshFiles();

$("btn-totp").onclick = guard("totp-out", async () => {
  const record = {
    secretBase32: $("totp-secret").value.trim(),
    period: 30,
    digits: 6,
    algorithm: "SHA1",
  };
  show("totp-out", await window.wezwordn.totpNow(JSON.stringify(record)));
});

$("btn-keygen").onclick = guard("key-out", async () => {
  const r = await window.wezwordn.keygen();
  show("key-out", r);
  $("share-keyid").value = r.keyId;
});
$("btn-keyimport").onclick = guard("key-out", async () => {
  show("key-out", await window.wezwordn.keyImport($("key-import").value.trim()));
});

$("btn-share").onclick = guard("share-out", async () => {
  show("share-out", await window.wezwordn.shareCreate($("share-item").value, $("share-pub").value.trim()));
});
$("btn-share-open").onclick = guard("share-open-out", async () => {
  show("share-open-out", await window.wezwordn.shareOpen($("share-open-in").value, $("share-keyid").value.trim()));
});

$("btn-rec").onclick = guard("rec-out", async () => {
  const pkg = await window.wezwordn.recoveryCreate(
    $("rec-vaultkey").value.trim(),
    $("rec-pub").value.trim(),
    "WezWordn Windows",
  );
  show("rec-out", pkg);
});
