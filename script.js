const $ = (id) => document.getElementById(id);

const authPage = $("authPage");
const vaultPage = $("vaultPage");
const setupForm = $("setupForm");
const loginForm = $("loginForm");
const authMessage = $("authMessage");
const fileGrid = $("fileGrid");
const emptyState = $("emptyState");

let vaultKey = null;
let currentFilter = "all";
let currentFiles = [];
let previewUrl = null;
let db;

const CONFIG = "privateVaultConfig";

function getConfig() {
  try {
    return JSON.parse(localStorage.getItem(CONFIG));
  } catch {
    return null;
  }
}

function saveConfig(config) {
  localStorage.setItem(CONFIG, JSON.stringify(config));
}

function randomBytes(length = 16) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function deriveKey(secret, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 310000,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptBytes(key, bytes) {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    bytes,
  );
  return { iv: toBase64(iv), data: encrypted };
}

async function decryptBytes(key, iv, data) {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv) },
    key,
    data,
  );
}

async function wrapVaultKey(secret, rawKey, salt) {
  const wrappingKey = await deriveKey(secret, salt);
  return encryptBytes(wrappingKey, rawKey);
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("PrivateVaultDB", 1);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains("files")) {
        database.createObjectStore("files", { keyPath: "id" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function storeFile(record) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("files", "readwrite");
    tx.objectStore("files").put(record);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

function getAllFiles() {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("files", "readonly");
    const request = tx.objectStore("files").getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function deleteRecord(id) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("files", "readwrite");
    tx.objectStore("files").delete(id);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

function updateRecord(record) {
  return storeFile(record);
}

function showMessage(message, error = false) {
  authMessage.textContent = message;
  authMessage.style.color = error ? "#ff9baf" : "#c4b5fd";
}

function showSetup() {
  setupForm.classList.remove("hidden");
  loginForm.classList.add("hidden");
}

function showLogin() {
  loginForm.classList.remove("hidden");
  setupForm.classList.add("hidden");
}

function makeRecoveryCode() {
  const bytes = randomBytes(24);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()
    .match(/.{1,8}/g)
    .join("-");
}

async function createVault(password) {
  const recoveryCode = makeRecoveryCode();
  const rawKey = randomBytes(32);
  const passwordSalt = randomBytes();
  const recoverySalt = randomBytes();

  const passwordWrap = await wrapVaultKey(password, rawKey, passwordSalt);

  const recoveryWrap = await wrapVaultKey(recoveryCode, rawKey, recoverySalt);

  saveConfig({
    version: 1,
    passwordSalt: toBase64(passwordSalt),
    passwordIv: passwordWrap.iv,
    passwordWrappedKey: toBase64(passwordWrap.data),
    recoverySalt: toBase64(recoverySalt),
    recoveryIv: recoveryWrap.iv,
    recoveryWrappedKey: toBase64(recoveryWrap.data),
  });

  return { rawKey, recoveryCode };
}

async function unlockWithPassword(password) {
  const config = getConfig();
  const wrappingKey = await deriveKey(
    password,
    fromBase64(config.passwordSalt),
  );

  const rawKey = await decryptBytes(
    wrappingKey,
    config.passwordIv,
    fromBase64(config.passwordWrappedKey),
  );

  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function unlockWithRecovery(code) {
  const config = getConfig();
  const wrappingKey = await deriveKey(
    code.replaceAll("-", "").toUpperCase(),
    fromBase64(config.recoverySalt),
  );

  const rawKey = await decryptBytes(
    wrappingKey,
    config.recoveryIv,
    fromBase64(config.recoveryWrappedKey),
  );

  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

function enterVault(key) {
  vaultKey = key;
  authPage.classList.add("hidden");
  vaultPage.classList.remove("hidden");
  $("loginPassword").value = "";
  refreshFiles();
}

function lockVault() {
  vaultKey = null;
  currentFiles = [];

  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;

  $("previewModal").classList.add("hidden");
  vaultPage.classList.add("hidden");
  authPage.classList.remove("hidden");
  showLogin();
  showMessage("Vault locked.");
}

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = $("newPassword").value;
  const confirm = $("confirmPassword").value;

  if (password.length < 8) {
    return showMessage("Use at least 8 characters.", true);
  }

  if (password !== confirm) {
    return showMessage("Passwords do not match.", true);
  }

  try {
    const { rawKey, recoveryCode } = await createVault(password);
    vaultKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );

    const confirmed = prompt(
      "IMPORTANT: Save this recovery code somewhere safe.\n" +
        "It is needed if you forget your password.\n\n" +
        recoveryCode +
        "\n\nType SAVED after saving the code to continue.",
    );

    if (confirmed !== "SAVED") {
      vaultKey = null;
      showMessage(
        "Vault created. Save your recovery code, then reload to unlock.",
        true,
      );
      showLogin();
      return;
    }

    enterVault(vaultKey);
  } catch (error) {
    showMessage("Could not create vault: " + error.message, true);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const key = await unlockWithPassword($("loginPassword").value);
    enterVault(key);
  } catch {
    showMessage("Incorrect password or damaged vault.", true);
  }
});

$("forgotBtn").addEventListener("click", async () => {
  const code = prompt("Enter your saved recovery code:");
  if (!code) return;

  const newPassword = prompt("Enter your new password (8+ characters):");
  if (!newPassword || newPassword.length < 8) {
    return alert("Password must be at least 8 characters.");
  }

  try {
    const key = await unlockWithRecovery(code);
    const rawKey = await crypto.subtle.exportKey("raw", key);
    const config = getConfig();
    const salt = randomBytes();
    const wrapped = await wrapVaultKey(newPassword, rawKey, salt);

    config.passwordSalt = toBase64(salt);
    config.passwordIv = wrapped.iv;
    config.passwordWrappedKey = toBase64(wrapped.data);
    saveConfig(config);

    enterVault(key);
    alert("Password reset successfully.");
  } catch {
    alert("Invalid recovery code. Your vault was not changed.");
  }
});

document.querySelectorAll("[data-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = $(button.dataset.toggle);
    input.type = input.type === "password" ? "text" : "password";
    button.textContent = input.type === "password" ? "Show" : "Hide";
  });
});

async function uploadFiles(fileList) {
  if (!vaultKey) return;

  for (const file of fileList) {
    if (!file.type.startsWith("image/") && !file.type.startsWith("video/"))
      continue;

    try {
      const encrypted = await encryptBytes(vaultKey, await file.arrayBuffer());

      await storeFile({
        id: crypto.randomUUID(),
        name: file.name,
        type: file.type,
        size: file.size,
        createdAt: Date.now(),
        favorite: false,
        iv: encrypted.iv,
        data: encrypted.data,
      });
    } catch (error) {
      alert("Could not save " + file.name + ": " + error.message);
    }
  }

  $("fileInput").value = "";
  document
    .querySelectorAll(".secondaryUpload")
    .forEach((el) => (el.value = ""));
  await refreshFiles();
}

$("fileInput").addEventListener("change", (event) => {
  uploadFiles(event.target.files);
});

document.querySelectorAll(".secondaryUpload").forEach((input) => {
  input.addEventListener("change", (event) => uploadFiles(event.target.files));
});

function formatSize(bytes) {
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

function formatDate(timestamp) {
  return new Date(timestamp).toLocaleDateString();
}

async function getObjectUrl(file) {
  const data = await decryptBytes(vaultKey, file.iv, file.data);
  return URL.createObjectURL(new Blob([data], { type: file.type }));
}

async function previewFile(file) {
  try {
    const url = await getObjectUrl(file);

    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = url;

    const content = $("previewContent");
    content.replaceChildren();

    const media = document.createElement(
      file.type.startsWith("video/") ? "video" : "img",
    );
    media.src = url;

    if (media.tagName === "VIDEO") {
      media.controls = true;
      media.playsInline = true;
    } else {
      media.alt = file.name;
    }

    content.appendChild(media);
    $("previewName").textContent = file.name;
    $("previewModal").classList.remove("hidden");
  } catch {
    alert("Unable to open this file.");
  }
}

async function refreshFiles() {
  if (!vaultKey) return;

  currentFiles = await getAllFiles();
  $("fileCount").textContent =
    `${currentFiles.length} file${currentFiles.length === 1 ? "" : "s"}`;

  const query = $("searchInput").value.toLowerCase().trim();

  let files = currentFiles.filter((file) =>
    file.name.toLowerCase().includes(query),
  );

  if (currentFilter === "image") {
    files = files.filter((file) => file.type.startsWith("image/"));
  } else if (currentFilter === "video") {
    files = files.filter((file) => file.type.startsWith("video/"));
  } else if (currentFilter === "favorites") {
    files = files.filter((file) => file.favorite);
  } else if (currentFilter === "recent") {
    files = files.filter((file) => Date.now() - file.createdAt < 7 * 86400000);
  }

  files.sort((a, b) => b.createdAt - a.createdAt);
  fileGrid.replaceChildren();
  emptyState.classList.toggle("hidden", files.length > 0);

  if (files.length === 0) {
    emptyState.querySelector("h2").textContent = query
      ? "No matching files"
      : "Your vault is empty";
  }

  for (const file of files) {
    const card = document.createElement("article");
    card.className = "file-card";

    const thumb = document.createElement("div");
    thumb.className = "thumb";
    thumb.title = "Preview file";

    if (file.type.startsWith("image/")) {
      const img = document.createElement("img");
      img.alt = file.name;
      thumb.appendChild(img);
      try {
        img.src = await getObjectUrl(file);
      } catch {
        img.alt = "Preview unavailable";
      }
    } else {
      const icon = document.createElement("span");
      icon.className = "video-placeholder";
      icon.textContent = "▶";
      thumb.appendChild(icon);
    }

    thumb.addEventListener("click", () => previewFile(file));

    const info = document.createElement("div");
    info.className = "file-info";

    const name = document.createElement("div");
    name.className = "file-name";
    name.textContent = file.name;
    name.title = file.name;

    const meta = document.createElement("div");
    meta.className = "file-meta";
    meta.textContent = `${formatSize(file.size)} · ${formatDate(file.createdAt)}`;

    const actions = document.createElement("div");
    actions.className = "card-actions";

    const favorite = document.createElement("button");
    favorite.textContent = file.favorite ? "♥ Saved" : "♡ Favorite";
    favorite.addEventListener("click", async () => {
      file.favorite = !file.favorite;
      await updateRecord(file);
      refreshFiles();
    });

    const open = document.createElement("button");
    open.textContent = "Open";
    open.addEventListener("click", () => previewFile(file));

    const remove = document.createElement("button");
    remove.className = "delete";
    remove.textContent = "Delete";
    remove.addEventListener("click", async () => {
      if (confirm(`Delete "${file.name}" permanently?`)) {
        await deleteRecord(file.id);
        refreshFiles();
      }
    });

    actions.append(favorite, open, remove);
    info.append(name, meta, actions);
    card.append(thumb, info);
    fileGrid.appendChild(card);
  }
}

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    currentFilter = button.dataset.filter;

    document
      .querySelectorAll("[data-filter]")
      .forEach((item) => item.classList.toggle("active", item === button));

    const titles = {
      all: "All Files",
      image: "Photos",
      video: "Videos",
      favorites: "Favorites",
      recent: "Recently Added",
    };

    $("sectionTitle").textContent = titles[currentFilter];
    refreshFiles();
  });
});

$("searchInput").addEventListener("input", refreshFiles);
$("lockBtn").addEventListener("click", lockVault);

$("recoveryBtn").addEventListener("click", () => {
  alert(
    "For safety, your recovery code is only shown when you first create " +
      "the vault. If you saved it, use Forgot Password to recover access. " +
      "If you lost it, do not delete your vault data.",
  );
});

$("closePreview").addEventListener("click", () => {
  $("previewModal").classList.add("hidden");
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  $("previewContent").replaceChildren();
});

$("previewModal").addEventListener("click", (event) => {
  if (event.target === $("previewModal")) {
    $("closePreview").click();
  }
});

async function startApp() {
  if (!window.crypto?.subtle || !window.indexedDB) {
    showMessage(
      "Your browser does not support secure storage. Use an updated browser.",
      true,
    );
    return;
  }

  try {
    db = await openDatabase();

    if (getConfig()) {
      showLogin();
    } else {
      showSetup();
    }
  } catch {
    showMessage("Could not initialize browser storage.", true);
  }
}

startApp();
