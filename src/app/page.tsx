"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import {
  generateAESKey,
  exportKey,
  importKey,
  encryptData,
  decryptData,
  wrapPrimaryKey,
  unwrapPrimaryKey,
  bufferToBase64,
} from "@/lib/crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AttachedFile {
  name: string;
  type: string;
  size: number;
  data: string; // dataURL
}

interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  has_password: boolean;
  salt?: string;
  key_iv?: string;
  wrapped_key?: string;
}

interface PasteResponse {
  payload: string;
  created_at: number;
  expires_at: number | null;
  burn_on_read: boolean;
}

interface CreateResponse {
  id: string;
  deletion_token: string;
  expires_at: number | null;
  burn_on_read: boolean;
}

interface DecryptedPaste {
  text: string;
  file: AttachedFile | null;
}

interface Toast {
  id: number;
  message: string;
  type: "success" | "error" | "info";
}

interface ServerConfig {
  localIp: string;
  port: number | string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

const EXPIRY_DURATIONS: Record<string, number> = {
  "5m": 5 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "1w": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

const TEMPLATES: Record<string, string> = {
  plain: "",
  markdown: `# Title Here\n\n## Subtitle\nUse **bolding**, *italics*, or \`inline code\`.\n\n- Bullet points\n- Simple lists\n\n> This is a quote block. Securely shared.`,
  javascript: `// JavaScript Template\nconst secureMsg = "Hello AegisShare";\n\nfunction verifyCrypto() {\n  console.log(secureMsg);\n}\n\nverifyCrypto();`,
  python: `# Python Template\ndef handle_payload(data):\n    print(f"Decrypting secure payload of size: {len(data)}")\n\nif __name__ == "__main__":\n    handle_payload("AegisShare")`,
  json: `{\n  "status": "secure",\n  "protocol": "AES-256-GCM",\n  "keys": {\n    "client_side_only": true\n  }\n}`,
  html: `<!DOCTYPE html>\n<html>\n<head>\n  <title>AegisShare</title>\n</head>\n<body>\n  <h1>Encrypted Content</h1>\n</body>\n</html>`,
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AegisSharePage() {
  // ── Create form state ──
  const [pasteText, setPasteText] = useState("");
  const [editorTab, setEditorTab] = useState<"write" | "preview">("write");
  const [mdHtml, setMdHtml] = useState("");
  const [expiry, setExpiry] = useState("1d");
  const [template, setTemplate] = useState("plain");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [pwStrength, setPwStrength] = useState(0);
  const [attachedFile, setAttachedFile] = useState<AttachedFile | null>(null);
  const [encrypting, setEncrypting] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  // ── View state ──
  const [viewMode, setViewMode] = useState<"create" | "view" | "loading">("create");
  const [viewTab, setViewTab] = useState<"text" | "markdown">("text");
  const [decryptedPaste, setDecryptedPaste] = useState<DecryptedPaste | null>(null);
  const [viewError, setViewError] = useState<string | null>(null);
  const [isBurn, setIsBurn] = useState(false);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [countdown, setCountdown] = useState("");

  // ── Password modal ──
  const [showPwModal, setShowPwModal] = useState(false);
  const [modalPw, setModalPw] = useState("");
  const [showModalPw, setShowModalPw] = useState(false);
  const [pwModalError, setPwModalError] = useState("");
  const [pendingPayload, setPendingPayload] = useState<EncryptedPayload | null>(null);
  const [decryptingPw, setDecryptingPw] = useState(false);

  // ── Result modal ──
  const [showResultModal, setShowResultModal] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [deleteUrl, setDeleteUrl] = useState("");
  const [qrSrc, setQrSrc] = useState("");

  // ── Toasts ──
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  // ── Server config (LAN IP) ──
  const [serverConfig, setServerConfig] = useState<ServerConfig>({ localIp: "localhost", port: 3080 });

  const fileInputRef = useRef<HTMLInputElement>(null);
  const handledHashRef = useRef<string | null>(null);

  // ─── Toast helper ───────────────────────────────────────────────────────────
  const showToast = useCallback((message: string, type: Toast["type"] = "info") => {
    const id = ++toastId.current;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
  }, []);

  // ─── Fetch server config ─────────────────────────────────────────────────────
  useEffect(() => {
    fetch("/api/config")
      .then((r) => r.json())
      .then((cfg: ServerConfig) => setServerConfig(cfg))
      .catch(() => {});
  }, []);

  // ─── Markdown preview ────────────────────────────────────────────────────────
  useEffect(() => {
    if (editorTab !== "preview") return;
    // dynamically import marked + DOMPurify only when needed
    Promise.all([
      import("marked"),
      import("dompurify"),
    ]).then(([{ marked }, { default: DOMPurify }]) => {
      setMdHtml(DOMPurify.sanitize(marked.parse(pasteText || "*No text entered*") as string));
    });
  }, [editorTab, pasteText]);

  // ─── Countdown timer ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (!expiresAt || isBurn) return;
    const tick = () => {
      const diff = expiresAt - Date.now();
      if (diff <= 0) { setCountdown("Expired"); return; }
      const h = Math.floor(diff / 3_600_000);
      const m = Math.floor((diff % 3_600_000) / 60_000);
      const s = Math.floor((diff % 60_000) / 1_000);
      setCountdown(h > 0 ? `${h}h ${m}m` : `${m}m ${s}s`);
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, [expiresAt, isBurn]);

  // ─── URL hash routing ─────────────────────────────────────────────────────────
  const handleHash = useCallback(async () => {
    const hash = window.location.hash;
    if (handledHashRef.current === hash) return;
    handledHashRef.current = hash;

    if (!hash || hash === "#") {
      setViewMode("create");
      return;
    }

    // Manual delete
    if (hash.startsWith("#delete=")) {
      const parts = hash.substring(8).split(":");
      const id = parts[0];
      const token = parts[1];
      setViewMode("view");
      setViewError(null);
      try {
        const res = await fetch(`/api/paste/${id}?token=${token}`, { method: "DELETE" });
        const data = await res.json();
        if (res.ok) {
          setDecryptedPaste({ text: "✅ Paste deleted successfully from the server.", file: null });
        } else {
          setViewError(data.error ?? "Deletion failed.");
        }
      } catch {
        setViewError("Network error during deletion.");
      }
      return;
    }

    // View paste
    const cleanHash = hash.substring(1);
    const colonIdx = cleanHash.indexOf(":");
    const id = colonIdx === -1 ? cleanHash : cleanHash.substring(0, colonIdx);
    const primaryKeyB64 = colonIdx === -1 ? "" : cleanHash.substring(colonIdx + 1);

    setViewMode("loading");
    setViewError(null);

    try {
      const res = await fetch(`/api/paste/${id}`);
      if (!res.ok) {
        const data = await res.json();
        setViewMode("view");
        setViewError(data.error ?? "Paste not found.");
        return;
      }
      const data: PasteResponse = await res.json();
      const payload: EncryptedPayload = JSON.parse(data.payload);

      setIsBurn(data.burn_on_read);
      setExpiresAt(data.expires_at);
      setViewMode("view");

      if (payload.has_password) {
        setPendingPayload(payload);
        setModalPw("");
        setPwModalError("");
        setShowPwModal(true);
      } else {
        if (!primaryKeyB64) { setViewError("Missing decryption key in URL fragment."); return; }
        const key = await importKey(primaryKeyB64);
        const plain = await decryptData(payload.ciphertext, payload.iv, key);
        setDecryptedPaste(JSON.parse(plain));
      }
    } catch (err) {
      setViewMode("view");
      setViewError("Failed to load or decrypt paste: " + (err as Error).message);
    }
  }, []);

  useEffect(() => {
    handleHash();
    window.addEventListener("hashchange", handleHash);
    return () => window.removeEventListener("hashchange", handleHash);
  }, [handleHash]);

  // ─── File handling ────────────────────────────────────────────────────────────
  function handleFileSelect(file: File) {
    if (file.size > 10 * 1024 * 1024) {
      showToast("File exceeds 10 MB limit.", "error");
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) =>
      setAttachedFile({ name: file.name, type: file.type || "application/octet-stream", size: file.size, data: e.target!.result as string });
    reader.onerror = () => showToast("Failed to read file.", "error");
    reader.readAsDataURL(file);
  }

  // ─── Password strength ────────────────────────────────────────────────────────
  function calcStrength(v: string): number {
    if (v.length >= 10 && /[A-Z]/.test(v) && /[^a-zA-Z0-9]/.test(v)) return 3;
    if (v.length >= 8 && /[a-zA-Z]/.test(v) && /[0-9]/.test(v)) return 2;
    if (v.length >= 6) return 1;
    return 0;
  }

  // ─── Encrypt & Share ──────────────────────────────────────────────────────────
  async function handleEncryptShare() {
    if (!pasteText.trim() && !attachedFile) {
      showToast("Enter some text or attach a file.", "error");
      return;
    }
    setEncrypting(true);
    try {
      const pasteObj = { text: pasteText, file: attachedFile };
      const pasteString = JSON.stringify(pasteObj);
      const primaryKey = await generateAESKey();
      const { ciphertext, iv } = await encryptData(pasteString, primaryKey);

      const burnOnRead = expiry === "burn";
      const expiresAtVal = burnOnRead ? null : Date.now() + (EXPIRY_DURATIONS[expiry] ?? EXPIRY_DURATIONS["1d"]);

      let uploadPackage: EncryptedPayload;
      let shareableFragment = "";

      if (password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const { wrapped_key, key_iv } = await wrapPrimaryKey(primaryKey, password, salt);
        uploadPackage = { ciphertext, iv, has_password: true, salt: bufferToBase64(salt.buffer as ArrayBuffer), key_iv, wrapped_key };
      } else {
        const keyB64 = await exportKey(primaryKey);
        uploadPackage = { ciphertext, iv, has_password: false };
        shareableFragment = `:${keyB64}`;
      }

      const res = await fetch("/api/paste", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: JSON.stringify(uploadPackage), burn_on_read: burnOnRead, expires_at: expiresAtVal }),
      });
      if (!res.ok) throw new Error("Server error " + res.status);
      const data: CreateResponse = await res.json();

      const origin = window.location.origin;
      const isLocalOrigin = ["localhost", "127.0.0.1", "0.0.0.0"].includes(window.location.hostname);
      const shareOrigin = isLocalOrigin && serverConfig.localIp !== "localhost"
        ? `http://${serverConfig.localIp}:${serverConfig.port}`
        : origin;
      const fullShareUrl = `${shareOrigin}/#${data.id}${shareableFragment}`;
      const fullDeleteUrl = `${shareOrigin}/#delete=${data.id}:${data.deletion_token}`;
      const qrUrl = fullShareUrl;

      setShareUrl(fullShareUrl);
      setDeleteUrl(fullDeleteUrl);
      setQrSrc(`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(qrUrl)}`);
      setShowResultModal(true);
      showToast("Secure paste created!", "success");

      // Reset form
      setPasteText(""); setPassword(""); setPwStrength(0); setAttachedFile(null);
      setExpiry("1d"); setTemplate("plain"); setEditorTab("write");
    } catch (err) {
      showToast("Failed to create paste: " + (err as Error).message, "error");
    } finally {
      setEncrypting(false);
    }
  }

  // ─── Password-modal decrypt ───────────────────────────────────────────────────
  async function handlePasswordDecrypt() {
    if (!modalPw || !pendingPayload) return;
    setDecryptingPw(true);
    setPwModalError("");
    try {
      const key = await unwrapPrimaryKey(
        pendingPayload.wrapped_key!,
        pendingPayload.key_iv!,
        modalPw,
        pendingPayload.salt!
      );
      const plain = await decryptData(pendingPayload.ciphertext, pendingPayload.iv, key);
      setDecryptedPaste(JSON.parse(plain));
      setShowPwModal(false);
      setPendingPayload(null);
      showToast("Decrypted successfully!", "success");
    } catch {
      setPwModalError("Wrong password or corrupt payload.");
    } finally {
      setDecryptingPw(false);
    }
  }

  async function copyText(text: string, msg: string) {
    try { await navigator.clipboard.writeText(text); showToast(msg, "success"); }
    catch { showToast("Copy failed.", "error"); }
  }

  // ─── Render Markdown for view panel ──────────────────────────────────────────
  const viewMdRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!decryptedPaste?.text || !viewMdRef.current) return;
    Promise.all([import("marked"), import("dompurify")]).then(([{ marked }, { default: DOMPurify }]) => {
      viewMdRef.current!.innerHTML = DOMPurify.sanitize(marked.parse(decryptedPaste.text) as string);
    });
  }, [decryptedPaste, viewTab]);

  // ────────────────────────────────────────────────────────────────────────────
  // JSX
  // ────────────────────────────────────────────────────────────────────────────
  return (
    <>
      {/* Background glows */}
      <div className="bg-glow bg-glow-1" />
      <div className="bg-glow bg-glow-2" />
      <div className="bg-glow bg-glow-3" />

      <div className="app-wrap">
        {/* ── Header ── */}
        <header className="app-header">
          <div className="container header-container">
            <a href="/" className="logo">
              <i className="fa-solid fa-shield-halved logo-icon" />
              <span>Aegis<span className="text-accent">Share</span></span>
            </a>
            <span className="badge badge-secure">
              <i className="fa-solid fa-lock" /> Zero-Knowledge AES-256
            </span>
          </div>
        </header>

        <main className="container main-content">
          {/* ═══════════════════════════════════════════════════════════
               CREATE PANEL
          ═══════════════════════════════════════════════════════════ */}
          {viewMode === "create" && (
            <section className="glass-panel fade-in">
              <div className="panel-header">
                <div>
                  <h2>Create Secure Paste</h2>
                  <p className="panel-subtitle">Encryption happens entirely in your browser before uploading.</p>
                </div>
                <div className="editor-modes">
                  <button className={`btn-tab${editorTab === "write" ? " active" : ""}`} onClick={() => setEditorTab("write")}>
                    <i className="fa-solid fa-align-left" /> Write
                  </button>
                  <button className={`btn-tab${editorTab === "preview" ? " active" : ""}`} onClick={() => setEditorTab("preview")}>
                    <i className="fa-brands fa-markdown" /> Preview
                  </button>
                </div>
              </div>

              <div className="panel-body">
                {/* Editor */}
                <div className="editor-wrapper">
                  {editorTab === "write" ? (
                    <textarea
                      className="paste-textarea"
                      placeholder="Type or paste your sensitive text here… Markdown is supported."
                      value={pasteText}
                      onChange={(e) => setPasteText(e.target.value)}
                    />
                  ) : (
                    <div className="markdown-preview-area md-body" dangerouslySetInnerHTML={{ __html: mdHtml }} />
                  )}
                </div>

                {/* Config Grid */}
                <div className="config-grid">
                  {/* File card */}
                  <div className="config-card">
                    <h3><i className="fa-solid fa-paperclip" /> Secure Attachment</h3>
                    {!attachedFile ? (
                      <div
                        className={`drop-zone${isDragOver ? " dragover" : ""}`}
                        onClick={() => fileInputRef.current?.click()}
                        onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                        onDragLeave={() => setIsDragOver(false)}
                        onDrop={(e) => { e.preventDefault(); setIsDragOver(false); if (e.dataTransfer.files[0]) handleFileSelect(e.dataTransfer.files[0]); }}
                      >
                        <i className="fa-solid fa-cloud-arrow-up drop-icon" />
                        <p className="drop-text">Drag & drop or <span className="text-accent-link">Browse</span></p>
                        <p className="drop-subtext">Max 10 MB · Encrypted with paste</p>
                        <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={(e) => { if (e.target.files?.[0]) handleFileSelect(e.target.files[0]); }} />
                      </div>
                    ) : (
                      <div className="file-info-bar">
                        <div className="file-details">
                          <i className="fa-solid fa-file-shield file-details-icon" />
                          <div className="file-meta">
                            <span className="file-name-txt">{attachedFile.name}</span>
                            <span className="file-size-txt">{formatBytes(attachedFile.size)}</span>
                          </div>
                        </div>
                        <button className="btn-icon-danger" onClick={() => setAttachedFile(null)} title="Remove">
                          <i className="fa-solid fa-trash-can" />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Settings card */}
                  <div className="config-card">
                    <h3><i className="fa-solid fa-sliders" /> Security Settings</h3>
                    <div className="form-row">
                      <div className="form-group">
                        <label className="form-label"><i className="fa-regular fa-clock" /> Expiration</label>
                        <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
                          <option value="burn">Burn on read</option>
                          <option value="5m">5 Minutes</option>
                          <option value="1h">1 Hour</option>
                          <option value="1d">1 Day</option>
                          <option value="1w">1 Week</option>
                          <option value="30d">30 Days</option>
                        </select>
                      </div>
                      <div className="form-group">
                        <label className="form-label"><i className="fa-solid fa-code" /> Template</label>
                        <select value={template} onChange={(e) => { setTemplate(e.target.value); if (TEMPLATES[e.target.value] !== undefined) setPasteText(TEMPLATES[e.target.value]); }}>
                          <option value="plain">Plain Text</option>
                          <option value="markdown">Markdown</option>
                          <option value="javascript">JavaScript</option>
                          <option value="python">Python</option>
                          <option value="json">JSON</option>
                          <option value="html">HTML</option>
                        </select>
                      </div>
                    </div>
                    <div className="form-group">
                      <label className="form-label"><i className="fa-solid fa-key" /> Password (Optional)</label>
                      <div className="pw-wrapper">
                        <input
                          type={showPw ? "text" : "password"}
                          placeholder="PBKDF2-derived key protection"
                          value={password}
                          onChange={(e) => { setPassword(e.target.value); setPwStrength(calcStrength(e.target.value)); }}
                        />
                        <button className="btn-eye" onClick={() => setShowPw(!showPw)}>
                          <i className={`fa-solid fa-eye${showPw ? "-slash" : ""}`} />
                        </button>
                      </div>
                      <div className="strength-bar">
                        <div className="strength-fill" style={{
                          width: pwStrength === 0 ? "0" : pwStrength === 1 ? "33%" : pwStrength === 2 ? "66%" : "100%",
                          background: pwStrength <= 1 ? "var(--color-danger)" : pwStrength === 2 ? "var(--color-warning)" : "var(--color-success)",
                        }} />
                      </div>
                      <p className="pw-hint">Recipients need both the link and this password.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="panel-footer">
                <button className="btn-primary btn-glow" onClick={handleEncryptShare} disabled={encrypting}>
                  {encrypting
                    ? <><i className="fa-solid fa-spinner fa-spin" /> Encrypting…</>
                    : <><i className="fa-solid fa-lock" /> Encrypt &amp; Share</>}
                </button>
              </div>
            </section>
          )}

          {/* ═══════════════════════════════════════════════════════════
               LOADING STATE
          ═══════════════════════════════════════════════════════════ */}
          {viewMode === "loading" && (
            <section className="glass-panel fade-in" style={{ padding: "60px 32px", textAlign: "center" }}>
              <i className="fa-solid fa-spinner fa-spin" style={{ fontSize: 36, color: "var(--accent-color)" }} />
              <p style={{ marginTop: 16, color: "var(--text-muted)" }}>Fetching encrypted payload…</p>
            </section>
          )}

          {/* ═══════════════════════════════════════════════════════════
               VIEW / DECRYPT PANEL
          ═══════════════════════════════════════════════════════════ */}
          {viewMode === "view" && (
            <section className="glass-panel fade-in">
              <div className="panel-header">
                <div>
                  <div className="status-tags">
                    {isBurn && <span className="badge badge-danger"><i className="fa-solid fa-fire-flame-curved" /> Burn On Read</span>}
                    {expiresAt && !isBurn && (
                      <span className="badge badge-warning"><i className="fa-regular fa-clock" /> Expires: {countdown}</span>
                    )}
                    {decryptedPaste && !viewError && (
                      <span className="badge badge-success"><i className="fa-solid fa-circle-check" /> Decrypted Client-Side</span>
                    )}
                  </div>
                  <h2>Decrypted Secure Paste</h2>
                  <p className="panel-subtitle">Payload decrypted in your browser. No plaintext was sent to the server.</p>
                </div>
                {decryptedPaste && !viewError && (
                  <div className="view-tabs">
                    <button className={`btn-tab${viewTab === "text" ? " active" : ""}`} onClick={() => setViewTab("text")}>
                      <i className="fa-solid fa-code" /> Plain Text
                    </button>
                    <button className={`btn-tab${viewTab === "markdown" ? " active" : ""}`} onClick={() => setViewTab("markdown")}>
                      <i className="fa-brands fa-markdown" /> Markdown
                    </button>
                  </div>
                )}
              </div>

              <div className="panel-body">
                {viewError && (
                  <div className="alert alert-danger">
                    <i className="fa-solid fa-triangle-exclamation" />
                    <span>{viewError}</span>
                  </div>
                )}

                {isBurn && decryptedPaste && (
                  <div className="alert alert-warning">
                    <i className="fa-solid fa-circle-info" />
                    <span><strong>Burn-On-Read:</strong> This paste is now deleted from the server. Copy it before closing this tab!</span>
                  </div>
                )}

                {decryptedPaste && (
                  <>
                    <div className="editor-wrapper">
                      {viewTab === "text"
                        ? <pre className="view-text-area">{decryptedPaste.text || "(empty)"}</pre>
                        : <div ref={viewMdRef} className="markdown-preview-area md-body" />}
                    </div>

                    {decryptedPaste.file && (
                      <div className="config-card file-download-card">
                        <h3><i className="fa-solid fa-paperclip" /> Decrypted Attachment</h3>
                        <div className="file-download-bar">
                          <div className="file-details">
                            <i className="fa-solid fa-file-shield file-details-icon" />
                            <div className="file-meta">
                              <span className="file-name-txt">{decryptedPaste.file.name}</span>
                              <span className="file-size-txt">{formatBytes(decryptedPaste.file.size)}</span>
                            </div>
                          </div>
                          <button className="btn-primary" onClick={() => {
                            const a = document.createElement("a");
                            a.href = decryptedPaste.file!.data;
                            a.download = decryptedPaste.file!.name;
                            a.click();
                            showToast("Download started.", "success");
                          }}>
                            <i className="fa-solid fa-download" /> Download
                          </button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>

              <div className="panel-footer view-footer">
                <button className="btn-secondary" onClick={() => copyText(decryptedPaste?.text ?? "", "Content copied!")}>
                  <i className="fa-solid fa-copy" /> Copy Content
                </button>
                <a href="/" className="btn-primary" onClick={(e) => { e.preventDefault(); window.location.hash = ""; setViewMode("create"); setDecryptedPaste(null); setViewError(null); }}>
                  <i className="fa-solid fa-plus" /> New Paste
                </a>
              </div>
            </section>
          )}
        </main>
      </div>

      {/* ══════════════════════════════════════════════════════════════
           PASSWORD MODAL
      ══════════════════════════════════════════════════════════════ */}
      {showPwModal && (
        <div className="modal-overlay">
          <div className="glass-panel modal-box">
            <div className="modal-header">
              <h3><i className="fa-solid fa-key" /> Password Required</h3>
            </div>
            <div className="modal-body">
              <p>This paste is double-encrypted with a custom password. Enter it to derive the decryption key client-side.</p>
              <div className="form-group">
                <div className="pw-wrapper">
                  <input type={showModalPw ? "text" : "password"} placeholder="Enter password" value={modalPw}
                    onChange={(e) => setModalPw(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handlePasswordDecrypt()} />
                  <button className="btn-eye" onClick={() => setShowModalPw(!showModalPw)}>
                    <i className={`fa-solid fa-eye${showModalPw ? "-slash" : ""}`} />
                  </button>
                </div>
                {pwModalError && <p className="error-text">{pwModalError}</p>}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={handlePasswordDecrypt} disabled={decryptingPw}>
                {decryptingPw ? <><i className="fa-solid fa-spinner fa-spin" /> Decrypting…</> : <><i className="fa-solid fa-unlock" /> Decrypt</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════
           RESULT MODAL
      ══════════════════════════════════════════════════════════════ */}
      {showResultModal && (
        <div className="modal-overlay">
          <div className="glass-panel modal-box modal-box-wide">
            <div className="modal-header">
              <h3><i className="fa-solid fa-circle-check" style={{ color: "var(--accent-color)" }} /> Paste Created Successfully</h3>
              <button className="btn-close" onClick={() => setShowResultModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <p className="result-notice">The decryption key is in the URL fragment (#) and was never sent to the server.</p>

              <div className="share-row">
                <input type="text" readOnly value={shareUrl} />
                <button className="btn-primary" onClick={() => copyText(shareUrl, "Link copied!")}><i className="fa-solid fa-copy" /></button>
              </div>

              <div className="deletion-box">
                <p className="deletion-notice"><i className="fa-solid fa-triangle-exclamation" /> Keep this deletion link safe to delete the paste early.</p>
                <div className="share-row">
                  <input type="text" readOnly value={deleteUrl} />
                  <button className="btn-secondary" onClick={() => copyText(deleteUrl, "Deletion link copied!")}><i className="fa-solid fa-copy" /></button>
                </div>
              </div>

              <div className="qr-section">
                <h4>Scan QR Code (Mobile Access)</h4>
                <div className="qr-bg">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={qrSrc} alt="Secure Share QR Code" width={150} height={150} />
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={() => setShowResultModal(false)}>Done</button>
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════
           TOAST CONTAINER
      ══════════════════════════════════════════════════════════════ */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            {t.type === "success" && <i className="fa-solid fa-circle-check" />}
            {t.type === "error"   && <i className="fa-solid fa-triangle-exclamation" />}
            {t.type === "info"    && <i className="fa-solid fa-circle-info" />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </>
  );
}
