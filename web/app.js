// 2F approval and enrollment page. No dependencies, no build step.
// Everything that comes from the server is written with textContent only.
(() => {
  "use strict";

  const TEXT = {
    en: {
      approveTitle: "Approve this transaction?", enrollTitle: "Register this device",
      type: "Operation", amount: "Amount", destination: "Destination", expires: "Expires in",
      approve: "Approve", reject: "Reject", register: "Register passkey",
      approved: "Approved.", rejected: "Rejected. Nothing will be executed.",
      waiting: "Recorded. Waiting for the other approvers.", registered: "Device registered. You can close this page.",
      expired: "This request has expired.", notFound: "This link is not valid or was already used.",
      state: { allowed: "This request was already allowed.", approved: "This request was already approved.",
               denied: "This request was denied by the rules.", rejected: "This request was rejected.",
               expired: "This request has expired." },
      refused: "The server did not accept this device for this request.",
      cancelled: "Nothing was signed.", unsupported: "This browser does not support passkeys.",
      failed: "Something went wrong. Try again.",
      approveHint: "Check the amount and the destination. Your device signs exactly what is shown here.",
      extra: "Notes sent by the requesting system",
      tampered: "This request failed an integrity check. Nothing can be signed. Tell whoever runs the server.",
      unusual: "Contains unusual characters. Compare it carefully.",
      closed: "This request is no longer waiting: it was already decided or has expired.",
      enrollHint: "Your device will ask for your fingerprint, face or PIN. The key never leaves it.",
      approver: "Approver",
    },
    pt: {
      approveTitle: "Aprovar esta transação?", enrollTitle: "Cadastrar este dispositivo",
      type: "Operação", amount: "Valor", destination: "Destino", expires: "Expira em",
      approve: "Aprovar", reject: "Recusar", register: "Cadastrar passkey",
      approved: "Aprovado.", rejected: "Recusado. Nada será executado.",
      waiting: "Registrado. Aguardando os outros aprovadores.", registered: "Dispositivo cadastrado. Pode fechar esta página.",
      expired: "Este pedido expirou.", notFound: "Este link não é válido ou já foi usado.",
      state: { allowed: "Este pedido já foi liberado.", approved: "Este pedido já foi aprovado.",
               denied: "Este pedido foi negado pelas regras.", rejected: "Este pedido foi recusado.",
               expired: "Este pedido expirou." },
      refused: "O servidor não aceitou este dispositivo para este pedido.",
      cancelled: "Nada foi assinado.", unsupported: "Este navegador não suporta passkeys.",
      failed: "Algo deu errado. Tente de novo.",
      approveHint: "Confira o valor e o destino. Seu dispositivo assina exatamente o que aparece aqui.",
      extra: "Observações enviadas pelo sistema solicitante",
      tampered: "Este pedido falhou na conferência de integridade. Nada pode ser assinado. Avise quem cuida do servidor.",
      unusual: "Contém caracteres incomuns. Compare com cuidado.",
      closed: "Este pedido não está mais aguardando: já foi decidido ou expirou.",
      enrollHint: "Seu dispositivo vai pedir digital, rosto ou PIN. A chave nunca sai dele.",
      approver: "Aprovador",
    },
  };
  const t = TEXT[(navigator.language || "en").toLowerCase().startsWith("pt") ? "pt" : "en"];
  document.documentElement.lang = t === TEXT.pt ? "pt-BR" : "en";

  const $ = (id) => document.getElementById(id);
  const encode = (buffer) => {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const decode = (text) => {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  };

  const setStatus = (message, kind) => {
    $("status").textContent = message;
    $("status").className = kind || "";
  };
  const row = (label, value, style, note) => {
    const wrap = document.createElement("div");
    wrap.className = note ? "row note" : "row";
    const l = document.createElement("div");
    l.className = "label";
    l.textContent = label;
    const v = document.createElement("div");
    v.className = "value" + (style ? " " + style : "");
    v.textContent = value;
    wrap.append(l, v);
    $("details").append(wrap);
    return v;
  };
  const button = (label, style, onClick) => {
    const b = document.createElement("button");
    b.textContent = label;
    b.className = style;
    b.addEventListener("click", onClick);
    $("actions").append(b);
    return b;
  };
  const finish = (message, kind) => {
    $("actions").replaceChildren();
    $("hint").textContent = "";
    setStatus(message, kind);
  };
  const busy = (on) => {
    for (const b of $("actions").querySelectorAll("button")) b.disabled = on;
  };
  const api = async (path, body) => {
    const response = await fetch(path, body === undefined ? {} : {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    let data = null;
    try { data = await response.json(); } catch (_) { /* not JSON */ }
    return { status: response.status, data };
  };
  const display = (value) => (typeof value === "string" ? value : JSON.stringify(value));

  // The same canonical form the server and the SDKs use, so this page can
  // recompute what is about to be signed from what is on screen.
  const canonical = (value) => {
    if (value === null || typeof value === "boolean") return String(value);
    if (typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new Error("number");
      return String(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  };
  const digest = async (tag, text) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(tag + "\n" + text)));
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  // True only when the hashes the device will sign are the hashes of the
  // action displayed, for this very challenge.
  const consistent = async (data, id) => {
    try {
      const binding = data.binding;
      if (binding.v !== 1 || binding.challenge !== id || data.id !== id) return false;
      if (hex(await digest("2F-ACTION-v1", canonical(data.action))) !== binding.action_hash) return false;
      const text = canonical(binding);
      return encode(await digest("2F-BINDING-v1", text)) === data.binding_hash
        && encode(await digest("2F-REJECT-v1", text)) === data.reject_hash;
    } catch (_) {
      return false;
    }
  };
  const warnIfUnusual = (element, value) => {
    if (!/[^\x20-\x7e]/.test(value)) return;
    const warning = document.createElement("div");
    warning.className = "warning";
    warning.textContent = t.unusual;
    element.parentNode.append(warning);
  };

  async function approvePage(id) {
    $("title").textContent = t.approveTitle;
    const { status, data } = await api("/v1/approvals/" + encodeURIComponent(id));
    if (status === 409) return finish(t.tampered, "error");
    if (status !== 200) return finish(t.notFound, "error");
    $("project").textContent = data.project_name;
    const action = data.action;
    const intact = await consistent(data, id);
    warnIfUnusual(row(t.type, action.type), action.type);
    if (action.amount !== undefined) {
      row(t.amount, action.amount + (action.asset ? " " + action.asset : ""), "big");
    } else if (action.asset !== undefined) {
      row(t.amount, action.asset, "big");
    }
    if (action.asset !== undefined) warnIfUnusual($("details").lastChild.lastChild, action.asset);
    if (action.destination !== undefined) {
      warnIfUnusual(row(t.destination, action.destination, "mono"), action.destination);
    }
    // Free form notes are kept visibly apart from the fields above, so a
    // note named "Destination" cannot pass for the real destination.
    const notes = Object.entries(action.meta || {});
    if (notes.length) {
      const heading = document.createElement("div");
      heading.className = "notes";
      heading.textContent = t.extra;
      $("details").append(heading);
      for (const [key, value] of notes) row(key, display(value), "", true);
    }
    if (!intact) return finish(t.tampered, "error");
    if (data.state !== "pending") return finish(t.state[data.state] || data.state, "error");

    const countdown = row(t.expires, "");
    const tick = () => {
      const left = data.expires_at - Math.floor(Date.now() / 1000);
      if (left <= 0) { clearInterval(timer); return finish(t.expired, "error"); }
      countdown.textContent = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
    };
    const timer = setInterval(tick, 1000);
    tick();

    const decide = async (decision) => {
      busy(true);
      setStatus("");
      try {
        const hash = decision === "reject" ? data.reject_hash : data.binding_hash;
        const credential = await navigator.credentials.get({ publicKey: {
          challenge: decode(hash), rpId: data.rp_id, userVerification: "required", timeout: 120000,
        } });
        const result = await api("/v1/challenges/" + encodeURIComponent(id) + "/approvals", {
          decision,
          passkey: {
            id: encode(credential.rawId),
            authenticator_data: encode(credential.response.authenticatorData),
            client_data_json: encode(credential.response.clientDataJSON),
            signature: encode(credential.response.signature),
          },
        });
        if (result.status === 200) {
          clearInterval(timer);
          const state = result.data.state;
          if (state === "approved") return finish(t.approved, "ok");
          if (state === "rejected") return finish(t.rejected, "ok");
          return finish(t.waiting, "ok");
        }
        if (result.status === 409) { clearInterval(timer); return finish(t.closed, "error"); }
        setStatus(result.status === 403 ? t.refused : t.failed, "error");
      } catch (error) {
        setStatus(error && error.name === "NotAllowedError" ? t.cancelled : t.failed, "error");
      }
      busy(false);
    };
    button(t.approve, "primary", () => decide("approve"));
    button(t.reject, "danger", () => decide("reject"));
    $("hint").textContent = t.approveHint;
  }

  async function enrollPage(token) {
    $("title").textContent = t.enrollTitle;
    const path = "/v1/enrollments/" + encodeURIComponent(token);
    const { status, data } = await api(path);
    if (status !== 200) return finish(t.notFound, "error");
    $("project").textContent = data.project_name;
    row(t.approver, data.approver_name);
    button(t.register, "primary", async () => {
      busy(true);
      setStatus("");
      try {
        const credential = await navigator.credentials.create({ publicKey: {
          rp: { id: data.rp_id, name: "2F" },
          user: { id: decode(data.user_id), name: data.approver, displayName: data.approver_name },
          challenge: decode(data.challenge),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          attestation: "none",
          timeout: 120000,
        } });
        const response = credential.response;
        const result = await api(path, {
          authenticator_data: encode(response.getAuthenticatorData()),
          client_data_json: encode(response.clientDataJSON),
          public_key: encode(response.getPublicKey()),
          algorithm: response.getPublicKeyAlgorithm(),
        });
        if (result.status === 200) return finish(t.registered, "ok");
        if (result.status === 404) return finish(t.notFound, "error");
        setStatus(t.failed, "error");
      } catch (error) {
        setStatus(error && error.name === "NotAllowedError" ? t.cancelled : t.failed, "error");
      }
      busy(false);
    });
    $("hint").textContent = t.enrollHint;
  }

  const [, page, id] = location.pathname.split("/");
  if (!window.PublicKeyCredential) {
    finish(t.unsupported, "error");
  } else if (page === "approve" && id) {
    approvePage(id).catch(() => finish(t.failed, "error"));
  } else if (page === "enroll" && id) {
    enrollPage(id).catch(() => finish(t.failed, "error"));
  } else {
    finish(t.notFound, "error");
  }
})();
