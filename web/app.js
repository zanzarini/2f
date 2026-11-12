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
  const row = (label, value, style) => {
    const wrap = document.createElement("div");
    wrap.className = "row";
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

  async function approvePage(id) {
    $("title").textContent = t.approveTitle;
    const { status, data } = await api("/v1/approvals/" + encodeURIComponent(id));
    if (status !== 200) return finish(t.notFound, "error");
    $("project").textContent = data.project_name;
    const action = data.action;
    row(t.type, action.type);
    if (action.amount !== undefined) {
      row(t.amount, action.amount + (action.asset ? " " + action.asset : ""), "big");
    } else if (action.asset !== undefined) {
      row(t.amount, action.asset, "big");
    }
    if (action.destination !== undefined) row(t.destination, action.destination, "mono");
    for (const [key, value] of Object.entries(action.meta || {})) row(key, display(value));
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
        if (result.status === 409) { clearInterval(timer); return finish(t.state.expired, "error"); }
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
