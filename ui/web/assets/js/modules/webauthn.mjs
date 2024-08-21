// WebAuthn 渐进增强：只使用服务端下发的 publicKey options；不加载远程 polyfill，
// 不输出 options/断言/凭证 ID 到控制台，不把失败当成功。无 JS/不支持时页面保留
// 其他服务端允许的路径。
function fromBase64URL(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
}

function toBase64URL(buffer) {
  const bytes = new Uint8Array(buffer);
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeOptions(publicKey) {
  const options = Object.assign({}, publicKey);
  if (options.challenge) options.challenge = fromBase64URL(options.challenge);
  if (options.user && options.user.id) options.user = Object.assign({}, options.user, {
    id: fromBase64URL(options.user.id),
  });
  if (Array.isArray(options.allowCredentials)) {
    options.allowCredentials = options.allowCredentials.map((item) =>
      Object.assign({}, item, { id: fromBase64URL(item.id) }));
  }
  if (Array.isArray(options.excludeCredentials)) {
    options.excludeCredentials = options.excludeCredentials.map((item) =>
      Object.assign({}, item, { id: fromBase64URL(item.id) }));
  }
  return options;
}

function serializeCredential(credential) {
  const response = credential.response || {};
  const payload = {
    id: credential.id,
    rawId: toBase64URL(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults() : {},
    response: {},
  };
  if (response.clientDataJSON) {
    payload.response.clientDataJSON = toBase64URL(response.clientDataJSON);
  }
  if (response.attestationObject) {
    payload.response.attestationObject = toBase64URL(response.attestationObject);
  }
  if (response.authenticatorData) {
    payload.response.authenticatorData = toBase64URL(response.authenticatorData);
  }
  if (response.signature) payload.response.signature = toBase64URL(response.signature);
  if (response.userHandle) payload.response.userHandle = toBase64URL(response.userHandle);
  return JSON.stringify(payload);
}

function reasonText(error) {
  switch (error && error.name) {
    case "NotAllowedError": return "页面提示：操作已取消或超时，请重试。";
    case "NotSupportedError": return "页面提示：当前认证方式不受此浏览器或认证器支持。";
    case "SecurityError": return "页面提示：当前页面来源未通过安全检查。";
    case "AbortError": return "页面提示：认证器操作已中止。";
    case "InvalidStateError": return "页面提示：该认证器已注册，或操作状态已变化。";
    default: return "页面提示：暂时无法使用认证器，请检查设备后重试。";
  }
}

export function mount(root, context) {
  const form = root.querySelector("form[data-ln-webauthn-form]") ||
    (root.tagName === "FORM" ? root : null);
  if (!form) return () => {};
  const button = form.querySelector("button[type=button]");
  const status = form.querySelector("[data-ln-webauthn-status]");
  if (!button) return () => {};
  let pending = false;
  const setStatus = (text) => {
    if (status) status.textContent = text;
  };
  const onClick = async () => {
    if (pending) return;
    const optionsRaw = form.getAttribute("data-ln-options") || "";
    if (!optionsRaw) return;
    if (!window.isSecureContext || !window.PublicKeyCredential ||
        !navigator.credentials) {
      setStatus("页面提示：当前浏览器或环境不支持 Passkey。");
      return;
    }
    pending = true;
    button.setAttribute("aria-busy", "true");
    button.setAttribute("aria-disabled", "true");
    setStatus("请在系统提示中完成验证。");
    try {
      const publicKey = decodeOptions(JSON.parse(optionsRaw));
      const mode = form.getAttribute("data-ln-mode") || "get";
      const credential = mode === "create"
        ? await navigator.credentials.create({ publicKey })
        : await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error("empty credential");
      const responseField = form.querySelector(
        `input[name="${form.getAttribute("data-ln-response-field") || "passkey_response"}"]`);
      if (responseField) responseField.value = serializeCredential(credential);
      form.submit();
    } catch (error) {
      setStatus(reasonText(error));
      pending = false;
      button.removeAttribute("aria-busy");
      button.removeAttribute("aria-disabled");
    }
  };
  button.addEventListener("click", onClick);
  return () => button.removeEventListener("click", onClick);
}
