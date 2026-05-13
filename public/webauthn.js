// Minimal WebAuthn client helpers. Converts base64url <-> ArrayBuffer
// and calls navigator.credentials.create / .get.

function b64urlToBuf(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

window.webauthnSupported = () => !!(window.PublicKeyCredential && navigator.credentials);

window.webauthnRegister = async function () {
  const res = await fetch('/api/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Fehler beim Anfordern der Optionen');
  const opts = await res.json();
  opts.challenge = b64urlToBuf(opts.challenge);
  opts.user.id = b64urlToBuf(opts.user.id);
  if (Array.isArray(opts.excludeCredentials)) {
    opts.excludeCredentials = opts.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
  }
  const cred = await navigator.credentials.create({ publicKey: opts });
  const att = cred.response;
  const payload = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64url(att.clientDataJSON),
      attestationObject: bufToB64url(att.attestationObject),
      transports: att.getTransports ? att.getTransports() : undefined,
    },
  };
  const verify = await fetch('/api/webauthn/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });
  if (!verify.ok) throw new Error((await verify.json()).error || 'Verifikation fehlgeschlagen');
  return verify.json();
};

window.webauthnLogin = async function (email) {
  const res = await fetch('/api/webauthn/login/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email: email || '' }),
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Fehler beim Anfordern der Optionen');
  const opts = await res.json();
  opts.challenge = b64urlToBuf(opts.challenge);
  if (Array.isArray(opts.allowCredentials)) {
    opts.allowCredentials = opts.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
  }
  const assertion = await navigator.credentials.get({ publicKey: opts });
  const r = assertion.response;
  const payload = {
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    clientExtensionResults: assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : undefined,
    },
  };
  const verify = await fetch('/api/webauthn/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });
  if (!verify.ok) throw new Error((await verify.json()).error || 'Login fehlgeschlagen');
  return verify.json();
};
