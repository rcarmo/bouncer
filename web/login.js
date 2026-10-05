async function login() {
  const errEl = document.getElementById('error');
  errEl.classList.add('hidden');
  try {
    const optRes = await fetch('/webauthn/login/options', { method: 'POST' });
    if (!optRes.ok) throw new Error(await optRes.text());
    const { options, challengeId } = await optRes.json();

    // Decode challenge and credential IDs from base64url.
    options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id)
      }));
    }

    const assertion = await navigator.credentials.get({ publicKey: options.publicKey });

    const body = {
      id: assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
        signature: bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
      },
    };

    const verRes = await fetch(`/webauthn/login/verify?challengeId=${challengeId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!verRes.ok) throw new Error(await verRes.text());
    window.location.href = '/';
  } catch (e) {
    errEl.textContent = e.message || 'Authentication failed';
    errEl.classList.remove('hidden');
  }
}

document.getElementById('login-btn').addEventListener('click', login);

function base64urlToBuffer(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}
function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.querySelectorAll("[data-navigate]").forEach(button => {
  button.addEventListener("click", () => { window.location.href = button.dataset.navigate; });
});
