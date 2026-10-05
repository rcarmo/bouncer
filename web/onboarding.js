import "./trust.js";
// Hide trust note in Cloudflare mode.
const cfMeta = document.querySelector('meta[name="cloudflare"]');
if (cfMeta && cfMeta.content === 'true') {
  document.getElementById('trust-step').classList.add('hidden');
}

// Hide token input if local bypass is active (server tells us via meta).
const meta = document.querySelector('meta[name="local-bypass"]');
if (meta && meta.content === 'true') {
  document.getElementById('token-group').classList.add('hidden');
}

const otpInputs = Array.from(document.querySelectorAll('.otp-input'));
const tokenField = document.getElementById('token-input');

function updateToken() {
  if (!tokenField) return;
  tokenField.value = otpInputs.map((input) => input.value).join('');
}

function fillFromText(startIndex, text) {
  let cursor = startIndex;
  for (const char of text) {
    if (cursor >= otpInputs.length) break;
    otpInputs[cursor].value = char;
    cursor += 1;
  }
  return cursor;
}

if (otpInputs.length && tokenField) {
  otpInputs.forEach((input, idx) => {
    input.addEventListener('input', () => {
      const raw = (input.value || '').replace(/\D/g, '');
      if (raw.length > 1) {
        input.value = raw[0] || '';
        const nextIndex = fillFromText(idx + 1, raw.slice(1));
        if (nextIndex < otpInputs.length) {
          otpInputs[nextIndex].focus();
        } else {
          otpInputs[otpInputs.length - 1].focus();
        }
      } else {
        input.value = raw;
        if (raw && idx < otpInputs.length - 1) {
          otpInputs[idx + 1].focus();
        }
      }
      updateToken();
    });

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Backspace' && !input.value && idx > 0) {
        otpInputs[idx - 1].focus();
        return;
      }
      if (event.key === 'ArrowLeft' && idx > 0) {
        otpInputs[idx - 1].focus();
      }
      if (event.key === 'ArrowRight' && idx < otpInputs.length - 1) {
        otpInputs[idx + 1].focus();
      }
    });

    input.addEventListener('paste', (event) => {
      const text = (event.clipboardData || window.clipboardData)?.getData('text') || '';
      const digits = text.replace(/\D/g, '');
      if (!digits) return;
      event.preventDefault();
      const nextIndex = fillFromText(idx, digits);
      updateToken();
      if (nextIndex < otpInputs.length) {
        otpInputs[nextIndex].focus();
      } else {
        otpInputs[otpInputs.length - 1].focus();
      }
    });

    input.addEventListener('focus', () => {
      input.select();
    });
  });
  updateToken();
}

document.getElementById('register-btn').addEventListener('click', register);

async function register() {
  const errEl = document.getElementById('reg-error');
  const successEl = document.getElementById('reg-success');
  errEl.classList.add('hidden');
  successEl.classList.add('hidden');

  const token = document.getElementById('token-input').value.trim();
  const name = document.getElementById('name-input').value.trim();

  try {
    const optRes = await fetch('/webauthn/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, displayName: name || 'User', name: name || '' }),
    });
    if (!optRes.ok) throw new Error(await optRes.text());
    const { options, challengeId, userId } = await optRes.json();

    // Decode base64url fields.
    options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
    options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
      options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id)
      }));
    }

    const credential = await navigator.credentials.create({ publicKey: options.publicKey });

    const body = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      },
    };

    const verRes = await fetch(`/webauthn/register/verify?challengeId=${challengeId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!verRes.ok) throw new Error(await verRes.text());

    successEl.textContent = 'Passkey created! Redirecting...';
    successEl.classList.remove('hidden');
    setTimeout(() => { window.location.href = '/'; }, 1000);
  } catch (e) {
    errEl.textContent = e.message || 'Registration failed';
    errEl.classList.remove('hidden');
  }
}

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
