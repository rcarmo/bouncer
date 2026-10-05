const meta = document.querySelector('meta[name="onboarding"]');
const enabled = meta && meta.content === 'true';
if (!enabled) {
  const btn = document.getElementById('onboard-btn');
  if (btn) btn.classList.add('hidden');
  const subtitle = document.getElementById('subtitle');
  if (subtitle) subtitle.textContent = 'Sign in with your passkey to continue.';
}

document.querySelectorAll("[data-navigate]").forEach(button => {
  button.addEventListener("click", () => { window.location.href = button.dataset.navigate; });
});
