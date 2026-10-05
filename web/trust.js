// UI acknowledgement is guidance, not authentication or a server-side access gate.
const acknowledgement = document.getElementById("trust-verified");
const downloads = document.querySelectorAll("[data-trust-download]");
function updateDownloads() {
  downloads.forEach(link => {
    if (acknowledgement?.checked) link.setAttribute("href", link.dataset.trustDownload);
    else link.removeAttribute("href");
    link.setAttribute("aria-disabled", String(!acknowledgement?.checked));
  });
}
acknowledgement?.addEventListener("change", updateDownloads);
updateDownloads();
