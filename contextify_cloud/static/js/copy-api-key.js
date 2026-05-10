/**
 * Copy API key to clipboard (register page).
 * Binds via addEventListener (inline onclick is blocked by nonce-based CSP).
 */
(function() {
  var btn = document.getElementById('copyKeyBtn');
  if (!btn) return;

  btn.addEventListener('click', function(event) {
    event.preventDefault();
    var input = document.getElementById('apiKeyValue');
    if (!input) return;

    navigator.clipboard.writeText(input.value).then(function() {
      btn.innerHTML = '<i class="bi bi-check"></i> Copied';
      setTimeout(function() {
        btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
      }, 2000);
    });
  });
})();
