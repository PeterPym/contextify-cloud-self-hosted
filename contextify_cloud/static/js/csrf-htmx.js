/**
 * CSRF header injection for htmx requests.
 *
 * Reads the CSRF token from <meta name="csrf-token"> and adds it
 * as an X-CSRF-Token header on every htmx request.
 */
document.body.addEventListener('htmx:configRequest', function (event) {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute('content') : '';
  if (token) {
    event.detail.headers['X-CSRF-Token'] = token;
  }
});
