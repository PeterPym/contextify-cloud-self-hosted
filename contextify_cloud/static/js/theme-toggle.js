/**
 * Dark mode toggle and system theme listener.
 *
 * Depends on window.__ctxfGetPreferredTheme and window.__ctxfApplyTheme
 * defined by the inline theme bootstrap script in <head>.
 */
(function() {
  var html = document.documentElement;
  var toggle = document.getElementById('themeToggle');
  var icon = document.getElementById('themeIcon');
  var getPreferred = window.__ctxfGetPreferredTheme;
  var applyTheme = window.__ctxfApplyTheme;

  function syncIcon(theme) {
    if (theme === 'dark') {
      icon.className = 'bi bi-sun-fill';
    } else {
      icon.className = 'bi bi-moon-fill';
    }
  }

  syncIcon(html.getAttribute('data-bs-theme') || getPreferred());

  toggle.addEventListener('click', function() {
    var current = html.getAttribute('data-bs-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('ctxf-theme', next);
    applyTheme(next);
    syncIcon(next);
  });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
    if (!localStorage.getItem('ctxf-theme')) {
      var next = e.matches ? 'dark' : 'light';
      applyTheme(next);
      syncIcon(next);
    }
  });
})();
