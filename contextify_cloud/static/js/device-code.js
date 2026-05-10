/**
 * Device code auto-formatter: uppercases input and formats as XXXX-XXXX.
 */
(function() {
  var input = document.getElementById('user_code');
  if (!input) return;

  input.addEventListener('input', function(e) {
    // Auto-uppercase and format as XXXX-XXXX
    var raw = e.target.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    if (raw.length > 8) raw = raw.substring(0, 8);
    if (raw.length > 4) {
      e.target.value = raw.substring(0, 4) + '-' + raw.substring(4);
    } else {
      e.target.value = raw;
    }
  });
})();
