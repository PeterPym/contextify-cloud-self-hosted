/* Scripted-submission checks for the public forms that send email
 * (services/form_shield.py). For each form marked data-form-shield it writes
 * the JavaScript proof derived from the signed render token, and holds a
 * submit made sooner than the minimum human time until that time has passed,
 * so a fast password-manager user is never rejected. Pages that submit with
 * fetch() use window.ctxFormShield directly. */
(function () {
  "use strict";
  var loadedAt = Date.now();

  function proof(token) {
    return "js." + token.split("").reverse().join("");
  }

  function fill(form) {
    var token = form.querySelector('input[name="form_token"]');
    var js = form.querySelector('input[name="form_js"]');
    if (token && js) js.value = proof(token.value);
  }

  function waitMs(minMs) {
    return Math.max(0, (minMs || 0) - (Date.now() - loadedAt));
  }

  // Fields to add to a fetch() body, read from the rendered form.
  function fields(form) {
    var out = {};
    if (!form) return out;
    fill(form);
    ["form_token", "form_js", "website"].forEach(function (name) {
      var input = form.querySelector('input[name="' + name + '"]');
      if (input) out[name] = input.value;
    });
    return out;
  }

  function minMsOf(form) {
    return parseInt((form && form.getAttribute("data-form-shield-min-ms")) || "0", 10);
  }

  window.ctxFormShield = { proof: proof, fields: fields, waitMs: waitMs, minMsOf: minMsOf };

  var forms = document.querySelectorAll("form[data-form-shield]");
  Array.prototype.forEach.call(forms, function (form) {
    fill(form);
    form.addEventListener("submit", function (event) {
      fill(form);
      if (form.getAttribute("data-form-shield-held") === "1") return;
      var wait = waitMs(minMsOf(form));
      if (wait <= 0) return;
      event.preventDefault();
      form.setAttribute("data-form-shield-held", "1");
      var submitter = event.submitter || null;
      setTimeout(function () {
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit(submitter);
        } else {
          form.submit();
        }
      }, wait);
    });
  });
})();
