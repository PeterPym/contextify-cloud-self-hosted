/**
 * device-flow.js — drives the State A / A' → State B → success transition
 * on /cloud/device (ct-1512 / ct-1565).
 *
 * Posts to:
 *   POST /api/v1/auth/device/email-init
 *   POST /api/v1/auth/device/verify-otp
 *
 * Vanilla JS (no external deps). Loaded with a CSP nonce; safe to attach
 * via addEventListener (no inline event handlers).
 *
 * On State A or A' renders the form has id="ctxf-device-init-form" and
 * the "Check your email" container is id="ctxf-device-await". On State C /
 * interstitial / error renders the form is absent and this script no-ops.
 *
 * Network-drop handling: friendly inline messages, preserve user input
 * (do NOT clear email or OTP on fetch failure).
 */
(function () {
  "use strict";

  var initForm = document.getElementById("ctxf-device-init-form");
  var awaitBlock = document.getElementById("ctxf-device-await");
  // ct-1512 audit P1-3 / P3-3: split the guard so "form rendered without
  // its required await partial" is treated as a configuration error
  // (fail-CLOSED with preventDefault) rather than the same no-op as
  // "this page has no init form at all". The form template now also has
  // method=post + action= so even if both safeguards lose, the worst
  // case is a real POST (no query-string leakage of email / setup_code).
  if (initForm && !awaitBlock) {
    if (window.console && window.console.error) {
      console.error(
        "ctxf-device-init-form rendered without ctxf-device-await — " +
        "form submit will be blocked to prevent leaking form fields " +
        "via the GET fallback."
      );
    }
    initForm.addEventListener("submit", function (ev) { ev.preventDefault(); });
    _wireCopyButton();
    return;
  }
  if (!initForm) {
    // No State A / A' / D form on this page — nothing to wire.
    _wireCopyButton();
    return;
  }

  var emailInput = document.getElementById("ctxf-device-email");
  var setupCodeInput = document.getElementById("ctxf-device-setup-code-input");
  var submitBtn = document.getElementById("ctxf-device-submit");
  var initError = document.getElementById("ctxf-device-init-error");
  var awaitCopy = document.getElementById("ctxf-device-await-copy");
  var otpInput = document.getElementById("ctxf-device-otp");
  var otpSubmit = document.getElementById("ctxf-device-otp-submit");
  var otpError = document.getElementById("ctxf-device-otp-error");
  var restartBtn = document.getElementById("ctxf-device-restart");
  var resendBtn = document.getElementById("ctxf-device-resend");
  var resendLabel = document.getElementById("ctxf-device-resend-label");
  var resendCountdown = document.getElementById("ctxf-device-resend-countdown");

  var currentTokenId = null;
  var currentEmail = null;
  var currentDeviceCode = null;
  var currentSetupCode = null;
  var resendTimer = null;

  _wireCopyButton();
  _autoFormatSetupCode();

  function _csrfToken() {
    var f = initForm.querySelector('input[name="csrf_token"]');
    return f ? f.value : "";
  }

  function _showError(el, msg) {
    // ct-1512 audit P2-3: empty error containers ship with class="d-none"
    // and no role="alert" attribute. When populating, set role="alert" so
    // assistive tech announces, and remove d-none so the message renders.
    // When clearing (msg falsy) restore d-none + drop role to keep
    // Playwright `get_by_role("alert")` strict locators clean.
    if (!el) return;
    el.textContent = msg || "";
    if (msg) {
      el.classList.remove("d-none");
      el.setAttribute("role", "alert");
    } else {
      el.classList.add("d-none");
      el.removeAttribute("role");
    }
  }

  function _showAwait(emailValue) {
    initForm.classList.add("d-none");
    awaitBlock.classList.remove("d-none");
    if (awaitCopy && emailValue) {
      awaitCopy.textContent =
        "Open the email we sent to " + emailValue +
        " and click \"Connect Contextify.\"";
    }
    if (otpInput) {
      otpInput.value = "";
      otpInput.focus();
    }
  }

  function _showInitForm() {
    awaitBlock.classList.add("d-none");
    initForm.classList.remove("d-none");
    _showError(otpError, "");
    _showError(initError, "");
    if (otpInput) otpInput.value = "";
    _stopResendCountdown();
  }

  function _stopResendCountdown() {
    if (resendTimer) {
      clearInterval(resendTimer);
      resendTimer = null;
    }
  }

  function _enableResend() {
    if (!resendBtn || !resendLabel) return;
    resendBtn.disabled = false;
    resendLabel.textContent = "Resend sign-in link";
  }

  function _startResendCountdown(seconds) {
    _stopResendCountdown();
    if (!resendBtn || !resendLabel) return;
    var remaining = parseInt(seconds, 10);
    if (isNaN(remaining) || remaining < 0) remaining = 30;
    if (remaining === 0) {
      _enableResend();
      return;
    }
    resendBtn.disabled = true;
    resendLabel.innerHTML =
      'Resend in <span id="ctxf-device-resend-countdown">' +
      remaining + '</span>s';
    resendCountdown = document.getElementById("ctxf-device-resend-countdown");
    resendTimer = setInterval(function () {
      remaining -= 1;
      if (remaining <= 0) {
        _stopResendCountdown();
        _enableResend();
        return;
      }
      if (resendCountdown) resendCountdown.textContent = String(remaining);
    }, 1000);
  }

  function _emailInitBody() {
    var email = (emailInput && emailInput.value || "").trim();
    var deviceCodeInput = initForm.querySelector('input[name="device_code"]');
    var userCodeInput = initForm.querySelector('input[name="user_code"]');
    var deviceCode = deviceCodeInput ? deviceCodeInput.value : "";
    var userCode = userCodeInput ? userCodeInput.value : "";
    var typedSetup = setupCodeInput ? setupCodeInput.value.trim() : "";
    // Prefer the URL-supplied user_code (State A / D); fall back to the
    // user-typed setup_code (State A').
    var setupCode = userCode || typedSetup;
    var body = { email: email };
    if (deviceCode) body.device_code = deviceCode;
    if (setupCode) body.setup_code = setupCode;
    return body;
  }

  initForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    _showError(initError, "");
    var body = _emailInitBody();
    if (!body.email || body.email.indexOf("@") === -1) {
      _showError(initError, "Enter a valid email address.");
      return;
    }
    if (!body.device_code && !body.setup_code) {
      _showError(initError,
        "Enter the setup code shown in the Contextify app.");
      return;
    }
    if (submitBtn) submitBtn.disabled = true;
    fetch("/api/v1/auth/device/email-init", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": _csrfToken(),
      },
      body: JSON.stringify(body),
    }).then(function (res) {
      if (submitBtn) submitBtn.disabled = false;
      if (res.status === 429) {
        _showError(initError,
          "Too many requests. Try again in a minute.");
        return null;
      }
      return res.json().then(function (data) {
        return { res: res, data: data };
      });
    }).then(function (out) {
      if (!out) return;
      var data = out.data || {};
      if (out.res.status >= 400) {
        var errCode = data && data.error;
        if (errCode === "invalid_email") {
          _showError(initError, "Enter a valid email address.");
        } else if (errCode === "invalid_user_code") {
          _showError(initError,
            "That setup code didn't match. Check the code in the " +
            "Contextify app and try again.");
        } else {
          _showError(initError, "Something went wrong. Please try again.");
        }
        return;
      }
      // Generic 200 — could be silent-skip or real send. Either way show
      // "Check your email" so account existence is not leaked.
      currentTokenId = data.token_id || null;
      currentEmail = body.email;
      currentDeviceCode = body.device_code || null;
      currentSetupCode = body.setup_code || null;
      _showAwait(body.email);
      var resendIn = (data && typeof data.resend_available_in === "number")
        ? data.resend_available_in
        : 30;
      _startResendCountdown(resendIn);
    }).catch(function () {
      if (submitBtn) submitBtn.disabled = false;
      // Network drop on email-init: preserve email, show retry message.
      _showError(initError,
        "We couldn't send the email. Check your connection and try again.");
    });
  });

  // ct-1576: auto-submit when the OTP input reaches 6 digits (paste OR
  // last keystroke OR Apple Keychain / 1Password autocomplete=one-time-code
  // autofill). Stripping non-digits handles paste with spaces/hyphens.
  // Click the existing verify button so we route through the same handler
  // (no duplicated fetch logic).
  if (otpInput && otpSubmit) {
    otpInput.addEventListener("input", function () {
      var digits = (otpInput.value || "").replace(/[^0-9]/g, "");
      if (digits !== otpInput.value) otpInput.value = digits;
      if (digits.length === 6 && !otpSubmit.disabled) {
        otpSubmit.click();
      }
    });
  }

  if (otpSubmit) {
    otpSubmit.addEventListener("click", function () {
      _showError(otpError, "");
      if (!currentTokenId) {
        _showError(otpError, "Request a sign-in link first.");
        return;
      }
      var otp = (otpInput.value || "").trim();
      if (!/^[0-9]{6}$/.test(otp)) {
        _showError(otpError, "Enter the 6-digit code from the email.");
        return;
      }
      otpSubmit.disabled = true;
      var verifyBody = { token_id: currentTokenId, otp: otp };
      fetch("/api/v1/auth/device/verify-otp", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": _csrfToken(),
        },
        body: JSON.stringify(verifyBody),
      }).then(function (res) {
        otpSubmit.disabled = false;
        return res.json();
      }).then(function (data) {
        if (data && data.ok === true && data.redirect) {
          window.location.href = data.redirect;
          return;
        }
        var code = (data && data.error_code) || "otp_wrong";
        if (code === "otp_locked") {
          _showError(otpError,
            "Too many incorrect codes. Send a new email to try again.");
          if (resendBtn) {
            resendBtn.disabled = false;
            if (resendLabel) resendLabel.textContent = "Send a new email";
          }
        } else if (code === "token_expired" || code === "token_consumed" ||
                   code === "token_unknown") {
          _showError(otpError,
            "That code can't be used. Request a new sign-in link below.");
        } else {
          var rem = data && data.attempts_remaining;
          _showError(otpError,
            (rem != null && rem >= 0)
              ? ("That code didn't work. You have " + rem + " tries left.")
              : "That code didn't work. Try again.");
        }
      }).catch(function () {
        otpSubmit.disabled = false;
        // Network drop on verify-otp: preserve OTP value (do not clear),
        // show inline retry message.
        _showError(otpError,
          "We couldn't verify the code. Check your connection and " +
          "try again.");
      });
    });
  }

  if (restartBtn) {
    restartBtn.addEventListener("click", function () {
      currentTokenId = null;
      currentEmail = null;
      _showInitForm();
    });
  }

  // Resend button — re-POSTs email-init with the same email + device_code /
  // setup_code, resets the countdown using the new server-provided window.
  if (resendBtn) {
    resendBtn.addEventListener("click", function () {
      if (resendBtn.disabled) return;
      if (!currentEmail) return;
      _showError(otpError, "");
      resendBtn.disabled = true;
      if (resendLabel) resendLabel.textContent = "Sending...";
      var body = { email: currentEmail };
      if (currentDeviceCode) body.device_code = currentDeviceCode;
      if (currentSetupCode) body.setup_code = currentSetupCode;
      fetch("/api/v1/auth/device/email-init", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": _csrfToken(),
        },
        body: JSON.stringify(body),
      }).then(function (res) {
        if (res.status === 429) {
          _showError(otpError,
            "Too many requests. Try again in a minute.");
          _startResendCountdown(60);
          return null;
        }
        return res.json().then(function (data) {
          return { res: res, data: data };
        });
      }).then(function (out) {
        if (!out) return;
        var data = out.data || {};
        if (out.res.status >= 400) {
          _showError(otpError, "Could not resend. Please try again.");
          _enableResend();
          return;
        }
        currentTokenId = data.token_id || currentTokenId;
        var resendIn = (typeof data.resend_available_in === "number")
          ? data.resend_available_in
          : 30;
        _startResendCountdown(resendIn);
      }).catch(function () {
        _showError(otpError,
          "We couldn't resend the email. Check your connection and " +
          "try again.");
        _enableResend();
      });
    });
  }

  // ── Setup-code pill copy button ───────────────────────────────────────
  function _wireCopyButton() {
    var btns = document.querySelectorAll(".ctxf-copy-setup-code");
    if (!btns || btns.length === 0) return;
    btns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var targetId = btn.getAttribute("data-copy-target");
        if (!targetId) return;
        var target = document.getElementById(targetId);
        if (!target) return;
        var value = (target.textContent || "").trim();
        if (!value) return;
        var done = function () {
          var icon = btn.querySelector("i");
          if (!icon) return;
          var prev = icon.className;
          icon.className = "bi bi-clipboard-check";
          setTimeout(function () {
            icon.className = prev;
          }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(value).then(done, function () {});
        }
      });
    });
  }

  // ── Auto-format the setup-code input as XXXX-XXXX ────────────────────
  function _autoFormatSetupCode() {
    if (!setupCodeInput) return;
    setupCodeInput.addEventListener("input", function (ev) {
      var raw = (ev.target.value || "")
        .replace(/[^A-Za-z0-9]/g, "").toUpperCase();
      if (raw.length > 8) raw = raw.substring(0, 8);
      if (raw.length > 4) {
        ev.target.value = raw.substring(0, 4) + "-" + raw.substring(4);
      } else {
        ev.target.value = raw;
      }
    });
  }
})();
