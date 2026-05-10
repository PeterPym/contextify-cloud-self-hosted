"""Structured JSON logging formatter, redaction filter, and configuration.

Provides a JSONFormatter for stdlib logging that outputs structured log lines
suitable for log aggregation services. Uses contextvars to propagate per-request
context (request_id, tenant_id, user_id) into every log record automatically.

Includes APIKeyRedactionFilter that scrubs API key secrets from all log output
to prevent accidental credential exposure. See docs/engineering/redaction-policy.md.

Structured logging is controlled by the LOG_FORMAT env var:
  - "json": structured JSON output (production)
  - "text" (default): human-readable plaintext (local development)
"""

import json
import logging
import re
import types
from contextvars import ContextVar
from datetime import UTC, datetime

# Context variables for per-request log enrichment.
# Set by RequestIDMiddleware and auth dependencies; automatically included
# in every log record by JSONFormatter.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_var: ContextVar[str | None] = ContextVar("tenant_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)

# Matches full API keys: ctx_{key_id}_{secret} where key_id is 16 hex chars
# and secret is 24 hex chars. Captures the key_id for replacement.
_API_KEY_PATTERN = re.compile(r"ctx_([a-fA-F0-9]{16})_[a-fA-F0-9]{24}")


def redact_api_key_secrets(text: str) -> str:
    """Replace full API keys with redacted form preserving key_id for debugging.

    Example: ctx_abcdef0123456789_111122223333444455556666
          -> ctx_abcdef0123456789_[REDACTED]
    """
    return _API_KEY_PATTERN.sub(r"ctx_\1_[REDACTED]", text)


class APIKeyRedactionFilter(logging.Filter):
    """Logging filter that scrubs API key secrets from log messages.

    Applies to the formatted message text. Any full API key
    (ctx_{key_id}_{secret}) is replaced with ctx_{key_id}_[REDACTED]
    so the key_id remains available for debugging while the secret
    is never written to log output.

    See docs/engineering/redaction-policy.md for the full policy.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Normalize any message shape (str, dict, object) into a redacted string.
        record.msg = redact_api_key_secrets(record.getMessage())
        record.args = None
        if record.stack_info:
            record.stack_info = redact_api_key_secrets(record.stack_info)
        return True


class RedactingTextFormatter(logging.Formatter):
    """Plaintext formatter that scrubs API key secrets from traceback output."""

    def formatException(  # noqa: N802
        self,
        ei: tuple[type[BaseException], BaseException, "types.TracebackType | None"]
        | tuple[None, None, None],
    ) -> str:
        return redact_api_key_secrets(super().formatException(ei))

    def format(self, record: logging.LogRecord) -> str:
        return redact_api_key_secrets(super().format(record))


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects.

    Output format:
        {"timestamp": "...", "level": "INFO", "logger": "...",
         "message": "...", "request_id": "...", "tenant_id": "...",
         "user_id": "..."}

    Fields with None values are omitted for cleaner output.
    Exception info is included as an "exception" field when present.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add request context from contextvars
        req_id = request_id_var.get()
        if req_id:
            log_entry["request_id"] = req_id

        t_id = tenant_id_var.get()
        if t_id:
            log_entry["tenant_id"] = t_id

        u_id = user_id_var.get()
        if u_id:
            log_entry["user_id"] = u_id

        # Include exception info if present
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = redact_api_key_secrets(
                self.formatException(record.exc_info)
            )

        return json.dumps(log_entry, default=str)


def configure_logging(log_level: str, log_format: str = "text") -> None:
    """Configure root logger with the specified format and level.

    Args:
        log_level: Logging level name (e.g., "info", "debug").
        log_format: "json" for structured output, "text" for plaintext.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicate output
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler()
    handler.setLevel(level)

    if log_format.lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )

    # Attach the API key redaction filter to strip secrets from all log output.
    handler.addFilter(APIKeyRedactionFilter())

    root.addHandler(handler)
