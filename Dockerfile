FROM python:3.13-slim

WORKDIR /app

# Install uv for fast, reproducible dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.11.0 /uv /usr/local/bin/uv

# Copy dependency metadata first for layer caching
COPY pyproject.toml requirements.lock README.md ./

# Install dependencies only (no project install yet) using lockfile
ENV UV_NO_DEV=1
RUN uv venv && uv pip install -r requirements.lock

# Copy ALL source files before installing the package
COPY contextify_cloud/ contextify_cloud/
COPY alembic/ alembic/
COPY alembic.ini .

# Install the project (source is now present)
RUN uv pip install --no-deps .

# Ensure venv tools are on PATH
ENV PATH="/app/.venv/bin:$PATH"

# Copy entrypoint script
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Run as non-root for defense in depth
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --create-home --home-dir /home/appuser appuser && \
    chown -R appuser:appuser /app /home/appuser
ENV HOME=/home/appuser
USER appuser

ENTRYPOINT ["./entrypoint.sh"]
