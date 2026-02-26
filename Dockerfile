# ── Stage 1: Builder ────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && TWARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x64") \
    && curl -sL -o /usr/local/bin/tailwindcss \
       "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.16/tailwindcss-linux-${TWARCH}" \
    && chmod +x /usr/local/bin/tailwindcss

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p static/icons && python generate_icons.py
RUN tailwindcss -i static/input.css -o static/dist.css --minify

ARG GIT_SHA=dev
RUN sed -i "s/CACHE_VERSION_PLACEHOLDER/ha-pass-${GIT_SHA}/" static/sw.js

# ── Stage 2: Runtime ────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /build/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only runtime files (no Tailwind binary, no curl, no generate_icons.py)
COPY --from=builder /build/app ./app
COPY --from=builder /build/main.py .
COPY --from=builder /build/alembic.ini .
COPY --from=builder /build/migrations ./migrations
COPY --from=builder /build/templates ./templates
COPY --from=builder /build/static ./static

RUN mkdir -p /data

EXPOSE 5880

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",5880)}/health')"

CMD ["sh", "-c", "python -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-5880} --workers 1"]
