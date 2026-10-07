FROM ollama/ollama:latest AS ollama

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=8080 \
    OLLAMA_HOST=127.0.0.1:11434 \
    OLLAMA_MODEL=qwen2.5:3b
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ollama /usr/bin/ollama /usr/bin/ollama
COPY --from=ollama /usr/lib/ollama /usr/lib/ollama
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

RUN useradd --create-home --shell /bin/bash appuser && \
    mkdir -p /root/.ollama /app/workspace && \
    chown -R appuser:appuser /app

COPY <<'EOF' /usr/local/bin/start.sh
#!/bin/sh
set -eu
ollama serve > /tmp/ollama.log 2>&1 &
OLLAMA_PID=$!
cleanup() { kill "$OLLAMA_PID" 2>/dev/null || true; }
trap cleanup INT TERM EXIT

echo "Waiting for Ollama..."
for i in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then break; fi
  if [ "$i" = "60" ]; then echo "Ollama did not become ready" >&2; exit 1; fi
  sleep 1
done
if [ "${PULL_MODEL:-true}" = "true" ]; then
  if ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | grep -Fxq "${OLLAMA_MODEL}"; then
    echo "Model ${OLLAMA_MODEL} is already available on the volume."
  else
    echo "Ensuring model ${OLLAMA_MODEL} is available..."
    success=false
    for attempt in 1 2 3; do
      if ollama pull "${OLLAMA_MODEL}"; then success=true; break; fi
      echo "Model pull attempt ${attempt}/3 failed; retrying..." >&2
      sleep 5
    done
    if [ "$success" != "true" ]; then
      echo "Unable to download ${OLLAMA_MODEL}; refusing to start an unusable app." >&2
      exit 1
    fi
  fi
fi
exec su appuser -s /bin/sh -c 'node /app/server.mjs'
EOF
RUN chmod +x /usr/local/bin/start.sh

EXPOSE 8080
VOLUME ["/root/.ollama"]
CMD ["/usr/local/bin/start.sh"]
