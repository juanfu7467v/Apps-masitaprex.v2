FROM ollama/ollama:latest AS ollama

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=8080 \
    OLLAMA_HOST=127.0.0.1:11434 \
    OLLAMA_MODEL=qwen2.5:3b
WORKDIR /app

COPY --from=ollama /usr/bin/ollama /usr/bin/ollama
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
  sleep 1
done
if [ "${PULL_MODEL:-true}" = "true" ]; then
  echo "Ensuring model ${OLLAMA_MODEL} is available..."
  ollama pull "${OLLAMA_MODEL}" || echo "Model pull failed; the app will report the Ollama error."
fi
exec su appuser -s /bin/sh -c 'node /app/server.mjs'
EOF
RUN chmod +x /usr/local/bin/start.sh

EXPOSE 8080
VOLUME ["/root/.ollama"]
CMD ["/usr/local/bin/start.sh"]
