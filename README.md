# Forge — Ollama Code Agent

Agente de programación con una interfaz tipo ChatGPT/Claude, ejecutable en un único contenedor Docker y preparado para **Fly.io**. Usa Ollama para generar respuestas, puede investigar documentación técnica actualizada mediante DuckDuckGo y empaqueta archivos generados como ZIP.

## Características

- Backend Node.js 22 + Fastify con API `/api/chat`, `/api/models`, `/api/health` y `/api/project/zip`.
- Ollama en el mismo contenedor, con descarga automática del modelo definido en `OLLAMA_MODEL`.
- Tool calling para búsqueda web con DuckDuckGo HTML, sin exponer claves API.
- UI responsive en modo oscuro, Markdown, bloques de código con botón **Copiar**, configuración de modelo/system prompt y estado de herramientas.
- Reconoce archivos generados en bloques de código con el formato `// FILE: ruta/archivo.ext`, `# FILE: ...` o `<!-- FILE: ... -->`.
- Volumen Fly.io montado en `/root/.ollama` para conservar los pesos de los modelos entre reinicios.

## Desarrollo local

Requisitos: Node.js 22+, Docker opcional y Ollama local si no se usa el contenedor.

```bash
npm install
cp .env.example .env
npm start
# abrir http://localhost:8080
```

Para usar Ollama instalado fuera del contenedor, asegúrate de que escuche en `127.0.0.1:11434` y descarga un modelo:

```bash
ollama serve
ollama pull qwen2.5:3b
```

También puedes ejecutar todo con Docker:

```bash
docker build -t forge-ollama .
docker run --rm -p 8080:8080 -v forge-models:/root/.ollama forge-ollama
```

## Despliegue en Fly.io

> Ollama necesita memoria y almacenamiento. El `fly.toml` base usa 2 CPU compartidas, 4 GB RAM y un volumen de 20 GB. Ajusta estos valores según el modelo y el tráfico.

1. Instala y autentica Fly CLI: [fly.io/docs/flyctl/install](https://fly.io/docs/flyctl/install/).
2. Desde este directorio, crea o selecciona la aplicación:

```bash
fly auth login
fly apps create agente-de-pruevas
```

3. Crea el volumen persistente en la misma región que `primary_region`:

```bash
fly volumes create ollama_models --region mia --size 20 --app agente-de-pruevas
```

Si el volumen ya existe, no lo recrees. Para modelos grandes, aumenta `--size`.

4. Revisa `fly.toml`. Las variables importantes son:

```toml
OLLAMA_HOST = "127.0.0.1:11434"
OLLAMA_MODEL = "qwen2.5:3b"
PULL_MODEL = "true"
```

`OLLAMA_HOST` es interno al contenedor: el servidor Fastify habla con Ollama por localhost y Fly expone únicamente el puerto 8080 de la aplicación.

5. Configura secretos opcionales. Para Tavily, si en el futuro sustituyes el adaptador DuckDuckGo por Tavily, guarda la clave como secreto; no la pongas en el frontend:

```bash
fly secrets set TAVILY_API_KEY="tu-clave" --app agente-de-pruevas
```

También puedes cambiar el modelo y desactivar la descarga automática:

```bash
fly secrets set OLLAMA_MODEL="llama3.2:3b" PULL_MODEL="true" --app agente-de-pruevas
```

6. Despliega:

```bash
fly deploy --ha=false --app agente-de-pruevas
fly logs --app agente-de-pruevas
```

La primera ejecución puede tardar mientras descarga el modelo. La comprobación de salud está en `GET /api/health`.

## Operación y costes

- Los pesos se guardan en `/root/.ollama`, respaldado por el volumen Fly.
- El volumen es local a una máquina/región; si cambias de región, crea otro volumen y vuelve a descargar el modelo.
- `auto_stop_machines = false` evita que la máquina se duerma durante una sesión de chat, pero incrementa el coste de cómputo.
- Para modelos de 7B o más, aumenta RAM y disco; para producción multiusuario considera separar Ollama en una máquina dedicada.
- El endpoint ZIP sólo acepta rutas relativas seguras y limita el lote a 100 archivos.

## Formato recomendado para generar proyectos

Pide al agente: `Genera un proyecto Vite y devuelve cada archivo en un bloque usando // FILE: ruta/archivo`. Forge mostrará los archivos detectados y habilitará **Descargar proyecto (.zip)**.

## Variables de entorno

| Variable | Default | Uso |
|---|---|---|
| `PORT` | `8080` | Puerto HTTP de Fastify |
| `OLLAMA_HOST` | `127.0.0.1:11434` | Dirección interna de Ollama |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Modelo por defecto |
| `OLLAMA_KEEP_ALIVE` | `5m` | Tiempo que Ollama mantiene el modelo en memoria |
| `PULL_MODEL` | `true` | Descargar el modelo en el arranque |
| `MAX_TOOL_ROUNDS` | `3` | Máximo de rondas de búsqueda web |
| `DDG_SAFESEARCH` | `moderate` | `moderate` u `off` |
