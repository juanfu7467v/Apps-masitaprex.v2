import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import archiver from 'archiver';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = Fastify({ logger: true, bodyLimit: 2 * 1024 * 1024 });
const PORT = Number(process.env.PORT || 8080);
const OLLAMA_HOST = process.env.OLLAMA_HOST || '127.0.0.1:11434';
const OLLAMA_URL = `http://${OLLAMA_HOST.replace(/^https?:\/\//, '')}`;
const DEFAULT_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:3b';
const MAX_TOOL_ROUNDS = Number(process.env.MAX_TOOL_ROUNDS || 3);

await app.register(fastifyStatic, { root: path.join(__dirname, 'public'), prefix: '/' });

const json = (value) => JSON.stringify(value, null, 2);

async function ollama(pathname, options = {}) {
  const response = await fetch(`${OLLAMA_URL}${pathname}`, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { error: text }; }
  if (!response.ok) throw new Error(data.error || `Ollama respondió ${response.status}`);
  return data;
}

function cleanUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null;
  } catch { return null; }
}

async function webSearch(query) {
  const endpoint = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}&kl=wt-wt&kp=${process.env.DDG_SAFESEARCH === 'off' ? '-2' : '1'}`;
  const response = await fetch(endpoint, { headers: { 'user-agent': 'OllamaCodeAgent/1.0 (+https://fly.io)' } });
  if (!response.ok) throw new Error(`DuckDuckGo respondió ${response.status}`);
  const html = await response.text();
  const results = [];
  const pattern = /result__a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?result__snippet[^>]*>([\s\S]*?)<\/a?>/gi;
  for (const match of html.matchAll(pattern)) {
    const href = cleanUrl(match[1]);
    if (!href) continue;
    const title = match[2].replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').trim();
    const snippet = match[3].replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').trim();
    if (title) results.push({ title, url: href, snippet });
    if (results.length >= 6) break;
  }
  return results;
}

const tools = [{
  type: 'function',
  function: {
    name: 'web_search',
    description: 'Busca documentación técnica reciente en Internet. Úsala cuando la pregunta requiera APIs, librerías o información que pueda haber cambiado.',
    parameters: {
      type: 'object', required: ['query'], properties: {
        query: { type: 'string', description: 'Consulta breve y específica para DuckDuckGo' },
      },
    },
  },
}];

async function runAgent({ messages, model, systemPrompt, onEvent }) {
  const conversation = [
    { role: 'system', content: systemPrompt || 'Eres un ingeniero de software senior. Responde en español, explica decisiones y entrega código ejecutable. Cuando generes archivos, usa bloques con la primera línea `// FILE: ruta/archivo.ext`.' },
    ...messages.filter((m) => ['user', 'assistant'].includes(m.role)).map((m) => ({ role: m.role, content: String(m.content || '') })),
  ];
  for (let round = 0; round <= MAX_TOOL_ROUNDS; round += 1) {
    const result = await ollama('/api/chat', { method: 'POST', body: json({ model: model || DEFAULT_MODEL, messages: conversation, tools, stream: false, keep_alive: process.env.OLLAMA_KEEP_ALIVE || '5m', options: { temperature: 0.2 } }) });
    const message = result.message || {};
    if (!message.tool_calls?.length) return message.content || 'No recibí contenido del modelo.';
    conversation.push(message);
    for (const call of message.tool_calls) {
      if (call.function?.name !== 'web_search') continue;
      const query = call.function.arguments?.query || '';
      await onEvent({ type: 'tool_start', tool: 'web_search', query });
      const results = await webSearch(query);
      await onEvent({ type: 'tool_result', tool: 'web_search', results });
      conversation.push({ role: 'tool', tool_name: 'web_search', content: json(results) });
    }
  }
  throw new Error('El agente alcanzó el máximo de rondas de herramientas.');
}

function extractFiles(text) {
  const files = [];
  const blocks = /```(?:[a-zA-Z0-9_+-]+)?\s*\n([\s\S]*?)```/g;
  for (const match of text.matchAll(blocks)) {
    const content = match[1].trimEnd();
    const firstLine = content.match(/^\s*(?:\/\/|#|<!--)\s*FILE:\s*([^\n>-]+?)(?:\s*-->)?\s*\n/i);
    if (firstLine) files.push({ path: firstLine[1].trim().replace(/^\/+/, ''), content: content.slice(match[0].indexOf('\n') + 1).replace(/^\s*\n/, '') });
  }
  return files.filter((file) => file.path && !file.path.includes('..')).slice(0, 100);
}

app.get('/api/health', async (_request, reply) => {
  try {
    const tags = await ollama('/api/tags');
    const models = (tags.models || []).map((m) => m.name);
    if (!models.length) return reply.code(503).send({ ok: false, ollama: true, models, error: 'Ollama está listo, pero no hay modelos instalados.' });
    return { ok: true, ollama: true, models };
  } catch (error) {
    return reply.code(503).send({ ok: false, ollama: false, error: error.message, models: [] });
  }
});

app.get('/api/models', async (_request, reply) => {
  try { return await ollama('/api/tags'); } catch (error) { return reply.code(503).send({ error: error.message }); }
});

app.post('/api/chat', async (request, reply) => {
  const { messages = [], model = DEFAULT_MODEL, systemPrompt = '' } = request.body || {};
  if (!Array.isArray(messages) || !messages.length) return reply.code(400).send({ error: 'Se requiere al menos un mensaje.' });
  try {
    const events = [];
    const answer = await runAgent({ messages, model, systemPrompt, onEvent: async (event) => events.push(event) });
    return { answer, events, files: extractFiles(answer), model };
  } catch (error) { request.log.error(error); return reply.code(502).send({ error: error.message }); }
});

app.post('/api/project/zip', async (request, reply) => {
  const files = request.body?.files;
  if (!Array.isArray(files) || !files.length) return reply.code(400).send({ error: 'No hay archivos para empaquetar.' });
  reply.header('content-type', 'application/zip').header('content-disposition', 'attachment; filename="ollama-code-project.zip"');
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', (error) => { throw error; });
  reply.send(archive);
  for (const file of files.slice(0, 100)) {
    if (!file?.path || file.path.includes('..')) continue;
    archive.append(String(file.content || ''), { name: file.path.replace(/^\/+/, '') });
  }
  await archive.finalize();
});

app.setNotFoundHandler(async (_request, reply) => reply.sendFile('index.html'));
app.listen({ port: PORT, host: '0.0.0.0' }).catch((error) => { app.log.error(error); process.exit(1); });
