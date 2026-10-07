const $ = (selector) => document.querySelector(selector);
const chat = $('#chat');
const prompt = $('#prompt');
const composer = $('#composer');
const activity = $('#activity');
const activityText = $('#activityText');
const sendBtn = $('#sendBtn');
const modelSelect = $('#modelSelect');
const systemPrompt = $('#systemPrompt');
let messages = [];
let lastFiles = [];

const savedModel = localStorage.getItem('forge-model');
const savedSystem = localStorage.getItem('forge-system');
if (savedModel) modelSelect.value = savedModel;
if (savedSystem) systemPrompt.value = savedSystem;

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#039;', '"':'&quot;' }[char])); }
function renderMarkdown(text) {
  const chunks = [];
  let html = escapeHtml(text).replace(/```([\w+-]*)\n([\s\S]*?)```/g, (_match, language, code) => {
    const token = `___CODE_${chunks.length}___`;
    chunks.push(`<pre><button class="copy-btn" data-code="${encodeURIComponent(code.trimEnd())}">Copiar</button><code class="language-${language || 'text'}">${code.trimEnd()}</code></pre>`);
    return token;
  });
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>').replace(/^## (.+)$/gm, '<h2>$1</h2>').replace(/^# (.+)$/gm, '<h1>$1</h1>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.split(/\n{2,}/).map((part) => part.startsWith('<___') ? part : `<p>${part.replace(/\n/g, '<br>')}</p>`).join('');
  chunks.forEach((chunk, index) => { html = html.replace(`___CODE_${index}___`, chunk); });
  return html;
}
function addMessage(role, content, meta = {}) {
  $('#welcome')?.remove();
  const wrapper = document.createElement('article');
  wrapper.className = `message ${role}`;
  const icon = role === 'user' ? 'Y' : '✦';
  let extra = '';
  if (meta.events?.some((event) => event.type === 'tool_result')) {
    const results = meta.events.find((event) => event.type === 'tool_result')?.results || [];
    if (results.length) extra += `<div class="source-list"><strong>Fuentes consultadas</strong>${results.map((item) => `<a href="${item.url}" target="_blank" rel="noreferrer">↗ ${escapeHtml(item.title)}</a>`).join('')}</div>`;
  }
  if (meta.files?.length) {
    lastFiles = meta.files;
    extra += `<div>${meta.files.map((file) => `<span class="file-badge">▧ ${escapeHtml(file.path)}</span>`).join('')}</div><button class="download" id="downloadProject">↓ Descargar proyecto (.zip)</button>`;
  }
  wrapper.innerHTML = `<div class="avatar">${icon}</div><div class="message-content">${role === 'assistant' ? renderMarkdown(content) : `<p>${escapeHtml(content).replace(/\n/g, '<br>')}</p>`}${extra}</div>`;
  chat.appendChild(wrapper);
  wrapper.querySelectorAll('.copy-btn').forEach((button) => button.addEventListener('click', async () => { await navigator.clipboard.writeText(decodeURIComponent(button.dataset.code)); button.textContent = 'Copiado'; setTimeout(() => { button.textContent = 'Copiar'; }, 1200); }));
  wrapper.querySelector('#downloadProject')?.addEventListener('click', downloadProject);
  chat.scrollTop = chat.scrollHeight;
}
async function downloadProject() {
  const response = await fetch('/api/project/zip', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ files: lastFiles }) });
  if (!response.ok) return alert('No se pudo crear el ZIP.');
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'ollama-code-project.zip'; link.click(); URL.revokeObjectURL(url);
}
function setActivity(text, visible = true) { activity.hidden = !visible; activityText.textContent = text; }
composer.addEventListener('submit', async (event) => {
  event.preventDefault(); const content = prompt.value.trim(); if (!content || sendBtn.disabled) return;
  prompt.value = ''; prompt.style.height = 'auto'; messages.push({ role: 'user', content }); addMessage('user', content); sendBtn.disabled = true; setActivity('Pensando…');
  try {
    const response = await fetch('/api/chat', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ messages, model: modelSelect.value, systemPrompt: systemPrompt.value }) });
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Error del servidor');
    if (data.events?.some((event) => event.type === 'tool_start')) setActivity('Búsqueda web completada', true); else setActivity('', false);
    messages.push({ role: 'assistant', content: data.answer }); addMessage('assistant', data.answer, data); setActivity('', false);
  } catch (error) { addMessage('assistant', `**Error:** ${error.message}\n\nComprueba que Ollama esté ejecutándose y que el modelo seleccionado esté disponible.`); setActivity('', false); }
  finally { sendBtn.disabled = false; prompt.focus(); }
});
prompt.addEventListener('keydown', (event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); composer.requestSubmit(); } });
prompt.addEventListener('input', () => { prompt.style.height = 'auto'; prompt.style.height = `${Math.min(prompt.scrollHeight, 150)}px`; });
$('#settingsBtn').addEventListener('click', () => $('#settingsDialog').showModal());
$('#settingsDialog').addEventListener('close', () => { localStorage.setItem('forge-model', modelSelect.value); localStorage.setItem('forge-system', systemPrompt.value); });
$('#newChat').addEventListener('click', () => { messages = []; lastFiles = []; chat.innerHTML = '<div class="welcome" id="welcome"><div class="hero-icon">✦</div><h2>Construye algo extraordinario.</h2><p>Pregunta, depura o describe un proyecto. Forge puede investigar documentación actualizada y devolverte archivos listos para ejecutar.</p><div class="suggestions"><button data-prompt="Crea una API REST con Fastify, validación y tests">Crear una API</button><button data-prompt="Explícame cómo usar la API de streams de Node.js con un ejemplo">Investigar documentación</button></div></div>'; bindSuggestions(); });
$('#menuBtn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
function bindSuggestions() { document.querySelectorAll('[data-prompt]').forEach((button) => button.addEventListener('click', () => { prompt.value = button.dataset.prompt; composer.requestSubmit(); })); }
bindSuggestions();
fetch('/api/health').then((r) => r.json()).then((data) => { $('#healthText').textContent = data.ollama ? `Ollama listo · ${data.models.length} modelo(s)` : 'Ollama no disponible'; }).catch(() => { $('#healthText').textContent = 'Backend no disponible'; });
fetch('/api/models').then((r) => r.ok ? r.json() : null).then((data) => { if (!data?.models) return; const names = data.models.map((item) => item.name); if (names.length) { modelSelect.innerHTML = names.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join(''); if (savedModel && names.includes(savedModel)) modelSelect.value = savedModel; } }).catch(() => {});
