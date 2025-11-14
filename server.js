// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
// fs, path, cheerio, puppeteer, FormData ya no son necesarios
// Los mantengo si los necesitas para otros procesos, pero no se usan en este código.

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; // ¡Debes añadir esta variable a tu .env!
const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal
// ----------------------------------------------------
/**
 * Envía un archivo a VirusTotal para escanear y espera el resultado.
 * @param {Buffer} apkBuffer - Buffer del archivo APK.
 * @param {string} fileName - Nombre del archivo (solo para referencia).
 * @returns {object} Resultado del escaneo de VirusTotal.
 */
async function scanWithVirusTotal(apkBuffer, fileName) {
    if (!VIRUSTOTAL_API_KEY) {
        return { message: "Clave de VirusTotal no configurada. Saltando el escaneo.", status: "skipped" };
    }

    const form = new FormData();
    form.append('file', apkBuffer, {
        filename: fileName,
        contentType: 'application/vnd.android.package-archive',
    });

    try {
        // 1. Subir el archivo y obtener el ID de análisis
        const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': VIRUSTOTAL_API_KEY,
            },
            maxBodyLength: Infinity,
        });
        
        const analysisId = uploadResponse.data.data.id;
        
        // 2. Esperar el resultado del análisis (poll)
        let result = null;
        let checks = 0;
        
        while (checks < 10) { // Máximo 10 intentos (aprox. 50 segundos)
            await new Promise(resolve => setTimeout(resolve, 5000)); // Esperar 5 segundos
            
            const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });
            
            const status = analysisResponse.data.data.attributes.status;
            
            if (status === 'completed') {
                result = analysisResponse.data.data.attributes.results;
                const stats = analysisResponse.data.data.attributes.stats;
                
                // Contar detecciones de malware
                const maliciousDetections = stats.malicious || 0;
                
                return {
                    status: "completed",
                    malicious: maliciousDetections,
                    totalEngines: stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout,
                    resultsUrl: `https://www.virustotal.com/gui/file-analysis/${analysisId}/detection`,
                    summary: stats
                };
            }
            checks++;
        }
        
        return { status: "timeout", message: "VirusTotal tardó demasiado en completar el análisis." };
        
    } catch (error) {
        console.error("Error en VirusTotal:", error.response ? error.response.data : error.message);
        return { status: "error", message: "Error al comunicarse con VirusTotal." };
    }
}

/* --------- Helpers GitHub (sin cambios) --------- */
async function createOrUpdateGithubFile(pathInRepo, contentBase64, message) {
  try {
    const get = await octokit.repos.getContent({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
    });
    const sha = get.data.sha;
    const res = await octokit.repos.createOrUpdateFileContents({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
      message,
      content: contentBase64,
      sha,
    });
    return res.data;
  } catch (err) {
    const res = await octokit.repos.createOrUpdateFileContents({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
      message,
      content: contentBase64,
    });
    return res.data;
  }
}

// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   1. 🟢 F-DROID / IZYYONDR0ID (Repositorios API)
   Uso: GET /api/sync_repo?packageName=
------------------------------------*/

/**
 * Función para obtener metadatos y APK de F-Droid o IzzyOnDroid.
 * @param {string} packageName - Nombre del paquete de la aplicación (ej: org.mozilla.fenix).
 * @param {string} source - 'fdroid' o 'izzyondroid'.
 */
async function syncFromRepo(packageName, source) {
    const apiUrl = source === 'fdroid' 
        ? `https://f-droid.org/repo/index-v1.json` // El index-v1.json contiene los metadatos
        : `https://apt.izzysoft.de/fdroid/repo/index-v1.json`; // IzzyOnDroid usa el mismo formato de F-Droid

    const repoBaseUrl = source === 'fdroid' ? 'https://f-droid.org/repo/' : 'https://apt.izzysoft.de/fdroid/repo/';

    const response = await axios.get(apiUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
    const { packages } = response.data;
    const app = packages[packageName];

    if (!app) {
        throw new Error(`Paquete ${packageName} no encontrado en ${source}.`);
    }

    // Buscar la versión más reciente
    const latestVersion = Object.keys(app).sort().pop();
    const latestMeta = app[latestVersion].pop(); // Tomar el primer (y generalmente único) archivo de esa versión

    const version = latestMeta.versionName || latestVersion;
    const apkFileName = latestMeta.apkName;
    const downloadUrl = repoBaseUrl + apkFileName;
    
    // Descargar APK
    const apkResp = await axios.get(downloadUrl, { 
        responseType: "arraybuffer", 
        headers: { 'User-Agent': AXIOS_USER_AGENT }
    });
    const apkBuffer = Buffer.from(apkResp.data);

    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
        throw new Error(`APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.`);
    }

    // Guardar APK en GitHub
    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${packageName} v${version} (${source})`);

    // Crear y guardar Metadatos
    const meta = {
        source,
        packageName,
        displayName: latestMeta.localized || packageName, // Usar localized si está disponible
        version,
        description: latestMeta.localized || 'No description found in API meta.',
        iconUrl: latestMeta.icon || '', 
        size: apkBuffer.length,
        addedAt: new Date().toISOString(),
        apkPath
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${packageName} v${version} (${source})`);

    return { meta, message: "APK sincronizado." };
}

// Endpoint para F-Droid
app.get("/api/sync_fdroid", async (req, res) => {
    const { packageName } = req.query;
    if (!packageName) return res.status(400).json({ ok: false, error: "packageName requerido." });
    try {
        const result = await syncFromRepo(packageName, 'fdroid');
        return res.json({ ok: true, ...result });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

// Endpoint para IzzyOnDroid
app.get("/api/sync_izzyondroid", async (req, res) => {
    const { packageName } = req.query;
    if (!packageName) return res.status(400).json({ ok: false, error: "packageName requerido." });
    try {
        const result = await syncFromRepo(packageName, 'izzyondroid');
        return res.json({ ok: true, ...result });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   2. ⚙️ GITHUB RELEASES (Apps Open-Source)
   Uso: GET /api/sync_github_release?repo=owner/repo&packageName=com.app.name
------------------------------------*/
app.get("/api/sync_github_release", async (req, res) => {
    const { repo, packageName } = req.query;
    if (!repo) return res.status(400).json({ ok: false, error: "repo param requerido (owner/repo)" });
    try {
        const [owner, repoName] = repo.split("/");
        const pName = packageName || repoName;
        
        // Obtener el último release
        const release = await octokit.repos.getLatestRelease({ owner, repo: repoName });
        
        const version = release.data.tag_name || release.data.name || "unknown";
        let assetUrl = null;
        let assetName = null;
        
        // Buscar el asset .apk en el release
        if (release.data.assets && release.data.assets.length) {
            for (const a of release.data.assets) {
                if (a.name.endsWith(".apk")) {
                    assetUrl = a.browser_download_url;
                    assetName = a.name;
                    break;
                }
            }
        }
        
        if (!assetUrl) return res.json({ ok: false, error: "No se encontró ningún asset .apk en el último release." });

        // Descargar APK
        const apkResp = await axios.get(assetUrl, { responseType: "arraybuffer" });
        const apkBuffer = Buffer.from(apkResp.data);

        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }

        // Guardar APK en GitHub
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${pName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Add APK ${pName} ${version} (GitHub Release)`);

        // Crear y guardar Metadatos
        const meta = {
            source: "github_release",
            owner,
            repo: repoName,
            packageName: pName,
            version,
            assetName,
            size: apkBuffer.length,
            description: release.data.body || "No description provided in release body.",
            addedAt: new Date().toISOString(),
            apkPath
        };
        const metaPath = `public/apps/${pName}/meta_${version}.json`;
        await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Add meta ${pName} ${version}`);

        return res.json({ ok: true, meta, message: "APK sincronizado." });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   3. 💾 REPOS PRIVADOS / MANUAL ADD (para Desarrolladores)
   Uso: POST /api/manual_add 
   Body: { url: "...", packageName: "...", displayName: "..." }
------------------------------------*/
app.post("/api/manual_add", async (req, res) => {
    try {
        const { url, packageName, displayName, version } = req.body;
        if (!url || !packageName || !version) return res.status(400).json({ ok: false, error: "url, packageName y version son requeridos." });
        
        // 1. Descargar APK
        const apkResp = await axios.get(url, { responseType: "arraybuffer", headers: { 'User-Agent': AXIOS_USER_AGENT } });
        const apkBuffer = Buffer.from(apkResp.data);
        
        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }
        
        // 2. Escaneo de VirusTotal
        const fileName = `${packageName}_v${version}.apk`;
        const vtResult = await scanWithVirusTotal(apkBuffer, fileName);
        
        if (vtResult.status === "completed" && vtResult.malicious > 0) {
             return res.status(403).json({ 
                ok: false, 
                error: `Subida bloqueada: El análisis de VirusTotal encontró ${vtResult.malicious} detecciones maliciosas.`,
                details: vtResult 
            });
        }
        
        // 3. Guardar APK en GitHub
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Add manual APK ${packageName} ${version}`);
        
        // 4. Crear y guardar Metadatos
        const meta = { 
            source: "manual", 
            url, 
            packageName, 
            displayName: displayName || packageName, 
            version,
            size: apkBuffer.length, 
            addedAt: new Date().toISOString(), 
            apkPath,
            virustotal: vtResult 
        };
        const metaPath = `public/apps/${packageName}/meta_${version}.json`;
        await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Add meta ${packageName} ${version}`);
        
        return res.json({ 
            ok: true, 
            meta, 
            message: "APK agregado manualmente y verificado.", 
            virustotal: vtResult 
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});


/* ---------------------------------
   4. 🔍 ENDPOINTS DE BÚSQUEDA Y LISTADO
------------------------------------*/

// NOTA: Los endpoints de scraping (`/api/search_app`, `/api/sync_app_by_search`, `/api/sync_popular_apps`) han sido eliminados.
// El cliente ahora deberá usar los nuevos endpoints de repositorios (`/api/sync_fdroid`, etc.).

// List apps simple: reads repo tree for public/apps
app.get("/api/list_apps", async (req, res) => {
  try {
    const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
    const apps = [];
    for (const dir of tree.data) {
      if (dir.type === "dir") apps.push({ packageName: dir.name, path: dir.path });
    }
    return res.json({ ok:true, apps });
  } catch (e) {
    if (e.status === 404) return res.json({ ok:true, apps: [], message: "No se encontró el directorio public/apps, el catálogo está vacío." });
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// Get metadata for a package (most recent meta_*.json)
app.get("/api/get_app_meta", async (req,res) => {
  const { packageName } = req.query;
  if (!packageName) return res.status(400).json({ ok:false, error:"packageName required" });
  try {
    const dir = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: `public/apps/${packageName}` });
    const metas = dir.data.filter(d=>d.name.startsWith("meta_") && d.name.endsWith(".json"));
    if (!metas.length) return res.json({ ok:false, error:"No metadata found" });
    metas.sort((a,b)=> b.name.localeCompare(a.name));
    const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metas[0].path });
    const content = Buffer.from(raw.data.content, "base64").toString("utf8");
    return res.json({ ok:true, meta: JSON.parse(content) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

/* --------- Simple health --------- */
app.get("/api/ping", (req,res)=> res.json({ ok:true, ts: new Date().toISOString() }) );

/* --------- Start server --------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log("App running on", PORT));
