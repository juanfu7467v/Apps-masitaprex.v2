// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; // Necesario para VirusTotal
// fs, path, cheerio, puppeteer ya no se usan

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
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
        let checks = 0;
        
        while (checks < 10) { // Máximo 10 intentos (aprox. 50 segundos)
            await new Promise(resolve => setTimeout(resolve, 5000)); // Esperar 5 segundos
            
            const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });
            
            const status = analysisResponse.data.data.attributes.status;
            
            if (status === 'completed') {
                const stats = analysisResponse.data.data.attributes.stats;
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
// FUNCIONES CENTRALES DE SINCRONIZACIÓN (SIN CAMBIOS)
// ---------------------------------------------------

/**
 * Función para obtener metadatos y APK de F-Droid o IzzyOnDroid.
 * @param {string} packageName - Nombre del paquete de la aplicación (ej: org.mozilla.fenix).
 * @param {string} source - 'fdroid' o 'izzyondroid'.
 */
async function syncFromRepo(packageName, source) {
    const apiUrl = source === 'fdroid' 
        ? `https://f-droid.org/repo/index-v1.json`
        : `https://apt.izzysoft.de/fdroid/repo/index-v1.json`;

    const repoBaseUrl = source === 'fdroid' ? 'https://f-droid.org/repo/' : 'https://apt.izzysoft.de/fdroid/repo/';

    const response = await axios.get(apiUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
    const { packages } = response.data;
    const app = packages[packageName];

    if (!app) {
        throw new Error(`Paquete ${packageName} no encontrado en ${source}.`);
    }

    const latestVersion = Object.keys(app).sort().pop();
    const latestMeta = app[latestVersion].pop(); 

    const version = latestMeta.versionName || latestVersion;
    const apkFileName = latestMeta.apkName;
    const downloadUrl = repoBaseUrl + apkFileName;
    
    const apkResp = await axios.get(downloadUrl, { 
        responseType: "arraybuffer", 
        headers: { 'User-Agent': AXIOS_USER_AGENT }
    });
    const apkBuffer = Buffer.from(apkResp.data);

    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
        throw new Error(`APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.`);
    }

    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${packageName} v${version} (${source})`);

    const meta = {
        source,
        packageName,
        displayName: latestMeta.localized || packageName, 
        version,
        description: latestMeta.localized || 'No description found in API meta.',
        iconUrl: latestMeta.icon || '', 
        size: apkBuffer.length,
        addedAt: new Date().toISOString(),
        apkPath
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${packageName} v${version} (${source})`);

    return { meta, message: "APK sincronizado.", source };
}

/**
 * Función para obtener metadatos y APK de GitHub Releases.
 * @param {string} repo - Nombre del repositorio (ej: owner/repo).
 * @param {string} packageName - Nombre del paquete.
 */
async function syncFromGitHubRelease(repo, packageName) {
    const [owner, repoName] = repo.split("/");
    const pName = packageName || repoName;
    
    const release = await octokit.repos.getLatestRelease({ owner, repo: repoName });
    const version = release.data.tag_name || release.data.name || "unknown";
    let assetUrl = null;
    let assetName = null;
    
    if (release.data.assets && release.data.assets.length) {
        for (const a of release.data.assets) {
            if (a.name.endsWith(".apk")) {
                assetUrl = a.browser_download_url;
                assetName = a.name;
                break;
            }
        }
    }
    
    if (!assetUrl) {
        throw new Error("No se encontró ningún asset .apk en el último release de GitHub.");
    }

    const apkResp = await axios.get(assetUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);

    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
        throw new Error(`APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.`);
    }

    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${pName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Add APK ${pName} ${version} (GitHub Release)`);

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

    return { meta, message: "APK sincronizado.", source: "github_release" };
}

// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   1. 🔍 Nuevo ENDPOINT DE BÚSQUEDA Y SINCRONIZACIÓN
   Uso: GET /api/search_and_sync?q=paquete.o.repo
------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    const { q } = req.query; // 'q' puede ser packageName (F-Droid) o repo (GitHub)
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta) es requerido." });

    let appInfo = null;
    let errors = [];

    // Intento 1: Buscar en F-Droid (asumiendo que q es el packageName)
    if (!appInfo) {
        try {
            appInfo = await syncFromRepo(q, 'fdroid');
        } catch (e) {
            errors.push(`F-Droid falló: ${e.message.includes('Paquete') ? e.message : 'Error de API/descarga.'}`);
        }
    }

    // Intento 2: Buscar en IzzyOnDroid (asumiendo que q es el packageName)
    if (!appInfo) {
        try {
            appInfo = await syncFromRepo(q, 'izzyondroid');
        } catch (e) {
            errors.push(`IzzyOnDroid falló: ${e.message.includes('Paquete') ? e.message : 'Error de API/descarga.'}`);
        }
    }

    // Intento 3: Buscar en GitHub Releases (asumiendo que q es el formato owner/repo)
    if (!appInfo && q.includes('/')) {
        try {
            appInfo = await syncFromGitHubRelease(q);
        } catch (e) {
            errors.push(`GitHub Releases falló: ${e.message.includes('No se encontró') ? e.message : 'Error de API/descarga.'}`);
        }
    }

    if (appInfo) {
        return res.json({
            ok: true,
            status: `Éxito: Sincronizado desde ${appInfo.source}`,
            meta: appInfo.meta,
            errors: errors.length ? errors : undefined,
        });
    } else {
        return res.status(404).json({
            ok: false,
            error: `La aplicación '${q}' no se encontró en ninguna fuente automatizada (F-Droid, IzzyOnDroid, GitHub).`,
            details: errors,
        });
    }
});
// Nota: El antiguo /api/search_app?q=facebook ahora se reemplaza por /api/search_and_sync?q=paquete.o.repo

/* ---------------------------------
   2. ⭐️ ENDPOINT DE CATÁLOGO MASIVO
   Uso: POST /api/sync_popular_apps
------------------------------------*/
const POPULAR_APPS_FDROID = [
    { name: "NewPipe", package: "org.schabi.newpipe" },
    { name: "F-Droid", package: "org.fdroid.fdroid" },
    { name: "Tachiyomi", package: "eu.kanade.tachiyomi" },
    { name: "Signal", package: "org.thoughtcrime.securesms" },
    { name: "K-9 Mail", package: "com.fsck.k9" },
];

const POPULAR_APPS_GITHUB = [
    { name: "Vanced Manager", repo: "YTVanced/VancedManager" }, 
    { name: "ReVanced Manager", repo: "revanced/revanced-manager" }, 
];


app.post("/api/sync_popular_apps", async (req, res) => {
    let results = [];
    let successCount = 0;
    const totalApps = POPULAR_APPS_FDROID.length + POPULAR_APPS_GITHUB.length;

    // Sincronizar F-Droid/IzzyOnDroid
    for (const app of POPULAR_APPS_FDROID) {
        try {
            const result = await syncFromRepo(app.package, 'fdroid');
            results.push({ query: app.name, ok: true, source: result.source, packageName: result.meta.packageName, version: result.meta.version });
            successCount++;
        } catch (e) {
            try {
                // Si falla F-Droid, intentar IzzyOnDroid
                const result = await syncFromRepo(app.package, 'izzyondroid');
                results.push({ query: app.name, ok: true, source: result.source, packageName: result.meta.packageName, version: result.meta.version });
                successCount++;
            } catch (e) {
                results.push({ query: app.name, ok: false, message: `F-Droid/IzzyOnDroid falló: ${e.message}` });
            }
        }
    }
    
    // Sincronizar GitHub Releases
    for (const app of POPULAR_APPS_GITHUB) {
        try {
            const result = await syncFromGitHubRelease(app.repo, app.package);
            results.push({ query: app.name, ok: true, source: result.source, packageName: result.meta.packageName, version: result.meta.version });
            successCount++;
        } catch (e) {
            results.push({ query: app.name, ok: false, message: `GitHub falló: ${e.message}` });
        }
    }

    return res.json({ 
        ok: true, 
        totalProcessed: totalApps,
        totalSuccess: successCount,
        results,
        message: "Proceso de sincronización masiva finalizado. Usa /api/list_apps para ver el catálogo."
    });
});


/* ---------------------------------
   3. ENDPOINTS INDIVIDUALES (Mantenidos para uso directo)
------------------------------------*/
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

app.get("/api/sync_github_release", async (req, res) => {
    const { repo, packageName } = req.query;
    if (!repo) return res.status(400).json({ ok: false, error: "repo param requerido (owner/repo)" });
    try {
        const result = await syncFromGitHubRelease(repo, packageName);
        return res.json({ ok: true, ...result });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

app.post("/api/manual_add", async (req, res) => {
    try {
        const { url, packageName, displayName, version } = req.body;
        if (!url || !packageName || !version) return res.status(400).json({ ok: false, error: "url, packageName y version son requeridos." });
        
        const apkResp = await axios.get(url, { responseType: "arraybuffer", headers: { 'User-Agent': AXIOS_USER_AGENT } });
        const apkBuffer = Buffer.from(apkResp.data);
        
        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }
        
        const fileName = `${packageName}_v${version}.apk`;
        const vtResult = await scanWithVirusTotal(apkBuffer, fileName);
        
        if (vtResult.status === "completed" && vtResult.malicious > 0) {
             return res.status(403).json({ 
                ok: false, 
                error: `Subida bloqueada: El análisis de VirusTotal encontró ${vtResult.malicious} detecciones maliciosas.`,
                details: vtResult 
            });
        }
        
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Add manual APK ${packageName} ${version}`);
        
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
   4. 🔍 ENDPOINTS DE LISTADO (Sin cambios)
------------------------------------*/

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
