// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data";
import * as cheerio from "cheerio"; // AÑADIDO: Necesario para Web Scraping

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
// FUNCIÓN HELPER: Extracción de Metadatos Ricos (Scraping)
// ----------------------------------------------------
/**
 * Realiza Web Scraping en la página de F-Droid para obtener información rica.
 * @param {string} packageName - Nombre del paquete de la aplicación.
 * @returns {object} Información detallada (descripción, icono, capturas).
 */
async function scrapeFDroidPage(packageName) {
    const appUrl = `https://f-droid.org/es/packages/${packageName}/`;
    
    try {
        const { data } = await axios.get(appUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
        const $ = cheerio.load(data);
        
        const longDescription = $('.package-page__description').text().trim();
        const shortDescription = $('.package-page__summary').text().trim();
        const iconUrl = $('.package-page__icon img').attr('src');
        
        const screenshots = [];
        $('.package-page__screenshots img').each((i, el) => {
            screenshots.push($(el).attr('src'));
        });

        // Aclaración de seguridad (buscando secciones relevantes, esto puede variar)
        let safetyNote = 'Información de seguridad no encontrada.';
        $('.package-page__issue-note').each((i, el) => {
            safetyNote = $(el).text().trim();
        });
        
        return {
            longDescription,
            shortDescription,
            iconUrl: iconUrl ? `https://f-droid.org${iconUrl}` : '',
            screenshots,
            safetyNote
        };

    } catch (error) {
        console.error(`Error de scraping en ${packageName}:`, error.message);
        return { 
            longDescription: 'No disponible por error de scraping.',
            shortDescription: '',
            iconUrl: '',
            screenshots: [],
            safetyNote: 'No disponible.'
        };
    }
}


// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal (sin cambios)
// ----------------------------------------------------
async function scanWithVirusTotal(apkBuffer, fileName) {
    if (!VIRUSTOTAL_API_KEY) {
        return { message: "Clave de VirusTotal no configurada. Saltando el escaneo.", status: "skipped" };
    }
    // ... (El cuerpo de la función sigue siendo el mismo) ...
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
// FUNCIONES CENTRALES DE SINCRONIZACIÓN (MODIFICADAS para incluir Scraping)
// ---------------------------------------------------

/**
 * Función para obtener metadatos y APK de F-Droid o IzzyOnDroid.
 * Se añadió la llamada a scrapeFDroidPage para obtener metadatos ricos.
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
    
    // 1. Scraping para obtener datos ricos (icono, descripción larga, capturas)
    const richData = await scrapeFDroidPage(packageName);

    // 2. Descargar APK
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

    // 3. Combinar metadatos y guardar
    const meta = {
        source,
        packageName,
        displayName: latestMeta.localized || packageName, 
        version,
        size: apkBuffer.length,
        addedAt: new Date().toISOString(),
        apkPath,
        // DATOS ENRIQUECIDOS
        iconUrl: richData.iconUrl || latestMeta.icon || '', // Usar el icono del scraping si existe
        shortDescription: richData.shortDescription, 
        longDescription: richData.longDescription,
        screenshots: richData.screenshots,
        safetyNote: richData.safetyNote, // Aclaraciones de seguridad
        // DATOS BÁSICOS
        descriptionFromRepo: latestMeta.localized, // Descripción simple del index
    };
    
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${packageName} v${version} (${source})`);

    return { meta, message: "APK sincronizado.", source };
}

/**
 * Función para obtener metadatos y APK de GitHub Releases (sin cambios funcionales, solo datos)
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
        // DATOS BÁSICOS DE GITHUB
        description: release.data.body || "No description provided in release body.",
        addedAt: new Date().toISOString(),
        apkPath,
        // CAMPOS ADICIONALES (vacíos para GitHub ya que no se puede hacer scraping de la misma forma)
        iconUrl: '',
        shortDescription: '',
        longDescription: '',
        screenshots: [],
        safetyNote: 'Fuente: GitHub Release. Depende de la confianza en el repositorio. No verificado por F-Droid.',
    };
    const metaPath = `public/apps/${pName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Add meta ${pName} ${version}`);

    return { meta, message: "APK sincronizado.", source: "github_release" };
}

// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   1. 🔍 ENDPOINT DE BÚSQUEDA Y SINCRONIZACIÓN (sin cambios)
------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    const { q } = req.query; 
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta) es requerido." });

    let appInfo = null;
    let errors = [];

    // Intento 1: F-Droid
    if (!appInfo) {
        try {
            appInfo = await syncFromRepo(q, 'fdroid');
        } catch (e) {
            errors.push(`F-Droid falló: ${e.message.includes('Paquete') ? e.message : 'Error de API/descarga/scraping.'}`);
        }
    }

    // Intento 2: IzzyOnDroid
    if (!appInfo) {
        try {
            appInfo = await syncFromRepo(q, 'izzyondroid');
        } catch (e) {
            errors.push(`IzzyOnDroid falló: ${e.message.includes('Paquete') ? e.message : 'Error de API/descarga/scraping.'}`);
        }
    }

    // Intento 3: GitHub Releases
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

/* ---------------------------------
   2. ⭐️ ENDPOINT DE CATÁLOGO MASIVO (MODIFICADO para retornar inmediatamente y evitar timeout)
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
    
    // RESPUESTA INMEDIATA: Esto ayuda a evitar el timeout de Fly.io/servidores proxy.
    // El proceso real de sincronización se ejecuta en segundo plano.
    res.json({ 
        ok: true, 
        message: "Proceso de sincronización masiva iniciado en segundo plano. Los resultados se subirán a GitHub. Por favor, consulta /api/list_apps en unos minutos."
    });

    let results = [];
    let successCount = 0;
    const totalApps = POPULAR_APPS_FDROID.length + POPULAR_APPS_GITHUB.length;

    console.log(`[SYNC_MASIVO] Iniciando sincronización de ${totalApps} apps...`);

    // Sincronizar F-Droid/IzzyOnDroid
    for (const app of POPULAR_APPS_FDROID) {
        try {
            const result = await syncFromRepo(app.package, 'fdroid');
            results.push({ query: app.name, ok: true, source: result.source, packageName: result.meta.packageName, version: result.meta.version });
            successCount++;
        } catch (e) {
            try {
                const result = await syncFromRepo(app.package, 'izzyondroid');
                results.push({ query: app.name, ok: true, source: result.source, packageName: result.meta.packageName, version: result.meta.version });
                successCount++;
            } catch (e) {
                console.error(`[SYNC_MASIVO] Fallo completo para ${app.name}: ${e.message}`);
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
            console.error(`[SYNC_MASIVO] Fallo de GitHub para ${app.name}: ${e.message}`);
            results.push({ query: app.name, ok: false, message: `GitHub falló: ${e.message}` });
        }
    }

    console.log(`[SYNC_MASIVO] Finalizado. Éxito: ${successCount}/${totalApps}`);
    // No se envía respuesta HTTP aquí ya que se hizo al inicio.
});


/* ---------------------------------
   3. ENDPOINTS INDIVIDUALES (sin cambios de funcionalidad)
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
