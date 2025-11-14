// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import gplay from "google-play-scraper"; 

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const BASE_URL = process.env.BASE_URL; // <--- NUEVA CONSTANTE
const MAX_GITHUB_FILE_SIZE_MB = 100;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// ----------------------------------------------------
// NUEVA FUNCIÓN HELPER: Generar URL de Descarga
// ----------------------------------------------------
function generateDownloadUrl(apkPath) {
    if (!BASE_URL || apkPath.startsWith('N/A')) {
        return "URL_NO_DISPONIBLE (Falta BASE_URL o APK no sincronizado)";
    }
    // Asegurarse de que la ruta sea correcta. Reemplazar 'public/' que es la ruta interna
    // con la ruta base pública.
    const cleanPath = apkPath.replace(/^public\//, '');
    
    // Devolver la URL completa
    return `${BASE_URL.replace(/\/$/, '')}/${cleanPath}`;
}


// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal (SIN CAMBIOS)
// ----------------------------------------------------
async function scanWithVirusTotal(apkBuffer, fileName) {
    if (!VIRUSTOTAL_API_KEY) {
        return { message: "Clave de VirusTotal no configurada. Saltando el escaneo.", status: "skipped" };
    }
    // ... (rest of the VirusTotal logic remains the same)
    const form = new FormData();
    form.append('file', apkBuffer, {
        filename: fileName,
        contentType: 'application/vnd.android.package-archive',
    });

    try {
        const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': VIRUSTOTAL_API_KEY, 
            },
            maxBodyLength: Infinity,
        });
        
        const analysisId = uploadResponse.data.data.id;
        
        let checks = 0;
        
        while (checks < 10) { 
            await new Promise(resolve => setTimeout(resolve, 5000)); 
            
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

/* --------- Helpers GitHub (SIN CAMBIOS) --------- */
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
// FUNCIÓN CENTRAL DE SINCRONIZACIÓN DE APK (SIN CAMBIOS)
// ---------------------------------------------------
async function syncAndSaveApk(packageName, version, displayName, source, apkBuffer, metaExtra = {}) {
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
        throw new Error(`APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.`);
    }

    // 1. Verificar con VirusTotal
    const fileName = `${packageName}_v${version}.apk`;
    const vtResult = await scanWithVirusTotal(apkBuffer, fileName);

    if (vtResult.status === "completed" && vtResult.malicious > 0) {
        throw new Error(`Subida bloqueada: VirusTotal encontró ${vtResult.malicious} detecciones maliciosas.`);
    }

    // 2. Guardar APK en GitHub
    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${packageName} v${version} (${source})`);

    // 3. Crear y guardar Metadatos
    const meta = {
        source,
        packageName,
        displayName: displayName || packageName, 
        version,
        iconUrl: metaExtra.iconUrl || null,
        
        // Contenido
        summary: metaExtra.summary || 'No summary available.',
        description: metaExtra.description || 'No description available.',
        screenshots: metaExtra.screenshots || [],
        warnings: metaExtra.warnings || `APK sincronizado desde ${source}. Se recomienda precaución.`,
        
        // Campos técnicos:
        size: apkBuffer.length,
        addedAt: new Date().toISOString(),
        apkPath,
        virustotal: vtResult
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${packageName} v${version} (${source})`);

    return { meta, message: "APK sincronizado.", source, downloadUrl: generateDownloadUrl(apkPath) }; // <-- Retornar URL aquí
}


// ---------------------------------------------------
// NUEVA FUNCIÓN DE DESCARGA DE APK POR PROXY (SIN CAMBIOS)
// ---------------------------------------------------
async function downloadApkFromProxy(packageName, appDetails) {
    if (!appDetails || !appDetails.appId) {
        throw new Error("Se requiere metadatos válidos de Google Play.");
    }
    
    const downloadUrl = `https://d.apk-dl.com/details?id=${packageName}`; 
    
    let apkResp;
    try {
        apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer", 
            headers: { 'User-Agent': AXIOS_USER_AGENT } 
        });
    } catch (e) {
        const altDownloadUrl = `https://m.apk-dl.com/details?id=${packageName}`;
        apkResp = await axios.get(altDownloadUrl, { 
            responseType: "arraybuffer", 
            headers: { 'User-Agent': AXIOS_USER_AGENT } 
        });
    }

    const apkBuffer = Buffer.from(apkResp.data);

    const version = appDetails.version || 'unknown';
    const displayName = appDetails.title || packageName;

    const metaExtra = {
        iconUrl: appDetails.icon,
        summary: appDetails.summary,
        description: appDetails.descriptionHTML,
        screenshots: appDetails.screenshots || [],
        warnings: "ADVERTENCIA: Descarga de APK de fuente Proxy/Terceros. ¡Verifique VirusTotal!"
    };

    return syncAndSaveApk(packageName, version, displayName, "apk_proxy_dl", apkBuffer, metaExtra);
}


// ---------------------------------------------------
// FUNCIONES DE BÚSQUEDA Y METADATOS DE GOOGLE PLAY (SIN CAMBIOS)
// ---------------------------------------------------
async function searchGooglePlay(appName) {
    try {
        const results = await gplay.search({ term: appName, num: 5, lang: 'es', country: 'us' });
        return (results && results.length > 0) ? results[0].appId : null;
    } catch (e) {
        console.error("Error en searchGooglePlay:", e.message);
        return null;
    }
}

async function getGooglePlayDetails(packageName) {
    try {
        const appDetails = await gplay.app({ appId: packageName, lang: 'es', country: 'us' });
        return appDetails;
    } catch (e) {
        throw new Error(`No se pudieron obtener metadatos de Google Play para ${packageName}.`);
    }
}

function formatGooglePlayMeta(appDetails) {
    const meta = {
        source: "google_play_scraper",
        packageName: appDetails.appId,
        displayName: appDetails.title,
        version: appDetails.version || 'unknown',
        iconUrl: appDetails.icon,
        summary: appDetails.summary,
        description: appDetails.descriptionHTML,
        screenshots: appDetails.screenshots || [],
        warnings: "ADVERTENCIA: Solo se obtuvieron metadatos. El APK no se puede descargar desde Google Play Store con esta herramienta.",
        size: 'N/A', 
        addedAt: new Date().toISOString(),
        apkPath: 'N/A (Solo metadatos)'
    };
    return meta;
}


// ---------------------------------------------------
// OTRAS FUNCIONES (SIN CAMBIOS)
// ---------------------------------------------------
async function findPackageNameByAppName(appName, source) {
    const metaIndexUrl = source === 'fdroid' 
        ? `https://f-droid.org/repo/index.json`
        : `https://apt.izzysoft.de/fdroid/repo/index.json`;

    try {
        const query = appName.toLowerCase();
        const response = await axios.get(metaIndexUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
        const appInfoList = response.data.apps;
        const foundApp = appInfoList.find(app => {
            const name = app.name ? app.name.toLowerCase() : '';
            const localizedName = app.localized?.['en-US']?.name ? app.localized['en-US'].name.toLowerCase() : '';
            return name.includes(query) || localizedName.includes(query);
        });
        return foundApp ? foundApp.packageName : null;
    } catch (e) {
        console.error(`Error al buscar nombre en ${source}:`, e.message);
        return null;
    }
}

async function syncFromRepo(packageName, source) {
    const apiUrl = source === 'fdroid' ? `https://f-droid.org/repo/index-v1.json` : `https://apt.izzysoft.de/fdroid/repo/index-v1.json`;
    const repoBaseUrl = source === 'fdroid' ? 'https://f-droid.org/repo/' : 'https://apt.izzysoft.de/fdroid/repo/';

    const indexResponse = await axios.get(apiUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
    const { packages } = indexResponse.data;
    const appData = packages[packageName];

    if (!appData) {
        throw new Error(`Paquete ${packageName} no encontrado en ${source}.`);
    }

    const latestVersion = Object.keys(appData).sort().pop();
    const latestMeta = appData[latestVersion].pop(); 

    const version = latestMeta.versionName || latestVersion;
    const apkFileName = latestMeta.apkName;
    const downloadUrl = repoBaseUrl + apkFileName;

    let extendedMeta = {};
    try {
        const metaIndexUrl = source === 'fdroid' ? `https://f-droid.org/repo/index.json` : `https://apt.izzysoft.de/fdroid/repo/index.json`;
        const metaIndexResponse = await axios.get(metaIndexUrl, { headers: { 'User-Agent': AXIOS_USER_AGENT } });
        const foundApp = metaIndexResponse.data.apps.find(app => app.packageName === packageName);

        if (foundApp) {
            extendedMeta = {
                summary: foundApp.localized?.['en-US']?.summary || foundApp.summary,
                description: foundApp.localized?.['en-US']?.description || foundApp.description, 
                screenshots: (foundApp.localized?.['en-US']?.screenshots || foundApp.screenshots || []).map(fileName => repoBaseUrl + 'screenshots/' + fileName),
                warnings: foundApp.localized?.['en-US']?.issue || foundApp.issue,
            };
        }
    } catch (e) {
        console.warn(`No se pudieron obtener metadatos extendidos para ${packageName} de ${source}.`);
    }
    
    const apkResp = await axios.get(downloadUrl, { responseType: "arraybuffer", headers: { 'User-Agent': AXIOS_USER_AGENT } });
    const apkBuffer = Buffer.from(apkResp.data);

    const metaExtra = {
        ...extendedMeta,
        iconUrl: latestMeta.icon ? repoBaseUrl + 'icons/' + latestMeta.icon : null,
    };

    return syncAndSaveApk(packageName, version, latestMeta.localized || packageName, source, apkBuffer, metaExtra);
}

async function syncFromGitHubRelease(repo, packageName) {
    const [owner, repoName] = repo.split("/");
    const pName = packageName || repoName;
    
    const release = await octokit.repos.getLatestRelease({ owner, repo: repoName });
    const version = release.data.tag_name || release.data.name || "unknown";
    
    let assetUrl = null;
    let assetName = null;
    for (const a of release.data.assets) {
        if (a.name.endsWith(".apk")) {
            assetUrl = a.browser_download_url;
            assetName = a.name;
            break;
        }
    }
    
    if (!assetUrl) {
        throw new Error("No se encontró ningún asset .apk en el último release de GitHub.");
    }

    const apkResp = await axios.get(assetUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);

    const releaseBody = release.data.body || "";
    const metaExtra = {
        summary: releaseBody.split('\n')[0].substring(0, 100) + '...', 
        description: releaseBody,
        warnings: "Esta es una descarga de GitHub Release. Se recomienda siempre verificar la fuente.",
    };

    return syncAndSaveApk(pName, version, pName, "github_release", apkBuffer, metaExtra);
}

// ... (Popular Apps and Background Sync remain the same) ...

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

function syncPopularAppsInBackground() {
    console.log("--- INICIANDO PROCESO DE SINCRONIZACIÓN MASIVA EN SEGUNDO PLANO ---");
    
    let successCount = 0;
    
    const runSync = async (app, type) => {
        try {
            let result;
            if (type === 'fdroid') {
                result = await syncFromRepo(app.package, 'fdroid');
            } else if (type === 'izzyondroid') {
                result = await syncFromRepo(app.package, 'izzyondroid');
            } else if (type === 'github') {
                result = await syncFromGitHubRelease(app.repo, app.package);
            }
            console.log(`[ÉXITO] Sincronizado ${app.name} (${result.source})`);
            successCount++;
        } catch (e) {
            console.error(`[FALLO] ${app.name} (${type}): ${e.message}`);
        }
    };
    
    (async () => {
        for (const app of POPULAR_APPS_FDROID) {
            try {
                await runSync(app, 'fdroid');
            } catch (e) {
                await runSync(app, 'izzyondroid');
            }
        }
        
        for (const app of POPULAR_APPS_GITHUB) {
            await runSync(app, 'github');
        }
        
        console.log(`--- PROCESO DE SINCRONIZACIÓN MASIVA FINALIZADO: ${successCount} apps sincronizadas. ---`);
    })();
    
    return { 
        message: "Sincronización masiva iniciada en segundo plano.",
        totalApps: POPULAR_APPS_FDROID.length + POPULAR_APPS_GITHUB.length,
    };
}


// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   1. 🔍 ENDPOINT DE BÚSQUEDA Y SINCRONIZACIÓN (MODIFICADO para devolver URL)
------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    let { q } = req.query; 
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta) es requerido." });

    let appInfo = null;
    let errors = [];
    let packageName = q; 
    let gpDetails = null;

    const isPackageName = packageName.includes('.');
    const isRepo = packageName.includes('/');
    
    // 0. Si la consulta es un nombre de app, buscar el packageName en Google Play
    if (!isPackageName && !isRepo) {
        console.log(`Buscando PackageName para el nombre: ${q} en Google Play.`);
        const gpPackage = await searchGooglePlay(q);
        if (gpPackage) {
            packageName = gpPackage;
            errors.push(`Encontrado: El nombre de app '${q}' corresponde al paquete: ${packageName}.`);
        } else {
            errors.push(`Advertencia: El nombre de app '${q}' no se pudo mapear a un packageName conocido.`);
        }
    }
    
    // 0.5 Obtener detalles de Google Play si tenemos el packageName
    if (packageName && packageName.includes('.')) {
        try {
            gpDetails = await getGooglePlayDetails(packageName);
        } catch (e) {
            errors.push(`Google Play Metadatos falló (pre-descarga): ${e.message}`);
        }
    }


    // ** INICIO DE LA CASCADA DE DESCARGA DE APK **

    // 1. Intento: GitHub Releases
    if (!appInfo && packageName.includes('/')) {
        try {
            appInfo = await syncFromGitHubRelease(packageName);
            errors.push(`Éxito: APK sincronizado desde GitHub Releases.`);
        } catch (e) {
            errors.push(`GitHub Releases falló: ${e.message.includes('No se encontró') ? e.message : 'Error de API/descarga.'}`);
        }
    }

    // 2. Intento: F-Droid
    if (!appInfo && packageName && packageName.includes('.')) {
        try {
            appInfo = await syncFromRepo(packageName, 'fdroid');
            errors.push(`Éxito: APK sincronizado desde F-Droid.`);
        } catch (e) {
            errors.push(`F-Droid falló: ${e.message.includes('Paquete') ? e.message : e.message}`);
        }
    }

    // 3. Intento: IzzyOnDroid
    if (!appInfo && packageName && packageName.includes('.')) {
        try {
            appInfo = await syncFromRepo(packageName, 'izzyondroid');
            errors.push(`Éxito: APK sincronizado desde IzzyOnDroid.`);
        } catch (e) {
            errors.push(`IzzyOnDroid falló: ${e.message.includes('Paquete') ? e.message : e.message}`);
        }
    }
    
    // 4. Intento: Proxy de descarga de APK
    if (!appInfo && gpDetails) {
        try {
            appInfo = await downloadApkFromProxy(packageName, gpDetails); 
            errors.push(`Éxito: APK sincronizado desde Proxy de Descarga.`);
        } catch (e) {
            errors.push(`Proxy de Descarga falló: ${e.message}`);
        }
    }
    
    // ** FIN DE LA CASCADA DE DESCARGA DE APK **

    // 5. Intento Final: Metadatos de Google Play (si no se sincronizó nada pero tenemos los detalles)
    if (!appInfo && gpDetails) {
        const meta = formatGooglePlayMeta(gpDetails);
        appInfo = { meta, source: "Google Play Metadata Only" };
        errors.push("ADVERTENCIA: Se obtuvieron metadatos de Google Play. No se pudo obtener el APK.");
    }


    if (appInfo) {
        // RESPUESTA MODIFICADA PARA INCLUIR EL LINK DE DESCARGA
        return res.json({
            ok: true,
            status: `Éxito: Proceso completado desde ${appInfo.source}`,
            downloadUrl: appInfo.downloadUrl || 'N/A (Solo metadatos)', // <-- NUEVO CAMPO
            meta: appInfo.meta,
            errors: errors.length ? errors : undefined,
        });
    } else {
        return res.status(404).json({
            ok: false,
            error: `La aplicación o paquete '${q}' no se encontró ni se pudo sincronizar en ninguna fuente.`,
            details: errors,
        });
    }
});


/* ---------------------------------
   2. ⭐️ ENDPOINT DE CATÁLOGO MASIVO (SIN CAMBIOS)
------------------------------------*/
app.post("/api/sync_popular_apps", (req, res) => {
    const result = syncPopularAppsInBackground();
    
    return res.json({ 
        ok: true, 
        ...result,
        warning: "La sincronización masiva se ejecuta en segundo plano. Revisa tu repositorio y usa /api/list_apps en unos minutos para confirmar los resultados."
    });
});


/* ---------------------------------
   3. ENDPOINTS INDIVIDUALES (SIN CAMBIOS)
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

        const metaExtra = {
            url,
            warnings: "APK agregado manualmente. Se recomienda precaución."
        };
        
        const result = await syncAndSaveApk(packageName, version, displayName, "manual", apkBuffer, metaExtra);
        
        return res.json({ 
            ok: true, 
            ...result,
            virustotal: result.meta.virustotal 
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   4. 🔍 ENDPOINTS DE LISTADO (SIN CAMBIOS)
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
