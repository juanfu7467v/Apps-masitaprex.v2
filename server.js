// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import gplay from "google-play-scraper"; 
import cheerio from "cheerio"; // Se añade para el análisis de HTML

const app = express();
app.use(express.json({ limit: "10mb" }));

// Mantener la solución de archivos estáticos
app.use(express.static('public'));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
// Usar el User-Agent estándar para evitar bloqueos
const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// CONSTANTE: URL base para la descarga (Usada para el link directo)
const BASE_URL = 'https://apps-masitaprex-v2.fly.dev';

// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal (SIN CAMBIOS)
// ----------------------------------------------------
/**
 * Envía un archivo a VirusTotal para escanear y espera el resultado.
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

    // CONSTRUIR EL ENLACE DE DESCARGA DIRECTO
    const downloadUrl = `${BASE_URL}/${apkPath}`; 

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
        downloadUrl, // Campo de URL de descarga
        virustotal: vtResult
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${packageName} v${version} (${source})`);

    return { meta, message: "APK sincronizado.", source };
}


// ---------------------------------------------------
// FUNCIÓN DE DESCARGA DE APK POR PROXY (MODIFICADA)
// ---------------------------------------------------

/**
 * Intenta descargar el APK usando un servicio de proxy de descarga (ej. basándose en apk-dl.com).
 * Se ha añadido lógica para verificar que la respuesta sea un APK y no un HTML.
 */
async function downloadApkFromProxy(packageName, appDetails) {
    if (!appDetails || !appDetails.appId) {
        throw new Error("Se requiere metadatos válidos de Google Play.");
    }
    
    const initialUrl = `https://d.apk-dl.com/details?id=${packageName}`; 
    let finalApkUrl = null;
    let htmlResponse;

    try {
        // 1. Obtener la página HTML del proxy (no el APK directamente)
        htmlResponse = await axios.get(initialUrl, { 
            responseType: "text", 
            headers: { 'User-Agent': AXIOS_USER_AGENT } 
        });
    } catch (e) {
        throw new Error(`Fallo en la solicitud inicial al proxy: ${e.message}`);
    }

    // 2. Analizar el HTML para encontrar el enlace de descarga directa del APK
    const $ = cheerio.load(htmlResponse.data);
    
    // Busca el botón de descarga o el enlace real al APK
    const downloadButton = $('a.download-btn'); 
    
    if (downloadButton.length) {
        finalApkUrl = downloadButton.attr('href');
    } else {
        throw new Error("No se pudo encontrar el enlace de descarga directo en la página proxy. Posiblemente requiere Captcha o la app no está disponible.");
    }

    if (!finalApkUrl || !finalApkUrl.endsWith('.apk')) {
        throw new Error("Enlace de descarga inválido encontrado o es una redirección no deseada.");
    }

    // 3. Descargar el APK binario desde el enlace final
    let apkResp;
    try {
        apkResp = await axios.get(finalApkUrl, {
            responseType: "arraybuffer",
            headers: { 'User-Agent': AXIOS_USER_AGENT }
        });

        // 🚨 VERIFICACIÓN CRÍTICA: Asegurarse de que el Content-Type sea un APK (no un HTML/Error)
        const contentType = apkResp.headers['content-type'];
        if (!contentType || !contentType.includes('application/vnd.android.package-archive')) {
             throw new Error(`El proxy devolvió un tipo de contenido inesperado: ${contentType}`);
        }
        
        const apkBuffer = Buffer.from(apkResp.data);

        // 🚨 VERIFICACIÓN DE TAMAÑO: Un APK real de WhatsApp debe tener más de ~10MB.
        const MIN_APK_SIZE_BYTES = 5 * 1024 * 1024; // 5MB mínimo heurístico
        if (apkBuffer.length < MIN_APK_SIZE_BYTES) {
            throw new Error(`El archivo descargado es demasiado pequeño (${(apkBuffer.length / 1024 / 1024).toFixed(2)}MB). Probablemente es un error o HTML.`);
        }


        // 4. Obtener versión y nombre de los metadatos de Google Play
        const version = appDetails.version || 'unknown';
        const displayName = appDetails.title || packageName;

        // 5. Preparar metadatos extendidos
        const metaExtra = {
            iconUrl: appDetails.icon,
            summary: appDetails.summary,
            description: appDetails.descriptionHTML,
            screenshots: appDetails.screenshots || [],
            warnings: "ADVERTENCIA: Descarga de APK de fuente Proxy/Terceros. ¡Verifique VirusTotal!"
        };

        // 6. Sincronizar y guardar
        return syncAndSaveApk(packageName, version, displayName, "apk_proxy_dl", apkBuffer, metaExtra);

    } catch (e) {
        console.error("Error durante la descarga final del APK desde el proxy:", e.message);
        throw new Error(`Fallo en la descarga final del APK. Causa: ${e.message}`);
    }
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

/**
 * Obtiene metadatos completos de una app en Google Play.
 * Retorna los detalles COMPLETOS (gplay.app result) para usar en el proxy.
 */
async function getGooglePlayDetails(packageName) {
    try {
        const appDetails = await gplay.app({ appId: packageName, lang: 'es', country: 'us' });
        return appDetails;
    } catch (e) {
        throw new Error(`No se pudieron obtener metadatos de Google Play para ${packageName}.`);
    }
}

/**
 * Formatea los detalles para el resultado final de solo metadatos.
 */
function formatGooglePlayMeta(appDetails) {
    return {
        source: "google_play_scraper",
        packageName: appDetails.appId,
        displayName: appDetails.title,
        version: appDetails.version || 'unknown',
        iconUrl: appDetails.icon,
        summary: appDetails.summary,
        description: appDetails.descriptionHTML,
        screenshots: appDetails.screenshots || [],
        warnings: "ADVERTENCIA: Solo se obtuvieron metadatos. El APK no se pudo descargar desde esta herramienta.",
        size: 'N/A', 
        addedAt: new Date().toISOString(),
        apkPath: 'N/A (Solo metadatos)',
        downloadUrl: 'N/A (Solo metadatos)' 
    };
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
    // ... (Lógica de F-Droid/IzzyOnDroid para obtener APK y metadatos)
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
    // ... (Lógica de GitHub Release para obtener APK y metadatos)
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

// ... (El resto de las funciones: syncPopularAppsInBackground, /api/sync_*, /api/list_apps, etc. no han sido modificadas) ...

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

// 🚨 ENDPOINT: Manejar la descarga del APK directamente desde GitHub (Sin Cambios)
app.get("/public/apps/:packageName/apk_:version.apk", async (req, res) => {
    const { packageName, version } = req.params;
    const pathInRepo = `public/apps/${packageName}/apk_${version}.apk`;
    const fileName = `${packageName}_v${version}.apk`;

    try {
        // 1. Obtener el contenido del archivo de GitHub
        const file = await octokit.repos.getContent({
            owner: G_OWNER,
            repo: G_REPO,
            path: pathInRepo,
            mediaType: {
                format: "raw", // Solicitar el contenido del archivo en formato raw (no base64)
            }
        });

        // 2. Establecer las cabeceras para forzar la descarga
        res.setHeader('Content-Type', 'application/vnd.android.package-archive');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        
        // 3. Enviar el contenido del archivo (que viene como buffer/string)
        res.send(file.data);

    } catch (e) {
        console.error(`Error al servir el APK ${pathInRepo} desde GitHub:`, e.message);
        if (e.status === 404) {
            return res.status(404).send("Error: El APK solicitado no fue encontrado en el repositorio.");
        }
        return res.status(500).send("Error interno al intentar descargar el APK.");
    }
});


/* ---------------------------------
   1. 🔍 ENDPOINT DE BÚSQUEDA Y SINCRONIZACIÓN (SIN CAMBIOS)
------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    let { q } = req.query; 
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta) es requerido." });

    let appInfo = null;
    let errors = [];
    let packageName = q; 
    let gpDetails = null; // Almacena los detalles de Google Play si se encuentran

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
    
    // 0.5 Obtener detalles de Google Play si tenemos el packageName (necesario para el proxy)
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
    
    // 4. Intento: Proxy de descarga de APK (Nuevo Fallback Comercial)
    if (!appInfo && gpDetails) {
        try {
            // Se llama a la función corregida
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
        return res.json({
            ok: true,
            status: `Éxito: Proceso completado desde ${appInfo.source}`,
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
