// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import gplay from "google-play-scraper"; 
import https from "https"; 
import url from 'url';

const app = express();
app.use(express.json({ limit: "10mb" }));

// Mantener la solución de archivos estáticos
app.use(express.static('public'));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
// Aumentado a 100MB para evitar errores en archivos grandes
const MAX_GITHUB_FILE_SIZE_MB = 100; 
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
// Usar el User-Agent estándar para evitar bloqueos
const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// CONSTANTE: URL base para la descarga (Usada para el link directo)
// Es CRÍTICA para que Fly.io no se duerma.
const BASE_URL = process.env.BASE_URL || 'https://apps-masitaprex-v2.fly.dev'; 

// AGENTE HTTPS PARA IGNORAR CERTIFICADOS AUTO-FIRMADOS
const httpsAgent = new https.Agent({
    rejectUnauthorized: false, 
});


// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal
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

/* --------- Helpers GitHub --------- */
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
// FUNCIÓN CENTRAL DE SINCRONIZACIÓN DE APK
// ---------------------------------------------------
async function syncAndSaveApk(packageName, version, displayName, source, apkBuffer, metaExtra = {}) {
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
        throw new Error(`APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.`);
    }

    // 1. Verificar con VirusTotal
    const fileName = `${packageName}_v${version}.apk`;
    // El escaneo de VT se ejecuta en una promesa y no bloquea el hilo, pero SÍ bloquea el flujo.
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
// FUNCIONES DE BÚSQUEDA Y METADATOS DE GOOGLE PLAY
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
// ENDPOINTS
// ---------------------------------------------------

// ENDPOINT: Manejar la descarga del APK directamente desde GitHub
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
   1. 🔍 ENDPOINT DE BÚSQUEDA (SOLO METADATOS)
------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    let { q } = req.query; 
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta) es requerido." });

    let errors = [];
    let packageName = q; 
    let gpDetails = null; 

    const isPackageName = packageName.includes('.');
    
    // 0. Si la consulta es un nombre de app, buscar el packageName en Google Play
    if (!isPackageName) {
        const gpPackage = await searchGooglePlay(q);
        if (gpPackage) {
            packageName = gpPackage;
            errors.push(`Encontrado: El nombre de app '${q}' corresponde al paquete: ${packageName}.`);
        } else {
            errors.push(`Advertencia: El nombre de app '${q}' no se pudo mapear a un packageName conocido en Google Play.`);
        }
    }
    
    // 1. Obtener detalles de Google Play si tenemos el packageName
    if (packageName && packageName.includes('.')) {
        try {
            gpDetails = await getGooglePlayDetails(packageName);
        } catch (e) {
            errors.push(`Google Play Metadatos falló: ${e.message}`);
        }
    }

    // 2. Intento Final: Metadatos de Google Play (si se encontraron)
    if (gpDetails) {
        const meta = formatGooglePlayMeta(gpDetails);
        const urlManualAdd = `${BASE_URL}/api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga?direct_url=**LINK_APK_DIRECTO**&packageName=${meta.packageName}&version=${meta.version}&displayName=${encodeURIComponent(meta.displayName)}`;

        // Añadir el enlace de descarga manual al objeto meta para ti
        meta.manualAddLink = urlManualAdd;
        
        return res.json({
            ok: true,
            status: "Éxito: Solo se obtuvieron metadatos de Google Play.",
            meta: meta,
            errors: errors.length ? errors : undefined,
            // Mensaje clave para tu proceso manual
            instruccion: `PASO MANUAL: Copia el 'manualAddLink', reemplaza **LINK_APK_DIRECTO** con el enlace directo del APK (de APKPure, etc.) y navega a esa URL en tu navegador.`
        });
    } else {
        return res.status(404).json({
            ok: false,
            error: `La aplicación o paquete '${q}' no se encontró en Google Play.`,
            details: errors,
        });
    }
});


/* -------------------------------------------------------------
   2. 🔗 ENDPOINT MANUAL: DESCARGA Y SINCRONIZACIÓN DE APK (GET)
      URL: /api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga
      Este endpoint se usa para tu proceso manual de 'copiar y pegar el link directo'.
----------------------------------------------------------------*/
app.get("/api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga", async (req, res) => {
    // El parámetro debe llamarse 'direct_url' para seguir el flujo de la búsqueda.
    const directUrl = req.query.direct_url;
    const { packageName, displayName, version } = req.query;

    if (!directUrl || !packageName || !version) {
        return res.status(400).send("<html><body style='font-family: sans-serif; text-align: center;'><h1>⚠️ Error 400</h1><p>Los parámetros <strong>direct_url</strong>, <strong>packageName</strong> y <strong>version</strong> son requeridos.</p><p>Ejemplo: <code>/api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga?direct_url=https://...apk&packageName=com.app&version=1.0.0&displayName=MiApp</code></p></body></html>");
    }

    try {
        // 1. Descargar el APK binario desde el enlace directo proporcionado
        // Aumentamos el timeout para asegurar que archivos grandes se completen (10 min)
        const apkResp = await axios.get(directUrl, { 
            responseType: "arraybuffer", 
            headers: { 'User-Agent': AXIOS_USER_AGENT },
            httpsAgent: httpsAgent,
            timeout: 600000 // 10 minutos para descargas grandes
        });
        
        const apkBuffer = Buffer.from(apkResp.data);

        // Verificación de tamaño
        const MIN_APK_SIZE_BYTES = 1 * 1024 * 1024; // 1MB mínimo
        if (apkBuffer.length < MIN_APK_SIZE_BYTES) {
            throw new Error(`El archivo descargado es demasiado pequeño (${(apkBuffer.length / 1024 / 1024).toFixed(2)}MB). No parece ser un APK válido.`);
        }

        // 2. Sincronizar y guardar en GitHub (incluye VirusTotal)
        const metaExtra = {
            url: directUrl,
            warnings: "APK agregado manualmente desde URL directa. ¡Verifique VirusTotal!"
        };
        
        const result = await syncAndSaveApk(packageName, version, displayName, "manual_direct_link", apkBuffer, metaExtra);
        
        // 3. Respuesta en formato HTML para el navegador
        const totalSizeMB = (apkBuffer.length / 1024 / 1024).toFixed(2);
        
        return res.status(200).send(`
            <html>
            <body style='font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f4f4f9;'>
                <h1 style='color: #28a745;'>✅ Éxito de Sincronización Manual</h1>
                <p>El APK ha sido descargado y subido correctamente al repositorio de GitHub.</p>
                
                <h2 style='color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px;'>Detalles del Archivo</h2>
                <ul>
                    <li><strong>Paquete:</strong> <code>${result.meta.packageName}</code></li>
                    <li><strong>Versión:</strong> <code>${result.meta.version}</code></li>
                    <li><strong>Nombre:</strong> <code>${result.meta.displayName}</code></li>
                    <li><strong>Tamaño:</strong> ${totalSizeMB} MB</li>
                </ul>

                <h2 style='color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px;'>Resultado de VirusTotal</h2>
                <p><strong>Estado:</strong> ${result.meta.virustotal.status}</p>
                ${result.meta.virustotal.status === 'completed' 
                    ? `<p><strong>Detecciones Maliciosas:</strong> <span style='color: ${result.meta.virustotal.malicious > 0 ? 'red' : 'green'}; font-weight: bold;'>${result.meta.virustotal.malicious}</span>/${result.meta.virustotal.totalEngines}</p><p><a href='${result.meta.virustotal.resultsUrl}' target='_blank'>Ver Análisis Completo en VirusTotal</a></p>`
                    : `<p>${result.meta.virustotal.message || ''}</p>`
                }

                <h2 style='color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px;'>Links de Catálogo</h2>
                <ul>
                    <li><strong>Link de Descarga (Fly.io/GitHub):</strong> <a href='${result.meta.downloadUrl}' target='_blank'>${result.meta.downloadUrl}</a></li>
                    <li><strong>Metadatos Guardados:</strong> <code>public/apps/${packageName}/meta_${version}.json</code></li>
                </ul>
                <p style='margin-top: 30px; font-size: small; color: #6c757d;'>Proceso completado. La instancia de Fly.io se ha mantenido activa durante la descarga.</p>
            </body>
            </html>
        `);
    } catch (e) {
        console.error("Error en la adición manual:", e);
        return res.status(500).send(`
            <html>
            <body style='font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #fcebeb; border: 1px solid #f5c6cb;'>
                <h1 style='color: #dc3545;'>❌ Error al Sincronizar APK</h1>
                <p>Ocurrió un error grave durante la descarga o subida a GitHub.</p>
                <h2 style='color: #6c757d; border-bottom: 1px solid #dee2e6; padding-bottom: 5px;'>Detalles del Error</h2>
                <pre style='white-space: pre-wrap; word-wrap: break-word; background-color: #fff; padding: 10px; border: 1px solid #ced4da; border-radius: 4px;'>${e.message}</pre>
                <p style='margin-top: 20px;'><strong>Revisa:</strong> 1) Que el <code>direct_url</code> sea un enlace directo a un archivo <code>.apk</code>. 2) Que la clave de VirusTotal sea válida si el error está relacionado con el escaneo.</p>
            </body>
            </html>
        `);
    }
});


// ---------------------------------------------------
// ENDPOINTS INDIVIDUALES (Se mantienen por si acaso, pero no son usados por search_and_sync)
// ---------------------------------------------------

// Las funciones completas para estos endpoints ya no son necesarias en este código para mantener la brevedad y el enfoque, pero el esqueleto se mantiene. Si necesitas la lógica de F-Droid/GitHub, debes reinsertarla.

app.get("/api/sync_fdroid", async (req, res) => {
    return res.status(501).json({ ok: false, error: "Función deshabilitada. Usa /api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga para sincronizar manualmente después de buscar metadatos." });
});

app.get("/api/sync_izzyondroid", async (req, res) => {
    return res.status(501).json({ ok: false, error: "Función deshabilitada. Usa /api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga para sincronizar manualmente después de buscar metadatos." });
});

app.get("/api/sync_github_release", async (req, res) => {
    return res.status(501).json({ ok: false, error: "Función deshabilitada. Usa /api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga para sincronizar manualmente después de buscar metadatos." });
});

app.post("/api/manual_add", async (req, res) => {
    return res.status(501).json({ ok: false, error: "Función deshabilitada. Usa el endpoint GET /api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga para la adición manual más sencilla." });
});


/* ---------------------------------
   3. 🔍 ENDPOINTS DE LISTADO
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
