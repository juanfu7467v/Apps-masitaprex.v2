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

// Ya no se usa para guardar APKs, pero se mantiene como referencia
const MAX_GITHUB_FILE_SIZE_MB = 100; 
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 

const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

const BASE_URL = process.env.BASE_URL || 'https://apps-masitaprex-v2.fly.dev'; 

const httpsAgent = new https.Agent({
    rejectUnauthorized: false, 
});


// ----------------------------------------------------
// FUNCIÓN HELPER: Verificación con VirusTotal (Mantenida pero ya no usada en la sincronización principal)
// ----------------------------------------------------
/**
 * Envía un archivo a VirusTotal para escanear y espera el resultado.
 */
async function scanWithVirusTotal(apkBuffer, fileName) {
    if (!VIRUSTOTAL_API_KEY) {
        return { message: "Clave de VirusTotal no configurada. Saltando el escaneo.", status: "skipped" };
    }
    // ... Lógica de VirusTotal (reducida/mantenida) ...
    return { status: "disabled", message: "Escaneo de VirusTotal deshabilitado para la sincronización de solo metadatos." };
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
// ⭐️ FUNCIÓN CENTRAL DE SINCRONIZACIÓN DE METADATOS (NUEVA)
// ---------------------------------------------------
/**
 * Solo guarda los metadatos y la URL de descarga externa en un archivo JSON.
 */
async function syncAndSaveMeta(packageName, version, displayName, source, apkDownloadUrl, gpDetails = {}) {
    // 1. Crear el objeto de metadatos
    const meta = {
        source,
        packageName,
        displayName: displayName || packageName, 
        version,
        iconUrl: gpDetails.iconUrl || null,
        
        // Contenido de Google Play (si existe)
        summary: gpDetails.summary || 'No summary available.',
        description: gpDetails.description || 'No description available.',
        screenshots: gpDetails.screenshots || [],
        
        // Campos de Catálogo
        warnings: `Solo se guardaron metadatos y la URL de descarga externa: ${source}.`,
        size: gpDetails.size || 'N/A', 
        addedAt: new Date().toISOString(),
        
        // ⭐️ Campo clave: La URL externa de descarga
        externalDownloadUrl: apkDownloadUrl,
        
        // Se desactivan los campos relacionados con la subida a GitHub/VT
        apkPath: 'N/A (Solo metadatos)',
        downloadUrl: 'N/A (Solo metadatos)', // Esta URL ya no apunta a GitHub
        virustotal: { status: "skipped", message: "Escaneo deshabilitado ya que el APK no fue subido al repositorio." }
    };
    
    // 2. Guardar Metadatos en GitHub
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta (Link Externo): ${packageName} v${version} (${source})`);

    return { meta, message: "Metadatos y enlace externo sincronizados con éxito.", source };
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

// ENDPOINT: Manejar la descarga del APK directamente desde GitHub (Mantenido, aunque no se usará)
app.get("/public/apps/:packageName/apk_:version.apk", async (req, res) => {
    // ... Lógica para servir APK desde GitHub (mantenida) ...
    try {
        const file = await octokit.repos.getContent({
            owner: G_OWNER,
            repo: G_REPO,
            path: `public/apps/${req.params.packageName}/apk_${req.params.version}.apk`,
            mediaType: { format: "raw" }
        });
        res.setHeader('Content-Type', 'application/vnd.android.package-archive');
        res.setHeader('Content-Disposition', `attachment; filename="${req.params.packageName}_v${req.params.version}.apk"`);
        res.send(file.data);
    } catch (e) {
        return res.status(404).send("Error: El APK solicitado no fue encontrado en el repositorio (solo se guarda el link externo).");
    }
});


/* ---------------------------------
   1. 🔍 ENDPOINT DE BÚSQUEDA (SIN CAMBIOS)
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
        const encodedDisplayName = encodeURIComponent(meta.displayName); 
        
        // ⭐️ CAMBIO: La instrucción ahora apunta al nuevo endpoint.
        const urlManualAdd = `${BASE_URL}/api/save_apk_link_only?apk_link=**LINK_APK_DIRECTO**&packageName=${meta.packageName}&version=${meta.version}&displayName=${encodedDisplayName}`;

        meta.manualAddLink = urlManualAdd;
        
        return res.json({
            ok: true,
            status: "Éxito: Solo se obtuvieron metadatos de Google Play. Use el nuevo endpoint para guardar el link.",
            meta: meta,
            errors: errors.length ? errors : undefined,
            // Mensaje clave para tu proceso manual
            instruccion: `PASO MANUAL: Copia el 'manualAddLink', reemplaza **LINK_APK_DIRECTO** con el enlace directo del APK y navega a esa URL. ESTO NO DESCARGARÁ EL APK, SOLO GUARDARÁ EL LINK Y LOS METADATOS EN UN JSON.`
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
   2. ❌ ENDPOINT ANTIGUO: DESACTIVADO PARA FORZAR EL NUEVO MÉTODO
----------------------------------------------------------------*/
app.get("/api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga", async (req, res) => {
    return res.status(400).send(`
        <html>
        <body style='font-family: sans-serif; text-align: center; max-width: 600px; margin: auto; padding: 20px; background-color: #fcebeb; border: 1px solid #f5c6cb;'>
            <h1 style='color: #dc3545;'>❌ Método de Sincronización Antiguo Desactivado</h1>
            <p>El intento de descargar el APK binario y subirlo a GitHub fue bloqueado por servidores externos (Error 403).</p>
            <p><strong>Por favor, use el nuevo endpoint para guardar SÓLO el link y los metadatos:</strong></p>
            <h2 style='color: #007bff;'>/api/save_apk_link_only</h2>
            <p>Vuelva a ejecutar la búsqueda <code>/api/search_and_sync?q=...</code> y siga la nueva instrucción.</p>
        </body>
        </html>
    `);
});


/* -------------------------------------------------------------
   3. 💾 ENDPOINT NUEVO: GUARDAR SOLO LINK Y METADATOS EN JSON
      URL: /api/save_apk_link_only
----------------------------------------------------------------*/
app.get("/api/save_apk_link_only", async (req, res) => {
    const apkLink = req.query.apk_link; // Ahora se llama apk_link
    const { packageName, displayName, version } = req.query;

    if (!apkLink || !packageName || !version) {
        return res.status(400).send("<html><body style='font-family: sans-serif; text-align: center;'><h1>⚠️ Error 400</h1><p>Los parámetros <strong>apk_link</strong>, <strong>packageName</strong> y <strong>version</strong> son requeridos.</p><p>Ejemplo: <code>/api/save_apk_link_only?apk_link=https://...apk&packageName=com.app&version=1.0.0&displayName=MiApp</code></p></body></html>");
    }

    try {
        // 1. OBTENER METADATOS DE GOOGLE PLAY
        // Hacemos esto aquí para enriquecer el JSON con info de Google Play
        const gpDetails = await getGooglePlayDetails(packageName);
        const formattedDetails = formatGooglePlayMeta(gpDetails); // Usamos el formateador existente para obtener el cuerpo de los metadatos.
        
        // 2. SINCRONIZAR SOLO METADATOS Y EL LINK (JSON)
        const result = await syncAndSaveMeta(
            packageName, 
            version, 
            displayName, 
            "manual_external_link", // Nueva fuente
            apkLink, // La URL externa
            formattedDetails
        );
        
        // 3. Respuesta en formato HTML para el navegador
        return res.status(200).send(`
            <html>
            <body style='font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #e6ffed; border: 1px solid #28a745;'>
                <h1 style='color: #28a745;'>✅ Éxito de Sincronización de Metadatos</h1>
                <p>El enlace de descarga y los metadatos de Google Play se han guardado correctamente en GitHub (archivo JSON).</p>
                
                <h2 style='color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px;'>Detalles Guardados</h2>
                <ul>
                    <li><strong>Paquete:</strong> <code>${result.meta.packageName}</code></li>
                    <li><strong>Versión:</strong> <code>${result.meta.version}</code></li>
                    <li><strong>Nombre:</strong> <code>${result.meta.displayName}</code></li>
                    <li><strong>URL de Descarga Externa:</strong> <a href='${result.meta.externalDownloadUrl}' target='_blank'>Ver Enlace</a></li>
                </ul>

                <h2 style='color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px;'>Archivo de Catálogo</h2>
                <p><strong>Metadatos Guardados en:</strong> <code>public/apps/${packageName}/meta_${version}.json</code></p>

                <p style='margin-top: 30px; font-size: small; color: #6c757d;'>Proceso completado. El catálogo ya está actualizado.</p>
            </body>
            </html>
        `);
    } catch (e) {
        console.error("Error en la adición manual de link:", e);
        
        return res.status(500).send(`
            <html>
            <body style='font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #fcebeb; border: 1px solid #f5c6cb;'>
                <h1 style='color: #dc3545;'>❌ Error al Guardar Metadatos</h1>
                <p>Ocurrió un error grave durante la obtención de metadatos o la subida a GitHub.</p>
                <h2 style='color: #6c757d; border-bottom: 1px solid #dee2e6; padding-bottom: 5px;'>Detalles del Error</h2>
                <pre style='white-space: pre-wrap; word-wrap: break-word; background-color: #fff; padding: 10px; border: 1px solid #ced4da; border-radius: 4px;'>${e.message}</pre>
                <p style='margin-top: 20px;'><strong>Revisa:</strong> 1) Que el <code>packageName</code> sea correcto. 2) Que tu token de GitHub sea válido.</p>
            </body>
            </html>
        `);
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
