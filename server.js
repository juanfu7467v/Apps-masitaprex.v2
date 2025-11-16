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
// ⭐️ FUNCIÓN CENTRAL DE SINCRONIZACIÓN DE METADATOS (MODIFICADA)
// ---------------------------------------------------
/**
 * Guarda el objeto completo de Google Play (gpDetails) junto con la URL externa en un archivo JSON.
 */
async function syncAndSaveMeta(packageName, version, source, apkDownloadUrl, gpDetails) {
    
    // 1. Crear el objeto FINAL de metadatos, incluyendo TODOS los campos de Google Play.
    // Usamos el resultado crudo de gplay.app y le agregamos nuestros campos.
    const finalMeta = {
        ...gpDetails, // Incluye todos los campos como title, summary, descriptionHTML, etc.
        
        // Sobrescribir/Agregar campos clave
        source,
        packageName,
        version: version || gpDetails.version || 'unknown', 
        addedAt: new Date().toISOString(),
        
        // ⭐️ Campo clave: La URL externa de descarga
        externalDownloadUrl: apkDownloadUrl,
        
        // Campos de Catálogo/Advertencias
        warnings: `Metadatos sincronizados desde Google Play. Enlace de descarga externo guardado.`,
        apkPath: 'N/A (Solo metadatos)',
        downloadUrl: 'N/A (Solo metadatos)', 
        virustotal: { status: "skipped", message: "Escaneo deshabilitado ya que el APK no fue subido al repositorio." }
    };
    
    // 2. Guardar Metadatos en GitHub
    // Usamos el 'version' real o el proporcionado para nombrar el archivo.
    const versionToUse = version || finalMeta.version || 'latest';
    
    const metaPath = `public/apps/${packageName}/meta_${versionToUse.replace(/[./]/g, '_')}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(finalMeta, null, 2)).toString("base64"), `Sincronizar Meta (Link Externo): ${packageName} v${versionToUse} (${source})`);

    return { meta: finalMeta, message: "Metadatos y enlace externo sincronizados con éxito.", source };
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
 */
async function getGooglePlayDetails(packageName) {
    try {
        const appDetails = await gplay.app({ appId: packageName, lang: 'es', country: 'us' });
        return appDetails;
    } catch (e) {
        throw new Error(`No se pudieron obtener metadatos de Google Play para ${packageName}.`);
    }
}


// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

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


/* -----------------------------------------------------
   1. 🚀 ENDPOINT UNIFICADO: BÚSQUEDA Y SINCRONIZACIÓN
      URL: /api/search_and_sync?q=...&apk_link=...&version=...
--------------------------------------------------------*/
app.get("/api/search_and_sync", async (req, res) => {
    let { q, apk_link, version } = req.query; 
    
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
    
    if (!gpDetails) {
         return res.status(404).json({
            ok: false,
            error: `La aplicación o paquete '${q}' no se encontró en Google Play o falló la conexión.`,
            details: errors,
        });
    }

    // 2. SINCRONIZACIÓN AUTOMÁTICA si se proporciona el link
    if (apk_link && version) {
        try {
            const displayName = gpDetails.title;
            const result = await syncAndSaveMeta(
                packageName, 
                version, // Usamos la versión proporcionada en la URL
                "manual_external_link",
                apk_link, 
                gpDetails // Objeto completo de Google Play
            );
            
            const fileUrl = `${BASE_URL}/public/apps/${packageName}/meta_${version.replace(/[./]/g, '_')}.json`;
            
            return res.json({
                ok: true,
                status: "Éxito: Metadatos y link de APK guardados en un solo paso.",
                meta: result.meta,
                file_url: fileUrl,
                details: errors.length ? errors : undefined,
                instruccion: `¡Sincronización completa! El archivo JSON con todos los metadatos y el enlace externo ha sido guardado en GitHub.`
            });

        } catch (e) {
            console.error("Error en la sincronización automática:", e);
             return res.status(500).json({
                ok: false,
                error: `Error al guardar en GitHub: ${e.message}. Asegúrate de que la versión no contenga caracteres inválidos para el nombre del archivo.`,
                details: errors,
            });
        }
    }


    // 3. RESPUESTA MANUAL si NO se proporciona el link (comportamiento anterior)
    const encodedDisplayName = encodeURIComponent(gpDetails.title); 
    
    // Instrucción para el paso final (requiere la versión)
    const urlManualAdd = `${BASE_URL}/api/search_and_sync?q=${packageName}&apk_link=**LINK_APK_DIRECTO**&version=**VERSION_REAL_APK**`;

    
    return res.json({
        ok: true,
        status: "Éxito: Metadatos de Google Play obtenidos. Se requiere el link y la versión para guardar.",
        gpDetails: gpDetails, // Devolvemos los detalles completos
        errors: errors.length ? errors : undefined,
        instruccion: `PASO MANUAL: Copia el 'manualAddLink', reemplaza **LINK_APK_DIRECTO** con el enlace directo del APK, reemplaza **VERSION_REAL_APK** con el número de versión (ej: 533.0.0.47.109) y navega a esa URL para guardar el JSON.`,
        manualAddLink: urlManualAdd
    });
    
});


/* -------------------------------------------------------------
   2. ❌ ENDPOINT ANTIGUO: DESACTIVADO 
----------------------------------------------------------------*/
app.get("/api/habre_este_link_y_seguido_pega_el_link_directo_de_descarga", async (req, res) => {
    return res.status(400).send(`
        <html>
        <body style='font-family: sans-serif; text-align: center; max-width: 600px; margin: auto; padding: 20px; background-color: #fcebeb; border: 1px solid #f5c6cb;'>
            <h1 style='color: #dc3545;'>❌ Método de Sincronización Antiguo Desactivado</h1>
            <p><strong>Por favor, use el nuevo método unificado:</strong></p>
            <h2 style='color: #007bff;'>/api/search_and_sync?q=...&apk_link=...&version=...</h2>
            <p>Ejecute <code>/api/search_and_sync?q=Messenger</code> primero para obtener el paquete si no lo conoce, o use el formato completo.</p>
        </body>
        </html>
    `);
});

app.get("/api/save_apk_link_only", async (req, res) => {
    return res.status(400).send(`
        <html>
        <body style='font-family: sans-serif; text-align: center; max-width: 600px; margin: auto; padding: 20px; background-color: #fcebeb; border: 1px solid #f5c6cb;'>
            <h1 style='color: #dc3545;'>❌ Endpoint Desactivado</h1>
            <p><strong>Use el método unificado:</strong></p>
            <h2 style='color: #007bff;'>/api/search_and_sync?q=...&apk_link=...&version=...</h2>
        </body>
        </html>
    `);
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
