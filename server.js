// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import fs from "fs"; 
import path from "path"; 
import * as cheerio from 'cheerio'; // <-- Nuevo/re-incluido
import puppeteer from 'puppeteer';

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;

// URL DE PROXY PÚBLICO (Usado para ocultar IP en búsqueda)
// ADVERTENCIA: Esta URL puede fallar o ser lenta.
const FREE_PROXY_URL = 'http://api.scraperapi.com?api_key=TU_CLAVE_AQUI&url='; // Reemplaza 'TU_CLAVE_AQUI' con una clave gratuita de ScraperAPI si tienes, o usa otro proxy
// Para la prueba, usaremos solo axios para evitar el proxy si no tienes una clave de ScraperAPI.
// Si el siguiente código falla, intenta añadir un proxy real o cambiar el User-Agent.

const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';


// ----------------------------------------------------
// FUNCIÓN CENTRAL PARA INICIAR EL NAVEGADOR VIRTUAL
// ----------------------------------------------------
async function launchBrowser() {
    // Puppeteer solo se usará para la página de descarga final si Cheerio falla en obtener el link directo.
    const browser = await puppeteer.launch({ 
        headless: true,
        args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox', 
            '--disable-dev-shm-usage'
        ],
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
        timeout: 60000 
    });
    return browser;
}


/* --------- Helpers GitHub (sin cambios) --------- */
async function createOrUpdateGithubFile(pathInRepo, contentBase64, message) {
  // ... (código helper de GitHub sin cambios)
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

/* ----------------------------------------------------------------------
   FUNCIÓN FINAL: Búsqueda y Extracción de Metadatos de Uptodown con Cheerio/Axios
   Usaremos Cheerio para mayor discreción.
------------------------------------------------------------------------- */
async function searchAppAndScrapeInfoUptodown(query) {
    const searchUrl = `https://www.uptodown.com/search?q=${encodeURIComponent(query)}`;
    
    try {
        // 1. Obtener la página de resultados de búsqueda usando Axios (simulando un navegador)
        const response = await axios.get(searchUrl, {
            headers: { 'User-Agent': AXIOS_USER_AGENT },
            timeout: 20000 
        });
        
        const $ = cheerio.load(response.data);

        // Selector para el primer resultado de la aplicación
        const resultLinkElement = $('.app-list > .item:first-child .info > a'); 
        
        if (resultLinkElement.length === 0) {
            console.error(`[Cheerio] No se encontró el primer resultado de búsqueda en Uptodown.`);
            return null;
        }

        // 2. Extraer el enlace a la página de la aplicación
        const appPageUrl = resultLinkElement.attr('href');

        if (!appPageUrl || !appPageUrl.startsWith('https://')) {
             console.log("[Cheerio] El enlace encontrado no es válido o no sigue el patrón esperado en Uptodown.");
             return null;
        }

        // 3. Navegar a la página de la aplicación para metadatos detallados (usando Axios/Cheerio nuevamente)
        const appPageResponse = await axios.get(appPageUrl, {
             headers: { 'User-Agent': AXIOS_USER_AGENT },
             timeout: 20000 
        });
        const $$ = cheerio.load(appPageResponse.data);
        
        // 4. Extraer Metadatos
        const downloadLink = $$('.button-download').attr('href');
        
        if (!downloadLink) {
             console.log("No se encontró enlace de descarga directo en la página de detalles de Uptodown.");
             return null;
        }
        
        // Extracción de PackageName (basado en la URL de Uptodown)
        const linkParts = appPageUrl.split('/');
        const appSlug = linkParts[linkParts.length - 2] || 'unknown'; 
        let packageName = `com.uptodown.${appSlug}`;
        
        // Intenta obtener el nombre de paquete del botón de descarga (a veces contiene el packageID)
        const downloadButtonText = $$('.button-download').text();
        const pkgMatch = downloadButtonText.match(/([a-zA-Z0-9.]+)\/download/);
        if (pkgMatch) {
             packageName = pkgMatch[1];
        }


        const displayName = $$('.info .name').text().trim() || 'Nombre Desconocido';
        const version = $$('.version-name').text().trim() || '0.0'; 
        const description = ($$('.full-description p').text().trim() || 'No se encontró descripción.').substring(0, 500) + '...';
        const iconUrl = $$('.logo img').attr('src') || '';
        
        // El enlace de Uptodown es directo
        const finalDownloadLink = downloadLink; 

        return {
            packageName: packageName,
            displayName: displayName,
            version: version,
            description: description,
            iconUrl: iconUrl.startsWith('//') ? 'https:' + iconUrl : iconUrl,
            screenshots: [], 
            downloadUrl: finalDownloadLink, 
            source: "uptodown"
        };
        
    } catch (e) {
        console.error("Error EN EL SCRAPING (GENERAL Uptodown/Cheerio):", e.message);
        return null;
    }
}

// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   ENDPOINT 1: Buscar Aplicación (Ahora usando Uptodown con Cheerio)
   Uso: GET /api/search_app?q=facebook
------------------------------------*/
app.get("/api/search_app", async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta de búsqueda) es requerido." });

    try {
        const appInfo = await searchAppAndScrapeInfoUptodown(q);
        
        if (!appInfo) {
            return res.json({ ok: true, results: [], message: "No se encontraron resultados para la búsqueda en Uptodown (cheerio)." });
        }

        return res.json({ 
            ok: true, 
            results: [appInfo],
            message: `Resultados de búsqueda scrapeados de ${appInfo.source} (cheerio).`
        });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   ENDPOINT 2: Sincronización Automática
   Uso: POST /api/sync_app_by_search 
   Body: { query: "facebook" }
------------------------------------*/
app.post("/api/sync_app_by_search", async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ ok: false, error: "El campo 'query' es requerido en el body." });
    
    const AXIOS_USER_AGENT_DOWNLOAD = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    try {
        // 1. Buscar y extraer metadatos usando Cheerio
        const appInfo = await searchAppAndScrapeInfoUptodown(query); 
        if (!appInfo || !appInfo.downloadUrl) {
            return res.json({ ok: false, error: "No se encontraron datos completos o URL de descarga para la aplicación en Uptodown." });
        }

        const { packageName, version, downloadUrl, displayName, description, iconUrl, screenshots } = appInfo;

        // 2. Descargar la APK usando Axios
        const apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer",
            headers: { 'User-Agent': AXIOS_USER_AGENT_DOWNLOAD },
            timeout: 60000 // Aumentar timeout para descarga de archivo grande
        });
        const apkBuffer = Buffer.from(apkResp.data);

        // 3. Verificar límite de tamaño
        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }

        // 4. Guardar APK en GitHub
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${displayName} v${version} (Uptodown/Cheerio)`);
        
        // 5. Crear Metadatos completos
        const meta = {
            source: appInfo.source,
            packageName,
            displayName,
            version,
            description,
            iconUrl,
            screenshots,
            size: apkBuffer.length,
            addedAt: new Date().toISOString(),
            apkPath
        };

        // 6. Guardar Metadatos en GitHub
        const metaPath = `public/apps/${packageName}/meta_${version}.json`;
        await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${displayName} v${version} (Uptodown/Cheerio)`);

        return res.json({ 
            ok: true, 
            meta, 
            message: `APK y Metadatos de ${displayName} v${version} sincronizados exitosamente desde Uptodown (Cheerio).` 
        });

    } catch (e) {
        console.error("Error en sync_app_by_search:", e);
        return res.status(500).json({ ok: false, error: `Error durante la sincronización: ${e.message}` });
    }
});

/* ---------------------------------
   ENDPOINT 3: Sincronización Masiva de Apps Populares
------------------------------------*/
const POPULAR_APPS = [
    "facebook",
    "whatsapp",
    "instagram",
    "telegram",
    "spotify"
];

app.post("/api/sync_popular_apps", async (req, res) => {
    let results = [];
    let successCount = 0;
    
    const AXIOS_USER_AGENT_DOWNLOAD = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
    
    const syncSingleApp = async (query) => {
        try {
            // Usar la nueva función de Uptodown con Cheerio
            const appInfo = await searchAppAndScrapeInfoUptodown(query);
            
            if (!appInfo || !appInfo.downloadUrl) {
                return { query, ok: false, message: "No se encontraron datos o URL de descarga en Uptodown (Cheerio)." };
            }

            const { packageName, version, downloadUrl, displayName } = appInfo;

            const apkResp = await axios.get(downloadUrl, { 
                responseType: "arraybuffer",
                headers: { 'User-Agent': AXIOS_USER_AGENT_DOWNLOAD }
            });
            const apkBuffer = Buffer.from(apkResp.data);

            if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
                return { query, ok: false, message: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB).` };
            }

            // Guardar APK y Metadatos en GitHub
            const base64Apk = apkBuffer.toString("base64");
            const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
            
            const meta = {
                source: appInfo.source,
                packageName,
                displayName,
                version,
                size: apkBuffer.length,
                addedAt: new Date().toISOString(),
                apkPath,
                description: appInfo.description,
                iconUrl: appInfo.iconUrl,
                screenshots: appInfo.screenshots
            };
            
            // Subir APK
            await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK Masiva: ${displayName} v${version} (Uptodown/Cheerio)`);
            
            // Subir Metadatos
            const metaPath = `public/apps/${packageName}/meta_${version}.json`;
            await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta Masiva: ${displayName} v${version} (Uptodown/Cheerio)`);

            successCount++;
            return { query, ok: true, version, packageName, message: "Sincronizado correctamente desde Uptodown (Cheerio)." };

        } catch (e) {
            console.error(`Error al sincronizar ${query}:`, e.message);
            return { query, ok: false, message: `Error desconocido: ${e.message}` };
        }
    };

    for (const appQuery of POPULAR_APPS) {
        const result = await syncSingleApp(appQuery);
        results.push(result);
    }

    return res.json({ 
        ok: true, 
        totalProcessed: POPULAR_APPS.length,
        totalSuccess: successCount,
        results,
        message: "Proceso de sincronización masiva finalizado (Uptodown/Cheerio)."
    });
});


/* ---------------------------------
   CRAWLERS ORIGINALES (Mantenidos)
------------------------------------*/
// ... (El resto de los endpoints de sync_github_release, sync_fdroid, manual_add, list_apps, get_app_meta, ping permanecen igual)
// Los endpoints de sync_github_release, sync_fdroid, manual_add, list_apps, get_app_meta, y ping no necesitan cambios.
// Mantener el código original de esos endpoints.

app.get("/api/sync_github_release", async (req, res) => {
  const { repo, packageName } = req.query; 
  if (!repo) return res.status(400).json({ ok:false, error: "repo param required (owner/repo)"});
  try {
    const [owner, repoName] = repo.split("/");
    const pName = packageName || repoName;
    const releases = await octokit.repos.listReleases({ owner, repo: repoName, per_page: 5 });
    if (!releases.data.length) return res.json({ ok:false, error: "No releases found" });

    let assetUrl=null, assetName=null, version=null;
    for (const r of releases.data) {
      version = r.tag_name || r.name || "unknown";
      if (r.assets && r.assets.length) {
        for (const a of r.assets) {
          if (a.name.endsWith(".apk")) {
            assetUrl = a.browser_download_url;
            assetName = a.name;
            break;
          }
        }
      }
      if (assetUrl) break;
    }
    if (!assetUrl) return res.json({ ok:false, error: "No APK asset in recent releases" });

    const apkResp = await axios.get(assetUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);

    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage (S3) or Git LFS.`});
    }

    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${pName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Add APK ${pName} ${version}`);

    const meta = {
      source: "github_release",
      owner,
      repo: repoName,
      packageName: pName,
      version,
      assetName,
      size: apkBuffer.length,
      addedAt: new Date().toISOString(),
      apkPath
    };
    const metaPath = `public/apps/${pName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${pName} ${version}`);

    return res.json({ ok:true, meta, message: "APK sincronizado." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 2) F-Droid fetcher (requires package name)
app.get("/api/sync_fdroid", async (req, res) => {
  const { packageName } = req.query;
  if (!packageName) return res.status(400).json({ ok:false, error:"packageName required" });
  try {
    const page = `https://f-droid.org/en/packages/${packageName}/`;
    const html = await axios.get(page).then(r=>r.data).catch(()=>null);
    if (!html) return res.json({ ok:false, error: "Package not found on F-Droid" });

    const m = html.match(/href="([^"]+\.apk)"/);
    if (!m) return res.json({ ok:false, error:"APK link not found in page" });
    let apkUrl = m[1];
    if (!apkUrl.startsWith("http")) apkUrl = "https://f-droid.org" + apkUrl;

    const apkResp = await axios.get(apkUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);
    const versionMatch = html.match(/Version<\/th>\s*<td[^>]*>([^<]+)</);
    const version = versionMatch ? versionMatch[1].trim() : "unknown";

    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage.`});
    }
    
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, apkBuffer.toString("base64"), `Add F-Droid APK ${packageName} ${version}`);

    const meta = {
      source: "f-droid",
      packageName,
      version,
      size: apkBuffer.length,
      addedAt: new Date().toISOString(),
      apkPath
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${packageName} ${version}`);

    return res.json({ ok:true, meta, message: "APK sincronizado." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 3) Manual add by direct URL
app.post("/api/manual_add", async (req, res) => {
  try {
    const { url, packageName, displayName } = req.body;
    if (!url || !packageName) return res.status(400).json({ ok:false, error:"url and packageName required" });
    
    const apkResp = await axios.get(url, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);
    
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage.`});
    }
    
    const version = "manual-" + Date.now();
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, apkBuffer.toString("base64"), `Add manual APK ${packageName} ${version}`);
    
    const meta = { 
        source:"manual", 
        url, 
        packageName, 
        displayName, 
        size: apkBuffer.length, 
        addedAt: new Date().toISOString(), 
        apkPath 
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${packageName} ${version}`);
    
    return res.json({ ok:true, meta, message: "APK agregado manualmente." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 4) List apps simple: reads repo tree for public/apps
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

// 5) Get metadata for a package (most recent meta_*.json)
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
