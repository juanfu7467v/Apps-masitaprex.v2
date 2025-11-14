// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import fs from "fs"; 
import path from "path"; 
import puppeteer from 'puppeteer';

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;

// ----------------------------------------------------
// FUNCIÓN CENTRAL PARA INICIAR EL NAVEGADOR VIRTUAL
// ----------------------------------------------------
async function launchBrowser() {
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
   FUNCIÓN NUEVA: Búsqueda y Extracción de Metadatos de APK Pure con Puppeteer
------------------------------------------------------------------------- */
async function searchAppAndScrapeInfoAPKPure(query) {
    const browser = await launchBrowser();
    const page = await browser.newPage();
    const searchUrl = `https://apkpure.com/search?q=${encodeURIComponent(query)}`;
    
    try {
        await page.goto(searchUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // Esperamos el primer contenedor de resultado
        const resultSelector = '.apk_list > li:first-child a.search_item'; 
        
        try {
            await page.waitForSelector(resultSelector, { timeout: 15000 }); 
        } catch (e) {
            console.error(`No se encontró el primer resultado de búsqueda en APKPure.`);
            return null;
        }

        // 1. Encontrar el enlace a la página de la aplicación
        const appPageLink = await page.$eval(resultSelector, a => a.getAttribute('href')).catch(e => {
             console.error("No se pudo extraer el appPageLink (Error de eval):", e.message);
             return null;
        });

        if (!appPageLink || !appPageLink.startsWith('/')) {
             console.log("El enlace encontrado no es válido o no sigue el patrón esperado en APKPure.");
             return null;
        }
        const appPageUrl = `https://apkpure.com${appPageLink}`;

        // 2. Navegar a la página de la aplicación para metadatos detallados
        await page.goto(appPageUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // Esperar a que el botón de descarga esté cargado
        try {
            // El selector para el botón de descarga principal de la aplicación
            await page.waitForSelector('.download_box a.apk_download_btn', { timeout: 5000 });
        } catch (e) {
            console.log("No se pudo cargar la página de detalles de la aplicación o el botón de descarga no aparece.");
            return null;
        }


        // 3. Extraer Metadatos usando page.evaluate
        const metaData = await page.evaluate((appPageUrl) => {
            const getText = (selector) => document.querySelector(selector)?.textContent.trim() || '';
            const getAttr = (selector, attr) => document.querySelector(selector)?.getAttribute(attr) || '';
            
            // Extracción de nombre de paquete (packageName)
            // APK Pure lo suele tener en la URL: /paquete-de-la-app/com.ejemplo.paquete
            const packageNameMatch = appPageUrl.match(/([^/]+)$/);
            const packageName = packageNameMatch ? packageNameMatch[1] : 'unknown.package.name';
            
            const displayName = getText('.main-info .title') || 'Nombre Desconocido';
            const version = getText('.version-pw > span:nth-child(2)') || '0.0';
            
            // La descripción se corta a veces
            const description = getText('.description p') || 'No se encontró descripción.';
            
            const iconUrl = getAttr('.icon img', 'src') || '';

            // Extraer URL de Descarga - el botón "Download" principal
            const downloadLink = getAttr('.download_box a.apk_download_btn', 'href');
            
            return {
                packageName,
                displayName,
                version,
                description,
                iconUrl,
                downloadLink
            };
        }, appPageUrl); 

        if (!metaData.downloadLink) {
             console.log("No se encontró enlace de descarga directo en la página de detalles de APKPure.");
             return null;
        }
        
        // En APKPure, el primer enlace de descarga a menudo va a la página final de descarga
        const downloadPageUrl = metaData.downloadLink; // Este ya es un enlace absoluto

        // 4. Obtener el enlace final de descarga (APK Pure es directo)
        // La URL que obtenemos suele ser la URL final de descarga de la APK.
        const finalDownloadLink = downloadPageUrl; 

        return {
            packageName: metaData.packageName,
            displayName: metaData.displayName,
            version: metaData.version,
            description: metaData.description.substring(0, 500) + '...',
            iconUrl: metaData.iconUrl,
            screenshots: [], 
            downloadUrl: finalDownloadLink, 
            source: "apkpure"
        };
        
    } catch (e) {
        console.error("Error EN EL SCRAPING (GENERAL APKPure):", e.message);
        return null;
    } finally {
        await browser.close(); 
    }
}

// ---------------------------------------------------
// ENDPOINTS
// ---------------------------------------------------

/* ---------------------------------
   ENDPOINT 1: Buscar Aplicación (Ahora usando APK Pure)
   Uso: GET /api/search_app?q=facebook
------------------------------------*/
app.get("/api/search_app", async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta de búsqueda) es requerido." });

    try {
        // CAMBIAMOS A APK PURE
        const appInfo = await searchAppAndScrapeInfoAPKPure(q);
        
        if (!appInfo) {
            return res.json({ ok: true, results: [], message: "No se encontraron resultados para la búsqueda en APKPure." });
        }

        return res.json({ 
            ok: true, 
            results: [appInfo],
            message: `Resultados de búsqueda scrapeados de ${appInfo.source}.`
        });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   ENDPOINT 2: Sincronización Automática (Reutiliza la nueva búsqueda)
   Uso: POST /api/sync_app_by_search 
   Body: { query: "facebook" }
------------------------------------*/
app.post("/api/sync_app_by_search", async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ ok: false, error: "El campo 'query' es requerido en el body." });
    
    const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    try {
        // 1. Buscar y extraer metadatos usando la nueva función
        const appInfo = await searchAppAndScrapeInfoAPKPure(query); 
        if (!appInfo || !appInfo.downloadUrl) {
            return res.json({ ok: false, error: "No se encontraron datos completos o URL de descarga para la aplicación en APKPure." });
        }

        const { packageName, version, downloadUrl, displayName, description, iconUrl, screenshots } = appInfo;

        // 2. Descargar la APK usando Axios
        const apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer",
            headers: { 'User-Agent': AXIOS_USER_AGENT } 
        });
        const apkBuffer = Buffer.from(apkResp.data);

        // 3. Verificar límite de tamaño
        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }

        // 4. Guardar APK en GitHub
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${displayName} v${version} (APKPure)`);
        
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
        await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${displayName} v${version} (APKPure)`);

        return res.json({ 
            ok: true, 
            meta, 
            message: `APK y Metadatos de ${displayName} v${version} sincronizados exitosamente desde APKPure.` 
        });

    } catch (e) {
        console.error("Error en sync_app_by_search:", e);
        return res.status(500).json({ ok: false, error: `Error durante la sincronización: ${e.message}` });
    }
});

/* ---------------------------------
   ENDPOINT 3: Sincronización Masiva de Apps Populares
   Uso: POST /api/sync_popular_apps 
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
    
    const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
    
    const syncSingleApp = async (query) => {
        try {
            // Usar la nueva función de APKPure
            const appInfo = await searchAppAndScrapeInfoAPKPure(query);
            
            if (!appInfo || !appInfo.downloadUrl) {
                return { query, ok: false, message: "No se encontraron datos o URL de descarga en APKPure." };
            }

            const { packageName, version, downloadUrl, displayName } = appInfo;

            const apkResp = await axios.get(downloadUrl, { 
                responseType: "arraybuffer",
                headers: { 'User-Agent': AXIOS_USER_AGENT }
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
            await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK Masiva: ${displayName} v${version} (APKPure)`);
            
            // Subir Metadatos
            const metaPath = `public/apps/${packageName}/meta_${version}.json`;
            await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta Masiva: ${displayName} v${version} (APKPure)`);

            successCount++;
            return { query, ok: true, version, packageName, message: "Sincronizado correctamente desde APKPure." };

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
        message: "Proceso de sincronización masiva finalizado (APKPure)."
    });
});


/* ---------------------------------
   CRAWLERS ORIGINALES (Mantenidos)
------------------------------------*/

// 1) GitHub Releases fetcher
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
